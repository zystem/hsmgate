// Package ca is a small certificate authority for the certificates of hsmgate itself: a server certificate for the listener and client certificates for the programs that call it, so
// that nothing outside the program (no openssl) is needed to bring the service up with mutual TLS. It is made of the standard library (crypto/x509, ECDSA P-256, SHA-256) and nothing
// else. One authority has one key and one certificate in a directory; each certificate that it issues is recorded in an index. There is no revocation list: a client is refused by
// removing it from the configuration (a reload applies at once), a server certificate by replacing it.
//
// Where the key of the authority lives is a choice (Mode): in a file (ModeFile: simple, and the file must be kept as a secret), sealed to a token (ModeSealed: the key is made in
// memory, written only in the form sealed to the public key of a token's ECDH key, and opened by the token for the time of a signing: the files of the directory are no secret), or
// on the token (ModeToken: the key is a signing key of the token, which makes the signatures; it never exists anywhere else).
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

const (
	keyFile    = "ca.key"
	sealedFile = "ca.key.sealed"
	certFile   = "ca.pem"
	indexFile  = "index.tsv"
	metaFile   = "ca.json"
	sealAAD    = "hsmgate/ca/key/v1"

	// DefaultCADays is the life of a new authority; DefaultDays the life of a certificate that it issues.
	DefaultCADays = 3650
	DefaultDays   = 365
	maxNames      = 20
	clockSkew     = 5 * time.Minute
)

// Kind is what a certificate is for.
type Kind int

const (
	Server Kind = iota + 1
	Client
)

func (k Kind) String() string {
	if k == Server {
		return "server"
	}
	return "client"
}

// Mode says where the key of the authority is.
type Mode string

const (
	ModeFile   Mode = "file"
	ModeSealed Mode = "sealed"
	ModeToken  Mode = "token"
)

// Meta is what ca.json records: the mode, and for the modes that use a token its name and the label of its key (the names of a configuration of the service).
type Meta struct {
	Mode  Mode   `json:"mode"`
	Token string `json:"token,omitempty"`
	Label string `json:"label,omitempty"`
}

// CA is an authority loaded from its directory.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Meta    Meta
	signer  crypto.Signer
	dir     string
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

// writeNew creates a file that must not exist yet, with the mode given, and writes b to it.
func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304 -- the path is the operator's
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists: it is not overwritten", path)
		}
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Options are the choices of Init. Mode "" is ModeFile. The other modes need a Token and the Label of one of its keys (and TokenName, the name the configuration gives the token,
// which is recorded so that a later command opens the same one). For ModeSealed the key is an ECDH key of the token (the master key, or a key of its own); for ModeToken it is a
// signing key that is already on the token (a key is used for signing or for ECDH, never both).
type Options struct {
	Name      string
	Days      int
	Mode      Mode
	Token     backend.Token
	TokenName string
	Label     string
}

// tokenSigner is a crypto.Signer whose signatures are made by a key of a token.
type tokenSigner struct {
	tok   backend.Token
	label string
	pub   *ecdsa.PublicKey
}

func (t *tokenSigner) Public() crypto.PublicKey { return t.pub }

func (t *tokenSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, errors.New("the token signs ECDSA P-256 over SHA-256 only")
	}
	return t.tok.Sign(t.label, digest)
}

func newTokenSigner(tok backend.Token, label string) (*tokenSigner, error) {
	point, err := tok.Point(label)
	if err != nil {
		return nil, fmt.Errorf("the token's key %q: %w", label, err)
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return nil, fmt.Errorf("the token's key %q: %w", label, err)
	}
	return &tokenSigner{tok: tok, label: label, pub: pub}, nil
}

// derive adapts a token key to the Deriver of the sealed format.
type derive struct {
	tok   backend.Token
	label string
}

func (d derive) Derive(peer []byte) ([]byte, error) { return d.tok.Derive(d.label, peer) }

// Init makes a new authority in dir (which is created, mode 0700, if it is not there). It refuses to touch a directory that already holds one.
func Init(dir string, o Options, now time.Time) error {
	name, days, mode := o.Name, o.Days, o.Mode
	if name == "" {
		name = "hsmgate CA"
	}
	if days <= 0 {
		days = DefaultCADays
	}
	if mode == "" {
		mode = ModeFile
	}
	if mode != ModeFile && (o.Token == nil || o.Label == "" || o.TokenName == "") {
		return fmt.Errorf("the mode %s needs a token and the label of its key", mode)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, f := range []string{keyFile, sealedFile, certFile, metaFile} {
		if _, err := os.Lstat(filepath.Join(dir, f)); err == nil {
			return fmt.Errorf("%s already holds an authority: it is not overwritten", dir)
		}
	}
	var signer crypto.Signer
	var keyDER []byte
	switch mode {
	case ModeFile, ModeSealed:
		key, err := newKey()
		if err != nil {
			return err
		}
		signer = key
		if keyDER, err = x509.MarshalPKCS8PrivateKey(key); err != nil {
			return err
		}
		defer wipe(keyDER)
	case ModeToken:
		ts, err := newTokenSigner(o.Token, o.Label)
		if err != nil {
			return err
		}
		signer = ts
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	sn, err := serial()
	if err != nil {
		return err
	}
	tpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              now.AddDate(0, 0, days).UTC(),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true, // it signs certificates of programs, not other authorities
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, signer.Public(), signer)
	if err != nil {
		return err
	}
	switch mode {
	case ModeFile:
		if err := writeNew(filepath.Join(dir, keyFile), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
			return err
		}
	case ModeSealed:
		point, err := o.Token.Point(o.Label)
		if err != nil {
			return fmt.Errorf("the token's key %q: %w", o.Label, err)
		}
		text, err := ecies.Wrap(point, keyDER, []byte(sealAAD)) // sealing needs no login
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(dir, sealedFile), []byte(text+"\n"), 0o644); err != nil {
			return err
		}
	}
	meta := Meta{Mode: mode}
	if mode != ModeFile {
		meta.Token, meta.Label = o.TokenName, o.Label
	}
	mb, _ := json.MarshalIndent(meta, "", "  ")
	if err := writeNew(filepath.Join(dir, metaFile), append(mb, '\n'), 0o644); err != nil {
		return err
	}
	return writeNew(filepath.Join(dir, certFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ReadMeta reads ca.json (an authority made before the modes existed has none: it is a file authority).
func ReadMeta(dir string) (Meta, error) {
	b, err := os.ReadFile(filepath.Join(dir, metaFile)) // #nosec G304
	if errors.Is(err, os.ErrNotExist) {
		return Meta{Mode: ModeFile}, nil
	}
	if err != nil {
		return Meta{}, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return Meta{}, fmt.Errorf("%s: %w", filepath.Join(dir, metaFile), err)
	}
	switch m.Mode {
	case ModeFile, ModeSealed, ModeToken:
		return m, nil
	}
	return Meta{}, fmt.Errorf("%s: unknown mode %q", filepath.Join(dir, metaFile), m.Mode)
}

func readCert(dir string) (*x509.Certificate, []byte, error) {
	cp := filepath.Join(dir, certFile)
	cb, err := os.ReadFile(cp) // #nosec G304
	if err != nil {
		return nil, nil, fmt.Errorf("no authority in %s (make one with: hsmgate ca init -dir %s)", dir, dir)
	}
	cblk, _ := pem.Decode(cb)
	if cblk == nil {
		return nil, nil, fmt.Errorf("%s holds no PEM block", cp)
	}
	cert, err := x509.ParseCertificate(cblk.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", cp, err)
	}
	if !cert.IsCA {
		return nil, nil, fmt.Errorf("%s is not a CA certificate", cp)
	}
	return cert, cb, nil
}

// Open reads what is public about the authority: its certificate and where its key is. It needs no key and no token.
func Open(dir string) (*CA, error) {
	meta, err := ReadMeta(dir)
	if err != nil {
		return nil, err
	}
	cert, cb, err := readCert(dir)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, CertPEM: cb, Meta: meta, dir: dir}, nil
}

// Load reads the authority of dir and makes it ready to sign. A file authority needs a key file that group and others cannot read; a sealed one needs tok to open its key (the
// token must be unlocked); one on a token needs tok to sign. In each case the key must be the one of the certificate.
func Load(dir string, tok backend.Token) (*CA, error) {
	c, err := Open(dir)
	if err != nil {
		return nil, err
	}
	switch c.Meta.Mode {
	case ModeFile:
		kp := filepath.Join(dir, keyFile)
		st, err := os.Lstat(kp)
		if err != nil {
			return nil, fmt.Errorf("no key in %s (make an authority with: hsmgate ca init -dir %s)", dir, dir)
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s must be a regular file that group and others cannot read (mode %o)", kp, st.Mode().Perm())
		}
		kb, err := os.ReadFile(kp) // #nosec G304
		if err != nil {
			return nil, err
		}
		blk, _ := pem.Decode(kb)
		if blk == nil {
			return nil, fmt.Errorf("%s holds no PEM block", kp)
		}
		if c.signer, err = parseKey(blk.Bytes, kp); err != nil {
			return nil, err
		}
	case ModeSealed:
		if tok == nil {
			return nil, errors.New("this authority's key is sealed to a token: give the token (-config, -token) and unlock it")
		}
		text, err := os.ReadFile(filepath.Join(dir, sealedFile)) // #nosec G304
		if err != nil {
			return nil, err
		}
		point, err := tok.Point(c.Meta.Label)
		if err != nil {
			return nil, fmt.Errorf("the token's key %q: %w", c.Meta.Label, err)
		}
		der, err := ecies.Unwrap(point, derive{tok, c.Meta.Label}, strings.TrimSpace(string(text)), []byte(sealAAD))
		if err != nil {
			if errors.Is(err, ecies.ErrWrongKey) || errors.Is(err, ecies.ErrDamaged) {
				return nil, errors.New("the sealed key does not open with this token's key: it is another token, or the file is damaged")
			}
			return nil, err
		}
		defer wipe(der)
		if c.signer, err = parseKey(der, filepath.Join(dir, sealedFile)); err != nil {
			return nil, err
		}
	case ModeToken:
		if tok == nil {
			return nil, errors.New("this authority's key is on a token: give the token (-config, -token) and unlock it")
		}
		ts, err := newTokenSigner(tok, c.Meta.Label)
		if err != nil {
			return nil, err
		}
		c.signer = ts
	}
	pub, ok := c.Cert.PublicKey.(*ecdsa.PublicKey)
	sp, sok := c.signer.Public().(*ecdsa.PublicKey)
	if !ok || !sok || !pub.Equal(sp) {
		return nil, fmt.Errorf("the key of the authority (%s) is not the key of %s", c.Meta.Mode, filepath.Join(dir, certFile))
	}
	return c, nil
}

func parseKey(der []byte, where string) (*ecdsa.PrivateKey, error) {
	pk, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	key, ok := pk.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not an ECDSA P-256 key", where)
	}
	return key, nil
}

// Request is a certificate to issue. A server needs at least one DNS name or IP address; a client needs a CN or a URI (the identity that the policy of the service matches: cn, uri
// or the sha256 of the certificate).
type Request struct {
	Kind Kind
	CN   string
	DNS  []string
	IPs  []net.IP
	URIs []string
	Days int
}

// Issued is the result: the certificate, its private key (PKCS#8, PEM) and the hex SHA-256 of the certificate, which is what `identity: {sha256: …}` of a client holds.
type Issued struct {
	CertPEM     []byte
	KeyPEM      []byte
	Fingerprint string
	Serial      string
	NotAfter    time.Time
}

func validName(s string) bool {
	return s != "" && len(s) <= 253 && !strings.ContainsAny(s, " \t\r\n/\\\x00")
}

// Issue makes a key pair and a certificate signed by the authority, and records it in the index. It never makes a certificate that outlives the authority.
func (c *CA) Issue(r Request, now time.Time) (*Issued, error) {
	days := r.Days
	if days <= 0 {
		days = DefaultDays
	}
	notAfter := now.AddDate(0, 0, days).UTC()
	if notAfter.After(c.Cert.NotAfter) {
		return nil, fmt.Errorf("the certificate would outlive the authority (it ends %s): give fewer days", c.Cert.NotAfter.Format("2006-01-02"))
	}
	if !now.Before(c.Cert.NotAfter) {
		return nil, fmt.Errorf("the authority expired on %s", c.Cert.NotAfter.Format("2006-01-02"))
	}
	if len(r.DNS)+len(r.IPs)+len(r.URIs) > maxNames {
		return nil, fmt.Errorf("at most %d names in a certificate", maxNames)
	}
	tpl := &x509.Certificate{
		NotBefore:             now.Add(-clockSkew).UTC(),
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	for _, d := range r.DNS {
		if !validName(d) {
			return nil, fmt.Errorf("%q is not a DNS name", d)
		}
	}
	tpl.DNSNames = r.DNS
	tpl.IPAddresses = r.IPs
	for _, u := range r.URIs {
		pu, err := url.Parse(u)
		if err != nil || pu.Scheme == "" || pu.Host == "" && pu.Opaque == "" {
			return nil, fmt.Errorf("%q is not a URI", u)
		}
		tpl.URIs = append(tpl.URIs, pu)
	}
	switch r.Kind {
	case Server:
		if len(r.DNS)+len(r.IPs) == 0 {
			return nil, errors.New("a server certificate needs at least one DNS name or IP address")
		}
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.Subject.CommonName = r.CN
		if tpl.Subject.CommonName == "" {
			if len(r.DNS) > 0 {
				tpl.Subject.CommonName = r.DNS[0]
			} else {
				tpl.Subject.CommonName = r.IPs[0].String()
			}
		}
	case Client:
		if r.CN == "" && len(r.URIs) == 0 {
			return nil, errors.New("a client certificate needs a CN or a URI")
		}
		if len(r.DNS)+len(r.IPs) > 0 {
			return nil, errors.New("a client certificate has no DNS names or IP addresses")
		}
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		tpl.Subject.CommonName = r.CN
	default:
		return nil, errors.New("unknown kind")
	}
	if tpl.Subject.CommonName != "" && !validName(tpl.Subject.CommonName) {
		return nil, fmt.Errorf("%q is not a usable common name", tpl.Subject.CommonName)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tpl.SerialNumber = sn
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, c.Cert, &key.PublicKey, c.signer)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	out := &Issued{
		CertPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:      pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		Fingerprint: hex.EncodeToString(sum[:]),
		Serial:      hex.EncodeToString(sn.Bytes()),
		NotAfter:    notAfter,
	}
	if err := c.record(r, tpl, out); err != nil {
		return nil, err
	}
	return out, nil
}

// record appends a line to the index: serial, kind, common name, names, end of life, fingerprint.
func (c *CA) record(r Request, tpl *x509.Certificate, o *Issued) error {
	var names []string
	names = append(names, tpl.DNSNames...)
	for _, ip := range tpl.IPAddresses {
		names = append(names, ip.String())
	}
	for _, u := range tpl.URIs {
		names = append(names, u.String())
	}
	line := strings.Join([]string{o.Serial, r.Kind.String(), tpl.Subject.CommonName, strings.Join(names, ","), o.NotAfter.Format("2006-01-02"), o.Fingerprint}, "\t") + "\n"
	f, err := os.OpenFile(filepath.Join(c.dir, indexFile), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) // #nosec G304
	if err != nil {
		return err
	}
	if _, err := f.WriteString(line); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Entry is a line of the index.
type Entry struct {
	Serial, Kind, CN, Names, NotAfter, Fingerprint string
}

// List reads the index of what the authority has issued.
func (c *CA) List() ([]Entry, error) {
	b, err := os.ReadFile(filepath.Join(c.dir, indexFile)) // #nosec G304
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		f := strings.Split(l, "\t")
		if len(f) != 6 {
			continue
		}
		out = append(out, Entry{f[0], f[1], f[2], f[3], f[4], f[5]})
	}
	return out, nil
}

// WriteFiles writes an issued certificate and its key into dir under the names given: the key with mode 0400 and the certificate with 0644; neither is overwritten. owner, if not
// empty, becomes the owner of both (the user the service runs as, so that it can read its key).
func WriteFiles(o *Issued, certPath, keyPath, owner string) error {
	if err := writeNew(keyPath, o.KeyPEM, 0o400); err != nil {
		return err
	}
	if err := writeNew(certPath, o.CertPEM, 0o644); err != nil {
		os.Remove(keyPath)
		return err
	}
	if owner != "" {
		return chown(owner, certPath, keyPath)
	}
	return nil
}
