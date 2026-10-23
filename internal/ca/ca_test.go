package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/backend"
)

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func newCA(t *testing.T) (*CA, string) {
	dir := filepath.Join(t.TempDir(), "ca")
	if err := Init(dir, Options{Name: "test CA"}, now); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c, dir
}

func parse(t *testing.T, certPEM []byte) *x509.Certificate {
	blk, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestInitModesAndNoOverwrite(t *testing.T) {
	c, dir := newCA(t)
	if st, _ := os.Stat(filepath.Join(dir, "ca.key")); st.Mode().Perm() != 0o600 {
		t.Errorf("the key has mode %o", st.Mode().Perm())
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("the directory has mode %o", st.Mode().Perm())
	}
	if !c.Cert.IsCA || c.Cert.MaxPathLen != 0 || !c.Cert.MaxPathLenZero || c.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("the CA certificate: %+v", c.Cert)
	}
	if got := c.Cert.NotAfter.Sub(now).Hours() / 24; got < 3649 || got > 3651 {
		t.Errorf("the life of the authority: %v days", got)
	}
	if err := Init(dir, Options{Name: "again"}, now); err == nil {
		t.Error("an existing authority was overwritten")
	}
}

func TestLoadRefusesWhatIsNotSafe(t *testing.T) {
	_, dir := newCA(t)
	kp := filepath.Join(dir, "ca.key")
	os.Chmod(kp, 0o640)
	if _, err := Load(dir, nil); err == nil || !strings.Contains(err.Error(), "cannot read") {
		t.Errorf("a key readable by the group: %v", err)
	}
	os.Chmod(kp, 0o600)
	// the key of another authority with the certificate of this one
	_, dir2 := newCA(t)
	b, _ := os.ReadFile(filepath.Join(dir2, "ca.key"))
	os.WriteFile(kp, b, 0o600)
	if _, err := Load(dir, nil); err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Errorf("a key that does not match: %v", err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "none"), nil); err == nil {
		t.Error("a missing authority")
	}
}

func TestServerAndClientCertificatesVerify(t *testing.T) {
	c, _ := newCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	srv, err := c.Issue(Request{Kind: Server, DNS: []string{"hsmgate.example"}, IPs: []net.IP{net.ParseIP("192.168.1.5")}}, now)
	if err != nil {
		t.Fatal(err)
	}
	s := parse(t, srv.CertPEM)
	if s.Subject.CommonName != "hsmgate.example" {
		t.Errorf("the default common name: %q", s.Subject.CommonName)
	}
	for _, name := range []string{"hsmgate.example", "192.168.1.5"} {
		if _, err := s.Verify(x509.VerifyOptions{Roots: pool, DNSName: name, CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("server %s: %v", name, err)
		}
	}
	if _, err := s.Verify(x509.VerifyOptions{Roots: pool, DNSName: "other.example", CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("a name that is not in the certificate verified")
	}
	if _, err := s.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("a server certificate was good for a client")
	}
	cl, err := c.Issue(Request{Kind: Client, CN: "demo", URIs: []string{"spiffe://example.org/ns/x/sa/demo"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	k := parse(t, cl.CertPEM)
	if k.Subject.CommonName != "demo" || len(k.URIs) != 1 || k.URIs[0].String() != "spiffe://example.org/ns/x/sa/demo" {
		t.Errorf("the client certificate: %+v", k.Subject)
	}
	if _, err := k.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Errorf("client: %v", err)
	}
	if _, err := k.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Error("a client certificate was good for a server")
	}
	// another authority's certificate does not verify, and neither does an expired one
	other, _ := newCA(t)
	foreign, _ := other.Issue(Request{Kind: Client, CN: "demo"}, now)
	if _, err := parse(t, foreign.CertPEM).Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("a certificate of another authority verified")
	}
	if _, err := k.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.AddDate(0, 0, 400), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Error("an expired certificate verified")
	}
	if len(cl.Fingerprint) != 64 || cl.Fingerprint == srv.Fingerprint {
		t.Errorf("fingerprint %q", cl.Fingerprint)
	}
}

func TestIssueRefusals(t *testing.T) {
	c, _ := newCA(t)
	for name, r := range map[string]Request{
		"a server with no name":     {Kind: Server},
		"a client with no identity": {Kind: Client},
		"a client with a DNS name":  {Kind: Client, CN: "x", DNS: []string{"a.example"}},
		"a bad DNS name":            {Kind: Server, DNS: []string{"a b"}},
		"a bad URI":                 {Kind: Client, URIs: []string{"nope"}},
		"outliving the authority":   {Kind: Client, CN: "x", Days: 5000},
		"a bad common name":         {Kind: Client, CN: "a/b"},
		"no kind":                   {CN: "x"},
		"too many names":            {Kind: Server, DNS: strings.Split(strings.Repeat("a.example,", 25), ",")[:25]},
	} {
		if _, err := c.Issue(r, now); err == nil {
			t.Errorf("%s was issued", name)
		}
	}
	if _, err := c.Issue(Request{Kind: Client, CN: "x"}, now.AddDate(11, 0, 0)); err == nil {
		t.Error("issued by an expired authority")
	}
}

func TestIndexAndFiles(t *testing.T) {
	c, dir := newCA(t)
	a, _ := c.Issue(Request{Kind: Client, CN: "demo"}, now)
	b, _ := c.Issue(Request{Kind: Server, DNS: []string{"h.example"}, IPs: []net.IP{net.ParseIP("10.0.0.1")}}, now)
	list, err := c.List()
	if err != nil || len(list) != 2 || list[0].Fingerprint != a.Fingerprint || list[1].Kind != "server" || !strings.Contains(list[1].Names, "10.0.0.1") {
		t.Fatalf("%+v %v", list, err)
	}
	out := t.TempDir()
	if err := WriteFiles(a, filepath.Join(out, "demo.pem"), filepath.Join(out, "demo.key"), ""); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(filepath.Join(out, "demo.key")); st.Mode().Perm() != 0o400 {
		t.Errorf("the key file has mode %o", st.Mode().Perm())
	}
	if err := WriteFiles(b, filepath.Join(out, "demo.pem"), filepath.Join(out, "x.key"), ""); err == nil {
		t.Error("a certificate file was overwritten")
	}
	if _, err := os.Stat(filepath.Join(out, "x.key")); err == nil {
		t.Error("the key of a failed write is left behind")
	}
	if err := WriteFiles(a, filepath.Join(out, "a.pem"), filepath.Join(out, "a.key"), "no-such-user-hsmgate"); err == nil {
		t.Error("an unknown owner")
	}
	if _, err := os.Stat(filepath.Join(dir, "index.tsv")); err != nil {
		t.Error(err)
	}
}

// What it is for: a TLS 1.3 handshake with the certificates, the way the service uses them (the client must show its certificate).
func TestMutualTLS13(t *testing.T) {
	c, _ := newCA(t)
	srv, _ := c.Issue(Request{Kind: Server, IPs: []net.IP{net.ParseIP("127.0.0.1")}}, time.Now())
	cl, _ := c.Issue(Request{Kind: Client, CN: "demo"}, time.Now())
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	sc, err := tls.X509KeyPair(srv.CertPEM, srv.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := tls.X509KeyPair(cl.CertPEM, cl.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{sc}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			got <- "accept: " + err.Error()
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			got <- "handshake: " + err.Error()
			return
		}
		got <- tc.ConnectionState().PeerCertificates[0].Subject.CommonName
	}()
	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{cc}})
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if who := <-got; who != "demo" {
		t.Errorf("the server saw %q", who)
	}
}

// a soft token with one key: the same scalar serves ECDH (sealing) and ECDSA (a signing key of the token); a real token keeps the two uses apart
func softToken(t *testing.T, seed string) backend.Token {
	p := filepath.Join(t.TempDir(), "k.hex")
	if err := os.WriteFile(p, []byte(strings.Repeat(seed, 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	tok, err := backend.NewSoft(map[string]string{"m": p})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func files(t *testing.T, dir string) []string {
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

func verifies(t *testing.T, c *CA, certPEM []byte, usage x509.ExtKeyUsage) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(c.Cert)
	if _, err := parse(t, certPEM).Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now.Add(time.Hour), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
		t.Errorf("the certificate does not verify: %v", err)
	}
}

func TestKeyOnTheTokenNeverExistsAnywhereElse(t *testing.T) {
	tok := softToken(t, "0b")
	dir := filepath.Join(t.TempDir(), "ca")
	if err := Init(dir, Options{Mode: ModeToken, Token: tok, TokenName: "card", Label: "m"}, now); err != nil {
		t.Fatal(err)
	}
	// nothing secret in the directory: a certificate, a note of where the key is, an index
	if got := strings.Join(files(t, dir), " "); got != "ca.json ca.pem" {
		t.Errorf("the files: %s", got)
	}
	c, err := Load(dir, tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Meta.Mode != ModeToken || c.Meta.Token != "card" || c.Meta.Label != "m" {
		t.Errorf("%+v", c.Meta)
	}
	point, _ := tok.Point("m")
	if !bytes.Equal(point, mustPoint(t, c.Cert)) {
		t.Error("the certificate does not carry the public key of the token's key")
	}
	cl, err := c.Issue(Request{Kind: Client, CN: "demo"}, now)
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, c, cl.CertPEM, x509.ExtKeyUsageClientAuth)
	// without the token, or with another token's key, nothing is signed
	if _, err := Load(dir, nil); err == nil {
		t.Error("loaded without the token")
	}
	if _, err := Load(dir, softToken(t, "0c")); err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Errorf("another token's key: %v", err)
	}
	if err := Init(dir, Options{Mode: ModeToken, Token: tok, TokenName: "card", Label: "m"}, now); err == nil {
		t.Error("overwritten")
	}
	if _, err := Open(dir); err != nil { // the public part needs no token
		t.Error(err)
	}
}

func mustPoint(t *testing.T, c *x509.Certificate) []byte {
	pub := c.PublicKey.(*ecdsa.PublicKey)
	b, err := pub.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSealedKeyIsNoSecretAndOpensOnlyWithTheToken(t *testing.T) {
	tok := softToken(t, "0b")
	dir := filepath.Join(t.TempDir(), "ca")
	if err := Init(dir, Options{Mode: ModeSealed, Token: tok, TokenName: "card", Label: "m"}, now); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(files(t, dir), " "); got != "ca.json ca.key.sealed ca.pem" {
		t.Errorf("the files: %s", got)
	}
	sealed, _ := os.ReadFile(filepath.Join(dir, "ca.key.sealed"))
	if !strings.HasPrefix(string(sealed), "ecies2.") || bytes.Contains(sealed, []byte("PRIVATE KEY")) {
		t.Errorf("the sealed file: %.30s", sealed)
	}
	c, err := Load(dir, tok)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := c.Issue(Request{Kind: Server, IPs: []net.IP{net.ParseIP("10.1.1.1")}}, now)
	if err != nil {
		t.Fatal(err)
	}
	verifies(t, c, srv.CertPEM, x509.ExtKeyUsageServerAuth)
	if _, err := Load(dir, nil); err == nil || !strings.Contains(err.Error(), "sealed to a token") {
		t.Errorf("without the token: %v", err)
	}
	if _, err := Load(dir, softToken(t, "0c")); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Errorf("another token: %v", err)
	}
	// a damaged sealed file
	bad := []byte(strings.Replace(string(sealed), "ecies2.", "ecies2.00", 1))
	os.WriteFile(filepath.Join(dir, "ca.key.sealed"), bad, 0o644)
	if _, err := Load(dir, tok); err == nil {
		t.Error("a damaged sealed key opened")
	}
}

func TestInitRefusesWhatNeedsATokenWithoutOne(t *testing.T) {
	for _, m := range []Mode{ModeSealed, ModeToken} {
		if err := Init(filepath.Join(t.TempDir(), "ca"), Options{Mode: m}, now); err == nil {
			t.Errorf("%s with no token", m)
		}
	}
	if err := Init(filepath.Join(t.TempDir(), "ca"), Options{Mode: "nope", Token: softToken(t, "0b"), TokenName: "t", Label: "m"}, now); err == nil {
		t.Error("an unknown mode")
	}
	if err := Init(filepath.Join(t.TempDir(), "ca"), Options{Mode: ModeToken, Token: softToken(t, "0b"), TokenName: "t", Label: "nope"}, now); err == nil {
		t.Error("a key the token does not have")
	}
}
