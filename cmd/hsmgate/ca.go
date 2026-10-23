package main

// hsmgate ca: the certificates of the service without openssl (internal/ca). init makes the authority; server and client issue the certificate of the listener and of a calling
// program; list shows what was issued.

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/ca"
	"github.com/zystem/hsmgate/internal/config"
)

const caUsage = `usage: hsmgate ca init   -dir DIR [-name "hsmgate CA"] [-days 3650] [-mode file|sealed|token -config hsmgate.yaml -token NAME -label LABEL]
       hsmgate ca server -dir DIR -out DIR (-dns NAME[,NAME] | -ip ADDR[,ADDR]) [-cn NAME] [-days 365] [-owner USER]
       hsmgate ca client -dir DIR -out DIR -cn NAME [-uri URI] [-days 365] [-owner USER]
       hsmgate ca list   -dir DIR
the key of the authority: -mode file (the default: ca.key in DIR, a secret), sealed (sealed to the ECDH key LABEL of the token: nothing secret in DIR, the token opens it when a
certificate is issued), token (the signing key LABEL of the token makes the signatures: the key exists nowhere else). Commands that issue need -config (and the PIN, asked
for on the terminal or with -pin-stdin) when the key is on or sealed to a token.`

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runCA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, caUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("ca "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "ca", "the directory of the authority (its key is there: keep it private)")
	name := fs.String("name", "hsmgate CA", "init: the name of the authority")
	days := fs.Int("days", 0, "life in days (init: 3650, a certificate: 365)")
	out := fs.String("out", "", "server, client: the directory to write the certificate and key to")
	cn := fs.String("cn", "", "the common name (a client: its identity in the policy)")
	dns := fs.String("dns", "", "server: DNS names, comma separated")
	ips := fs.String("ip", "", "server: IP addresses, comma separated")
	uri := fs.String("uri", "", "client: URI names, comma separated (a SPIFFE id for example)")
	owner := fs.String("owner", "", "server, client: the user that owns the key file (the user the service runs as)")
	mode := fs.String("mode", "file", "init: where the key of the authority is: file, sealed or token")
	cfgPath := fs.String("config", "", "the configuration that names the token (modes sealed and token)")
	tokName := fs.String("token", "", "the token of the configuration (default: the one the authority was made with)")
	label := fs.String("label", "", "init: the label of the token's key (ECDH key for sealed, signing key for token)")
	pinStdin := fs.Bool("pin-stdin", false, "read the PIN of the token from standard input instead of the terminal")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	now := time.Now()
	fail := func(err error) int {
		fmt.Fprintln(stderr, "hsmgate:", err)
		return 1
	}
	switch sub {
	case "init":
		o := ca.Options{Name: *name, Days: *days, Mode: ca.Mode(*mode), Label: *label, TokenName: *tokName}
		if o.Mode != ca.ModeFile {
			// sealing needs only the public key of the token; a key on the token has to sign the certificate of the authority, which needs the login
			tok, closeTok, err := openToken(*cfgPath, *tokName, *pinStdin, o.Mode == ca.ModeToken)
			if err != nil {
				return fail(err)
			}
			defer closeTok()
			o.Token = tok
		}
		if err := ca.Init(*dir, o, now); err != nil {
			return fail(err)
		}
		switch o.Mode {
		case ca.ModeFile:
			fmt.Fprintf(stdout, "authority made in %s\n  %s (public: give it to clients as the trust anchor, and to the service as tls.client_ca)\n  %s (PRIVATE: it signs every certificate; keep it off the service host if you can)\n",
				*dir, filepath.Join(*dir, "ca.pem"), filepath.Join(*dir, "ca.key"))
		case ca.ModeSealed:
			fmt.Fprintf(stdout, "authority made in %s, its key sealed to the token key %q of %q\n  %s (public: the trust anchor, and tls.client_ca)\n  %s (sealed: opens only with that token; it is no secret)\n  to issue a certificate: hsmgate ca server|client -dir %s -config %s ...\n",
				*dir, *label, *tokName, filepath.Join(*dir, "ca.pem"), filepath.Join(*dir, "ca.key.sealed"), *dir, *cfgPath)
		case ca.ModeToken:
			fmt.Fprintf(stdout, "authority made in %s, its key is the key %q of the token %q (it never leaves the token)\n  %s (public: the trust anchor, and tls.client_ca)\n  to issue a certificate: hsmgate ca server|client -dir %s -config %s ...\n",
				*dir, *label, *tokName, filepath.Join(*dir, "ca.pem"), *dir, *cfgPath)
		}
		return 0
	case "list":
		c, err := ca.Open(*dir)
		if err != nil {
			return fail(err)
		}
		list, err := c.List()
		if err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "authority %q (key: %s), valid until %s\n", c.Cert.Subject.CommonName, c.Meta.Mode, c.Cert.NotAfter.Format("2006-01-02"))
		for _, e := range list {
			fmt.Fprintf(stdout, "%s  %-6s  cn=%s  names=%s  until %s  sha256=%s\n", e.Serial, e.Kind, e.CN, e.Names, e.NotAfter, e.Fingerprint)
		}
		return 0
	case "server", "client":
		if *out == "" {
			fmt.Fprintln(stderr, "hsmgate: -out DIR is required")
			return 2
		}
		req := ca.Request{CN: *cn, DNS: splitList(*dns), URIs: splitList(*uri), Days: *days}
		for _, s := range splitList(*ips) {
			ip := net.ParseIP(s)
			if ip == nil {
				return fail(fmt.Errorf("%q is not an IP address", s))
			}
			req.IPs = append(req.IPs, ip)
		}
		base := "server"
		if sub == "client" {
			req.Kind = ca.Client
			base = *cn
			if base == "" || !safeName.MatchString(base) {
				if base == "" {
					return fail(fmt.Errorf("a client needs -cn NAME (it names its files)"))
				}
				return fail(fmt.Errorf("-cn %q: use letters, digits, dot, dash and underscore for a client name (it names its files)", base))
			}
		} else {
			req.Kind = ca.Server
		}
		meta, err := ca.ReadMeta(*dir)
		if err != nil {
			return fail(err)
		}
		var tok backend.Token
		if meta.Mode != ca.ModeFile {
			name := *tokName
			if name == "" {
				name = meta.Token
			}
			t, closeTok, err := openToken(*cfgPath, name, *pinStdin, true)
			if err != nil {
				return fail(err)
			}
			defer closeTok()
			tok = t
		}
		c, err := ca.Load(*dir, tok)
		if err != nil {
			return fail(err)
		}
		if err := os.MkdirAll(*out, 0o755); err != nil { // #nosec G301 G703 -- an operator's command: -out is the directory the operator names; certificates are public, the keys are 0400
			return fail(err)
		}
		certPath, keyPath := filepath.Join(*out, base+".pem"), filepath.Join(*out, base+".key")
		for _, p := range []string{certPath, keyPath} { // before anything is made or recorded: nothing is overwritten
			if _, err := os.Lstat(p); err == nil { // #nosec G703 -- an operator's path
				return fail(fmt.Errorf("%s exists: it is not overwritten", p))
			}
		}
		iss, err := c.Issue(req, now)
		if err != nil {
			return fail(err)
		}
		if err := ca.WriteFiles(iss, certPath, keyPath, *owner); err != nil {
			return fail(err)
		}
		caPath := filepath.Join(*out, "ca.pem")
		if _, err := os.Stat(caPath); err != nil { // #nosec G703 -- an operator's path
			if err := os.WriteFile(caPath, c.CertPEM, 0o644); err != nil { // #nosec G306 G703 -- public, at an operator's path
				return fail(err)
			}
		}
		fmt.Fprintf(stdout, "%s certificate until %s\n  %s\n  %s (private, mode 0400)\n  %s (the authority's certificate)\n  sha256 %s\n", sub, iss.NotAfter.Format("2006-01-02"), certPath, keyPath, caPath, iss.Fingerprint)
		if sub == "server" {
			fmt.Fprintf(stdout, "\nin hsmgate.yaml:\ntls:\n  cert: %s\n  key: %s\n  client_ca: %s\n", certPath, keyPath, caPath)
		} else {
			fmt.Fprintf(stdout, "\nin hsmgate.yaml, a client is known by one of:\n  identity: {cn: %s}\n  identity: {sha256: %s}\n", *cn, iss.Fingerprint)
			if len(req.URIs) > 0 {
				fmt.Fprintf(stdout, "  identity: {uri: %q}\n", req.URIs[0])
			}
		}
		return 0
	}
	fmt.Fprintln(stderr, caUsage)
	return 2
}

// openToken opens a token of the configuration for this command. A soft token needs nothing more; a PKCS#11 token is logged in with a PIN (asked for, not an argument) when
// login is true. The returned function closes it: the session ends and the PIN is forgotten.
func openToken(cfgPath, name string, pinStdin, login bool) (backend.Token, func(), error) {
	none := func() {}
	if cfgPath == "" || name == "" {
		return nil, none, errors.New("this needs -config hsmgate.yaml and -token NAME (the token that holds the key of the authority)")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, none, err
	}
	for _, t := range cfg.Tokens {
		if t.Name != name {
			continue
		}
		switch t.Type {
		case "soft":
			s, err := backend.NewSoft(t.Keys)
			return s, none, err
		case "pkcs11":
			p, err := backend.OpenPKCS11(backend.PKCS11Config{Module: t.Module, TokenLabel: t.TokenLabel, TokenSerial: t.TokenSerial, Keys: t.Keys})
			if err != nil {
				return nil, none, err
			}
			if login {
				pin, err := readPIN(name, pinStdin)
				if err != nil {
					p.Close()
					return nil, none, err
				}
				if err := p.Unlock([]byte(pin)); err != nil {
					p.Close()
					return nil, none, fmt.Errorf("token %s: %w", name, err)
				}
			}
			return p, p.Close, nil
		}
	}
	return nil, none, fmt.Errorf("the configuration %s has no token %q", cfgPath, name)
}
