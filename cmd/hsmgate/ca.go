package main

// hsmgate ca: the certificates of the service without openssl (internal/ca). setup does it all in one command from the configuration; init makes the authority; server and client
// issue the certificate of the listener and of a calling program; list shows what was issued.

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/ca"
	"github.com/zystem/hsmgate/internal/config"
)

const caUsage = `usage:
  hsmgate ca setup  -config hsmgate.yaml [-client NAME[,NAME]]      everything in one command: the authority, the server certificate (written where tls: of the
                                                                    configuration says, its names guessed from listen: and the interfaces) and client certificates
  hsmgate ca init   -dir DIR [-name "hsmgate CA"] [-days 3650] [-mode file|sealed|token -config hsmgate.yaml -token NAME -label LABEL]
  hsmgate ca server -dir DIR (-config hsmgate.yaml | -out DIR) [-dns NAME[,NAME]] [-ip ADDR[,ADDR]] [-cn NAME] [-days 365] [-owner USER]
  hsmgate ca client -dir DIR (-config hsmgate.yaml | -out DIR) -cn NAME [-uri URI] [-days 365] [-owner USER]
  hsmgate ca list   -dir DIR
the key of the authority: -mode file (the default: ca.key in DIR, a secret), sealed (sealed to the ECDH key LABEL of the token: nothing secret in DIR, the token opens it when a
certificate is issued), token (the signing key LABEL of the token makes the signatures: the key exists nowhere else). Commands that issue need -config (and the PIN, asked
for on the terminal or with -pin-stdin) when the key is on or sealed to a token. With -config the names of the server certificate, the paths and the owner of the key file are
guessed when they are not given; the commands say what they guessed.`

var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

const maxGuessedIPs = 8

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// guessNames makes the names of a server certificate from what the service listens on: an address that listen: names is the one address; a wildcard or no address means every
// address of the interfaces (global unicast, not loopback or link-local; IPv4 first, at most maxGuessedIPs). 127.0.0.1 and localhost are always in (the service is called from its
// own host to check it), and so is the host name.
func guessNames(listen, hostname string, addrs []net.Addr) (dns []string, ips []net.IP) {
	dnsSet := map[string]bool{"localhost": true}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		host = listen
	}
	var all []net.IP
	switch ip := net.ParseIP(host); {
	case ip != nil && !ip.IsUnspecified():
		all = append(all, ip)
	default:
		if host != "" && ip == nil && validHost(host) {
			dnsSet[host] = true
		}
		var v4, v6 []net.IP
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || !n.IP.IsGlobalUnicast() || n.IP.IsLinkLocalUnicast() {
				continue
			}
			if n.IP.To4() != nil {
				v4 = append(v4, n.IP)
			} else {
				v6 = append(v6, n.IP)
			}
		}
		all = append(v4, v6...)
	}
	if len(all) > maxGuessedIPs {
		all = all[:maxGuessedIPs]
	}
	seen := map[string]bool{}
	for _, ip := range append(all, net.ParseIP("127.0.0.1")) {
		if !seen[ip.String()] {
			seen[ip.String()] = true
			ips = append(ips, ip)
		}
	}
	if hostname != "" && validHost(hostname) {
		dnsSet[strings.ToLower(hostname)] = true
	}
	for d := range dnsSet {
		dns = append(dns, d)
	}
	sort.Strings(dns)
	return dns, ips
}

// interfaceAddrs are the addresses of the interfaces that are up, without the virtual ones of containers and bridges (docker, veth, br-, virbr, cni, flannel, tun/tap): they are not
// where a client reaches the service. A name that is missed can be given with -ip.
func interfaceAddrs() []net.Addr {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []net.Addr
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || virtualInterface(i.Name) {
			continue
		}
		if a, err := i.Addrs(); err == nil {
			out = append(out, a...)
		}
	}
	return out
}

func virtualInterface(name string) bool {
	for _, p := range []string{"docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "tun", "tap", "lxc", "podman", "vmnet", "vboxnet", "kube", "weave"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

var hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

func validHost(s string) bool { return hostRE.MatchString(s) }

// guessOwner is the user that owns the key file when none is given: "hsmgate", if the command runs as root and there is such a user (the user that the unit of the service names).
func guessOwner() string {
	if os.Geteuid() != 0 {
		return ""
	}
	if _, err := user.Lookup("hsmgate"); err == nil {
		return "hsmgate"
	}
	return ""
}

func runCA(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, caUsage)
		return 2
	}
	sub := args[0]
	fs := flag.NewFlagSet("ca "+sub, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "the directory of the authority (with -config: ca/ next to the configuration)")
	name := fs.String("name", "hsmgate CA", "init, setup: the name of the authority")
	days := fs.Int("days", 0, "life in days (the authority: 3650, a certificate: 365)")
	out := fs.String("out", "", "server, client: the directory to write the certificate and key to (with -config: where tls: names, and clients/ next to the configuration)")
	cn := fs.String("cn", "", "the common name (a client: its identity in the policy)")
	dns := fs.String("dns", "", "server: DNS names, comma separated (guessed with -config)")
	ips := fs.String("ip", "", "server: IP addresses, comma separated (guessed with -config)")
	uri := fs.String("uri", "", "client: URI names, comma separated (a SPIFFE id for example)")
	owner := fs.String("owner", "", "server, client: the user that owns the key file (default: hsmgate, if it exists and this runs as root)")
	mode := fs.String("mode", "file", "init, setup: where the key of the authority is: file, sealed or token")
	cfgPath := fs.String("config", "", "the configuration of the service (the token, the tls paths, listen)")
	tokName := fs.String("token", "", "the token of the configuration (default: the one the authority was made with)")
	label := fs.String("label", "", "init, setup: the label of the token's key (ECDH key for sealed, signing key for token)")
	pinStdin := fs.Bool("pin-stdin", false, "read the PIN of the token from standard input instead of the terminal")
	clients := fs.String("client", "", "setup: names of clients to make certificates for, comma separated")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	now := time.Now()
	fail := func(err error) int {
		fmt.Fprintln(stderr, "hsmgate:", err)
		return 1
	}
	var cfg *config.Config
	cfgDir := ""
	if *cfgPath != "" {
		c, err := config.Load(*cfgPath)
		if err != nil {
			return fail(err)
		}
		cfg, cfgDir = c, filepath.Dir(*cfgPath)
	}
	if *dir == "" {
		if cfg == nil {
			*dir = "ca"
		} else {
			*dir = filepath.Join(cfgDir, "ca")
		}
	}
	if *owner == "" {
		*owner = guessOwner()
	}
	switch sub {
	case "init":
		return caInit(stdout, fail, *dir, *name, *days, ca.Mode(*mode), *cfgPath, *tokName, *label, *pinStdin, now)
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
	case "setup":
		if cfg == nil {
			fmt.Fprintln(stderr, "hsmgate: setup needs -config hsmgate.yaml")
			return 2
		}
		return caSetup(stdout, fail, cfg, cfgDir, *dir, *name, *days, ca.Mode(*mode), *cfgPath, *tokName, *label, *pinStdin, *owner, *dns, *ips, *clients, *out, given["out"], now)
	case "server", "client":
		return caIssue(stdout, stderr, fail, sub, cfg, cfgDir, *dir, *out, *cn, *dns, *ips, *uri, *days, *owner, *cfgPath, *tokName, *pinStdin, now)
	}
	fmt.Fprintln(stderr, caUsage)
	return 2
}

func caInit(stdout io.Writer, fail func(error) int, dir, name string, days int, mode ca.Mode, cfgPath, tokName, label string, pinStdin bool, now time.Time) int {
	o := ca.Options{Name: name, Days: days, Mode: mode, Label: label, TokenName: tokName}
	if o.Mode != ca.ModeFile {
		// sealing needs only the public key of the token; a key on the token has to sign the certificate of the authority, which needs the login
		tok, closeTok, err := openToken(cfgPath, tokName, pinStdin, o.Mode == ca.ModeToken)
		if err != nil {
			return fail(err)
		}
		defer closeTok()
		o.Token = tok
	}
	if err := ca.Init(dir, o, now); err != nil {
		return fail(err)
	}
	switch o.Mode {
	case ca.ModeFile:
		fmt.Fprintf(stdout, "authority made in %s\n  %s (public: give it to clients as the trust anchor, and to the service as tls.client_ca)\n  %s (PRIVATE: it signs every certificate; keep it off the service host if you can)\n",
			dir, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	case ca.ModeSealed:
		fmt.Fprintf(stdout, "authority made in %s, its key sealed to the token key %q of %q\n  %s (public: the trust anchor, and tls.client_ca)\n  %s (sealed: opens only with that token; it is no secret)\n  to issue a certificate: hsmgate ca server|client -dir %s -config %s ...\n",
			dir, label, tokName, filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key.sealed"), dir, cfgPath)
	case ca.ModeToken:
		fmt.Fprintf(stdout, "authority made in %s, its key is the key %q of the token %q (it never leaves the token)\n  %s (public: the trust anchor, and tls.client_ca)\n  to issue a certificate: hsmgate ca server|client -dir %s -config %s ...\n",
			dir, label, tokName, filepath.Join(dir, "ca.pem"), dir, cfgPath)
	}
	return 0
}

// loadAuthority opens the authority of dir ready to sign, with its token when its key is on or sealed to one. The returned function closes the token.
func loadAuthority(dir, cfgPath, tokName string, pinStdin bool) (*ca.CA, func(), error) {
	none := func() {}
	meta, err := ca.ReadMeta(dir)
	if err != nil {
		return nil, none, err
	}
	var tok backend.Token
	closeTok := none
	if meta.Mode != ca.ModeFile {
		name := tokName
		if name == "" {
			name = meta.Token
		}
		tok, closeTok, err = openToken(cfgPath, name, pinStdin, true)
		if err != nil {
			return nil, none, err
		}
	}
	c, err := ca.Load(dir, tok)
	if err != nil {
		closeTok()
		return nil, none, err
	}
	return c, closeTok, nil
}

// notThere refuses when a file that would be written exists: nothing is overwritten, and nothing is issued or recorded first.
func notThere(paths ...string) error {
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil { // #nosec G703 -- an operator's path
			return fmt.Errorf("%s exists: it is not overwritten (move it away to make a new one)", p)
		}
	}
	return nil
}

// writeCA puts the authority's certificate where it is needed (the trust anchor of clients, tls.client_ca); an identical file already there is fine, another one is not.
func writeCA(path string, pemBytes []byte) error {
	if have, err := os.ReadFile(path); err == nil { // #nosec G304 G703 -- an operator's path
		if bytes.Equal(have, pemBytes) {
			return nil
		}
		return fmt.Errorf("%s holds another certificate: it is not overwritten", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 G703 -- public
		return err
	}
	return os.WriteFile(path, pemBytes, 0o644) // #nosec G306 G703 -- public, at an operator's path
}

// serverRequest makes the request of a server certificate: the names given, else the ones guessed from the configuration.
func serverRequest(cfg *config.Config, cn, dns, ips string, days int, stdout io.Writer) (ca.Request, error) {
	req := ca.Request{Kind: ca.Server, CN: cn, DNS: splitList(dns), Days: days}
	for _, s := range splitList(ips) {
		ip := net.ParseIP(s)
		if ip == nil {
			return req, fmt.Errorf("%q is not an IP address", s)
		}
		req.IPs = append(req.IPs, ip)
	}
	if len(req.DNS)+len(req.IPs) == 0 {
		if cfg == nil {
			return req, errors.New("a server certificate needs -ip or -dns (or -config, to guess them from listen: and the interfaces)")
		}
		host, _ := os.Hostname()
		req.DNS, req.IPs = guessNames(cfg.Listen, host, interfaceAddrs())
		var names []string
		names = append(names, req.DNS...)
		for _, ip := range req.IPs {
			names = append(names, ip.String())
		}
		fmt.Fprintf(stdout, "names guessed from listen: %q and the interfaces: %s\n  (other names: -dns and -ip)\n", cfg.Listen, strings.Join(names, ", "))
	}
	return req, nil
}

func caIssue(stdout, stderr io.Writer, fail func(error) int, sub string, cfg *config.Config, cfgDir, dir, out, cn, dns, ips, uri string, days int, owner, cfgPath, tokName string, pinStdin bool, now time.Time) int {
	var req ca.Request
	var certPath, keyPath, caPath string
	if sub == "server" {
		r, err := serverRequest(cfg, cn, dns, ips, days, stdout)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate:", err)
			return 2
		}
		req = r
		switch {
		case out != "":
			certPath, keyPath, caPath = filepath.Join(out, "server.pem"), filepath.Join(out, "server.key"), filepath.Join(out, "ca.pem")
		case cfg != nil && cfg.TLS.Cert != "" && cfg.TLS.Key != "":
			certPath, keyPath, caPath = cfg.TLS.Cert, cfg.TLS.Key, cfg.TLS.ClientCA
		default:
			fmt.Fprintln(stderr, "hsmgate: -out DIR is required (or -config, whose tls: says where the files go)")
			return 2
		}
	} else {
		req = ca.Request{Kind: ca.Client, CN: cn, URIs: splitList(uri), Days: days}
		if cn == "" || !safeName.MatchString(cn) {
			if cn == "" {
				return fail(errors.New("a client needs -cn NAME (it names its files)"))
			}
			return fail(fmt.Errorf("-cn %q: use letters, digits, dot, dash and underscore for a client name (it names its files)", cn))
		}
		if out == "" && cfg != nil {
			out = filepath.Join(cfgDir, "clients")
		}
		if out == "" {
			fmt.Fprintln(stderr, "hsmgate: -out DIR is required (or -config: the files go to clients/ next to it)")
			return 2
		}
		certPath, keyPath, caPath = filepath.Join(out, cn+".pem"), filepath.Join(out, cn+".key"), filepath.Join(out, "ca.pem")
	}
	if err := notThere(certPath, keyPath); err != nil {
		return fail(err)
	}
	c, closeTok, err := loadAuthority(dir, cfgPath, tokName, pinStdin)
	if err != nil {
		return fail(err)
	}
	defer closeTok()
	if err := writeIssued(stdout, c, req, certPath, keyPath, caPath, owner, now); err != nil {
		return fail(err)
	}
	return 0
}

// writeIssued issues a certificate and writes it with its key, and the authority's certificate beside them, then says what to put into the configuration.
func writeIssued(stdout io.Writer, c *ca.CA, req ca.Request, certPath, keyPath, caPath, owner string, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil { // #nosec G301 G703 -- certificates are public; the keys are 0400
		return err
	}
	iss, err := c.Issue(req, now)
	if err != nil {
		return err
	}
	if err := ca.WriteFiles(iss, certPath, keyPath, owner); err != nil {
		return err
	}
	if err := writeCA(caPath, c.CertPEM); err != nil {
		return err
	}
	who := ""
	if owner != "" {
		who = ", owner " + owner
	}
	fmt.Fprintf(stdout, "%s certificate until %s\n  %s\n  %s (private, mode 0400%s)\n  %s (the authority's certificate)\n  sha256 %s\n", req.Kind, iss.NotAfter.Format("2006-01-02"), certPath, keyPath, who, caPath, iss.Fingerprint)
	if req.Kind == ca.Server {
		fmt.Fprintf(stdout, "\nin hsmgate.yaml:\ntls:\n  cert: %s\n  key: %s\n  client_ca: %s\n", certPath, keyPath, caPath)
	} else {
		fmt.Fprintf(stdout, "\nin hsmgate.yaml, this client is known by one of:\n  identity: {cn: %s}\n  identity: {sha256: %s}\n", req.CN, iss.Fingerprint)
		if len(req.URIs) > 0 {
			fmt.Fprintf(stdout, "  identity: {uri: %q}\n", req.URIs[0])
		}
	}
	return nil
}

// caSetup is the whole thing in one command, from the configuration: the authority if there is none (in ca/ next to the configuration), the server certificate where tls:
// says, with its names guessed, the certificate of the authority as tls.client_ca, and a certificate for each client named. It overwrites nothing; what exists is said, and
// the command stops before it makes anything.
func caSetup(stdout io.Writer, fail func(error) int, cfg *config.Config, cfgDir, dir, name string, days int, mode ca.Mode, cfgPath, tokName, label string, pinStdin bool, owner, dns, ips, clients, out string, outGiven bool, now time.Time) int {
	if cfg.TLS.Cert == "" || cfg.TLS.Key == "" || cfg.TLS.ClientCA == "" {
		return fail(errors.New("the configuration has no tls: cert, key and client_ca: they say where the files go"))
	}
	clientNames := splitList(clients)
	for _, n := range clientNames {
		if !safeName.MatchString(n) {
			return fail(fmt.Errorf("-client %q: use letters, digits, dot, dash and underscore for a client name (it names its files)", n))
		}
	}
	clientDir := filepath.Join(cfgDir, "clients")
	if outGiven {
		clientDir = out
	}
	targets := []string{cfg.TLS.Cert, cfg.TLS.Key}
	for _, n := range clientNames {
		targets = append(targets, filepath.Join(clientDir, n+".pem"), filepath.Join(clientDir, n+".key"))
	}
	if err := notThere(targets...); err != nil {
		return fail(err)
	}
	req, err := serverRequest(cfg, "", dns, ips, days, stdout)
	if err != nil {
		return fail(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "ca.pem")); err != nil { // #nosec G703 -- an operator's path
		if code := caInit(stdout, fail, dir, name, 0, mode, cfgPath, tokName, label, pinStdin, now); code != 0 {
			return code
		}
		fmt.Fprintln(stdout)
	} else {
		fmt.Fprintf(stdout, "using the authority in %s\n\n", dir)
	}
	c, closeTok, err := loadAuthority(dir, cfgPath, tokName, pinStdin)
	if err != nil {
		return fail(err)
	}
	defer closeTok()
	if err := writeIssued(stdout, c, req, cfg.TLS.Cert, cfg.TLS.Key, cfg.TLS.ClientCA, owner, now); err != nil {
		return fail(err)
	}
	for _, n := range clientNames {
		fmt.Fprintln(stdout)
		cr := ca.Request{Kind: ca.Client, CN: n, Days: days}
		if err := writeIssued(stdout, c, cr, filepath.Join(clientDir, n+".pem"), filepath.Join(clientDir, n+".key"), filepath.Join(clientDir, "ca.pem"), "", now); err != nil {
			return fail(err)
		}
	}
	fmt.Fprintf(stdout, "\ndone. Start or restart the service (it reads these files at start); give each client its files (<name>.pem, <name>.key, ca.pem) and add it to clients: in %s.\n", cfgPath)
	if len(clientNames) == 0 {
		fmt.Fprintf(stdout, "a client certificate: hsmgate ca client -dir %s -config %s -cn NAME\n", dir, cfgPath)
	}
	return 0
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
