// Package server wires the configuration into a running service: tokens, policy, audit, the Transit face, and TLS 1.3 with a required client certificate.
//
// A configuration is applied as a whole ("generation"): the configuration, the tokens (as views with their own label map), the policy, how clients are
// identified and the TLS settings are prepared and checked first and published together; a reload that fails changes nothing. SIGHUP is the way in (Reload).
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/authn"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/face/transit"
	"github.com/zystem/hsmgate/internal/policy"
)

// maxDrain bounds the wait for requests of an old generation before the tokens a reload dropped are closed anyway (a stuck driver call cannot be cancelled).
const maxDrain = 10 * time.Minute

type generation struct {
	cfg    *config.Config
	tokens map[string]backend.Token
	auth   *authn.Authenticator
	tlsCfg *tls.Config
	pol    *policy.Policy
}

type Server struct {
	HTTP     *http.Server
	Insecure bool

	audit *audit.Log
	face  *transit.Face

	mu  sync.RWMutex
	gen *generation
}

// New builds the service from a checked configuration; auditOut nil means the file of the configuration, or standard output.
func New(cfg *config.Config, auditOut io.Writer) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if auditOut == nil {
		auditOut = os.Stdout
		if cfg.Audit.File != "" {
			f, err := os.OpenFile(cfg.Audit.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
			if err != nil {
				return nil, err
			}
			auditOut = f
		}
	}
	s := &Server{audit: audit.New(auditOut)}
	gen, _, fresh, err := s.prepare(cfg, nil)
	if err != nil {
		closeTokens(fresh)
		return nil, err
	}
	s.gen = gen
	s.face = &transit.Face{Cfg: cfg, Tokens: gen.tokens, Policy: gen.pol, Audit: s.audit}
	conc, wait := cfg.Limits.MaxConcurrent, time.Duration(cfg.Limits.QueueSeconds)*time.Second
	if conc == 0 {
		conc = 8
	}
	if wait == 0 {
		wait = 2 * time.Second
	}
	s.face.Limit(conc, wait)
	s.HTTP = &http.Server{Addr: cfg.Listen, Handler: s.face, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	if cfg.InsecureLoopbackClient != "" {
		if !loopback(cfg.Listen) {
			closeTokens(gen.tokens)
			return nil, fmt.Errorf("insecure_loopback_client is allowed on a loopback address only")
		}
		who := cfg.InsecureLoopbackClient
		s.face.Identify = func(*http.Request) (string, bool) { return who, true }
		s.Insecure = true
		return s, nil
	}
	s.face.Identify = identifier(gen.auth)
	// the configuration of a connection is taken at its handshake, so a reload applies to the next connection (and requests are judged by the current CA anyway)
	s.HTTP.TLSConfig = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.gen.tlsCfg, nil
	}}
	return s, nil
}

func identifier(a *authn.Authenticator) transit.Identify {
	return func(r *http.Request) (string, bool) { return a.Identify(r.TLS) }
}

// prepare builds a generation from a configuration without changing anything that is running. old is the current generation (nil at the start).
// fresh are the tokens that were opened for it: the caller closes them if the generation is not used. removed are tokens of old that the new one does not name.
func (s *Server) prepare(cfg *config.Config, old *generation) (gen *generation, removed map[string]backend.Token, fresh map[string]backend.Token, err error) {
	fresh = map[string]backend.Token{}
	tokens := map[string]backend.Token{}
	for _, t := range cfg.Tokens {
		var prev backend.Token
		if old != nil {
			prev = old.tokens[t.Name]
		}
		switch t.Type {
		case "soft":
			k, e := backend.NewSoft(t.Keys)
			if e != nil {
				return nil, nil, fresh, fmt.Errorf("token %s: %w", t.Name, e)
			}
			tokens[t.Name] = k
		case "pkcs11":
			pc := backend.PKCS11Config{Module: t.Module, TokenLabel: t.TokenLabel, TokenSerial: t.TokenSerial, Keys: t.Keys}
			if p, ok := prev.(*backend.PKCS11); ok {
				if !p.SameToken(pc) {
					return nil, nil, fresh, fmt.Errorf("token %s: module, token_label and token_serial cannot change in a reload: restart", t.Name)
				}
				tokens[t.Name] = p.View(t.Keys)
				continue
			}
			p, e := backend.OpenPKCS11(pc)
			if e != nil {
				return nil, nil, fresh, fmt.Errorf("token %s: %w", t.Name, e)
			}
			fresh[t.Name] = p
			tokens[t.Name] = p
			if t.PinFile != "" {
				if e := unlockFromFile(p, t.PinFile); e != nil {
					// the PIN is tried once; the service starts locked and says why
					fmt.Fprintf(os.Stderr, "hsmgate: token %s stays locked: %v\n", t.Name, e)
				}
			}
		}
	}
	if err := VerifyReplicas(cfg, tokens); err != nil {
		return nil, nil, fresh, err
	}
	var roots *x509.CertPool
	var tcfg *tls.Config
	if cfg.InsecureLoopbackClient == "" {
		if tcfg, err = loadTLS(cfg); err != nil {
			return nil, nil, fresh, err
		}
		roots = tcfg.ClientCAs
	}
	var counters *policy.Counters
	if old != nil {
		counters = old.pol.Counters()
	}
	gen = &generation{cfg: cfg, tokens: tokens, auth: authn.New(cfg.Clients, roots), tlsCfg: tcfg, pol: policy.New(cfg, counters)}
	// a token is gone when no token of the new generation is the same physical token (by identity, not by name: a name can be given to another token)
	removed = map[string]backend.Token{}
	if old != nil {
		for n, t := range old.tokens {
			still := false
			for _, nt := range tokens {
				if sameToken(t, nt) {
					still = true
				}
			}
			if !still {
				removed[n] = t
			}
		}
	}
	return gen, removed, fresh, nil
}

func loadTLS(cfg *config.Config) (*tls.Config, error) {
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(cfg.TLS.ClientCA)
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("tls.client_ca: no certificates read")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
}

// VerifyReplicas: every holder of a key version that answers must have the same public key (and the pinned one, if the version has a fingerprint).
// A holder that cannot answer now (card out) is skipped here and judged again at every use.
func VerifyReplicas(cfg *config.Config, tokens map[string]backend.Token) error {
	for name, k := range cfg.Keys {
		for i, v := range k.Versions {
			var first []byte
			for _, h := range v.Holders() {
				tok, ok := tokens[h.Token]
				if !ok {
					return fmt.Errorf("key %s version %d: unknown token %q", name, i+1, h.Token)
				}
				pt, err := tok.Point(h.Label)
				if err != nil {
					continue
				}
				if v.Fingerprint != "" && !equalFold(v.Fingerprint, fingerprintOf(pt)) {
					return fmt.Errorf("key %s version %d: token %s holds a key that is not the pinned fingerprint", name, i+1, h.Token)
				}
				if first == nil {
					first = pt
				} else if string(first) != string(pt) {
					return fmt.Errorf("key %s version %d: token %s holds a different key than the first holder", name, i+1, h.Token)
				}
			}
		}
	}
	return nil
}

// Reload applies a new configuration as a whole, or not at all. The listen address, the admin socket, the audit file and the limits need a restart.
func (s *Server) Reload(cfg *config.Config) error {
	if s.Insecure {
		return fmt.Errorf("reload is for the TLS mode")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.RLock()
	old := s.gen
	s.mu.RUnlock()
	oc := old.cfg
	if cfg.Listen != oc.Listen || cfg.AdminSocket != oc.AdminSocket || cfg.Audit.File != oc.Audit.File || cfg.Limits != oc.Limits || cfg.Transit.Mount != oc.Transit.Mount {
		return fmt.Errorf("listen, admin_socket, audit.file, limits and transit.mount cannot change in a reload: restart")
	}
	gen, removed, fresh, err := s.prepare(cfg, old)
	if err != nil {
		closeTokens(fresh) // only what this attempt opened; nothing that is running was touched
		return err
	}
	s.mu.Lock()
	s.gen = gen
	s.mu.Unlock()
	waitOld := s.face.Reload(cfg, gen.tokens, gen.pol, identifier(gen.auth))
	// tokens the new configuration no longer uses are logged out when the requests that began with the old generation are done
	go func() {
		done := make(chan struct{})
		go func() { waitOld(); close(done) }()
		select {
		case <-done:
		case <-time.After(maxDrain):
		}
		closeTokens(removed)
	}()
	return nil
}

// Tokens is the current set (the admin door uses it).
func (s *Server) Tokens() map[string]backend.Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.gen.tokens
}

// Describe lists, for `hsmgate check`, every key version with the fingerprint of its public key and the state of its holders.
func (s *Server) Describe() []string {
	var out []string
	g := s.gen
	for _, name := range sortedKeys(g.cfg.Keys) {
		for i, v := range g.cfg.Keys[name].Versions {
			for j, h := range v.Holders() {
				fp, st := "(unreadable)", g.tokens[h.Token].State()
				if pt, err := g.tokens[h.Token].Point(h.Label); err == nil {
					fp = fingerprintOf(pt)
				}
				role := "primary"
				if j > 0 {
					role = "replica"
				}
				pin := ""
				if v.Fingerprint != "" {
					pin = " pinned=" + v.Fingerprint
				}
				out = append(out, fmt.Sprintf("key %s v%d %s token=%s state=%s fingerprint=%s%s", name, i+1, role, h.Token, st, fp, pin))
			}
		}
	}
	return out
}

func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

func (s *Server) Serve(l net.Listener) error {
	if s.Insecure {
		return s.HTTP.Serve(l)
	}
	return s.HTTP.ServeTLS(l, "", "")
}

func unlockFromFile(u Unlocker, path string) error {
	pin, err := backend.ReadSecretFile(path, 256)
	if err != nil {
		return err
	}
	for len(pin) > 0 && (pin[len(pin)-1] == '\n' || pin[len(pin)-1] == '\r') {
		pin = pin[:len(pin)-1]
	}
	defer func() {
		for i := range pin {
			pin[i] = 0
		}
	}()
	return u.Unlock(pin)
}

func closeTokens(m map[string]backend.Token) {
	for _, t := range m {
		if c, ok := t.(interface{ Close() }); ok {
			c.Close()
		}
	}
}

// Close stops the listener, logs the tokens out and makes them forget their PIN. The signal handler of `serve` calls it.
func (s *Server) Close() {
	s.HTTP.Close()
	closeTokens(s.Tokens())
}

func sameToken(a, b backend.Token) bool {
	ia, oka := a.(interface{ Identity() any })
	ib, okb := b.(interface{ Identity() any })
	return oka && okb && ia.Identity() == ib.Identity()
}
