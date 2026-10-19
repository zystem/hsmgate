// Package server wires the configuration into a running service: tokens, policy, audit, the Transit face, and TLS 1.3 with a required client certificate.
// SIGHUP (Reload) swaps the configuration, the policy, the client certificate and the CA without a restart and without a new PIN.
package server

import (
	"bytes"
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

type Server struct {
	HTTP     *http.Server
	Insecure bool

	audit *audit.Log
	face  *transit.Face

	mu     sync.RWMutex
	cfg    *config.Config
	tokens map[string]backend.Token
	auth   *authn.Authenticator
	tlsCfg *tls.Config
}

// New builds the service from a checked configuration; auditOut nil means the file of the configuration, or standard output.
func New(cfg *config.Config, auditOut io.Writer) (*Server, error) {
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
	tokens, err := s.buildTokens(cfg, nil)
	if err != nil {
		return nil, err
	}
	if err := VerifyReplicas(cfg, tokens); err != nil {
		return nil, err
	}
	s.cfg, s.tokens, s.auth = cfg, tokens, authn.New(cfg.Clients)
	s.face = &transit.Face{Cfg: cfg, Tokens: tokens, Policy: policy.New(cfg), Audit: s.audit}
	srv := &http.Server{Addr: cfg.Listen, Handler: s.face, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	s.HTTP = srv
	if cfg.InsecureLoopbackClient != "" {
		if !loopback(cfg.Listen) {
			return nil, fmt.Errorf("insecure_loopback_client is allowed on a loopback address only")
		}
		who := cfg.InsecureLoopbackClient
		s.face.Identify = func(*http.Request) (string, bool) { return who, true }
		s.Insecure = true
		return s, nil
	}
	if s.tlsCfg, err = loadTLS(cfg); err != nil {
		return nil, err
	}
	// the configuration of a connection is taken at its handshake, so a reload applies to the next connection
	srv.TLSConfig = &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.tlsCfg, nil
	}}
	s.face.Identify = func(r *http.Request) (string, bool) {
		s.mu.RLock()
		a := s.auth
		s.mu.RUnlock()
		return a.Identify(r.TLS)
	}
	return s, nil
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

// buildTokens makes the tokens of a configuration, reusing the ones of the same name and type (a logged-in card stays logged in).
func (s *Server) buildTokens(cfg *config.Config, old map[string]backend.Token) (map[string]backend.Token, error) {
	tokens := map[string]backend.Token{}
	for _, t := range cfg.Tokens {
		switch t.Type {
		case "soft":
			k, err := backend.NewSoft(t.Keys)
			if err != nil {
				return nil, fmt.Errorf("token %s: %w", t.Name, err)
			}
			tokens[t.Name] = k
		case "pkcs11":
			if p, ok := old[t.Name].(*backend.PKCS11); ok {
				p.SetKeys(t.Keys)
				tokens[t.Name] = p
				continue
			}
			p, err := backend.OpenPKCS11(backend.PKCS11Config{Module: t.Module, TokenLabel: t.TokenLabel, TokenSerial: t.TokenSerial, Keys: t.Keys})
			if err != nil {
				return nil, fmt.Errorf("token %s: %w", t.Name, err)
			}
			if t.PinFile != "" {
				if err := unlockFromFile(p, t.PinFile); err != nil {
					// the PIN is tried once; the service starts locked and says why
					fmt.Fprintf(os.Stderr, "hsmgate: token %s stays locked: %v\n", t.Name, err)
				}
			}
			tokens[t.Name] = p
		}
	}
	return tokens, nil
}

// VerifyReplicas: every holder of a key version that answers must have the same public key. A holder that cannot answer now (card out) is skipped.
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
				if first == nil {
					first = pt
				} else if !bytes.Equal(first, pt) {
					return fmt.Errorf("key %s version %d: token %s holds a different key than the first holder", name, i+1, h.Token)
				}
			}
		}
	}
	return nil
}

// Reload applies a new configuration. The listen address, the admin socket and the audit file need a restart. On any error nothing changes.
func (s *Server) Reload(cfg *config.Config) error {
	if s.Insecure {
		return fmt.Errorf("reload is for the TLS mode")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	s.mu.RLock()
	old := s.tokens
	s.mu.RUnlock()
	tokens, err := s.buildTokens(cfg, old)
	if err != nil {
		return err
	}
	if err := VerifyReplicas(cfg, tokens); err != nil {
		return err
	}
	t, err := loadTLS(cfg)
	if err != nil {
		return err
	}
	pol := policy.New(cfg)
	s.mu.Lock()
	pol.Inherit(s.face.Policy)
	s.cfg, s.tokens, s.auth, s.tlsCfg = cfg, tokens, authn.New(cfg.Clients), t
	s.mu.Unlock()
	s.face.Reload(cfg, tokens, pol)
	return nil
}

// Tokens is the current set (the admin door uses it).
func (s *Server) Tokens() map[string]backend.Token {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.tokens
}

// Describe lists, for `hsmgate check`, every key version with the fingerprint of its public key and the state of its holders.
func (s *Server) Describe() []string {
	var out []string
	cfg := s.cfg
	for _, name := range sortedKeys(cfg.Keys) {
		for i, v := range cfg.Keys[name].Versions {
			for j, h := range v.Holders() {
				fp, st := "(unreadable)", s.tokens[h.Token].State()
				if pt, err := s.tokens[h.Token].Point(h.Label); err == nil {
					fp = fingerprintOf(pt)
				}
				role := "primary"
				if j > 0 {
					role = "replica"
				}
				out = append(out, fmt.Sprintf("key %s v%d %s token=%s state=%s fingerprint=%s", name, i+1, role, h.Token, st, fp))
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
	pin, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pin = bytes.TrimRight(pin, "\r\n")
	defer func() {
		for i := range pin {
			pin[i] = 0
		}
	}()
	return u.Unlock(pin)
}
