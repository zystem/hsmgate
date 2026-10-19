// Package server wires the configuration into a running service: tokens, policy, audit, the Transit face, and TLS 1.3 with a required client certificate.
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
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
}

// New builds the service from a checked configuration; auditOut nil means the file of the configuration, or standard output.
func New(cfg *config.Config, auditOut io.Writer) (*Server, error) {
	tokens := map[string]backend.Token{}
	for _, t := range cfg.Tokens {
		s, err := backend.NewSoft(t.Keys)
		if err != nil {
			return nil, fmt.Errorf("token %s: %w", t.Name, err)
		}
		tokens[t.Name] = s
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
	srv := &http.Server{Addr: cfg.Listen, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	face := &transit.Face{Cfg: cfg, Tokens: tokens, Policy: policy.New(cfg), Audit: audit.New(auditOut)}
	s := &Server{HTTP: srv}
	if cfg.InsecureLoopbackClient != "" {
		if !loopback(cfg.Listen) {
			return nil, fmt.Errorf("insecure_loopback_client is allowed on a loopback address only")
		}
		who := cfg.InsecureLoopbackClient
		face.Identify = func(*http.Request) (string, bool) { return who, true }
		srv.Handler = face
		s.Insecure = true
		return s, nil
	}
	pool := x509.NewCertPool()
	ca, err := os.ReadFile(cfg.TLS.ClientCA)
	if err != nil || !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("tls.client_ca: no certificates read")
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return nil, err
	}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{cert}}
	a := authn.New(cfg.Clients)
	face.Identify = func(r *http.Request) (string, bool) { return a.Identify(r.TLS) }
	srv.Handler = face
	return s, nil
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
