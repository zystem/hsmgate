package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/config"
)

type ident struct {
	cert tls.Certificate
	pem  []byte
	x    *x509.Certificate
}

func mk(t *testing.T, cn string, ca *ident, isCA, server bool) ident {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: isCA,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	if server {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else if !isCA {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	parent, pk := tpl, k
	if ca != nil {
		parent, pk = ca.x, ca.cert.PrivateKey.(*ecdsa.PrivateKey)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &k.PublicKey, pk)
	if err != nil {
		t.Fatal(err)
	}
	x, _ := x509.ParseCertificate(der)
	return ident{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), x}
}

func writeKeyPEM(t *testing.T, path string, id ident) {
	b, _ := x509.MarshalECPrivateKey(id.cert.PrivateKey.(*ecdsa.PrivateKey))
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600)
}

func TestMutualTLSAndIdentity(t *testing.T) {
	dir := t.TempDir()
	ca := mk(t, "ca", nil, true, false)
	srvCert := mk(t, "hsmgate", &ca, false, true)
	good := mk(t, "openbao", &ca, false, false)
	stranger := mk(t, "nobody", &ca, false, false) // valid certificate, unknown to the policy
	otherCA := mk(t, "other-ca", nil, true, false)
	foreign := mk(t, "openbao", &otherCA, false, false)
	os.WriteFile(filepath.Join(dir, "ca.pem"), ca.pem, 0o600)
	os.WriteFile(filepath.Join(dir, "srv.pem"), srvCert.pem, 0o600)
	writeKeyPEM(t, filepath.Join(dir, "srv.key"), srvCert)
	os.WriteFile(filepath.Join(dir, "k1"), []byte(strings.Repeat("11", 32)), 0o600)
	cfg := &config.Config{Listen: "127.0.0.1:0",
		TLS:    config.TLS{Cert: filepath.Join(dir, "srv.pem"), Key: filepath.Join(dir, "srv.key"), ClientCA: filepath.Join(dir, "ca.pem")},
		Tokens: []config.Token{{Name: "soft", Type: "soft", Keys: map[string]string{"m": filepath.Join(dir, "k1")}}},
		Keys:   map[string]config.Key{"bao-seal": {Versions: []config.Version{{Token: "soft", Label: "m"}}, AAD: config.AAD{Mode: "fixed"}}},
		Clients: []config.Client{{Name: "openbao", Identity: config.Identity{CN: "openbao"},
			Keys: map[string]config.Grant{"bao-seal": {Ops: []string{"encrypt", "decrypt"}}}}}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	audit := &bytes.Buffer{}
	s, err := New(cfg, audit)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go s.Serve(l)
	defer s.HTTP.Close()
	pool := x509.NewCertPool()
	pool.AddCert(ca.x)
	call := func(c *tls.Certificate, maxV uint16) (int, error) {
		tc := &tls.Config{RootCAs: pool, MaxVersion: maxV}
		if c != nil {
			tc.Certificates = []tls.Certificate{*c}
		}
		cl := &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
		req, _ := http.NewRequest("PUT", "https://"+l.Addr().String()+"/v1/transit/encrypt/bao-seal", strings.NewReader(`{"plaintext":"`+base64.StdEncoding.EncodeToString([]byte("k"))+`"}`))
		resp, err := cl.Do(req)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return resp.StatusCode, nil
	}
	if st, err := call(&good.cert, 0); err != nil || st != 200 {
		t.Fatalf("good client: %d %v", st, err)
	}
	if st, err := call(&stranger.cert, 0); err != nil || st != 403 {
		t.Errorf("unknown identity: %d %v", st, err)
	}
	if _, err := call(nil, 0); err == nil {
		t.Error("no client certificate was accepted")
	}
	if _, err := call(&foreign.cert, 0); err == nil {
		t.Error("a certificate of another CA was accepted")
	}
	if _, err := call(&good.cert, tls.VersionTLS12); err == nil {
		t.Error("TLS 1.2 was accepted")
	}

	// a reload without a restart: the stranger is added to the policy
	cfg2 := *cfg
	cfg2.Clients = append(append([]config.Client{}, cfg.Clients...), config.Client{Name: "nobody", Identity: config.Identity{CN: "nobody"},
		Keys: map[string]config.Grant{"bao-seal": {Ops: []string{"encrypt"}}}})
	if err := s.Reload(&cfg2); err != nil {
		t.Fatal(err)
	}
	if st, err := call(&stranger.cert, 0); err != nil || st != 200 {
		t.Errorf("after the reload: %d %v", st, err)
	}
	// a configuration that names a token that does not exist is refused and changes nothing
	bad := cfg2
	bad.Tokens = nil
	if err := s.Reload(&bad); err == nil {
		t.Error("a broken reload was accepted")
	}
	if st, err := call(&good.cert, 0); err != nil || st != 200 {
		t.Errorf("after the refused reload: %d %v", st, err)
	}
	// a replica that holds another key is refused
	other := filepath.Join(dir, "k2")
	os.WriteFile(other, []byte(strings.Repeat("22", 32)), 0o600)
	cfg3 := cfg2
	cfg3.Tokens = append(append([]config.Token{}, cfg.Tokens...), config.Token{Name: "spare", Type: "soft", Keys: map[string]string{"m": other}})
	cfg3.Keys = map[string]config.Key{"bao-seal": {AAD: config.AAD{Mode: "fixed"}, Versions: []config.Version{{Token: "soft", Label: "m", Replicas: []config.Replica{{Token: "spare", Label: "m"}}}}}}
	if err := s.Reload(&cfg3); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Errorf("replica with another key: %v", err)
	}
}

func TestInsecureOnlyOnLoopback(t *testing.T) {
	cfg := &config.Config{Listen: "0.0.0.0:8443", InsecureLoopbackClient: "x"}
	if _, err := New(cfg, &bytes.Buffer{}); err == nil {
		t.Error("plain HTTP on a non-loopback address was allowed")
	}
}
