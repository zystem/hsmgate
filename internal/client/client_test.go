package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

const keyConfig = `
audit: {file: %AUDIT%}
tokens: [{name: soft, type: soft, keys: {m: %KEY%}}]
keys:
  apps: {versions: [{token: soft, label: m}], aad: {mode: context, allow: ["k8s/"]}}
  other: {versions: [{token: soft, label: m}], aad: {mode: fixed}}
clients:
  - {name: shop, identity: {cn: shop}, keys: {apps: {ops: [encrypt, decrypt], contexts: ["k8s/shop/"]}}}
`

func writeConfig(t *testing.T, dir, head string) *config.Config {
	os.WriteFile(filepath.Join(dir, "k"), []byte(strings.Repeat("22", 32)), 0o600)
	body := strings.NewReplacer("%AUDIT%", filepath.Join(dir, "audit.log"), "%KEY%", filepath.Join(dir, "k")).Replace(keyConfig)
	cfg, err := config.Parse([]byte(head + body))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// plainServer: the real service in development mode (plain HTTP, loopback, the client is "shop").
func plainServer(t *testing.T) *httptest.Server {
	cfg := writeConfig(t, t.TempDir(), "listen: 127.0.0.1:0\ninsecure_loopback_client: shop\n")
	s, err := server.New(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.HTTP.Handler)
	t.Cleanup(ts.Close)
	return ts
}

func newClient(t *testing.T, addr, key string) *Client {
	c, err := New(Config{Addr: addr, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTripAndTheMessagesThatHelp(t *testing.T) {
	ts := plainServer(t)
	c := newClient(t, ts.URL, "apps")
	ctx := context.Background()
	ct, ver, err := c.Encrypt(ctx, []byte("test-password"), "k8s/shop/app/api-keys-secret")
	if err != nil || ver != 1 || !strings.HasPrefix(ct, "vault:v1:") {
		t.Fatalf("%q %d %v", ct, ver, err)
	}
	if p, err := c.Decrypt(ctx, ct, "k8s/shop/app/api-keys-secret"); err != nil || string(p) != "test-password" {
		t.Fatalf("%q %v", p, err)
	}
	// another context: not opened, and the message says why without any secret
	_, err = c.Decrypt(ctx, ct, "k8s/shop/other/api-keys-secret")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 400 || ae.Retryable {
		t.Fatalf("%v", err)
	}
	msg := Explain(err, "apps", "k8s/shop/other/api-keys-secret")
	if !strings.Contains(msg, `key "apps"`) || !strings.Contains(msg, "another context") || strings.Contains(msg, "test-password") || strings.Contains(msg, ct) {
		t.Errorf("message: %s", msg)
	}
	// a context of another namespace: this client's grant does not cover it
	_, _, err = c.Encrypt(ctx, []byte("x"), "k8s/bank/app/x")
	if !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("%v", err)
	}
	if m := Explain(err, "apps", "k8s/bank/app/x"); !strings.Contains(m, "permission denied") || !strings.Contains(m, "k8s/bank/app/x") {
		t.Errorf("message: %s", m)
	}
	// a key the client has no grant for
	_, _, err = newClient(t, ts.URL, "other").Encrypt(ctx, []byte("x"), "")
	if !errors.As(err, &ae) || ae.Status != 403 {
		t.Fatalf("%v", err)
	}
}

func TestRetryFollowsTheServiceNotTheStatusNumber(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		switch {
		case r.URL.Path == "/v1/transit/decrypt/apps" && n <= 2: // a locked token: passes
			w.Header().Set("X-Hsmgate-Retryable", "true")
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(503)
			io.WriteString(w, `{"errors":["token locked"]}`)
		case r.URL.Path == "/v1/transit/decrypt/apps":
			io.WriteString(w, `{"data":{"plaintext":"aGk="}}`)
		default: // a refusal that will not pass, although it is also "an error"
			w.Header().Set("X-Hsmgate-Retryable", "false")
			w.WriteHeader(403)
			io.WriteString(w, `{"errors":["permission denied"]}`)
		}
	}))
	defer ts.Close()
	c := newClient(t, ts.URL, "apps")
	var slept []time.Duration
	var got []byte
	err := Retry(context.Background(), time.Minute, func() (e error) { got, e = c.Decrypt(context.Background(), "vault:v1:x", "k8s/a/b/c"); return }, func(d time.Duration) { slept = append(slept, d) })
	if err != nil || string(got) != "hi" || len(slept) != 2 || slept[0] != 3*time.Second {
		t.Fatalf("%v %q %v", err, got, slept)
	}
	atomic.StoreInt32(&calls, 100)
	c2 := newClient(t, ts.URL, "other")
	n := 0
	err = Retry(context.Background(), time.Minute, func() error { n++; _, _, e := c2.Encrypt(context.Background(), []byte("x"), ""); return e }, func(time.Duration) { t.Error("slept on a refusal") })
	if err == nil || n != 1 {
		t.Errorf("a refusal was tried %d times: %v", n, err)
	}
}

func TestRetryGivesUpWhenTheWaitIsOver(t *testing.T) {
	calls := 0
	err := Retry(context.Background(), 3*time.Second, func() error { calls++; return &APIError{Status: 503, Retryable: true, Op: "decrypt"} }, func(time.Duration) {})
	if err == nil || calls < 2 || calls > 6 {
		t.Errorf("%d calls, %v", calls, err)
	}
}

func TestPlainHTTPIsForLoopbackOnly(t *testing.T) {
	if _, err := New(Config{Addr: "http://hsmgate.example.org:8443", Key: "k"}); err == nil {
		t.Error("plain http to a remote host was accepted")
	}
	for _, a := range []string{"http://127.0.0.1:1", "http://localhost:1", "http://[::1]:1"} {
		if _, err := New(Config{Addr: a, Key: "k"}); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	if _, err := New(Config{Addr: "ftp://x", Key: "k"}); err == nil {
		t.Error("a strange scheme was accepted")
	}
	if _, err := New(Config{Addr: "https://x"}); err == nil {
		t.Error("no key name was accepted")
	}
}

// ---- mutual TLS, the way a pod uses it ----

type ident struct {
	cert tls.Certificate
	pem  []byte
	x    *x509.Certificate
}

func mk(t *testing.T, cn string, ca *ident, isCA, srv bool) ident {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: isCA, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign}
	if srv {
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

func writeKey(t *testing.T, path string, id ident) {
	b, _ := x509.MarshalECPrivateKey(id.cert.PrivateKey.(*ecdsa.PrivateKey))
	os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), 0o600)
}

func TestMutualTLSFromFiles(t *testing.T) {
	dir := t.TempDir()
	ca := mk(t, "ca", nil, true, false)
	srv := mk(t, "hsmgate", &ca, false, true)
	shop := mk(t, "shop", &ca, false, false)
	os.WriteFile(filepath.Join(dir, "ca.pem"), ca.pem, 0o600)
	os.WriteFile(filepath.Join(dir, "srv.pem"), srv.pem, 0o600)
	writeKey(t, filepath.Join(dir, "srv.key"), srv)
	os.WriteFile(filepath.Join(dir, "shop.pem"), shop.pem, 0o600)
	writeKey(t, filepath.Join(dir, "shop.key"), shop)
	head := "listen: 127.0.0.1:0\ntls: {cert: " + filepath.Join(dir, "srv.pem") + ", key: " + filepath.Join(dir, "srv.key") + ", client_ca: " + filepath.Join(dir, "ca.pem") + "}\n"
	s, err := server.New(writeConfig(t, dir, head), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go s.Serve(l)
	defer s.HTTP.Close()
	addr := "https://" + l.Addr().String()

	c, err := New(Config{Addr: addr, Key: "apps", CAFile: filepath.Join(dir, "ca.pem"), CertFile: filepath.Join(dir, "shop.pem"), KeyFile: filepath.Join(dir, "shop.key")})
	if err != nil {
		t.Fatal(err)
	}
	ct, _, err := c.Encrypt(context.Background(), []byte("v"), "k8s/shop/a/b")
	if err != nil {
		t.Fatal(err)
	}
	if p, err := c.Decrypt(context.Background(), ct, "k8s/shop/a/b"); err != nil || string(p) != "v" {
		t.Fatalf("%q %v", p, err)
	}
	// without a client certificate: the handshake is refused, and the message says the service could not be reached
	c2, _ := New(Config{Addr: addr, Key: "apps", CAFile: filepath.Join(dir, "ca.pem")})
	_, _, err = c2.Encrypt(context.Background(), []byte("v"), "k8s/shop/a/b")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 0 || !strings.Contains(Explain(err, "apps", "x"), "certificate") {
		t.Errorf("no certificate: %v / %s", err, Explain(err, "apps", "x"))
	}
	// a CA the client does not know
	other := mk(t, "other", nil, true, false)
	os.WriteFile(filepath.Join(dir, "other.pem"), other.pem, 0o600)
	c3, _ := New(Config{Addr: addr, Key: "apps", CAFile: filepath.Join(dir, "other.pem"), CertFile: filepath.Join(dir, "shop.pem"), KeyFile: filepath.Join(dir, "shop.key")})
	if _, _, err := c3.Encrypt(context.Background(), []byte("v"), "k8s/shop/a/b"); err == nil {
		t.Error("a service whose certificate is not from the given CA was trusted")
	}
}
