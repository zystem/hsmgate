package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/client"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

// What `hsmgate dev` makes must be a working service: a client with the files it prints seals and opens, the context of demo-ctx is enforced, and a connection
// with no certificate is refused.
func TestDevServiceWorks(t *testing.T) {
	dir := t.TempDir()
	cfgPath, err := devSetup(dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close()

	files := filepath.Join(dir, "clients")
	mk := func(key string) *client.Client {
		c, err := client.New(client.Config{Addr: "https://" + l.Addr().String(), Mount: "transit", Key: key,
			CAFile: filepath.Join(files, "ca.pem"), CertFile: filepath.Join(files, "demo.pem"), KeyFile: filepath.Join(files, "demo.key")})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c := mk("demo")
	ct, _, err := c.Encrypt(ctx, []byte("my secret"), "")
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := c.Decrypt(ctx, ct, ""); err != nil || string(pt) != "my secret" {
		t.Fatalf("round trip: %q %v", pt, err)
	}

	cc := mk("demo-ctx")
	ct, _, err = cc.Encrypt(ctx, []byte("x"), "demo/a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.Decrypt(ctx, ct, "demo/b"); err == nil {
		t.Error("another context was accepted")
	}
	if _, _, err := cc.Encrypt(ctx, []byte("x"), "other/a"); err == nil {
		t.Error("a context outside demo/ was accepted")
	}

	// no client certificate: the handshake fails
	pool := x509.NewCertPool()
	pem, _ := os.ReadFile(filepath.Join(files, "ca.pem"))
	pool.AppendCertsFromPEM(pem)
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	if resp, err := hc.Get("https://" + l.Addr().String() + "/v1/transit/keys/demo"); err == nil {
		resp.Body.Close()
		t.Errorf("answered a client with no certificate: %d", resp.StatusCode)
	}
}

// The same directory again is the same service (the key is not made anew: what was sealed still opens); a directory with other things in it is refused.
func TestDevSetupDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := devSetup(dir, "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(dir, "soft-key.hex"))
	if _, err := devSetup(dir, "127.0.0.1:8443"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, "soft-key.hex"))
	if len(before) != 64 || string(before) != string(after) {
		t.Error("the key changed or is not 64 hex digits")
	}

	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "precious"), []byte("x"), 0o600)
	if _, err := devSetup(other, "127.0.0.1:8443"); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a directory with other files was used: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(other, "precious")); string(b) != "x" {
		t.Error("a file was touched")
	}
}

// A service that listens on every address is reached on this machine by 127.0.0.1: that is what the help shows (the certificate has 127.0.0.1 in it).
func TestClientAddress(t *testing.T) {
	for in, want := range map[string]string{"[::]:8443": "127.0.0.1:8443", "0.0.0.0:8443": "127.0.0.1:8443", ":8443": "127.0.0.1:8443", "127.0.0.1:8443": "127.0.0.1:8443", "192.0.2.7:9000": "192.0.2.7:9000", "[2001:db8::1]:8443": "[2001:db8::1]:8443"} {
		if got := clientAddr(in); got != want {
			t.Errorf("clientAddr(%q) = %q, want %q", in, got, want)
		}
	}
}
