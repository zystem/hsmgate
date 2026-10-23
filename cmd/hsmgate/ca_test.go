package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

func runca(t *testing.T, args ...string) (string, int) {
	var out, errb bytes.Buffer
	code := runCA(args, &out, &errb)
	return out.String() + errb.String(), code
}

func TestCAUsageAndRefusals(t *testing.T) {
	d := t.TempDir()
	cadir, out := filepath.Join(d, "ca"), filepath.Join(d, "out")
	if _, code := runca(t); code != 2 {
		t.Error("no subcommand")
	}
	if _, code := runca(t, "nope"); code != 2 {
		t.Error("an unknown subcommand")
	}
	if o, code := runca(t, "server", "-dir", cadir, "-out", out, "-dns", "h.example"); code == 0 {
		t.Errorf("no authority yet: %s", o)
	}
	if o, code := runca(t, "init", "-dir", cadir); code != 0 {
		t.Fatalf("init: %s", o)
	}
	if _, code := runca(t, "init", "-dir", cadir); code == 0 {
		t.Error("init overwrote an authority")
	}
	for name, args := range map[string][]string{
		"server without -out":          {"server", "-dir", cadir, "-dns", "h.example"},
		"server without a name":        {"server", "-dir", cadir, "-out", out},
		"a bad IP":                     {"server", "-dir", cadir, "-out", out, "-ip", "999.1.1.1"},
		"client without -cn":           {"client", "-dir", cadir, "-out", out},
		"a client name that is a path": {"client", "-dir", cadir, "-out", out, "-cn", "../x"},
		"too many days":                {"client", "-dir", cadir, "-out", out, "-cn", "x", "-days", "99999"},
	} {
		if o, code := runca(t, args...); code == 0 {
			t.Errorf("%s was accepted: %s", name, o)
		}
	}
	if o, code := runca(t, "client", "-dir", cadir, "-out", out, "-cn", "demo"); code != 0 {
		t.Fatalf("client: %s", o)
	}
	before, _ := runca(t, "list", "-dir", cadir)
	if _, code := runca(t, "client", "-dir", cadir, "-out", out, "-cn", "demo"); code == 0 {
		t.Error("a client certificate was overwritten")
	}
	if after, _ := runca(t, "list", "-dir", cadir); after != before {
		t.Error("a refused certificate was recorded in the index")
	}
}

// The point of it: certificates made by `hsmgate ca` are all the service needs for mutual TLS with a soft key; no other tool.
func TestCertificatesOfTheBuiltInCAServeTheService(t *testing.T) {
	d := t.TempDir()
	cadir, out := filepath.Join(d, "ca"), filepath.Join(d, "out")
	for _, args := range [][]string{
		{"init", "-dir", cadir},
		{"server", "-dir", cadir, "-out", out, "-ip", "127.0.0.1", "-dns", "localhost"},
		{"client", "-dir", cadir, "-out", out, "-cn", "demo"},
	} {
		if o, code := runca(t, args...); code != 0 {
			t.Fatalf("%v: %s", args, o)
		}
	}
	os.WriteFile(filepath.Join(d, "key.hex"), []byte(strings.Repeat("0b", 32)), 0o600)
	cfg, err := config.Parse([]byte(`
listen: 127.0.0.1:0
tls: {cert: ` + out + `/server.pem, key: ` + out + `/server.key, client_ca: ` + out + `/ca.pem}
tokens: [{name: soft, type: soft, keys: {m1: ` + d + `/key.hex}}]
keys: {demo: {versions: [{token: soft, label: m1}], aad: {mode: fixed}}}
clients: [{name: demo, identity: {cn: demo}, keys: {demo: {ops: [encrypt, decrypt]}}}]
`))
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	defer s.Close()
	pool := x509.NewCertPool()
	caPEM, _ := os.ReadFile(filepath.Join(out, "ca.pem"))
	pool.AppendCertsFromPEM(caPEM)
	cert, err := tls.LoadX509KeyPair(filepath.Join(out, "demo.pem"), filepath.Join(out, "demo.key"))
	if err != nil {
		t.Fatal(err)
	}
	with := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
	without := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	base := "https://" + l.Addr().String() + "/v1/transit/"
	call := func(c *http.Client, op, body string) (int, map[string]any, error) {
		req, _ := http.NewRequest("PUT", base+op+"/demo", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		return resp.StatusCode, m, nil
	}
	st, m, err := call(with, "encrypt", `{"plaintext":"`+base64.StdEncoding.EncodeToString([]byte("secret"))+`"}`)
	if err != nil || st != 200 {
		t.Fatalf("encrypt: %d %v %v", st, m, err)
	}
	ct := m["data"].(map[string]any)["ciphertext"].(string)
	st, m, err = call(with, "decrypt", `{"ciphertext":"`+ct+`"}`)
	if err != nil || st != 200 {
		t.Fatalf("decrypt: %d %v %v", st, m, err)
	}
	if p, _ := base64.StdEncoding.DecodeString(m["data"].(map[string]any)["plaintext"].(string)); string(p) != "secret" {
		t.Errorf("plaintext %q", p)
	}
	if _, _, err := call(without, "encrypt", `{"plaintext":"AA=="}`); err == nil {
		t.Error("a client without a certificate was served")
	}
}

// The key of the authority on or sealed to a token: nothing secret in the authority's directory, and the certificates made are good for the service all the same.
func TestCAKeyOnOrSealedToAToken(t *testing.T) {
	for _, mode := range []string{"token", "sealed"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			os.WriteFile(filepath.Join(d, "k.hex"), []byte(strings.Repeat("0d", 32)), 0o600)
			cfgPath := filepath.Join(d, "hsmgate.yaml")
			os.WriteFile(cfgPath, []byte("tokens: [{name: soft, type: soft, keys: {ca: "+d+"/k.hex}}]\n"), 0o600)
			cadir, out := filepath.Join(d, "ca"), filepath.Join(d, "out")
			o, code := runca(t, "init", "-dir", cadir, "-mode", mode, "-config", cfgPath, "-token", "soft", "-label", "ca")
			if code != 0 {
				t.Fatalf("init: %s", o)
			}
			if _, err := os.Stat(filepath.Join(cadir, "ca.key")); err == nil {
				t.Error("a key file in the directory")
			}
			// issuing needs the token: without -config it is refused, with it the token is found by the name that ca.json records
			if o, code := runca(t, "server", "-dir", cadir, "-out", out, "-ip", "127.0.0.1"); code == 0 {
				t.Errorf("issued without the token: %s", o)
			}
			if o, code := runca(t, "server", "-dir", cadir, "-out", out, "-ip", "127.0.0.1", "-config", cfgPath); code != 0 {
				t.Fatalf("server: %s", o)
			}
			if o, code := runca(t, "client", "-dir", cadir, "-out", out, "-cn", "demo", "-config", cfgPath); code != 0 {
				t.Fatalf("client: %s", o)
			}
			list, code := runca(t, "list", "-dir", cadir) // the public part needs no token
			if code != 0 || !strings.Contains(list, "key: "+mode) || !strings.Contains(list, "cn=demo") {
				t.Errorf("list: %s", list)
			}
			caPEM, _ := os.ReadFile(filepath.Join(out, "ca.pem"))
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caPEM)
			for name, usage := range map[string]x509.ExtKeyUsage{"server": x509.ExtKeyUsageServerAuth, "demo": x509.ExtKeyUsageClientAuth} {
				b, _ := os.ReadFile(filepath.Join(out, name+".pem"))
				blk, _ := pem.Decode(b)
				c, err := x509.ParseCertificate(blk.Bytes)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := c.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
					t.Errorf("%s: %v", name, err)
				}
			}
			if o, code := runca(t, "server", "-dir", cadir, "-out", out, "-ip", "127.0.0.2", "-config", cfgPath, "-token", "nope"); code == 0 {
				t.Errorf("a token that is not in the configuration: %s", o)
			}
		})
	}
	if o, code := runca(t, "init", "-dir", filepath.Join(t.TempDir(), "ca"), "-mode", "sealed"); code == 0 {
		t.Errorf("sealed with no token: %s", o)
	}
}
