package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
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

func ipnet(s string) net.Addr {
	ip, n, _ := net.ParseCIDR(s)
	n.IP = ip
	return n
}

func TestGuessNames(t *testing.T) {
	addrs := []net.Addr{ipnet("127.0.0.1/8"), ipnet("192.0.2.10/24"), ipnet("fe80::1/64"), ipnet("2001:db8::5/64"), ipnet("10.9.8.7/16"), ipnet("224.0.0.1/4")}
	dns, ips := guessNames("0.0.0.0:8443", "Node-1", addrs)
	if strings.Join(dns, ",") != "localhost,node-1" {
		t.Errorf("dns %v", dns)
	}
	var got []string
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	// every global unicast address of the interfaces (IPv4 first), never loopback twice, link-local or multicast; 127.0.0.1 always
	if strings.Join(got, ",") != "192.0.2.10,10.9.8.7,2001:db8::5,127.0.0.1" {
		t.Errorf("ips %v", got)
	}
	// an address in listen: is the one address
	_, ips = guessNames("192.0.2.77:8443", "node", addrs)
	got = nil
	for _, ip := range ips {
		got = append(got, ip.String())
	}
	if strings.Join(got, ",") != "192.0.2.77,127.0.0.1" {
		t.Errorf("a listen address: %v", got)
	}
	// a name in listen: is a name of the certificate; a host name that is not a name is left out
	dns, _ = guessNames("hsmgate.example:8443", "not a host!", nil)
	if strings.Join(dns, ",") != "hsmgate.example,localhost" {
		t.Errorf("dns %v", dns)
	}
	// not more than maxGuessedIPs
	var many []net.Addr
	for i := 1; i <= 30; i++ {
		many = append(many, ipnet(fmt.Sprintf("198.51.100.%d/24", i)))
	}
	if _, ips := guessNames(":8443", "", many); len(ips) != maxGuessedIPs+1 {
		t.Errorf("%d addresses", len(ips))
	}
}

// One command: from the configuration alone, the authority, the server certificate where tls: says, the trust anchor, and a client certificate; and the service starts with them.
func TestSetupInOneCommand(t *testing.T) {
	for _, mode := range []string{"file", "sealed", "token"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			os.WriteFile(filepath.Join(d, "k.hex"), []byte(strings.Repeat("0e", 32)), 0o600)
			cfgPath := filepath.Join(d, "hsmgate.yaml")
			cfgText := `
listen: 127.0.0.1:0
tls: {cert: ` + d + `/tls/server.pem, key: ` + d + `/tls/server.key, client_ca: ` + d + `/tls/ca.pem}
tokens: [{name: soft, type: soft, keys: {m1: ` + d + `/k.hex}}]
keys: {demo: {versions: [{token: soft, label: m1}], aad: {mode: fixed}}}
clients: [{name: demo, identity: {cn: demo}, keys: {demo: {ops: [encrypt, decrypt]}}}]
`
			os.WriteFile(cfgPath, []byte(cfgText), 0o600)
			args := []string{"setup", "-config", cfgPath, "-client", "demo"}
			if mode != "file" {
				args = append(args, "-mode", mode, "-token", "soft", "-label", "m1")
			}
			o, code := runca(t, args...)
			if code != 0 {
				t.Fatalf("setup: %s", o)
			}
			for _, want := range []string{"names guessed from listen", "127.0.0.1", "server certificate until", "client certificate until", "identity: {cn: demo}", "restart the service"} {
				if !strings.Contains(o, want) {
					t.Errorf("the output lacks %q:\n%s", want, o)
				}
			}
			for _, f := range []string{"tls/server.pem", "tls/server.key", "tls/ca.pem", "clients/demo.pem", "clients/demo.key", "clients/ca.pem", "ca/ca.pem", "ca/index.tsv"} {
				if _, err := os.Stat(filepath.Join(d, f)); err != nil {
					t.Errorf("%s: %v", f, err)
				}
			}
			if _, err := os.Stat(filepath.Join(d, "ca/ca.key")); (err == nil) != (mode == "file") {
				t.Errorf("ca.key in mode %s: %v", mode, err)
			}
			// again: nothing is overwritten and nothing is made first (the authority keeps its index)
			before, _ := os.ReadFile(filepath.Join(d, "ca/index.tsv"))
			if o, code := runca(t, args...); code == 0 || !strings.Contains(o, "not overwritten") {
				t.Errorf("a second setup: %d %s", code, o)
			}
			if after, _ := os.ReadFile(filepath.Join(d, "ca/index.tsv")); !bytes.Equal(before, after) {
				t.Error("a refused setup recorded a certificate")
			}
			// the service starts with the files that were made, and a client with the made certificate is served
			cfg, err := config.Load(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			s, err := server.New(cfg, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			l, _ := net.Listen("tcp", "127.0.0.1:0")
			go s.Serve(l)
			defer s.Close()
			pool := x509.NewCertPool()
			caPEM, _ := os.ReadFile(filepath.Join(d, "clients/ca.pem"))
			pool.AppendCertsFromPEM(caPEM)
			cert, err := tls.LoadX509KeyPair(filepath.Join(d, "clients/demo.pem"), filepath.Join(d, "clients/demo.key"))
			if err != nil {
				t.Fatal(err)
			}
			cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
			req, _ := http.NewRequest("PUT", "https://"+l.Addr().String()+"/v1/transit/encrypt/demo", strings.NewReader(`{"plaintext":"AA=="}`))
			req.Header.Set("Content-Type", "application/json")
			resp, err := cl.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Errorf("encrypt: %d", resp.StatusCode)
			}
		})
	}
}

func TestSetupNeedsATLSBlockAndIssuesFromTheConfig(t *testing.T) {
	d := t.TempDir()
	cfgPath := filepath.Join(d, "hsmgate.yaml")
	os.WriteFile(cfgPath, []byte("listen: 127.0.0.1:0\n"), 0o600)
	if o, code := runca(t, "setup", "-config", cfgPath); code == 0 || !strings.Contains(o, "tls:") {
		t.Errorf("no tls block: %d %s", code, o)
	}
	if _, code := runca(t, "setup"); code != 2 {
		t.Error("setup without -config")
	}
	os.WriteFile(cfgPath, []byte("listen: 127.0.0.1:0\ntls: {cert: "+d+"/s.pem, key: "+d+"/s.key, client_ca: "+d+"/ca.pem}\n"), 0o600)
	if o, code := runca(t, "init", "-dir", filepath.Join(d, "ca")); code != 0 {
		t.Fatal(o)
	}
	// server and client with -config only: the files go where tls: says and to clients/, the names are guessed
	if o, code := runca(t, "server", "-dir", filepath.Join(d, "ca"), "-config", cfgPath); code != 0 || !strings.Contains(o, d+"/s.pem") {
		t.Errorf("server: %d %s", code, o)
	}
	if o, code := runca(t, "client", "-dir", filepath.Join(d, "ca"), "-config", cfgPath, "-cn", "x"); code != 0 || !strings.Contains(o, "clients") {
		t.Errorf("client: %d %s", code, o)
	}
	// the default directory of the authority is ca/ next to the configuration
	if o, code := runca(t, "list", "-dir", filepath.Join(d, "ca")); code != 0 || !strings.Contains(o, "cn=x") {
		t.Errorf("list: %s", o)
	}
}

func TestVirtualInterfacesAreLeftOut(t *testing.T) {
	for _, n := range []string{"docker0", "veth1a2b", "br-3f4e", "virbr0", "cni0", "tun0"} {
		if !virtualInterface(n) {
			t.Errorf("%s is virtual", n)
		}
	}
	for _, n := range []string{"eth0", "enp3s0", "wlp2s0", "ens18", "bond0"} {
		if virtualInterface(n) {
			t.Errorf("%s is real", n)
		}
	}
}
