package kmsgrpc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/policy"
)

type rig struct {
	t      *testing.T
	f      *Face
	srv    *httptest.Server
	client *http.Client
	rsaKey *rsa.PrivateKey
	log    *bytes.Buffer
	cfg    *config.Config
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (r *rig) jwt(issuer string, key *rsa.PrivateKey, life time.Duration) string {
	now := time.Now()
	return r.jwtClaims(key, map[string]any{"iss": issuer, "sub": issuer, "aud": "https://example.test/", "iat": now.Unix(), "exp": now.Add(life).Unix()})
}

func (r *rig) jwtClaims(key *rsa.PrivateKey, claims map[string]any) string {
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	cl, _ := json.Marshal(claims)
	in := b64(hdr) + "." + b64(cl)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		r.t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func newRig(t *testing.T) *rig {
	dir := t.TempDir()
	files := map[string]string{}
	for i, n := range []string{"m1", "m2", "m3", "m4", "m5"} {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte(strings.Repeat(string(rune('1'+i)), 64)), 0o600)
		files[n] = p
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	pubFile := filepath.Join(dir, "sa.pub")
	os.WriteFile(pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	cfg, err := config.Parse([]byte(`
kmsgrpc: {enabled: true}
tokens: [{name: soft, type: soft, keys: {m1: ` + files["m1"] + `, m2: ` + files["m2"] + `, m3: ` + files["m3"] + `, m4: ` + files["m4"] + `, m5: ` + files["m5"] + `}}]
keys:
  seal: {kmsgrpc: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  sig:  {kmsgrpc: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  mac:  {kmsgrpc: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  other: {kmsgrpc: false, kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m4}], aad: {mode: fixed}}
  mac512: {kmsgrpc: true, kmsjson_usage: generate_verify_mac, mac_hash: sha512, versions: [{token: soft, label: m5}], aad: {mode: fixed}}
clients:
  - name: app
    identity: {cn: app}
    jwt: {issuer: app@example.test, public_key_file: ` + pubFile + `}
    keys: {seal: {ops: [encrypt, decrypt]}, sig: {ops: [sign]}, mac: {ops: [generate_mac, verify_mac]}, mac512: {ops: [generate_mac, verify_mac]}, other: {ops: [encrypt]}}
`))
	if err != nil {
		t.Fatal(err)
	}
	soft, err := backend.NewSoft(cfg.Tokens[0].Keys)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, rsaKey: rk, log: &bytes.Buffer{}, cfg: cfg}
	r.f = New(audit.New(r.log), gate.New(4, time.Second), cfg.KMSGRPC.TokenPath)
	creds, err := LoadCreds(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.f.Reload(cfg, map[string]backend.Token{"soft": soft}, policy.New(cfg, nil), func(*http.Request) (string, bool) { return "", true }, creds)
	r.srv = httptest.NewUnstartedServer(http.HandlerFunc(r.f.ServeHTTP))
	r.srv.EnableHTTP2 = true
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)
	tr := r.srv.Client().Transport.(*http.Transport)
	tr.ForceAttemptHTTP2 = true
	tr.TLSClientConfig.NextProtos = []string{"h2"}
	r.client = &http.Client{Transport: tr}
	return r
}

// rpc makes one unary call and returns the status, the message of the status and the reply.
func (r *rig) rpc(method, bearer string, req *writer) (int, string, *reader) {
	r.t.Helper()
	body := make([]byte, 5, 5+len(req.b))
	body[3], body[4] = byte(len(req.b)>>8), byte(len(req.b))
	body = append(body, req.b...)
	hr, _ := http.NewRequest("POST", r.srv.URL+servicePath+method, bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/grpc")
	hr.Header.Set("Te", "trailers")
	if bearer != "" {
		hr.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := r.client.Do(hr)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 {
		r.t.Fatalf("not h2: %s", resp.Proto)
	}
	st := resp.Trailer.Get("Grpc-Status")
	if st == "" {
		st = resp.Header.Get("Grpc-Status")
	}
	code, _ := strconv.Atoi(st)
	msg := resp.Header.Get("Grpc-Message")
	if code != 0 {
		return code, msg, nil
	}
	if len(b) < 5 {
		r.t.Fatalf("short reply %x", b)
	}
	m, ok := parse(b[5:])
	if !ok {
		r.t.Fatal("reply does not parse")
	}
	return 0, "", m
}

const ring = "projects/hsmgate/locations/global/keyRings/main/cryptoKeys/"

func TestEndToEnd(t *testing.T) {
	r := newRig(t)
	// the bearer: a token from the endpoint
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {r.jwt("app@example.test", r.rsaKey, time.Hour)}}
	resp, err := r.client.PostForm(r.srv.URL+r.f.TokenPath, form)
	if err != nil {
		t.Fatal(err)
	}
	var tk struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	json.NewDecoder(resp.Body).Decode(&tk)
	resp.Body.Close()
	if resp.StatusCode != 200 || tk.TokenType != "Bearer" || tk.AccessToken == "" || tk.ExpiresIn < 590 || tk.ExpiresIn > 600 {
		t.Fatalf("token: %d %+v", resp.StatusCode, tk)
	}
	self := r.jwt("app@example.test", r.rsaKey, time.Hour) // the other way in: a bearer signed by the client itself
	for _, bearer := range []string{tk.AccessToken, self} {
		// encrypt / decrypt
		code, msg, rep := r.rpc("Encrypt", bearer, (&writer{}).str(1, ring+"seal").bytes(2, []byte("hello")).int64Value(7, crc32c([]byte("hello"))))
		if code != 0 {
			t.Fatalf("encrypt: %d %s", code, msg)
		}
		blob := rep.raw(2)
		if rep.str(1) != ring+"seal/cryptoKeyVersions/1" || len(blob) == 0 {
			t.Fatalf("encrypt reply: %q", rep.str(1))
		}
		if v, _ := rep.int64Value(4); v != crc32c(blob) {
			t.Error("ciphertext checksum")
		}
		code, msg, rep = r.rpc("Decrypt", bearer, (&writer{}).str(1, ring+"seal").bytes(2, blob))
		if code != 0 || string(rep.raw(1)) != "hello" || rep.u64(3) != 1 {
			t.Fatalf("decrypt: %d %s %q", code, msg, rep.raw(1))
		}
		if code, _, _ := r.rpc("Decrypt", bearer, (&writer{}).str(1, ring+"seal").bytes(2, blob).int64Value(5, 1)); code != cInvalid {
			t.Errorf("a wrong checksum: %d", code)
		}
	}
	// sign, and the public key checks the signature
	code, _, rep := r.rpc("GetPublicKey", tk.AccessToken, (&writer{}).str(1, ring+"sig/cryptoKeyVersions/1"))
	if code != 0 || rep.u64(2) != algECP256 {
		t.Fatalf("public key: %d", code)
	}
	blk, _ := pem.Decode([]byte(rep.str(1)))
	pk, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("message"))
	code, msg, rep := r.rpc("AsymmetricSign", tk.AccessToken, (&writer{}).str(1, ring+"sig/cryptoKeyVersions/1").msg(3, (&writer{}).bytes(1, digest[:])).int64Value(4, crc32c(digest[:])))
	if code != 0 {
		t.Fatalf("sign: %d %s", code, msg)
	}
	if !ecdsa.VerifyASN1(pk.(*ecdsa.PublicKey), digest[:], rep.raw(1)) {
		t.Error("the signature does not verify")
	}
	// mac
	code, _, rep = r.rpc("MacSign", tk.AccessToken, (&writer{}).str(1, ring+"mac/cryptoKeyVersions/1").bytes(2, []byte("data")))
	mac := rep.raw(2)
	if code != 0 || len(mac) != 32 {
		t.Fatalf("macsign: %d", code)
	}
	code, _, rep = r.rpc("MacVerify", tk.AccessToken, (&writer{}).str(1, ring+"mac").bytes(2, []byte("data")).bytes(4, mac))
	if code != 0 || rep.u64(2) != 1 {
		t.Fatalf("macverify: %d", code)
	}
	code, _, rep = r.rpc("MacVerify", tk.AccessToken, (&writer{}).str(1, ring+"mac").bytes(2, []byte("other")).bytes(4, mac))
	if code != 0 || rep.u64(2) != 0 {
		t.Fatalf("macverify of other data: %d", code)
	}
	// metadata
	code, _, rep = r.rpc("ListCryptoKeys", tk.AccessToken, (&writer{}).str(1, "projects/hsmgate/locations/global/keyRings/main"))
	if code != 0 || len(rep.bytes[1]) != 4 || rep.u64(3) != 4 {
		t.Fatalf("list: %d %d", code, len(rep.bytes[1]))
	}
	code, _, rep = r.rpc("GetCryptoKey", tk.AccessToken, (&writer{}).str(1, ring+"seal"))
	if code != 0 || rep.u64(3) != purposeEncrypt || !rep.has(2) {
		t.Fatalf("get key: %d", code)
	}
	code, _, rep = r.rpc("GenerateRandomBytes", tk.AccessToken, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 16))
	if code != 0 || len(rep.raw(1)) != 16 {
		t.Fatalf("random: %d", code)
	}
	// refusals
	for name, c := range map[string]struct {
		method, bearer string
		req            *writer
		want           int
	}{
		"no token":         {"Encrypt", "", (&writer{}).str(1, ring+"seal").bytes(2, []byte("x")), cUnauth},
		"garbage token":    {"Encrypt", "hg.nonsense", (&writer{}).str(1, ring+"seal").bytes(2, []byte("x")), cUnauth},
		"other face":       {"Encrypt", tk.AccessToken, (&writer{}).str(1, ring+"other").bytes(2, []byte("x")), cDenied},
		"no such key":      {"Encrypt", tk.AccessToken, (&writer{}).str(1, ring+"nope").bytes(2, []byte("x")), cDenied},
		"other ring":       {"Encrypt", tk.AccessToken, (&writer{}).str(1, "projects/p/locations/global/keyRings/main/cryptoKeys/seal").bytes(2, []byte("x")), cDenied},
		"no right to sign": {"Encrypt", tk.AccessToken, (&writer{}).str(1, ring+"sig").bytes(2, []byte("x")), cInvalid},
		"unsupported":      {"DestroyCryptoKeyVersion", tk.AccessToken, &writer{}, cUnimpl},
	} {
		if code, _, _ := r.rpc(c.method, c.bearer, c.req); code != c.want {
			t.Errorf("%s: code %d, want %d", name, code, c.want)
		}
	}
	// a token signed by another key, an expired one
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if code, _, _ := r.rpc("GenerateRandomBytes", r.jwt("app@example.test", other, time.Hour), (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8)); code != cUnauth {
		t.Errorf("a forged token: %d", code)
	}
	if code, _, _ := r.rpc("GenerateRandomBytes", r.jwt("app@example.test", r.rsaKey, -time.Hour), (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8)); code != cUnauth {
		t.Errorf("an expired token: %d", code)
	}
	// the audit log has a line for each call and none holds a token
	if strings.Contains(r.log.String(), tk.AccessToken) || !strings.Contains(r.log.String(), `"op":"encrypt"`) {
		t.Error("the audit log")
	}
}

func TestTokenEndpointRefusals(t *testing.T) {
	r := newRig(t)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, form := range map[string]url.Values{
		"wrong grant": {"grant_type": {"password"}, "assertion": {"x"}},
		"forged":      {"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {r.jwt("app@example.test", other, time.Hour)}},
		"unknown":     {"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {r.jwt("who@example.test", r.rsaKey, time.Hour)}},
		"not a token": {"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {"a.b.c"}},
		"a long life": {"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {r.jwt("app@example.test", r.rsaKey, 48*time.Hour)}},
	} {
		resp, err := r.client.PostForm(r.srv.URL+r.f.TokenPath, form)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
}

func TestCertlessMustBeAllowed(t *testing.T) {
	r := newRig(t)
	r.f.NoCertificate = func(*http.Request) bool { return true }
	cfg := r.cfg
	creds, _ := LoadCreds(cfg)
	// the connection shows no certificate and the credential is not marked no_cert
	r.f.Reload(cfg, nil, policy.New(cfg, nil), func(*http.Request) (string, bool) { return "", false }, creds)
	if code, _, _ := r.rpc("GenerateRandomBytes", r.jwt("app@example.test", r.rsaKey, time.Hour), (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8)); code != cUnauth {
		t.Errorf("a credential without no_cert, no certificate: %d", code)
	}
}

func TestVersionsHandlesAndCertless(t *testing.T) {
	r := newRig(t)
	code, bearer := 0, r.jwt("app@example.test", r.rsaKey, time.Hour)
	_ = code
	st, _, rep := r.rpc("ListCryptoKeyVersions", bearer, (&writer{}).str(1, ring+"seal"))
	if st != 0 || len(rep.bytes[1]) != 1 || rep.u64(3) != 1 {
		t.Fatalf("versions: %d", st)
	}
	st, _, rep = r.rpc("GetCryptoKeyVersion", bearer, (&writer{}).str(1, ring+"seal/cryptoKeyVersions/1"))
	if st != 0 || rep.u64(3) != stateEnabled || rep.u64(10) != algSymmetric {
		t.Fatalf("version: %d", st)
	}
	for _, name := range []string{ring + "seal", ring + "seal/cryptoKeyVersions/9"} {
		if st, _, _ := r.rpc("GetCryptoKeyVersion", bearer, (&writer{}).str(1, name)); st == 0 {
			t.Errorf("%s was accepted", name)
		}
	}
	if st, _, _ := r.rpc("GetCryptoKey", bearer, (&writer{}).str(1, ring+"seal/cryptoKeyVersions/1")); st == 0 {
		t.Error("a version name for a key")
	}
	if st, _, _ := r.rpc("ListCryptoKeyVersions", bearer, (&writer{}).str(1, ring+"seal/cryptoKeyVersions/1")); st == 0 {
		t.Error("a version name for a list")
	}
	if st, _, _ := r.rpc("GenerateRandomBytes", bearer, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 5000)); st != cInvalid {
		t.Errorf("too many bytes: %d", st)
	}
	if st, _, _ := r.rpc("GenerateRandomBytes", bearer, (&writer{}).str(1, "projects/x/locations/global").u64(2, 5)); st != cDenied {
		t.Errorf("another project: %d", st)
	}
	// Handles: a call of the service and the token endpoint, nothing else
	mk := func(method, path, ct string) *http.Request {
		q, _ := http.NewRequest(method, "https://x"+path, nil)
		q.Header.Set("Content-Type", ct)
		return q
	}
	if !r.f.Handles(mk("POST", servicePath+"Encrypt", "application/grpc")) || !r.f.Handles(mk("POST", r.f.TokenPath, "")) ||
		r.f.Handles(mk("GET", r.f.TokenPath, "")) || r.f.Handles(mk("POST", "/v1/transit/x", "application/json")) {
		t.Error("Handles")
	}
	// an h1 call, and a bearer on the wrong kind of request
	if st, _, _ := r.rpc("Encrypt", "", (&writer{}).str(1, ring+"seal")); st != cUnauth {
		t.Errorf("no bearer: %d", st)
	}
	// without a certificate: the credential is not marked no_cert, and a refused call is counted
	r.f.NoCertificate = func(*http.Request) bool { return true }
	r.f.Reload(r.cfg, nil, policy.New(r.cfg, nil), func(*http.Request) (string, bool) { return "", false }, mustCreds(t, r.cfg))
	for i := 0; i < 25; i++ {
		r.rpc("GenerateRandomBytes", bearer, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8))
	}
	if st, _, _ := r.rpc("GenerateRandomBytes", bearer, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8)); st != cExhausted {
		t.Errorf("a blocked address: %d", st)
	}
}

func mustCreds(t *testing.T, cfg *config.Config) map[string]Cred {
	c, err := LoadCreds(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNamesRefuseVersionsOverTheLimit(t *testing.T) {
	n := names{project: "p", location: "l", keyRing: "r"}
	if _, v, has, ok := n.parseKey(n.version("k", 1000)); !ok || !has || v != 1000 {
		t.Errorf("the largest version: %d %v %v", v, has, ok)
	}
	for _, name := range []string{n.version("k", 1001), n.version("k", 70000), n.key("k") + "/cryptoKeyVersions/0", n.key("k") + "/cryptoKeyVersions/-1", n.key("k") + "/cryptoKeyVersions/99999999999999999999"} {
		if _, _, _, ok := n.parseKey(name); ok {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Fuzzing: whatever bytes arrive as a message or a resource name, the parsers neither panic nor accept what is not theirs.
func FuzzParseMessage(f *testing.F) {
	f.Add([]byte{})
	f.Add((&writer{}).str(1, ring+"seal").bytes(2, []byte("x")).int64Value(7, 5).b)
	f.Add([]byte{0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, ok := parse(b)
		if !ok {
			return
		}
		r.str(1)
		r.raw(2)
		r.u64(3)
		r.int64Value(7)
		r.msg(3)
	})
}

func FuzzParseKeyName(f *testing.F) {
	n := names{project: "hsmgate", location: "global", keyRing: "main"}
	f.Add(n.version("seal", 1))
	f.Add(n.key("seal"))
	f.Add("projects/hsmgate/locations/global/keyRings/main/cryptoKeys//cryptoKeyVersions/")
	f.Fuzz(func(t *testing.T, name string) {
		key, ver, hasVer, ok := n.parseKey(name)
		if ok && (key == "" || strings.Contains(key, "/") || (hasVer && (ver < 1 || ver > config.MaxVersions)) || (!hasVer && ver != 0)) {
			t.Fatalf("%q parsed as %q %d %v", name, key, ver, hasVer)
		}
	})
}

// The hash of the HMAC is a choice of the key (mac_hash): the key's algorithm says it, and the MAC has that hash's size.
func TestMacHashIsChosenPerKey(t *testing.T) {
	r := newRig(t)
	bearer := r.jwt("app@example.test", r.rsaKey, time.Hour)
	for key, c := range map[string]struct {
		alg  uint64
		size int
	}{"mac": {algHMAC, 32}, "mac512": {algHMAC512, 64}} {
		st, _, rep := r.rpc("GetCryptoKeyVersion", bearer, (&writer{}).str(1, ring+key+"/cryptoKeyVersions/1"))
		if st != 0 || rep.u64(10) != c.alg {
			t.Errorf("%s: the algorithm is %d (%d)", key, rep.u64(10), st)
		}
		st, _, rep = r.rpc("MacSign", bearer, (&writer{}).str(1, ring+key+"/cryptoKeyVersions/1").bytes(2, []byte("data")))
		if st != 0 || len(rep.raw(2)) != c.size {
			t.Fatalf("%s: %d a MAC of %d bytes", key, st, len(rep.raw(2)))
		}
		mac := rep.raw(2)
		st, _, rep = r.rpc("MacVerify", bearer, (&writer{}).str(1, ring+key).bytes(2, []byte("data")).bytes(4, mac))
		if st != 0 || rep.u64(2) != 1 {
			t.Errorf("%s verify: %d", key, st)
		}
	}
}

// The audience and the subject of a token (the review of 2026-11-21, finding 1): a token made for the token endpoint is not a bearer for the API, one made for the API is not an
// assertion for the exchange, and neither is good for another service or for another subject.
func TestAudienceAndSubject(t *testing.T) {
	r := newRig(t)
	const endpoint, api = "https://kms.example.test/oauth2/token", "https://cloudkms.example.test/"
	r.cfg.KMSGRPC.TokenAudiences = []string{endpoint}
	r.cfg.KMSGRPC.BearerAudiences = []string{api}
	r.f.Reload(r.cfg, nil, policy.New(r.cfg, nil), func(*http.Request) (string, bool) { return "", true }, mustCreds(t, r.cfg))
	now := time.Now()
	mk := func(extra map[string]any) string {
		c := map[string]any{"iss": "app@example.test", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return r.jwtClaims(r.rsaKey, c)
	}
	exchange := func(assertion string) int {
		resp, err := r.client.PostForm(r.srv.URL+r.f.TokenPath, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	call := func(bearer string) int {
		code, _, _ := r.rpc("GenerateRandomBytes", bearer, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8))
		return code
	}
	for _, tc := range []struct {
		name   string
		claims map[string]any
		exch   int // the token endpoint
		bearer int // a call with the JWT as it is
		word   string
	}{
		{"made for the endpoint", map[string]any{"aud": endpoint}, 200, cUnauth, "bad_audience"},
		{"made for the API", map[string]any{"aud": api}, 400, 0, "bad_audience"},
		{"the endpoint and the API", map[string]any{"aud": []string{endpoint, api}}, 200, 0, ""},
		{"made for another service", map[string]any{"aud": "https://other.example.test/"}, 400, cUnauth, "bad_audience"},
		{"no audience", nil, 400, cUnauth, "bad_audience"},
		{"for another subject", map[string]any{"aud": []string{endpoint, api}, "sub": "boss@example.test"}, 400, cUnauth, "bad_subject"},
		{"the subject is the issuer", map[string]any{"aud": []string{endpoint, api}, "sub": "app@example.test"}, 200, 0, ""},
	} {
		tok := mk(tc.claims)
		r.log.Reset()
		if got := exchange(tok); got != tc.exch {
			t.Errorf("%s: the exchange answered %d, want %d", tc.name, got, tc.exch)
		}
		if tc.exch != 200 && tc.word != "" && !strings.Contains(r.log.String(), `"result":"`+tc.word+`"`) {
			t.Errorf("%s: the audit line of the exchange has no %q: %s", tc.name, tc.word, r.log.String())
		}
		r.log.Reset()
		if got := call(tok); got != tc.bearer {
			t.Errorf("%s: the call as a bearer gave %d, want %d", tc.name, got, tc.bearer)
		}
		if tc.bearer != 0 && tc.word != "" && !strings.Contains(r.log.String(), `"result":"`+tc.word+`"`) {
			t.Errorf("%s: the audit line of the call has no %q: %s", tc.name, tc.word, r.log.String())
		}
	}
}

// A token does not outlive the credential it was given for (the review of 2026-11-21, finding 2): a new key for the issuer ends it at the next call; a reload that changes
// nothing does not.
func TestTokenDiesWithItsKey(t *testing.T) {
	r := newRig(t)
	reload := func() {
		r.f.Reload(r.cfg, nil, policy.New(r.cfg, nil), func(*http.Request) (string, bool) { return "", true }, mustCreds(t, r.cfg))
	}
	exchange := func(key *rsa.PrivateKey) (int, string) {
		resp, err := r.client.PostForm(r.srv.URL+r.f.TokenPath, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {r.jwt("app@example.test", key, time.Hour)}})
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var tk struct {
			AccessToken string `json:"access_token"`
		}
		json.NewDecoder(resp.Body).Decode(&tk)
		return resp.StatusCode, tk.AccessToken
	}
	call := func(tok string) int {
		code, _, _ := r.rpc("GenerateRandomBytes", tok, (&writer{}).str(1, "projects/hsmgate/locations/global").u64(2, 8))
		return code
	}
	code, tok := exchange(r.rsaKey)
	if code != 200 || call(tok) != 0 {
		t.Fatalf("the token is good before: %d", code)
	}
	reload() // nothing changed
	if call(tok) != 0 {
		t.Fatal("a reload that changes nothing ended the token")
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	os.WriteFile(r.cfg.Clients[0].JWT.PublicKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	reload()
	r.log.Reset()
	if c := call(tok); c != cUnauth || !strings.Contains(r.log.String(), `"result":"credential_changed"`) {
		t.Errorf("the token of the replaced key: %d %s", c, r.log.String())
	}
	if code, _ := exchange(r.rsaKey); code == 200 {
		t.Error("the old key still gives a token")
	}
	if code, tok2 := exchange(other); code != 200 || call(tok2) != 0 {
		t.Error("the new key does not work")
	}
}

// recordingWriter keeps what the face hands to Write, by reference, to see what the face does with it afterwards.
type recordingWriter struct {
	httptest.ResponseRecorder
	frames [][]byte
	copies [][]byte
}

func (w *recordingWriter) Write(p []byte) (int, error) {
	w.frames = append(w.frames, p)
	w.copies = append(w.copies, append([]byte{}, p...))
	return len(p), nil
}

// The reply of a decryption holds the plaintext; the frame the face builds for it is zeroed once it has been handed to the writer (the review of 2026-11-21, finding 3).
func TestDecryptReplyFrameIsWipedAfterTheWrite(t *testing.T) {
	r := newRig(t)
	bearer := r.jwt("app@example.test", r.rsaKey, time.Hour)
	plain := []byte("a plaintext that must not stay in the buffer")
	code, msg, rep := r.rpc("Encrypt", bearer, (&writer{}).str(1, ring+"seal").bytes(2, plain).int64Value(7, crc32c(plain)))
	if code != 0 {
		t.Fatalf("encrypt: %d %s", code, msg)
	}
	blob := rep.raw(2)
	req := (&writer{}).str(1, ring+"seal").bytes(2, blob).int64Value(5, crc32c(blob))
	body := make([]byte, 5, 5+len(req.b))
	body[3], body[4] = byte(len(req.b)>>8), byte(len(req.b))
	body = append(body, req.b...)
	hr := httptest.NewRequest("POST", servicePath+"Decrypt", bytes.NewReader(body))
	hr.ProtoMajor, hr.ProtoMinor = 2, 0
	hr.Header.Set("Content-Type", "application/grpc")
	hr.Header.Set("Authorization", "Bearer "+bearer)
	w := &recordingWriter{}
	r.f.ServeHTTP(w, hr)
	if len(w.frames) == 0 {
		t.Fatal("the face wrote nothing")
	}
	var said bool
	for i, c := range w.copies {
		if bytes.Contains(c, plain) {
			said = true
			if !bytes.Equal(w.frames[i], make([]byte, len(w.frames[i]))) {
				t.Errorf("the frame with the plaintext was not zeroed after the write")
			}
		}
	}
	if !said {
		t.Fatal("the plaintext did not come out of the face (the test does not test what it says)")
	}
}
