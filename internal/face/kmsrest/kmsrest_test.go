package kmsrest

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/policy"
)

const secret = "a-client-secret-of-the-test-0123456789"

type rig struct {
	t      *testing.T
	f      *Face
	srv    *httptest.Server
	rsaKey *rsa.PrivateKey
	log    *bytes.Buffer
	cfg    *config.Config
}

func newRig(t *testing.T) *rig {
	dir := t.TempDir()
	files := map[string]string{}
	for i, n := range []string{"m1", "m2", "m3", "m4"} {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte(strings.Repeat(string(rune('1'+i)), 64)), 0o600)
		files[n] = p
	}
	os.WriteFile(filepath.Join(dir, "secret"), []byte(secret+"\n"), 0o600)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	os.WriteFile(filepath.Join(dir, "cert.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	cfg, err := config.Parse([]byte(`
kmsrest: {enabled: true}
tokens: [{name: soft, type: soft, keys: {m1: ` + files["m1"] + `, m2: ` + files["m2"] + `, m3: ` + files["m3"] + `, m4: ` + files["m4"] + `}}]
keys:
  seal: {kmsrest: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  sig:  {kmsrest: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  mac:  {kmsrest: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  other: {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m4}], aad: {mode: fixed}}
clients:
  - name: app
    identity: {cn: app}
    oauth: {client_id: app-client, secret_file: ` + filepath.Join(dir, "secret") + `}
    keys: {seal: {ops: [encrypt, decrypt]}, sig: {ops: [sign, verify]}, mac: {ops: [generate_mac, verify_mac]}}
  - name: cert
    identity: {cn: cert}
    oauth: {client_id: cert-client, public_key_file: ` + filepath.Join(dir, "cert.pub") + `}
    keys: {seal: {ops: [encrypt]}}
`))
	if err != nil {
		t.Fatal(err)
	}
	soft, err := backend.NewSoft(cfg.Tokens[0].Keys)
	if err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, rsaKey: rk, log: &bytes.Buffer{}, cfg: cfg}
	r.f = New(audit.New(r.log), gate.New(4, time.Second), cfg.KMSRest.Tenant)
	creds, err := LoadCreds(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.f.Reload(cfg, map[string]backend.Token{"soft": soft}, policy.New(cfg, nil), func(*http.Request) (string, bool) { return "", true }, creds)
	r.srv = httptest.NewTLSServer(http.HandlerFunc(r.f.ServeHTTP))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) token(form url.Values) (int, string) {
	resp, err := r.srv.Client().PostForm(r.srv.URL+r.f.tokenPath(), form)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var tk struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tk)
	return resp.StatusCode, tk.AccessToken
}

func (r *rig) do(method, path, bearer string, body any) (int, map[string]any, http.Header) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path+"?api-version=7.5", rd)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := r.srv.Client().Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func (r *rig) assertion(id string, key *rsa.PrivateKey) string {
	b64 := func(b []byte) string { return b64.EncodeToString(b) }
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	now := time.Now()
	cl, _ := json.Marshal(map[string]any{"iss": id, "sub": id, "aud": r.srv.URL + r.f.tokenPath(), "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix()})
	in := b64(hdr) + "." + b64(cl)
	sum := sha256.Sum256([]byte(in))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	return in + "." + b64(sig)
}

func TestEndToEnd(t *testing.T) {
	r := newRig(t)
	code, bearer := r.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"app-client"}, "client_secret": {secret}, "scope": {"https://vault.azure.net/.default"}})
	if code != 200 || bearer == "" {
		t.Fatalf("token: %d", code)
	}
	// without a token: a challenge
	st, _, h := r.do("GET", "/keys", "", nil)
	if st != 401 || !strings.Contains(h.Get("WWW-Authenticate"), `resource="https://vault.azure.net"`) || !strings.Contains(h.Get("WWW-Authenticate"), "authorization=") {
		t.Errorf("challenge: %d %q", st, h.Get("WWW-Authenticate"))
	}
	// encrypt / decrypt
	st, out, _ := r.do("POST", "/keys/seal//encrypt", bearer, map[string]string{"alg": "A256GCM", "value": b64.EncodeToString([]byte("hello"))})
	if st != 200 {
		t.Fatalf("encrypt: %d %v", st, out)
	}
	kid := out["kid"].(string)
	if !strings.Contains(kid, "/keys/seal/00000000000000000000000000000001") {
		t.Errorf("kid %s", kid)
	}
	st, out2, _ := r.do("POST", "/keys/seal/00000000000000000000000000000001/decrypt", bearer, map[string]string{"alg": "A256GCM", "value": out["value"].(string)})
	if st != 200 {
		t.Fatalf("decrypt: %d %v", st, out2)
	}
	if p, _ := dec(out2["value"].(string)); string(p) != "hello" {
		t.Errorf("plaintext %q", p)
	}
	// sign, with the key from the key bundle
	st, out, _ = r.do("GET", "/keys/sig", bearer, nil)
	if st != 200 {
		t.Fatalf("get key: %d %v", st, out)
	}
	jwk := out["key"].(map[string]any)
	if jwk["kty"] != "EC-HSM" || jwk["crv"] != "P-256" {
		t.Fatalf("%v", jwk)
	}
	x, _ := dec(jwk["x"].(string))
	y, _ := dec(jwk["y"].(string))
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("m"))
	st, out, _ = r.do("POST", "/keys/sig//sign", bearer, map[string]string{"alg": "ES256", "value": b64.EncodeToString(d[:])})
	if st != 200 {
		t.Fatalf("sign: %d %v", st, out)
	}
	sig, _ := dec(out["value"].(string))
	if len(sig) != 64 || !ecdsa.Verify(pub, d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatalf("the signature does not verify")
	}
	st, out, _ = r.do("POST", "/keys/sig//verify", bearer, map[string]string{"alg": "ES256", "digest": b64.EncodeToString(d[:]), "value": b64.EncodeToString(sig)})
	if st != 200 || out["value"] != true {
		t.Errorf("verify: %d %v", st, out)
	}
	sig[5] ^= 1
	_, out, _ = r.do("POST", "/keys/sig//verify", bearer, map[string]string{"alg": "ES256", "digest": b64.EncodeToString(d[:]), "value": b64.EncodeToString(sig)})
	if out["value"] != false {
		t.Errorf("a damaged signature verified")
	}
	// mac
	st, out, _ = r.do("POST", "/keys/mac//sign", bearer, map[string]string{"alg": "HS256", "value": b64.EncodeToString([]byte("data"))})
	if st != 200 {
		t.Fatalf("mac: %d %v", st, out)
	}
	_, out2, _ = r.do("POST", "/keys/mac//verify", bearer, map[string]string{"alg": "HS256", "digest": b64.EncodeToString([]byte("data")), "value": out["value"].(string)})
	if out2["value"] != true {
		t.Errorf("mac verify")
	}
	// lists and random
	st, out, _ = r.do("GET", "/keys", bearer, nil)
	if st != 200 || len(out["value"].([]any)) != 3 {
		t.Errorf("list: %d %v", st, out)
	}
	st, out, _ = r.do("POST", "/rng", bearer, map[string]int{"count": 16})
	if p, _ := dec(out["value"].(string)); st != 200 || len(p) != 16 {
		t.Errorf("rng: %d", st)
	}
	// refusals
	for name, c := range map[string]struct {
		method, path, bearer string
		body                 any
		want                 int
	}{
		"bad token":       {"GET", "/keys", "hg.nope", nil, 401},
		"other face":      {"POST", "/keys/other//encrypt", bearer, map[string]string{"alg": "A256GCM", "value": "AQ"}, 403},
		"no such key":     {"GET", "/keys/nope", bearer, nil, 403},
		"wrong usage":     {"POST", "/keys/seal//sign", bearer, map[string]string{"alg": "ES256", "value": "AQ"}, 400},
		"wrong algorithm": {"POST", "/keys/sig//sign", bearer, map[string]string{"alg": "RS256", "value": "AQ"}, 400},
		"no right":        {"POST", "/keys/seal//sign", bearer, map[string]string{"alg": "HS256", "value": "AQ"}, 400},
		"unknown path":    {"GET", "/keys/seal/1/2/3/4", bearer, nil, 404},
		"bad version":     {"GET", "/keys/seal/zz", bearer, nil, 404},
	} {
		if st, _, _ := r.do(c.method, c.path, c.bearer, c.body); st != c.want {
			t.Errorf("%s: %d, want %d", name, st, c.want)
		}
	}
	if strings.Contains(r.log.String(), bearer) || strings.Contains(r.log.String(), secret) {
		t.Error("the audit log holds a credential")
	}
}

func TestTokenEndpoint(t *testing.T) {
	r := newRig(t)
	if code, tok := r.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"cert-client"}, "client_assertion_type": {assertionTy}, "client_assertion": {r.assertion("cert-client", r.rsaKey)}}); code != 200 || tok == "" {
		t.Errorf("assertion: %d", code)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, form := range map[string]url.Values{
		"wrong secret":                  {"grant_type": {"client_credentials"}, "client_id": {"app-client"}, "client_secret": {secret + "x"}},
		"no secret":                     {"grant_type": {"client_credentials"}, "client_id": {"app-client"}},
		"unknown":                       {"grant_type": {"client_credentials"}, "client_id": {"who"}, "client_secret": {secret}},
		"forged assertion":              {"grant_type": {"client_credentials"}, "client_assertion_type": {assertionTy}, "client_assertion": {r.assertion("cert-client", other)}},
		"secret for a cert":             {"grant_type": {"client_credentials"}, "client_id": {"cert-client"}, "client_secret": {secret}},
		"assertion for a secret client": {"grant_type": {"client_credentials"}, "client_assertion_type": {assertionTy}, "client_assertion": {r.assertion("app-client", r.rsaKey)}},
		"wrong grant":                   {"grant_type": {"password"}, "client_id": {"app-client"}, "client_secret": {secret}},
	} {
		if code, tok := r.token(form); code == 200 || tok != "" {
			t.Errorf("%s: %d", name, code)
		}
	}
}

func TestVersionsDiscoveryAndHandles(t *testing.T) {
	r := newRig(t)
	_, bearer := r.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"app-client"}, "client_secret": {secret}})
	st, out, _ := r.do("GET", "/keys/seal/versions", bearer, nil)
	if st != 200 || len(out["value"].([]any)) != 1 {
		t.Fatalf("versions: %d %v", st, out)
	}
	st, out, _ = r.do("GET", "/keys/seal/00000000000000000000000000000001", bearer, nil)
	if st != 200 || out["key"].(map[string]any)["kty"] != "oct-HSM" {
		t.Errorf("key by version: %d %v", st, out)
	}
	st, out, _ = r.do("GET", "/keys/mac", bearer, nil)
	if st != 200 || out["key"].(map[string]any)["key_ops"] == nil {
		t.Errorf("mac key: %d %v", st, out)
	}
	if st, _, _ := r.do("GET", "/keys/seal/00000000000000000000000000000009", bearer, nil); st != 404 {
		t.Errorf("a version that is not there: %d", st)
	}
	if st, _, _ := r.do("POST", "/rng", bearer, map[string]int{"count": 500}); st != 400 {
		t.Errorf("too many bytes: %d", st)
	}
	if st, _, _ := r.do("POST", "/rng", bearer, map[string]string{"count": "x"}); st != 400 {
		t.Errorf("a bad body: %d", st)
	}
	if st, _, _ := r.do("POST", "/keys/seal//encrypt", bearer, map[string]string{"alg": "RSA-OAEP", "value": "AQ"}); st != 400 {
		t.Errorf("a bad algorithm: %d", st)
	}
	if st, _, _ := r.do("POST", "/keys/seal//decrypt", bearer, map[string]string{"alg": "A256GCM", "value": "AQ"}); st != 400 {
		t.Errorf("a damaged ciphertext: %d", st)
	}
	if st, _, _ := r.do("POST", "/keys/sig//verify", bearer, map[string]string{"alg": "ES256", "digest": "AQ", "value": "AQ"}); st != 200 {
		t.Errorf("a short signature simply does not verify: %d", st)
	}
	// the discovery document is public
	resp, err := r.srv.Client().Get(r.srv.URL + r.f.discoveryPath())
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	json.NewDecoder(resp.Body).Decode(&d)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.HasSuffix(d["token_endpoint"].(string), tokenSuffix) {
		t.Errorf("discovery: %d %v", resp.StatusCode, d)
	}
	mk := func(method, path string) *http.Request {
		q, _ := http.NewRequest(method, "https://x"+path, nil)
		return q
	}
	if !r.f.Handles(mk("GET", "/keys")) || !r.f.Handles(mk("POST", "/rng")) || !r.f.Handles(mk("POST", r.f.tokenPath())) || r.f.Handles(mk("GET", "/v1/transit/keys")) || r.f.Handles(mk("GET", "/keysx")) {
		t.Error("Handles")
	}
	// without a certificate: the credential is not marked no_cert; refused attempts are counted and the address is blocked
	r.f.NoCertificate = func(*http.Request) bool { return true }
	cfg := r.cfg
	creds, _ := LoadCreds(cfg)
	r.f.Reload(cfg, nil, policy.New(cfg, nil), func(*http.Request) (string, bool) { return "", false }, creds)
	for i := 0; i < 25; i++ {
		r.do("GET", "/keys", bearer, nil)
	}
	if st, _, _ := r.do("GET", "/keys", bearer, nil); st != 429 {
		t.Errorf("a blocked address: %d", st)
	}
	if code, _ := r.token(url.Values{"grant_type": {"client_credentials"}, "client_id": {"app-client"}, "client_secret": {secret}}); code == 200 {
		t.Error("a token was given to a blocked address")
	}
}

func FuzzRoute(f *testing.F) {
	for _, p := range []string{"/keys", "/keys/seal", "/keys/seal/versions", "/keys/seal//encrypt", "/keys/seal/00000000000000000000000000000001/sign", "/rng", "/keys//", "/keys/a/b/c/d"} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if !strings.HasPrefix(path, "/") {
			return
		}
		u, err := url.Parse("https://h" + path)
		if err != nil {
			return
		}
		r := &http.Request{URL: u}
		name, ver, rt := routeOf(r)
		if rt != nil {
			if n, ok := parseVersion(ver); ok && (n < 0 || n > config.MaxVersions) {
				t.Fatalf("%q: version %q is %d", path, ver, n)
			}
			_ = name
		}
	})
}
