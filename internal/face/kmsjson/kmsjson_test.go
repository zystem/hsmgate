package kmsjson

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/zystem/hsmgate/internal/sigv4"
)

const akid = "AKIDEXAMPLEEXAMPLE"

var secret = []byte("a-secret-of-the-client-0123456789")

type lockedToken struct{ backend.Token }

func (lockedToken) Derive(string, []byte) ([]byte, error) { return nil, backend.ErrLocked }

type rig struct {
	t     *testing.T
	srv   *httptest.Server
	face  *Face
	audit *bytes.Buffer
	cfg   *config.Config
	now   time.Time
	dir   string
}

func newRig(t *testing.T, mutate func(*config.Config, map[string]backend.Token, *Face)) *rig {
	dir := t.TempDir()
	write := func(n, v string) string { p := filepath.Join(dir, n); os.WriteFile(p, []byte(v), 0o600); return p }
	k1 := write("k1", strings.Repeat("01", 32))
	k2 := write("k2", strings.Repeat("02", 32))
	cfg, err := config.Parse([]byte(`
kmsjson: {enabled: true, region: local}
tokens: [{name: soft, type: soft, keys: {m1: ` + k1 + `, m2: ` + k2 + `}}]
keys:
  etcd: {kmsjson: true, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  rot:  {kmsjson: true, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  plain: {versions: [{token: soft, label: m1}], aad: {mode: fixed}}
clients:
  - {name: shop, identity: {cn: shop}, sigv4: {access_key_id: ` + akid + `, secret_file: /unused}, keys: {etcd: {ops: [derive]}, rot: {ops: [derive]}, plain: {ops: [encrypt]}}}
  - {name: viewer, identity: {cn: viewer}, sigv4: {access_key_id: AKIDVIEWERVIEWER00, secret_file: /unused}, keys: {etcd: {ops: [encrypt]}}}
`))
	if err != nil {
		t.Fatal(err)
	}
	soft, err := backend.NewSoft(cfg.Tokens[0].Keys)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]backend.Token{"soft": soft}
	buf := &bytes.Buffer{}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	f := &Face{Cfg: cfg, Tokens: tokens, Policy: policy.New(cfg, nil), Audit: audit.New(buf), Gate: gate.New(4, time.Second), Created: now, Now: func() time.Time { return now },
		Identify: func(r *http.Request) (string, bool) { c := r.Header.Get("X-Test-Client"); return c, c != "-" },
		Creds:    map[string]Cred{akid: {"shop", secret}, "AKIDVIEWERVIEWER00": {"viewer", secret}}}
	if mutate != nil {
		mutate(cfg, tokens, f)
		f.Tokens = tokens
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &rig{t, srv, f, buf, cfg, now, dir}
}

// call signs and sends one request; client is the identity of the "certificate" ("" = none, as in development; "-" = an unknown certificate).
func (r *rig) call(client, key, op string, body any, sign func(*http.Request, []byte)) (int, map[string]any, http.Header) {
	r.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", r.srv.URL+"/", bytes.NewReader(b))
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Test-Client", client)
	if sign == nil {
		sigv4.Sign(req, b, key, secret, "local", "kms", r.now)
	} else {
		sign(req, b)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func (r *rig) shop(op string, body any) (int, map[string]any, http.Header) {
	return r.call("shop", akid, op, body, nil)
}

func ephemeral(t *testing.T) (*ecdh.PrivateKey, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	e, _ := k.ECDH()
	return e, base64.StdEncoding.EncodeToString(der)
}

func masterPublic(t *testing.T, r *rig, keyID string) *ecdh.PublicKey {
	st, out, _ := r.shop("GetPublicKey", map[string]string{"KeyId": keyID})
	if st != 200 {
		t.Fatalf("GetPublicKey: %d %v", st, out)
	}
	der, _ := base64.StdEncoding.DecodeString(out["PublicKey"].(string))
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	e, err := pub.(*ecdsa.PublicKey).ECDH()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The point of the face: the shared secret the service returns is the ECDH of the key on the token with the key of the caller. The caller computes the same from its side.
func TestDeriveSharedSecretIsTheECDHOfTheTokenKey(t *testing.T) {
	r := newRig(t, nil)
	master := masterPublic(t, r, "etcd")
	mine, mineDER := ephemeral(t)
	want, _ := mine.ECDH(master)
	st, out, h := r.shop("DeriveSharedSecret", map[string]any{"KeyId": "alias/etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": mineDER})
	if st != 200 || h.Get("Content-Type") != contentType {
		t.Fatalf("%d %v %v", st, out, h)
	}
	got, _ := base64.StdEncoding.DecodeString(out["SharedSecret"].(string))
	if !bytes.Equal(got, want) || out["KeyAgreementAlgorithm"] != "ECDH" || !strings.HasPrefix(out["KeyId"].(string), "arn:hsmgate:kms:local:") {
		t.Errorf("%x vs %x, %v", got, want, out)
	}
	// the three forms of KeyId name the same key
	for _, id := range []string{"etcd", "alias/etcd", out["KeyId"].(string)} {
		if st, _, _ := r.shop("DeriveSharedSecret", map[string]any{"KeyId": id, "KeyAgreementAlgorithm": "ECDH", "PublicKey": mineDER}); st != 200 {
			t.Errorf("KeyId %q: %d", id, st)
		}
	}
	// the log has the line, with a short fingerprint of the caller's key and no secret
	if log := r.audit.String(); !strings.Contains(log, `"op":"derivesharedsecret"`) || !strings.Contains(log, `"context":"peer=`) || strings.Contains(log, out["SharedSecret"].(string)) {
		t.Errorf("audit: %s", log)
	}
}

func TestGetPublicKeyAndDescribeKeyHaveTheShapeOfSDKs(t *testing.T) {
	r := newRig(t, nil)
	st, out, _ := r.shop("GetPublicKey", map[string]string{"KeyId": "etcd"})
	if st != 200 || out["KeySpec"] != "ECC_NIST_P256" || out["KeyUsage"] != "KEY_AGREEMENT" {
		t.Fatalf("%d %v", st, out)
	}
	if a, _ := out["KeyAgreementAlgorithms"].([]any); len(a) != 1 || a[0] != "ECDH" {
		t.Errorf("%v", out["KeyAgreementAlgorithms"])
	}
	st, out, _ = r.shop("DescribeKey", map[string]string{"KeyId": "etcd"})
	md, _ := out["KeyMetadata"].(map[string]any)
	if st != 200 || md["KeyId"] != "etcd" || md["Enabled"] != true || md["KeyState"] != "Enabled" || md["KeyUsage"] != "KEY_AGREEMENT" {
		t.Fatalf("%d %v", st, out)
	}
	if _, isNumber := md["CreationDate"].(float64); !isNumber { // JSON 1.1 timestamps are numbers of seconds
		t.Errorf("CreationDate is %T", md["CreationDate"])
	}
	// only what the client may see, and only keys that are enabled for this face
	st, out, _ = r.shop("ListKeys", map[string]any{})
	keys, _ := out["Keys"].([]any)
	if st != 200 || len(keys) != 2 || out["Truncated"] != false { // etcd and rot; "plain" has no kmsjson
		t.Errorf("ListKeys: %d %v", st, out)
	}
	st, out, _ = r.shop("ListAliases", map[string]any{})
	al, _ := out["Aliases"].([]any)
	if st != 200 || len(al) != 2 || al[0].(map[string]any)["AliasName"] != "alias/etcd" {
		t.Errorf("ListAliases: %d %v", st, out)
	}
	if st, out, _ := r.call("viewer", "AKIDVIEWERVIEWER00", "ListKeys", map[string]any{}, nil); st != 200 || len(out["Keys"].([]any)) != 1 {
		t.Errorf("a client with a grant on one key sees that key only: %d %v", st, out)
	}
}

// Rotation: the latest version by default, an older one by "@N" (the protocol has no version).
func TestVersionsOfAKey(t *testing.T) {
	r := newRig(t, func(c *config.Config, tk map[string]backend.Token, f *Face) {
		c.Keys["rot"] = config.Key{KMSJSON: true, AAD: config.AAD{Mode: "fixed"}, Versions: []config.Version{{Token: "soft", Label: "m1"}, {Token: "soft", Label: "m2"}}}
	})
	v1, v2, latest := masterPublic(t, r, "rot@1"), masterPublic(t, r, "rot@2"), masterPublic(t, r, "rot")
	if bytes.Equal(v1.Bytes(), v2.Bytes()) || !bytes.Equal(latest.Bytes(), v2.Bytes()) {
		t.Error("versions")
	}
	mine, der := ephemeral(t)
	for ver, pub := range map[string]*ecdh.PublicKey{"rot@1": v1, "rot@2": v2, "rot": v2} {
		want, _ := mine.ECDH(pub)
		st, out, _ := r.shop("DeriveSharedSecret", map[string]any{"KeyId": ver, "KeyAgreementAlgorithm": "ECDH", "PublicKey": der})
		got, _ := base64.StdEncoding.DecodeString(out["SharedSecret"].(string))
		if st != 200 || !bytes.Equal(got, want) {
			t.Errorf("%s: %d", ver, st)
		}
	}
	if st, _, _ := r.shop("GetPublicKey", map[string]string{"KeyId": "rot@3"}); st != 400 {
		t.Errorf("a version that does not exist: %d", st)
	}
}

func TestRefusalsOfDerive(t *testing.T) {
	r := newRig(t, nil)
	_, der := ephemeral(t)
	good := map[string]any{"KeyId": "etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": der}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = v
		return m
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	off := append([]byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04}, bytes.Repeat([]byte{0x11}, 64)...)
	for name, tc := range map[string]struct {
		body map[string]any
		typ  string
	}{
		"another algorithm":         {with("KeyAgreementAlgorithm", "DH"), "ValidationException"},
		"not base64":                {with("PublicKey", "!!"), "ValidationException"},
		"not a DER key":             {with("PublicKey", base64.StdEncoding.EncodeToString([]byte("nonsense"))), "ValidationException"},
		"another curve":             {with("PublicKey", base64.StdEncoding.EncodeToString(der384)), "ValidationException"},
		"a point off the curve":     {with("PublicKey", base64.StdEncoding.EncodeToString(off)), "ValidationException"},
		"a recipient":               {with("Recipient", map[string]string{"KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"}), "ValidationException"},
		"a key that does not exist": {with("KeyId", "nope"), "AccessDeniedException"},
		"a key without kmsjson":     {with("KeyId", "plain"), "AccessDeniedException"},
		"no right to derive":        {with("KeyId", "plain"), "AccessDeniedException"},
	} {
		st, out, _ := r.shop("DeriveSharedSecret", tc.body)
		if st != 400 || out["__type"] != tc.typ || out["SharedSecret"] != nil {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
	// a client with a grant on the key but not the right to derive
	if st, out, _ := r.call("viewer", "AKIDVIEWERVIEWER00", "DeriveSharedSecret", good, nil); st != 400 || out["__type"] != "AccessDeniedException" {
		t.Errorf("no derive: %d %v", st, out)
	}
	// DryRun: authorised and valid, and the token is not asked
	st, out, _ := r.shop("DeriveSharedSecret", with("DryRun", true))
	if st != 400 || out["__type"] != "DryRunOperationException" {
		t.Errorf("dry run: %d %v", st, out)
	}
	// unsupported operations
	if st, out, _ := r.shop("Decrypt", map[string]any{}); st != 400 || out["__type"] != "UnsupportedOperationException" {
		t.Errorf("%d %v", st, out)
	}
}

func TestAuthenticationNeedsTheCertificateAndTheSignature(t *testing.T) {
	r := newRig(t, nil)
	_, der := ephemeral(t)
	body := map[string]any{"KeyId": "etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": der}
	type try struct {
		name        string
		client, key string
		sign        func(*http.Request, []byte)
		status      int
		typ         string
	}
	for _, tc := range []try{
		{"unsigned", "shop", akid, func(*http.Request, []byte) {}, 400, "MissingAuthenticationTokenException"},
		{"a wrong secret", "shop", akid, func(req *http.Request, b []byte) {
			sigv4.Sign(req, b, akid, []byte("another-secret-0123456789abcdef"), "local", "kms", r.now)
		}, 400, "InvalidSignatureException"},
		{"an unknown access key", "shop", "AKIDUNKNOWNUNKNOWN", nil, 400, "UnrecognizedClientException"},
		{"a stale request", "shop", akid, func(req *http.Request, b []byte) {
			sigv4.Sign(req, b, akid, secret, "local", "kms", r.now.Add(-10*time.Minute))
		}, 400, "InvalidSignatureException"},
		{"another region", "shop", akid, func(req *http.Request, b []byte) { sigv4.Sign(req, b, akid, secret, "elsewhere", "kms", r.now) }, 400, "InvalidSignatureException"},
		{"a certificate the policy does not know", "-", akid, nil, 403, "AccessDeniedException"},
		{"the credential of another client", "viewer", akid, nil, 403, "AccessDeniedException"},
	} {
		st, out, _ := r.call(tc.client, tc.key, "DeriveSharedSecret", body, tc.sign)
		if st != tc.status || out["__type"] != tc.typ || out["SharedSecret"] != nil {
			t.Errorf("%s: %d %v", tc.name, st, out)
		}
	}
	// a body changed after signing
	st, out, _ := r.call("shop", akid, "DeriveSharedSecret", body, func(req *http.Request, b []byte) {
		sigv4.Sign(req, b, akid, secret, "local", "kms", r.now)
		req.Body = io.NopCloser(strings.NewReader(`{"KeyId":"rot"}`))
		req.ContentLength = int64(len(`{"KeyId":"rot"}`))
	})
	if st != 400 || out["__type"] != "InvalidSignatureException" {
		t.Errorf("a changed body: %d %v", st, out)
	}
	// development mode: no certificate, the client is the one of the credential
	if st, _, _ := r.call("", akid, "DeriveSharedSecret", body, nil); st != 200 {
		t.Errorf("without a certificate (development): %d", st)
	}
}

// The answer with the secret is sent only after its line is written; with no log nothing leaves.
func TestNoSecretWithoutAnAuditLine(t *testing.T) {
	r := newRig(t, nil)
	r.face.Audit = audit.New(brokenWriter{})
	_, der := ephemeral(t)
	st, out, _ := r.shop("DeriveSharedSecret", map[string]any{"KeyId": "etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": der})
	if st != 500 || out["SharedSecret"] != nil || out["__type"] != "KMSInternalException" {
		t.Errorf("%d %v", st, out)
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestLockedTokenAndRates(t *testing.T) {
	r := newRig(t, func(c *config.Config, tk map[string]backend.Token, f *Face) { tk["soft"] = lockedToken{tk["soft"]} })
	_, der := ephemeral(t)
	st, out, h := r.shop("DeriveSharedSecret", map[string]any{"KeyId": "etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": der})
	if st != 500 || out["__type"] != "KeyUnavailableException" || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("a locked token: %d %v", st, out)
	}
	// the public key needs no login
	if st, _, _ := r.shop("GetPublicKey", map[string]string{"KeyId": "etcd"}); st != 200 {
		t.Errorf("GetPublicKey with a locked token: %d", st)
	}
	r2 := newRig(t, nil)
	r2.cfg.Clients[0].Keys["etcd"] = config.Grant{Ops: []string{"derive"}, PerMinute: 2}
	for i := 0; i < 2; i++ {
		if st, _, _ := r2.shop("DeriveSharedSecret", map[string]any{"KeyId": "etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": der}); st != 200 {
			t.Fatalf("%d: %d", i, st)
		}
	}
	if st, out, h := r2.shop("DeriveSharedSecret", map[string]any{"KeyId": "etcd", "KeyAgreementAlgorithm": "ECDH", "PublicKey": der}); st != 400 || out["__type"] != "ThrottlingException" || h.Get("Retry-After") == "" {
		t.Errorf("the rate: %d %v", st, out)
	}
}

func TestOnlyTheTargetOfThisFaceIsServed(t *testing.T) {
	r := newRig(t, nil)
	req, _ := http.NewRequest("POST", r.srv.URL+"/other", strings.NewReader("{}"))
	req.Header.Set("X-Amz-Target", "TrentService.ListKeys")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("%d", resp.StatusCode)
	}
	if IsKMSJSON(httptest.NewRequest("PUT", "/v1/transit/encrypt/k", nil)) {
		t.Error("a Transit request was taken for this face")
	}
}
