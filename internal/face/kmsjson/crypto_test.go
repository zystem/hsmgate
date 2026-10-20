package kmsjson

import (
	"bytes"
	"encoding/base64"
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
)

func cryptoRig(t *testing.T) *rig {
	dir := t.TempDir()
	write := func(n, v string) string { p := filepath.Join(dir, n); os.WriteFile(p, []byte(v), 0o600); return p }
	k1 := write("k1", strings.Repeat("01", 32))
	k2 := write("k2", strings.Repeat("02", 32))
	cfg, err := config.Parse([]byte(`
kmsjson: {enabled: true, region: local}
tokens: [{name: soft, type: soft, keys: {m1: ` + k1 + `, m2: ` + k2 + `}}]
keys:
  seal:  {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  seal2: {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  org:   {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}, {token: soft, label: m2}], aad: {mode: context, allow: ["purpose=dek"]}}
  ecdh:  {kmsjson: true, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
clients:
  - {name: app, identity: {cn: app}, sigv4: {access_key_id: ` + akid + `, secret_file: /unused}, keys: {seal: {ops: [encrypt, decrypt]}, seal2: {ops: [encrypt]}, org: {ops: [encrypt, decrypt]}, ecdh: {ops: [derive, encrypt]}}}
  - {name: reader, identity: {cn: reader}, sigv4: {access_key_id: AKIDVIEWERVIEWER00, secret_file: /unused}, keys: {seal: {ops: [decrypt]}}}
`))
	if err != nil {
		t.Fatal(err)
	}
	soft, err := backend.NewSoft(cfg.Tokens[0].Keys)
	if err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	f := &Face{Cfg: cfg, Tokens: map[string]backend.Token{"soft": soft}, Policy: policy.New(cfg, nil), Audit: audit.New(buf), Gate: gate.New(4, time.Second), Created: now, Now: func() time.Time { return now },
		Identify: func(r *http.Request) (string, bool) { c := r.Header.Get("X-Test-Client"); return c, c != "-" },
		Creds:    map[string]Cred{akid: {"app", secret}, "AKIDVIEWERVIEWER00": {"reader", secret}}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &rig{t, srv, f, buf, cfg, now, dir}
}

func (r *rig) app(op string, body any) (int, map[string]any) {
	st, out, _ := r.call("app", akid, op, body, nil)
	return st, out
}

func typ(out map[string]any) string { s, _ := out["__type"].(string); return s }

func TestEncryptDecryptRoundTrip(t *testing.T) {
	r := cryptoRig(t)
	pt := base64.StdEncoding.EncodeToString([]byte("a secret of the application"))
	st, enc := r.app("Encrypt", map[string]any{"KeyId": "alias/seal", "Plaintext": pt})
	if st != 200 || enc["EncryptionAlgorithm"] != "SYMMETRIC_DEFAULT" || !strings.HasSuffix(enc["KeyId"].(string), ":key/seal") {
		t.Fatalf("Encrypt: %d %v", st, enc)
	}
	blob := enc["CiphertextBlob"].(string)
	// Decrypt without a KeyId, as the clients do
	st, dec := r.app("Decrypt", map[string]any{"CiphertextBlob": blob})
	if st != 200 || dec["Plaintext"] != pt || !strings.HasSuffix(dec["KeyId"].(string), ":key/seal") {
		t.Fatalf("Decrypt: %d %v", st, dec)
	}
	// with the right KeyId, and with the wrong one
	if st, _ := r.app("Decrypt", map[string]any{"CiphertextBlob": blob, "KeyId": "seal"}); st != 200 {
		t.Errorf("Decrypt with KeyId: %d", st)
	}
	if st, out := r.app("Decrypt", map[string]any{"CiphertextBlob": blob, "KeyId": "seal2"}); st != 400 || typ(out) != "IncorrectKeyException" {
		t.Errorf("wrong KeyId: %d %v", st, out)
	}
	// the same plaintext sealed twice differs; a damaged blob and a blob of another key are not opened
	_, enc2 := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt})
	if enc2["CiphertextBlob"] == blob {
		t.Error("two encryptions are equal")
	}
	raw, _ := base64.StdEncoding.DecodeString(blob)
	raw[len(raw)-3] ^= 1
	if st, out := r.app("Decrypt", map[string]any{"CiphertextBlob": base64.StdEncoding.EncodeToString(raw)}); st != 400 || typ(out) != "InvalidCiphertextException" {
		t.Errorf("damaged: %d %v", st, out)
	}
	if st, out := r.app("Decrypt", map[string]any{"CiphertextBlob": base64.StdEncoding.EncodeToString([]byte("garbage"))}); st != 400 || typ(out) != "InvalidCiphertextException" {
		t.Errorf("garbage: %d %v", st, out)
	}
	// the audit names the operations
	if a := r.audit.String(); !strings.Contains(a, `"op":"encrypt"`) || !strings.Contains(a, `"op":"decrypt"`) || strings.Contains(a, "a secret") {
		t.Errorf("audit: %s", a)
	}
}

func TestContextIsTheAdditionalData(t *testing.T) {
	r := cryptoRig(t)
	pt := base64.StdEncoding.EncodeToString([]byte("dek"))
	ctx := map[string]string{"purpose": "dek", "org": "o1"}
	st, enc := r.app("Encrypt", map[string]any{"KeyId": "org", "Plaintext": pt, "EncryptionContext": ctx})
	if st != 200 {
		t.Fatalf("%d %v", st, enc)
	}
	blob := enc["CiphertextBlob"]
	if st, dec := r.app("Decrypt", map[string]any{"CiphertextBlob": blob, "EncryptionContext": ctx}); st != 200 || dec["Plaintext"] != pt {
		t.Fatalf("%d %v", st, dec)
	}
	for name, c := range map[string]map[string]string{"another value": {"purpose": "dek", "org": "o2"}, "missing name": {"purpose": "dek"}} {
		if st, out := r.app("Decrypt", map[string]any{"CiphertextBlob": blob, "EncryptionContext": c}); st != 400 || typ(out) != "InvalidCiphertextException" {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
	// the key's rules: a context is needed, and must begin as the key allows
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "org", "Plaintext": pt}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("no context: %d %v", st, out)
	}
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "org", "Plaintext": pt, "EncryptionContext": map[string]string{"zzz": "1"}}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("not allowed: %d %v", st, out)
	}
	// a key in fixed mode takes none
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt, "EncryptionContext": ctx}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("fixed key with context: %d %v", st, out)
	}
	// the context is in the audit (public by rule), the plaintext is not
	if a := r.audit.String(); !strings.Contains(a, "org=o1") || strings.Contains(a, "ZGVr") {
		t.Errorf("audit: %s", a)
	}
}

func TestReEncryptAndDataKeys(t *testing.T) {
	r := cryptoRig(t)
	pt := base64.StdEncoding.EncodeToString([]byte("moved"))
	_, enc := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt})
	st, re := r.app("ReEncrypt", map[string]any{"CiphertextBlob": enc["CiphertextBlob"], "DestinationKeyId": "seal2"})
	if st != 200 || !strings.HasSuffix(re["KeyId"].(string), ":key/seal2") || !strings.HasSuffix(re["SourceKeyId"].(string), ":key/seal") {
		t.Fatalf("ReEncrypt: %d %v", st, re)
	}
	// "app" has encrypt only on seal2, so the blob of seal2 is opened by a client that may: nobody here may decrypt it
	if st, out := r.app("Decrypt", map[string]any{"CiphertextBlob": re["CiphertextBlob"]}); st != 400 || typ(out) != "AccessDeniedException" {
		t.Errorf("decrypt of seal2: %d %v", st, out)
	}
	// data keys
	st, dk := r.app("GenerateDataKey", map[string]any{"KeyId": "seal", "KeySpec": "AES_256"})
	if st != 200 {
		t.Fatal(st, dk)
	}
	key, _ := base64.StdEncoding.DecodeString(dk["Plaintext"].(string))
	if len(key) != 32 {
		t.Errorf("data key of %d bytes", len(key))
	}
	_, dec := r.app("Decrypt", map[string]any{"CiphertextBlob": dk["CiphertextBlob"]})
	if dec["Plaintext"] != dk["Plaintext"] {
		t.Error("the data key does not open to itself")
	}
	st, dk2 := r.app("GenerateDataKeyWithoutPlaintext", map[string]any{"KeyId": "seal", "NumberOfBytes": 48})
	if _, has := dk2["Plaintext"]; st != 200 || has {
		t.Errorf("without plaintext: %d %v", st, dk2)
	}
	_, dec = r.app("Decrypt", map[string]any{"CiphertextBlob": dk2["CiphertextBlob"]})
	if b, _ := base64.StdEncoding.DecodeString(dec["Plaintext"].(string)); len(b) != 48 {
		t.Errorf("%d bytes", len(b))
	}
	for name, body := range map[string]map[string]any{
		"both":    {"KeyId": "seal", "KeySpec": "AES_256", "NumberOfBytes": 32},
		"neither": {"KeyId": "seal"},
		"huge":    {"KeyId": "seal", "NumberOfBytes": 5000},
		"spec":    {"KeyId": "seal", "KeySpec": "AES_512"},
	} {
		if st, out := r.app("GenerateDataKey", body); st != 400 || typ(out) != "ValidationException" {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
	st, rnd := r.app("GenerateRandom", map[string]any{"NumberOfBytes": 64})
	if b, _ := base64.StdEncoding.DecodeString(rnd["Plaintext"].(string)); st != 200 || len(b) != 64 {
		t.Errorf("GenerateRandom: %d %v", st, rnd)
	}
	if st, out := r.app("GenerateRandom", map[string]any{"NumberOfBytes": 0}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("GenerateRandom 0: %d %v", st, out)
	}
}

func TestUsageAndRightsAreKept(t *testing.T) {
	r := cryptoRig(t)
	pt := base64.StdEncoding.EncodeToString([]byte("x"))
	// a key for key agreement is not a key for sealing, and the reverse
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "ecdh", "Plaintext": pt}); st != 400 || typ(out) != "InvalidKeyUsageException" {
		t.Errorf("encrypt on an ECDH key: %d %v", st, out)
	}
	if st, out := r.app("DeriveSharedSecret", map[string]any{"KeyId": "seal", "KeyAgreementAlgorithm": "ECDH", "PublicKey": "AA=="}); st != 400 || typ(out) != "InvalidKeyUsageException" {
		t.Errorf("derive on a sealing key: %d %v", st, out)
	}
	// the symmetric key has no public key, and says what it is
	if st, out := r.app("GetPublicKey", map[string]any{"KeyId": "seal"}); st != 400 || typ(out) != "UnsupportedOperationException" {
		t.Errorf("GetPublicKey: %d %v", st, out)
	}
	st, d := r.app("DescribeKey", map[string]any{"KeyId": "seal"})
	md, _ := d["KeyMetadata"].(map[string]any)
	if st != 200 || md["KeyUsage"] != "ENCRYPT_DECRYPT" || md["KeySpec"] != "SYMMETRIC_DEFAULT" {
		t.Errorf("DescribeKey: %d %v", st, d)
	}
	// rights: "reader" may only decrypt
	_, enc := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt})
	if st, out, _ := r.call("reader", "AKIDVIEWERVIEWER00", "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt}, nil); st != 400 || typ(out) != "AccessDeniedException" {
		t.Errorf("reader encrypts: %d %v", st, out)
	}
	if st, out, _ := r.call("reader", "AKIDVIEWERVIEWER00", "Decrypt", map[string]any{"CiphertextBlob": enc["CiphertextBlob"]}, nil); st != 200 || out["Plaintext"] != pt {
		t.Errorf("reader decrypts: %d %v", st, out)
	}
	// a key the client has no grant on looks like one that does not exist
	if st, out, _ := r.call("reader", "AKIDVIEWERVIEWER00", "Encrypt", map[string]any{"KeyId": "org", "Plaintext": pt}, nil); st != 400 || typ(out) != "AccessDeniedException" {
		t.Errorf("reader on org: %d %v", st, out)
	}
	// too large, empty, dry run
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": base64.StdEncoding.EncodeToString(make([]byte, 4097))}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("too large: %d %v", st, out)
	}
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": ""}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("empty: %d %v", st, out)
	}
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt, "DryRun": true}); st != 400 || typ(out) != "DryRunOperationException" {
		t.Errorf("dry run: %d %v", st, out)
	}
}

func TestSealingNeedsTheAuditLine(t *testing.T) {
	r := cryptoRig(t)
	r.face.Audit = audit.New(brokenWriter{})
	st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": base64.StdEncoding.EncodeToString([]byte("x"))})
	if st != 500 || out["CiphertextBlob"] != nil {
		t.Errorf("%d %v", st, out)
	}
}
