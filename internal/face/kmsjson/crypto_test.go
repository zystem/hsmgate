package kmsjson

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"github.com/zystem/hsmgate/internal/keyops"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
	"github.com/zystem/hsmgate/internal/sigv4"
	"net/http"
	"net/http/httptest"
	"net/netip"
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
	k3 := write("k3", strings.Repeat("03", 32))
	k4 := write("k4", strings.Repeat("04", 32))
	k5 := write("k5", strings.Repeat("05", 32))
	cfg, err := config.Parse([]byte(`
kmsjson: {enabled: true, region: local}
tokens: [{name: soft, type: soft, keys: {m1: ` + k1 + `, m2: ` + k2 + `, m3: ` + k3 + `, m4: ` + k4 + `, m5: ` + k5 + `}}]
keys:
  seal:  {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  seal2: {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  org:   {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}, {token: soft, label: m2}], aad: {mode: context, allow: ["purpose=dek"]}}
  sig:   {kmsjson: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  mac:   {kmsjson: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m4}], aad: {mode: fixed}}
  macrot: {kmsjson: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m5}], aad: {mode: fixed}}
  ecdh:  {kmsjson: true, versions: [{token: soft, label: m1}], aad: {mode: fixed}}
clients:
  - {name: app, identity: {cn: app}, sigv4: {access_key_id: ` + akid + `, secret_file: /unused}, keys: {seal: {ops: [encrypt, decrypt]}, seal2: {ops: [encrypt]}, org: {ops: [encrypt, decrypt]}, ecdh: {ops: [derive, encrypt]}, sig: {ops: [sign, verify]}, mac: {ops: [generate_mac, verify_mac]}, macrot: {ops: [generate_mac, verify_mac]}}}
  - {name: bot, sigv4: {access_key_id: AKIDBOTBOTBOTBOT00, secret_file: /unused, no_cert: true, allow_from: [127.0.0.0/8]}, keys: {seal: {ops: [encrypt, decrypt]}}}
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
		Creds: map[string]Cred{akid: {Client: "app", Secret: secret}, "AKIDVIEWERVIEWER00": {Client: "reader", Secret: secret},
			"AKIDBOTBOTBOTBOT00": {Client: "bot", Secret: secret, NoCert: true, From: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}},
		NoCertificate: func(r *http.Request) bool { return r.Header.Get("X-Test-NoCert") == "1" }, Fails: NewFailures(), MacKeys: NewMacKeys()}
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

func TestParseBlobNeverPanics(t *testing.T) {
	good := makeBlob("seal", 1, "ecies1.aa.bb.cc")
	if n, v, txt, err := parseBlob(good); err != nil || n != "seal" || v != 1 || txt != "ecies1.aa.bb.cc" {
		t.Fatalf("%q %d %q %v", n, v, txt, err)
	}
	for i := 0; i <= len(good); i++ {
		parseBlob(good[:i])
	}
	for _, b := range [][]byte{nil, []byte("HGK1"), []byte("HGK1\x00"), []byte("HGK1\xffab"), []byte("HGK1\x01a\x00\x00ecies1."), []byte("HGK1\x01a\x00\x00x")} {
		if _, _, _, err := parseBlob(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func FuzzParseBlob(f *testing.F) {
	f.Add(makeBlob("seal", 1, "ecies1.aa.bb.cc"))
	f.Add([]byte("HGK1\x01a\x00\x01ecies1.x"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		name, ver, text, err := parseBlob(b)
		if err == nil && (name == "" || ver < 1 || !strings.HasPrefix(text, "ecies1.")) {
			t.Fatalf("accepted %q", b)
		}
	})
}

// Any body, signed with a good credential, gets a JSON answer with a known status and never a panic; a body that is not signed never gets a 200.
func FuzzRequestBody(f *testing.F) {
	f.Add("Encrypt", `{"KeyId":"seal","Plaintext":"aGk="}`)
	f.Add("Decrypt", `{"CiphertextBlob":"SEdLMQ=="}`)
	f.Add("ReEncrypt", `{"CiphertextBlob":null,"DestinationKeyId":5}`)
	f.Add("GenerateDataKey", `{"KeyId":"org","EncryptionContext":{"a":"b"},"NumberOfBytes":-1}`)
	f.Add("DeriveSharedSecret", `[1,2,3]`)
	f.Add("GenerateRandom", `{"NumberOfBytes":99999999999999999999}`)
	r := cryptoRig(&testing.T{})
	f.Fuzz(func(t *testing.T, op, body string) {
		if strings.ContainsAny(op, "\r\n\x00") {
			return
		}
		req, _ := http.NewRequest("POST", r.srv.URL+"/", strings.NewReader(body))
		req.Header.Set("X-Amz-Target", "TrentService."+op)
		req.Header.Set("X-Test-Client", "app")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return // a target the HTTP client refuses to send
		}
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatalf("an unsigned %s was served", op)
		}
	})
}

func (r *rig) certless(akid, op string, body any) (int, map[string]any) {
	st, out, _ := r.call("-", akid, op, body, func(req *http.Request, b []byte) {
		req.Header.Set("X-Test-NoCert", "1")
		sigv4.Sign(req, b, akid, secret, "local", "kms", r.now)
	})
	return st, out
}

func TestACredentialWithoutACertificate(t *testing.T) {
	r := cryptoRig(t)
	pt := base64.StdEncoding.EncodeToString([]byte("x"))
	st, enc := r.certless("AKIDBOTBOTBOTBOT00", "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt})
	if st != 200 {
		t.Fatalf("%d %v", st, enc)
	}
	if st, dec := r.certless("AKIDBOTBOTBOTBOT00", "Decrypt", map[string]any{"CiphertextBlob": enc["CiphertextBlob"]}); st != 200 || dec["Plaintext"] != pt {
		t.Errorf("%d %v", st, dec)
	}
	// the credential of a client that did not ask for it is not good without a certificate
	if st, out := r.certless(akid, "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt}); st != 403 || typ(out) != "AccessDeniedException" {
		t.Errorf("another credential: %d %v", st, out)
	}
	// from an address that is not listed
	r.face.Creds["AKIDBOTBOTBOTBOT00"] = Cred{Client: "bot", Secret: secret, NoCert: true, From: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if st, out := r.certless("AKIDBOTBOTBOTBOT00", "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt}); st != 403 || typ(out) != "AccessDeniedException" {
		t.Errorf("from another address: %d %v", st, out)
	}
	// the audit tells why
	if a := r.audit.String(); !strings.Contains(a, `"result":"address_refused"`) || !strings.Contains(a, `"result":"unauthenticated"`) {
		t.Errorf("audit: %s", a)
	}
}

func TestRefusedSignaturesOfACertlessPeerAreCounted(t *testing.T) {
	r := cryptoRig(t)
	pt := base64.StdEncoding.EncodeToString([]byte("x"))
	bad := func(akid string) {
		r.call("-", akid, "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt}, func(req *http.Request, b []byte) {
			req.Header.Set("X-Test-NoCert", "1")
			sigv4.Sign(req, b, akid, []byte("a-wrong-secret-a-wrong-secret-0000"), "local", "kms", r.now)
		})
	}
	for i := 0; i < failLimit; i++ {
		bad("AKIDBOTBOTBOTBOT00")
	}
	// from this address nothing without a certificate is judged any more, not even a good request
	st, out := r.certless("AKIDBOTBOTBOTBOT00", "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt})
	if st != 400 || typ(out) != "ThrottlingException" {
		t.Errorf("after %d refusals: %d %v", failLimit, st, out)
	}
	// but a client that shows a certificate is not locked out by them (a node, a NAT)
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt}); st != 200 {
		t.Errorf("a client with a certificate: %d %v", st, out)
	}
	// and it ends with the window
	r.face.Now = func() time.Time { return r.now.Add(2 * time.Minute) }
	if st, _, _ := r.call("-", "AKIDBOTBOTBOTBOT00", "Encrypt", map[string]any{"KeyId": "seal", "Plaintext": pt}, func(req *http.Request, b []byte) {
		req.Header.Set("X-Test-NoCert", "1")
		sigv4.Sign(req, b, "AKIDBOTBOTBOTBOT00", secret, "local", "kms", r.now.Add(2*time.Minute))
	}); st != 200 {
		t.Errorf("after the window: %d", st)
	}
}

func TestSignAndVerify(t *testing.T) {
	r := cryptoRig(t)
	msg := []byte("a message to sign")
	st, sg := r.app("Sign", map[string]any{"KeyId": "alias/sig", "Message": msg, "SigningAlgorithm": "ECDSA_SHA_256"})
	if st != 200 || sg["SigningAlgorithm"] != "ECDSA_SHA_256" || !strings.HasSuffix(sg["KeyId"].(string), ":key/sig") {
		t.Fatalf("Sign: %d %v", st, sg)
	}
	// the signature is ASN.1 DER that an ordinary verifier accepts with the public key of GetPublicKey
	_, pk := r.app("GetPublicKey", map[string]any{"KeyId": "sig"})
	if pk["KeyUsage"] != "SIGN_VERIFY" || pk["KeySpec"] != "ECC_NIST_P256" || pk["KeyAgreementAlgorithms"] != nil {
		t.Errorf("GetPublicKey: %v", pk)
	}
	der, _ := base64.StdEncoding.DecodeString(pk["PublicKey"].(string))
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(sg["Signature"].(string))
	d := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sig) {
		t.Fatal("the signature does not verify with the public key")
	}
	// Verify: valid, and invalid is the error clients expect; DIGEST gives the same
	if st, out := r.app("Verify", map[string]any{"KeyId": "sig", "Message": msg, "Signature": sig, "SigningAlgorithm": "ECDSA_SHA_256"}); st != 200 || out["SignatureValid"] != true {
		t.Errorf("Verify: %d %v", st, out)
	}
	if st, out := r.app("Verify", map[string]any{"KeyId": "sig", "Message": d[:], "MessageType": "DIGEST", "Signature": sig, "SigningAlgorithm": "ECDSA_SHA_256"}); st != 200 || out["SignatureValid"] != true {
		t.Errorf("Verify digest: %d %v", st, out)
	}
	if st, out := r.app("Verify", map[string]any{"KeyId": "sig", "Message": []byte("another"), "Signature": sig, "SigningAlgorithm": "ECDSA_SHA_256"}); st != 400 || typ(out) != "KMSInvalidSignatureException" {
		t.Errorf("Verify of another message: %d %v", st, out)
	}
	if st, out := r.app("Sign", map[string]any{"KeyId": "sig", "Message": d[:], "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"}); st != 200 {
		t.Errorf("Sign a digest: %d %v", st, out)
	}
	for name, body := range map[string]map[string]any{
		"algorithm":    {"KeyId": "sig", "Message": msg, "SigningAlgorithm": "NONSENSE"},
		"short digest": {"KeyId": "sig", "Message": []byte("x"), "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"},
		"empty":        {"KeyId": "sig", "SigningAlgorithm": "ECDSA_SHA_256"},
		"too long":     {"KeyId": "sig", "Message": make([]byte, 4097), "SigningAlgorithm": "ECDSA_SHA_256"},
		"unknown type": {"KeyId": "sig", "Message": msg, "MessageType": "X", "SigningAlgorithm": "ECDSA_SHA_256"},
	} {
		if st, out := r.app("Sign", body); st != 400 || typ(out) != "ValidationException" {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
	// usage is kept both ways, and the audit holds a piece of the digest, not the message
	if st, out := r.app("Sign", map[string]any{"KeyId": "seal", "Message": msg, "SigningAlgorithm": "ECDSA_SHA_256"}); st != 400 || typ(out) != "InvalidKeyUsageException" {
		t.Errorf("sign with a sealing key: %d %v", st, out)
	}
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "sig", "Plaintext": "eA=="}); st != 400 || typ(out) != "InvalidKeyUsageException" {
		t.Errorf("encrypt with a signing key: %d %v", st, out)
	}
	if st, out := r.app("DeriveSharedSecret", map[string]any{"KeyId": "sig", "KeyAgreementAlgorithm": "ECDH", "PublicKey": "AA=="}); st != 400 || typ(out) != "InvalidKeyUsageException" {
		t.Errorf("derive with a signing key: %d %v", st, out)
	}
	if a := r.audit.String(); !strings.Contains(a, `"op":"sign"`) || !strings.Contains(a, "digest=") || strings.Contains(a, "a message to sign") {
		t.Errorf("audit: %s", a)
	}
}

func TestSignNeedsTheRight(t *testing.T) {
	r := cryptoRig(t)
	// "reader" has no grant on the signing key: it looks like a key that does not exist
	if st, out, _ := r.call("reader", "AKIDVIEWERVIEWER00", "Sign", map[string]any{"KeyId": "sig", "Message": []byte("m"), "SigningAlgorithm": "ECDSA_SHA_256"}, nil); st != 400 || typ(out) != "AccessDeniedException" {
		t.Errorf("%d %v", st, out)
	}
}

// An algorithm of another key type gets the answer the cloud service gives for it (checked against that service with RSA keys): InvalidKeyUsageException.
func TestAlgorithmOfAnotherKeyType(t *testing.T) {
	r := cryptoRig(t)
	for op, body := range map[string]map[string]any{
		"Sign":    {"KeyId": "sig", "Message": []byte("m"), "SigningAlgorithm": "RSASSA_PSS_SHA_256"},
		"Encrypt": {"KeyId": "seal", "Plaintext": []byte("m"), "EncryptionAlgorithm": "RSAES_OAEP_SHA_256"},
		"Decrypt": {"CiphertextBlob": []byte("m"), "EncryptionAlgorithm": "RSAES_OAEP_SHA_1"},
	} {
		if st, out := r.app(op, body); st != 400 || typ(out) != "InvalidKeyUsageException" {
			t.Errorf("%s: %d %v", op, st, out)
		}
	}
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "seal", "Plaintext": []byte("m"), "EncryptionAlgorithm": "garbage"}); st != 400 || typ(out) != "ValidationException" {
		t.Errorf("garbage: %d %v", st, out)
	}
}

func TestGenerateAndVerifyMac(t *testing.T) {
	r := cryptoRig(t)
	msg := []byte("message to authenticate")
	st, g := r.app("GenerateMac", map[string]any{"KeyId": "alias/mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"})
	if st != 200 || g["MacAlgorithm"] != "HMAC_SHA_256" || !strings.HasSuffix(g["KeyId"].(string), ":key/mac") {
		t.Fatalf("GenerateMac: %d %v", st, g)
	}
	mac, _ := base64.StdEncoding.DecodeString(g["Mac"].(string))
	// the key is the one the design says: HKDF of the ECDH of the private key with the fixed point
	priv, _ := ecdh.P256().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	peer, err := ecdh.P256().NewPublicKey(keyops.MacPoint())
	if err != nil {
		t.Fatal(err)
	}
	z, _ := priv.ECDH(peer)
	fp := ecies.Fingerprint(priv.PublicKey().Bytes())
	mk, _ := hkdf.Key(sha256.New, z, []byte("hsmgate/mac/v1"), "mac|"+fp, 32)
	h := hmac.New(sha256.New, mk)
	h.Write(msg)
	if !bytes.Equal(mac, h.Sum(nil)) {
		t.Errorf("the MAC is not HMAC-SHA-256 under the derived key")
	}
	// the same message gives the same MAC; another message, another; another key, another
	_, g2 := r.app("GenerateMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"})
	if g2["Mac"] != g["Mac"] {
		t.Error("a MAC is not repeatable")
	}
	_, g3 := r.app("GenerateMac", map[string]any{"KeyId": "macrot", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"})
	if g3["Mac"] == g["Mac"] {
		t.Error("two keys give one MAC")
	}
	// VerifyMac
	if st, out := r.app("VerifyMac", map[string]any{"KeyId": "mac", "Message": msg, "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"}); st != 200 || out["MacValid"] != true {
		t.Errorf("VerifyMac: %d %v", st, out)
	}
	bad := append([]byte{}, mac...)
	bad[0] ^= 1
	for name, body := range map[string]map[string]any{
		"another message": {"KeyId": "mac", "Message": []byte("other"), "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"},
		"a damaged mac":   {"KeyId": "mac", "Message": msg, "Mac": bad, "MacAlgorithm": "HMAC_SHA_256"},
		"another key":     {"KeyId": "macrot", "Message": msg, "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"},
		"a short mac":     {"KeyId": "mac", "Message": msg, "Mac": mac[:5], "MacAlgorithm": "HMAC_SHA_256"},
	} {
		if st, out := r.app("VerifyMac", body); st != 400 || typ(out) != "KMSInvalidMacException" {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
	for name, c := range map[string]struct {
		op   string
		body map[string]any
		typ  string
	}{
		"algorithm of another size": {"GenerateMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_512"}, "InvalidKeyUsageException"},
		"nonsense algorithm":        {"GenerateMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "x"}, "ValidationException"},
		"empty message":             {"GenerateMac", map[string]any{"KeyId": "mac", "MacAlgorithm": "HMAC_SHA_256"}, "ValidationException"},
		"empty mac":                 {"VerifyMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"}, "ValidationException"},
		"dry run":                   {"GenerateMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_256", "DryRun": true}, "DryRunOperationException"},
		"a signing key":             {"GenerateMac", map[string]any{"KeyId": "sig", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"}, "InvalidKeyUsageException"},
		"a sealing key":             {"VerifyMac", map[string]any{"KeyId": "seal", "Message": msg, "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"}, "InvalidKeyUsageException"},
	} {
		if st, out := r.app(c.op, c.body); st != 400 || typ(out) != c.typ {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
	// a MAC key is not for other operations, and says what it is
	if st, out := r.app("Encrypt", map[string]any{"KeyId": "mac", "Plaintext": "eA=="}); st != 400 || typ(out) != "InvalidKeyUsageException" {
		t.Errorf("encrypt: %d %v", st, out)
	}
	if st, out := r.app("GetPublicKey", map[string]any{"KeyId": "mac"}); st != 400 || typ(out) != "UnsupportedOperationException" {
		t.Errorf("GetPublicKey: %d %v", st, out)
	}
	_, d := r.app("DescribeKey", map[string]any{"KeyId": "mac"})
	if md, _ := d["KeyMetadata"].(map[string]any); md["KeyUsage"] != "GENERATE_VERIFY_MAC" || md["KeySpec"] != "HMAC_256" {
		t.Errorf("DescribeKey: %v", d)
	}
	// the audit holds a piece of the hash of the message, not the message
	if a := r.audit.String(); !strings.Contains(a, `"op":"generatemac"`) || !strings.Contains(a, "msg=") || strings.Contains(a, "message to authenticate") {
		t.Errorf("audit: %s", a)
	}
}

type countingToken struct {
	backend.Token
	n *int
}

func (c countingToken) Derive(label string, peer []byte) ([]byte, error) {
	*c.n++
	return c.Token.Derive(label, peer)
}

func TestMacKeyCache(t *testing.T) {
	r := cryptoRig(t)
	n := 0
	r.face.Tokens["soft"] = countingToken{r.face.Tokens["soft"], &n}
	gen := func() {
		r.app("GenerateMac", map[string]any{"KeyId": "mac", "Message": []byte("m"), "MacAlgorithm": "HMAC_SHA_256"})
	}
	gen()
	gen()
	if n != 2 {
		t.Errorf("without a cache every MAC asks the token: %d", n)
	}
	n = 0
	r.cfg.KMSJSON.MacCacheSeconds = 60
	gen()
	gen()
	gen()
	if n != 1 {
		t.Errorf("with a cache the token is asked once: %d", n)
	}
	r.face.Now = func() time.Time { return r.now.Add(2 * time.Minute) }
	gen()
	if n != 2 {
		t.Errorf("after the time the key is derived again: %d", n)
	}
}

func TestMacVersions(t *testing.T) {
	r := cryptoRig(t)
	msg := []byte("m")
	_, g := r.app("GenerateMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"})
	mac, _ := base64.StdEncoding.DecodeString(g["Mac"].(string))
	// a second version of the key: the earlier MACs still verify (the latest is tried first, then the earlier), new ones differ
	key := r.cfg.Keys["mac"]
	key.Versions = append(key.Versions, config.Version{Token: "soft", Label: "m5"})
	r.cfg.Keys["mac"] = key
	if st, out := r.app("VerifyMac", map[string]any{"KeyId": "mac", "Message": msg, "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"}); st != 200 || out["MacValid"] != true {
		t.Errorf("the old MAC after rotation: %d %v", st, out)
	}
	_, g2 := r.app("GenerateMac", map[string]any{"KeyId": "mac", "Message": msg, "MacAlgorithm": "HMAC_SHA_256"})
	if g2["Mac"] == g["Mac"] {
		t.Error("the new version gives the old MAC")
	}
	// a version asked for by name@N is the only one tried
	if st, out := r.app("VerifyMac", map[string]any{"KeyId": "mac@2", "Message": msg, "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"}); st != 400 || typ(out) != "KMSInvalidMacException" {
		t.Errorf("version 2 against a MAC of version 1: %d %v", st, out)
	}
	if st, out := r.app("VerifyMac", map[string]any{"KeyId": "mac@1", "Message": msg, "Mac": mac, "MacAlgorithm": "HMAC_SHA_256"}); st != 200 || out["MacValid"] != true {
		t.Errorf("version 1: %d %v", st, out)
	}
}
