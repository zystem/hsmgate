package kmsops

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/policy"
)

func rig(t testing.TB) *Service {
	dir := t.TempDir()
	files := map[string]string{}
	for i, n := range []string{"m1", "m2", "m3", "m4", "m5", "m6", "m7"} {
		p := filepath.Join(dir, n)
		os.WriteFile(p, []byte(strings.Repeat(string(rune('1'+i)), 64)), 0o600)
		files[n] = p
	}
	cfg, err := config.Parse([]byte(`
kmsjson: {enabled: false, mac_cache_seconds: 60}
tokens: [{name: soft, type: soft, keys: {m1: ` + files["m1"] + `, m2: ` + files["m2"] + `, m3: ` + files["m3"] + `, m4: ` + files["m4"] + `, m5: ` + files["m5"] + `, m6: ` + files["m6"] + `, m7: ` + files["m7"] + `}}]
keys:
  seal:  {kmsgrpc: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m1}], aad: {mode: fixed}, max_bytes: 64}
  copy:  {kmsgrpc: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m2}, {token: soft, label: m3}], aad: {mode: context, allow: ["purpose=dek", "app/"]}}
  sig:   {kmsgrpc: true, kmsjson_usage: sign_verify, versions: [{token: soft, label: m4}, {token: soft, label: m5}], aad: {mode: fixed}}
  mac:   {kmsgrpc: true, kmsjson_usage: generate_verify_mac, versions: [{token: soft, label: m6}], aad: {mode: fixed}}
  aws:   {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m7}], aad: {mode: fixed}}
clients:
  - {name: app, identity: {cn: app}, keys: {seal: {ops: [encrypt, decrypt]}, copy: {ops: [encrypt, decrypt], contexts: ["purpose=dek", "app/"]}, sig: {ops: [sign, verify]}, mac: {ops: [generate_mac, verify_mac]}, aws: {ops: [encrypt]}}}
  - {name: reader, identity: {cn: reader}, keys: {seal: {ops: [decrypt]}}}
  - {name: limited, identity: {cn: limited}, keys: {seal: {ops: [encrypt], per_minute: 2}}}
`))
	if err != nil {
		t.Fatal(err)
	}
	soft, err := backend.NewSoft(cfg.Tokens[0].Keys)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Face: "kmsgrpc", Cfg: cfg, Tokens: map[string]backend.Token{"soft": soft}, Policy: policy.New(cfg, nil), Gate: gate.New(4, time.Second), Macs: NewMacCache()}
}

func kind(e *Error) Kind {
	if e == nil {
		return 0
	}
	return e.Kind
}

var bg = context.Background()

func TestSealOpenAndWhatTheBlobBinds(t *testing.T) {
	s := rig(t)
	blob, ver, e := s.Seal(bg, "app", "seal", 0, []byte("secret"), nil, AADBytes, 4096)
	if e != nil || ver != 1 {
		t.Fatal(e, ver)
	}
	plain, name, v, e := s.Open(bg, "app", "", blob, nil, AADBytes)
	if e != nil || string(plain) != "secret" || name != "seal" || v != 1 {
		t.Fatalf("%q %s %d %v", plain, name, v, e)
	}
	// the reader may only decrypt, and the hint must be the key of the blob
	if _, _, _, e := s.Open(bg, "reader", "seal", blob, nil, AADBytes); e != nil {
		t.Errorf("the reader: %v", e)
	}
	if _, _, _, e := s.Open(bg, "app", "copy", blob, nil, AADBytes); kind(e) != Invalid {
		t.Errorf("a hint for another key: %v", e)
	}
	// a blob relabelled to another key or version is refused: the name and the version are authenticated
	n, ver2, text, _ := ParseBlob(blob)
	for _, bad := range [][]byte{MakeBlob("copy", ver2, text), MakeBlob(n, 2, text)} {
		if _, _, _, e := s.Open(bg, "app", "", bad, nil, AADBytes); e == nil {
			t.Error("a relabelled blob was opened")
		}
	}
	// damaged, garbage, a limit on the way in and on the way out
	bad := append([]byte{}, blob...)
	bad[len(bad)-2] ^= 1
	if _, _, _, e := s.Open(bg, "app", "", bad, nil, AADBytes); kind(e) != BadCiphertext {
		t.Errorf("damaged: %v", e)
	}
	if _, _, _, e := s.Open(bg, "app", "", []byte("garbage"), nil, AADBytes); kind(e) != BadCiphertext {
		t.Errorf("garbage: %v", e)
	}
	if _, _, e := s.Seal(bg, "app", "seal", 0, bytes.Repeat([]byte("x"), 65), nil, AADBytes, 4096); kind(e) != Invalid {
		t.Errorf("over max_bytes: %v", e)
	}
	if _, _, e := s.Seal(bg, "app", "seal", 0, bytes.Repeat([]byte("x"), 40), nil, AADBytes, 16); kind(e) != Invalid {
		t.Errorf("over the limit of the face: %v", e)
	}
}

func TestRightsFaceAndUsage(t *testing.T) {
	s := rig(t)
	if _, _, e := s.Seal(bg, "reader", "seal", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Denied {
		t.Errorf("no right to encrypt: %v", e)
	}
	if _, _, e := s.Seal(bg, "nobody", "seal", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Denied {
		t.Errorf("an unknown client: %v", e)
	}
	// a key that is on another face looks like one that does not exist
	if _, _, e := s.Seal(bg, "app", "aws", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Denied {
		t.Errorf("a key of another face: %v", e)
	}
	if _, _, e := s.Seal(bg, "app", "nope", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Denied {
		t.Errorf("a key that does not exist: %v", e)
	}
	// usage both ways
	if _, _, e := s.Sign(bg, "app", "seal", 0, make([]byte, 32)); kind(e) != Usage {
		t.Errorf("sign with a sealing key: %v", e)
	}
	if _, _, e := s.Seal(bg, "app", "sig", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Usage {
		t.Errorf("seal with a signing key: %v", e)
	}
	// budget
	for i := 0; i < 2; i++ {
		if _, _, e := s.Seal(bg, "limited", "seal", 0, []byte("x"), nil, AADBytes, 100); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, e := s.Seal(bg, "limited", "seal", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Throttled || !e.Retry {
		t.Errorf("over the budget: %v", e)
	}
}

func TestAdditionalData(t *testing.T) {
	s := rig(t)
	// a fixed-mode key takes none
	if _, _, e := s.Seal(bg, "app", "seal", 0, []byte("x"), []byte("aad"), AADBytes, 100); kind(e) != Invalid {
		t.Errorf("fixed key with data: %v", e)
	}
	// a context-mode key needs some, within the key's prefixes and the grant's
	if _, _, e := s.Seal(bg, "app", "copy", 0, []byte("x"), nil, AADBytes, 100); kind(e) != Invalid {
		t.Errorf("no data: %v", e)
	}
	if _, _, e := s.Seal(bg, "app", "copy", 0, []byte("x"), []byte("other/thing"), AADBytes, 100); kind(e) != Denied && kind(e) != Invalid {
		t.Errorf("not allowed: %v", e)
	}
	blob, _, e := s.Seal(bg, "app", "copy", 0, []byte("dek"), []byte("app/dek/1"), AADBytes, 100)
	if e != nil {
		t.Fatal(e)
	}
	if p, _, _, e := s.Open(bg, "app", "", blob, []byte("app/dek/1"), AADBytes); e != nil || string(p) != "dek" {
		t.Errorf("same context: %v", e)
	}
	if _, _, _, e := s.Open(bg, "app", "", blob, []byte("app/dek/2"), AADBytes); kind(e) != BadCiphertext {
		t.Errorf("another context: %v", e)
	}
	// lines: one line with an allowed prefix is enough
	lb, _, e := s.Seal(bg, "app", "copy", 0, []byte("l"), []byte("org=o1\npurpose=dek"), AADLines, 100)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, _, e := s.Open(bg, "app", "", lb, []byte("org=o1\npurpose=dek"), AADLines); e != nil {
		t.Errorf("lines: %v", e)
	}
	if _, _, e := s.Seal(bg, "app", "copy", 0, []byte("l"), []byte("org=o1\nzzz=1"), AADLines, 100); e == nil {
		t.Error("lines without an allowed prefix were accepted")
	}
}

func TestSignVerifyAndPublic(t *testing.T) {
	s := rig(t)
	d := sha256.Sum256([]byte("message"))
	sig, ver, e := s.Sign(bg, "app", "sig", 0, d[:])
	if e != nil || ver != 2 {
		t.Fatal(e, ver)
	}
	der, _, e := s.Public(bg, "app", "sig", 0)
	if e != nil {
		t.Fatal(e)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil || !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), d[:], sig) {
		t.Fatalf("the signature does not verify with the public key: %v", err)
	}
	if ok, e := s.Verify(bg, "app", "sig", 0, d[:], sig); !ok || e != nil {
		t.Errorf("Verify: %v %v", ok, e)
	}
	// a signature of version 1 still verifies when no version is asked for, and only with version 1 when it is
	old, _, e := s.Sign(bg, "app", "sig", 1, d[:])
	if e != nil {
		t.Fatal(e)
	}
	if ok, _ := s.Verify(bg, "app", "sig", 0, d[:], old); !ok {
		t.Error("an old signature after a rotation")
	}
	if ok, _ := s.Verify(bg, "app", "sig", 2, d[:], old); ok {
		t.Error("version 2 accepted a signature of version 1")
	}
	d2 := sha256.Sum256([]byte("other"))
	if ok, e := s.Verify(bg, "app", "sig", 0, d2[:], sig); ok || e != nil {
		t.Errorf("another message: %v %v", ok, e)
	}
	if _, _, e := s.Sign(bg, "app", "sig", 0, []byte("short")); kind(e) != Invalid {
		t.Errorf("a short digest: %v", e)
	}
	if _, _, e := s.Sign(bg, "app", "sig", 3, d[:]); kind(e) != Invalid {
		t.Errorf("a version that does not exist: %v", e)
	}
	if _, _, e := s.Public(bg, "app", "seal", 0); kind(e) != Usage {
		t.Errorf("public key of a sealing key: %v", e)
	}
}

func TestMac(t *testing.T) {
	s := rig(t)
	mac, _, e := s.MacGenerate(bg, "app", "mac", 0, []byte("m"))
	if e != nil || len(mac) != 32 {
		t.Fatal(e, len(mac))
	}
	if ok, e := s.MacVerify(bg, "app", "mac", 0, []byte("m"), mac); !ok || e != nil {
		t.Errorf("%v %v", ok, e)
	}
	if ok, _ := s.MacVerify(bg, "app", "mac", 0, []byte("x"), mac); ok {
		t.Error("another message")
	}
	if _, _, e := s.MacGenerate(bg, "app", "sig", 0, []byte("m")); kind(e) != Usage {
		t.Errorf("mac with a signing key: %v", e)
	}
	// the cache gives the same MAC and a clear drops it
	again, _, _ := s.MacGenerate(bg, "app", "mac", 0, []byte("m"))
	if !bytes.Equal(again, mac) {
		t.Error("a cached key gives another MAC")
	}
	s.Macs.Clear()
	if third, _, _ := s.MacGenerate(bg, "app", "mac", 0, []byte("m")); !bytes.Equal(third, mac) {
		t.Error("the MAC changed after the cache was cleared")
	}
}

func TestMacCacheIsRaceFree(t *testing.T) {
	k := NewMacCache()
	key := bytes.Repeat([]byte{0x42}, 32)
	k.put("id", key, time.Now().Add(time.Hour))
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			if b, ok := k.get("id", time.Now()); ok && !bytes.Equal(b, key) {
				t.Error("a torn key")
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 3000; i++ {
			k.put("id", key, time.Now().Add(time.Hour))
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 300; i++ {
			k.Clear()
			k.put("id", key, time.Now().Add(time.Hour))
		}
	}()
	wg.Wait()
}

func TestRandomDescribeList(t *testing.T) {
	s := rig(t)
	b, e := s.Random("app", 32)
	if e != nil || len(b) != 32 {
		t.Fatal(e)
	}
	m, e := s.Describe("app", "sig")
	if e != nil || m.Usage != config.UsageSignVerify || m.Versions != 2 {
		t.Errorf("%+v %v", m, e)
	}
	if _, e := s.Describe("reader", "sig"); kind(e) != Denied {
		t.Errorf("describe without a grant: %v", e)
	}
	names, e := s.List("app")
	if e != nil || strings.Join(names, ",") != "copy,mac,seal,sig" { // "aws" is on another face
		t.Errorf("%v %v", names, e)
	}
	if names, _ := s.List("reader"); strings.Join(names, ",") != "seal" {
		t.Errorf("reader sees %v", names)
	}
}

func TestBlobParsingIsStrict(t *testing.T) {
	good := MakeBlob("seal", 1, "ecies2.aa.bb.cc")
	if n, v, txt, err := ParseBlob(good); err != nil || n != "seal" || v != 1 || txt != "ecies2.aa.bb.cc" {
		t.Fatal(n, v, txt, err)
	}
	for i := 0; i < len(good); i++ {
		ParseBlob(good[:i]) // no panic on any prefix
	}
	for _, b := range [][]byte{nil, []byte("HGK2"), []byte("HGK1\x01a\x00\x01ecies2.x"), []byte("HGK2\x00a\x00\x01ecies2.x"), []byte("HGK2\x01a\x00\x00ecies2.x"), []byte("HGK2\x01a\x00\x01nope")} {
		if _, _, _, err := ParseBlob(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestErrorsAndBlobKey(t *testing.T) {
	e := fail(Denied, "forbidden", "no", false)
	if e.Error() != "no (forbidden)" {
		t.Errorf("%q", e.Error())
	}
	blob := MakeBlob("seal", 3, "ecies2.aa.bb.cc")
	if n, v, err := BlobKey(blob); err != nil || n != "seal" || v != 3 {
		t.Errorf("%s %d %v", n, v, err)
	}
	if _, _, err := BlobKey([]byte("junk")); kind(err) != BadCiphertext {
		t.Errorf("junk: %v", err)
	}
	for in, want := range map[error]Kind{backend.ErrLocked: Locked, backend.ErrUnavailable: Unavailable, errors.New("x"): Internal} {
		if got := tokenErr(in); got.Kind != want {
			t.Errorf("%v: %v", in, got.Kind)
		}
	}
}

func TestBlobConversionsRefuseWhatDoesNotFit(t *testing.T) {
	for name, f := range map[string]func(){
		"a version over two bytes": func() { MakeBlob("seal", 70000, "ecies2.a.b.c") },
		"a negative version":       func() { BindAAD("seal", -1, nil) },
		"a name over one byte":     func() { MakeBlob(strings.Repeat("a", 300), 1, "ecies2.a.b.c") },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s was written into a blob", name)
				}
			}()
			f()
		}()
	}
	// what the configuration allows fits
	if _, v, _, err := ParseBlob(MakeBlob("seal", config.MaxVersions, "ecies2.a.b.c")); err != nil || v != config.MaxVersions {
		t.Errorf("%d %v", v, err)
	}
}
