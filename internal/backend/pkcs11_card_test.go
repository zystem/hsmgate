package backend

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"testing"
)

// A run against a real module (SoftHSM2, or the SmartCard-HSM through OpenSC). Set HSMGATE_P11_MODULE, HSMGATE_P11_KEY_ID (CKA_ID in hex) and
// optionally HSMGATE_P11_TOKEN_LABEL. Only the public key is read: no PIN is used, so no PIN try can be lost.
func TestRealModulePublicKey(t *testing.T) {
	mod, id := os.Getenv("HSMGATE_P11_MODULE"), os.Getenv("HSMGATE_P11_KEY_ID")
	if mod == "" || id == "" {
		t.Skip("HSMGATE_P11_MODULE and HSMGATE_P11_KEY_ID are not set")
	}
	p, err := OpenPKCS11(PKCS11Config{Module: mod, TokenLabel: os.Getenv("HSMGATE_P11_TOKEN_LABEL"), Keys: map[string]string{"m": id}})
	if err != nil {
		t.Fatal(err)
	}
	pt, err := p.Point("m")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ecdh.P256().NewPublicKey(pt); err != nil {
		t.Fatalf("not a P-256 point: %v", err)
	}
	t.Logf("point %x, state %s", pt, p.State())
	if p.State() != "locked" {
		t.Errorf("state %s without a login", p.State())
	}
}

// With a PIN file (HSMGATE_P11_PIN_FILE): login once and ECDH on the token against a software ECDH. The PIN is read here and never printed. On the real card this costs
// one login; a refused PIN costs one of its 3 tries, so use SoftHSM2 in CI (tools/softhsm-test.sh).
func TestRealModuleDerive(t *testing.T) {
	mod, id, pinFile := os.Getenv("HSMGATE_P11_MODULE"), os.Getenv("HSMGATE_P11_KEY_ID"), os.Getenv("HSMGATE_P11_PIN_FILE")
	if mod == "" || id == "" || pinFile == "" {
		t.Skip("HSMGATE_P11_MODULE, HSMGATE_P11_KEY_ID and HSMGATE_P11_PIN_FILE are not set")
	}
	pin, err := os.ReadFile(pinFile)
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenPKCS11(PKCS11Config{Module: mod, TokenLabel: os.Getenv("HSMGATE_P11_TOKEN_LABEL"), Keys: map[string]string{"m": id}})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.Unlock(bytes.TrimRight(pin, "\r\n")); err != nil {
		t.Fatal(err)
	}
	master, err := p.Point("m")
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := ecdh.P256().NewPublicKey(master)
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	want, _ := eph.ECDH(pub)
	got, err := p.Derive("m", eph.PublicKey().Bytes())
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("derive: %v, equal=%v", err, bytes.Equal(got, want))
	}
	if p.State() != "ready" {
		t.Errorf("state %s", p.State())
	}
}
