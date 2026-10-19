package backend

import (
	"crypto/ecdh"
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
