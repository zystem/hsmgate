package backend

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

// fakeModule is a token in software: one EC key pair with id 01, a PIN, and switches for the faults a card has.
type fakeModule struct {
	priv         *ecdh.PrivateKey
	pin          string
	present      bool
	logins       int
	opens        int
	destroyed    int
	deriveErr    error // returned once by DeriveKey
	wrapPoint    bool  // CKA_EC_POINT as a DER OCTET STRING
	loggedIn     bool
	last         []*pkcs11.Attribute
	foundClass   uint
	peer, secret []byte // the test sets peer to what it passes to Derive
}

func newFake() *fakeModule {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	return &fakeModule{priv: k, pin: "123456", present: true, wrapPoint: true}
}

func (f *fakeModule) GetSlotList(bool) ([]uint, error) {
	if !f.present {
		return nil, nil
	}
	return []uint{7}, nil
}
func (f *fakeModule) GetTokenInfo(uint) (pkcs11.TokenInfo, error) {
	return pkcs11.TokenInfo{Label: "cinim (UserPIN)", SerialNumber: "S1"}, nil
}
func (f *fakeModule) OpenSession(uint, uint) (pkcs11.SessionHandle, error) {
	f.opens++
	f.loggedIn = false
	return 1, nil
}
func (f *fakeModule) CloseSession(pkcs11.SessionHandle) error { return nil }
func (f *fakeModule) Login(_ pkcs11.SessionHandle, _ uint, pin string) error {
	f.logins++
	if pin != f.pin {
		return pkcs11.Error(pkcs11.CKR_PIN_INCORRECT)
	}
	f.loggedIn = true
	return nil
}
func (f *fakeModule) Logout(pkcs11.SessionHandle) error { f.loggedIn = false; return nil }
func (f *fakeModule) FindObjectsInit(_ pkcs11.SessionHandle, t []*pkcs11.Attribute) error {
	for _, a := range t {
		if a.Type == pkcs11.CKA_CLASS {
			f.foundClass = bytesToUint(a.Value)
		}
	}
	return nil
}
func bytesToUint(b []byte) uint {
	var v uint
	for i := len(b) - 1; i >= 0; i-- {
		v = v<<8 | uint(b[i])
	}
	return v
}
func (f *fakeModule) FindObjects(pkcs11.SessionHandle, int) ([]pkcs11.ObjectHandle, bool, error) {
	return []pkcs11.ObjectHandle{pkcs11.ObjectHandle(f.foundClass)}, false, nil
}
func (f *fakeModule) FindObjectsFinal(pkcs11.SessionHandle) error { return nil }
func (f *fakeModule) GetAttributeValue(_ pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error) {
	switch a[0].Type {
	case pkcs11.CKA_EC_POINT:
		pt := f.priv.PublicKey().Bytes()
		if f.wrapPoint {
			pt = append([]byte{0x04, 0x41}, pt...)
		}
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, pt)}, nil
	case pkcs11.CKA_VALUE:
		return []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, f.secret)}, nil
	}
	return nil, errors.New("unexpected attribute")
}
func (f *fakeModule) DeriveKey(_ pkcs11.SessionHandle, m []*pkcs11.Mechanism, _ pkcs11.ObjectHandle, _ []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	if f.deriveErr != nil {
		e := f.deriveErr
		f.deriveErr = nil
		return 0, e
	}
	if !f.loggedIn {
		return 0, pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}
	// the peer point is inside the mechanism parameter; the fake reads it back from what the test stored
	pub, err := ecdh.P256().NewPublicKey(f.peer)
	if err != nil {
		return 0, pkcs11.Error(pkcs11.CKR_MECHANISM_PARAM_INVALID)
	}
	f.secret, _ = f.priv.ECDH(pub)
	return 99, nil
}
func (f *fakeModule) DestroyObject(pkcs11.SessionHandle, pkcs11.ObjectHandle) error {
	f.destroyed++
	return nil
}

func cfg() PKCS11Config { return PKCS11Config{TokenLabel: "cinim", Keys: map[string]string{"m": "01"}} }

func peerOf(t *testing.T, f *fakeModule) ([]byte, []byte) {
	k, _ := ecdh.P256().GenerateKey(rand.Reader)
	f.peer = k.PublicKey().Bytes()
	want, _ := k.ECDH(f.priv.PublicKey())
	return f.peer, want
}

func TestPointNeedsNoLoginAndUnwrapsDER(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	pt, err := p.Point("m")
	if err != nil || !bytes.Equal(pt, f.priv.PublicKey().Bytes()) || f.logins != 0 {
		t.Fatalf("%x %v logins=%d", pt, err, f.logins)
	}
	if p.State() != "locked" {
		t.Errorf("state %s", p.State())
	}
}

func TestDeriveBeforeUnlockIsLocked(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	peer, _ := peerOf(t, f)
	if _, err := p.Derive("m", peer); !errors.Is(err, ErrLocked) || f.logins != 0 {
		t.Errorf("%v logins=%d", err, f.logins)
	}
}

func TestPINIsTriedOnceAndNeverAgainByItself(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	peer, _ := peerOf(t, f)
	if err := p.Unlock([]byte("000000")); !errors.Is(err, ErrPINRefused) {
		t.Fatalf("%v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := p.Derive("m", peer); !errors.Is(err, ErrLocked) {
			t.Fatalf("%v", err)
		}
	}
	if f.logins != 1 || p.State() != "locked" {
		t.Errorf("logins=%d state=%s", f.logins, p.State())
	}
	// an operator unlocks again with the right PIN
	if err := p.Unlock([]byte("123456")); err != nil || p.State() != "ready" {
		t.Errorf("%v %s", err, p.State())
	}
}

func TestDeriveGivesTheSharedSecretAndDestroysTheKey(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	peer, want := peerOf(t, f)
	if err := p.Unlock([]byte("123456")); err != nil {
		t.Fatal(err)
	}
	got, err := p.Derive("m", peer)
	if err != nil || !bytes.Equal(got, want) || f.destroyed != 1 {
		t.Errorf("%x %v destroyed=%d", got, err, f.destroyed)
	}
}

func TestLostSessionIsRetryableAndLogsInAgainWithoutNewPINTries(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	peer, want := peerOf(t, f)
	p.Unlock([]byte("123456"))
	f.deriveErr = pkcs11.Error(pkcs11.CKR_SESSION_CLOSED)
	if _, err := p.Derive("m", peer); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("%v", err)
	}
	got, err := p.Derive("m", peer)
	if err != nil || !bytes.Equal(got, want) || f.opens != 2 || f.logins != 2 {
		t.Errorf("%v opens=%d logins=%d", err, f.opens, f.logins)
	}
}

func TestTokenOutIsAbsentAndComesBack(t *testing.T) {
	f := newFake()
	f.present = false
	p := newPKCS11(cfg(), f)
	peer, _ := peerOf(t, f)
	if _, err := p.Derive("m", peer); !errors.Is(err, ErrUnavailable) || p.State() != "absent" {
		t.Fatalf("%v %s", err, p.State())
	}
	f.present = true
	if err := p.Unlock([]byte("123456")); err != nil || p.State() != "ready" {
		t.Errorf("%v %s", err, p.State())
	}
}

func TestWrongKeyLabel(t *testing.T) {
	p := newPKCS11(cfg(), newFake())
	if _, err := p.Point("nope"); err == nil {
		t.Error("an unknown label was accepted")
	}
}
