package backend

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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

func (f *fakeModule) SignInit(pkcs11.SessionHandle, []*pkcs11.Mechanism, pkcs11.ObjectHandle) error {
	if !f.loggedIn {
		return pkcs11.Error(pkcs11.CKR_USER_NOT_LOGGED_IN)
	}
	return nil
}

// Sign gives the raw r||s of ECDSA with the key of the fake, as a token does.
func (f *fakeModule) Sign(_ pkcs11.SessionHandle, digest []byte) ([]byte, error) {
	k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), f.priv.Bytes())
	if err != nil {
		return nil, err
	}
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
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

// A PIN given to a token that is logged in is not taken: C_Login would answer "already logged in" and the wrong PIN would be kept for the next login.
func TestUnlockWhenLoggedInKeepsTheRightPIN(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	peer, want := peerOf(t, f)
	if err := p.Unlock([]byte("123456")); err != nil {
		t.Fatal(err)
	}
	if err := p.Unlock([]byte("wrong!")); !errors.Is(err, ErrAlreadyUnlocked) {
		t.Fatalf("%v", err)
	}
	f.deriveErr = pkcs11.Error(pkcs11.CKR_SESSION_CLOSED)
	p.Derive("m", peer) // the session is lost
	got, err := p.Derive("m", peer)
	if err != nil || !bytes.Equal(got, want) {
		t.Errorf("relogin with the remembered PIN: %v", err)
	}
}

// A view has its own label map; the token, its session and its PIN are shared. A new view changes nothing for the old one.
func TestViewsShareTheSessionButNotTheKeys(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	v2 := p.View(map[string]string{"other": "02"})
	if err := p.Unlock([]byte("123456")); err != nil {
		t.Fatal(err)
	}
	if v2.State() != "ready" {
		t.Errorf("the view does not share the login: %s", v2.State())
	}
	if _, err := p.Point("m"); err != nil {
		t.Errorf("old view lost its key: %v", err)
	}
	if _, err := v2.Point("m"); err == nil {
		t.Error("the new view knows the label of the old one")
	}
}

// Public keys read in an earlier session are read again in the next one (the card may have been replaced meanwhile).
func TestPointsAreReadAgainInANewSession(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	first, _ := p.Point("m")
	old := f.priv
	f.priv, _ = ecdh.P256().GenerateKey(rand.Reader) // another card with the same label
	if again, _ := p.Point("m"); !bytes.Equal(again, first) {
		t.Fatal("cache not used within a session")
	}
	f.deriveErr = pkcs11.Error(pkcs11.CKR_SESSION_CLOSED)
	p.Unlock([]byte("123456"))
	peer, _ := peerOf(t, f)
	p.Derive("m", peer) // the session is lost
	p.Unlock([]byte("123456"))
	second, err := p.Point("m")
	if err != nil || bytes.Equal(second, first) || !bytes.Equal(second, f.priv.PublicKey().Bytes()) {
		t.Errorf("stale point after a new session: %v", err)
	}
	_ = old
}

// R-01: after a session is dropped the cached public key is not served any more; if the card is gone, so is the answer.
func TestPointIsNotServedFromTheCacheAfterTheSessionWasDropped(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	first, err := p.Point("m")
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.dropSession() // what a lost session or a failed destroy does
	p.mu.Unlock()
	f.present = false
	if pt, err := p.Point("m"); err == nil {
		t.Errorf("a stale point was served: %x", pt)
	}
	f.present = true
	f.priv, _ = ecdh.P256().GenerateKey(rand.Reader) // another card
	second, err := p.Point("m")
	if err != nil || bytes.Equal(second, first) {
		t.Errorf("the new card's key was not read: %v", err)
	}
}

// A retired token (Close) opens no session again, even if a request of the old generation still calls it.
func TestRetiredTokenOpensNoSession(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	p.Unlock([]byte("123456"))
	p.Close()
	opens := f.opens
	peer, _ := peerOf(t, f)
	if _, err := p.Derive("m", peer); !errors.Is(err, ErrUnavailable) || f.opens != opens {
		t.Errorf("%v opens %d->%d", err, opens, f.opens)
	}
}

// Sign: the token's raw signature becomes ASN.1 DER that verifies with the public key; a locked token is "locked", a digest of the wrong size is refused.
func TestSignGivesDERThatVerifies(t *testing.T) {
	f := newFake()
	p := newPKCS11(cfg(), f)
	digest := sha256.Sum256([]byte("message"))
	if _, err := p.Sign("m", digest[:]); !errors.Is(err, ErrLocked) {
		t.Fatalf("before the unlock: %v", err)
	}
	if err := p.Unlock([]byte("123456")); err != nil {
		t.Fatal(err)
	}
	sig, err := p.Sign("m", digest[:])
	if err != nil {
		t.Fatal(err)
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), f.priv.PublicKey().Bytes())
	if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], sig) {
		t.Error("the signature does not verify")
	}
	if _, err := p.Sign("m", digest[:5]); err == nil {
		t.Error("a short digest was signed")
	}
}
