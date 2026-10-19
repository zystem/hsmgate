package backend

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

// module is the part of a PKCS#11 library that is used; *pkcs11.Ctx is one, a fake is another (tests).
type module interface {
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetTokenInfo(slot uint) (pkcs11.TokenInfo, error)
	OpenSession(slot uint, flags uint) (pkcs11.SessionHandle, error)
	CloseSession(sh pkcs11.SessionHandle) error
	Login(sh pkcs11.SessionHandle, userType uint, pin string) error
	Logout(sh pkcs11.SessionHandle) error
	FindObjectsInit(sh pkcs11.SessionHandle, temp []*pkcs11.Attribute) error
	FindObjects(sh pkcs11.SessionHandle, max int) ([]pkcs11.ObjectHandle, bool, error)
	FindObjectsFinal(sh pkcs11.SessionHandle) error
	GetAttributeValue(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle, a []*pkcs11.Attribute) ([]*pkcs11.Attribute, error)
	DeriveKey(sh pkcs11.SessionHandle, m []*pkcs11.Mechanism, base pkcs11.ObjectHandle, a []*pkcs11.Attribute) (pkcs11.ObjectHandle, error)
	DestroyObject(sh pkcs11.SessionHandle, o pkcs11.ObjectHandle) error
}

// PKCS11Config: Keys maps a label (as the configuration names it) to the CKA_ID of the key pair, in hex.
type PKCS11Config struct {
	Module      string
	TokenLabel  string // the first token when empty and TokenSerial is empty too
	TokenSerial string
	Keys        map[string]string
}

// ErrPINRefused: the token refused the PIN. It is not tried again by the service; an operator unlocks again, knowing the card blocks after a few wrong tries.
var ErrPINRefused = errors.New("the token refused the PIN")

type PKCS11 struct {
	cfg PKCS11Config
	m   module

	mu       sync.Mutex
	slot     uint
	sh       pkcs11.SessionHandle
	open     bool
	loggedIn bool
	pin      []byte // kept in memory only, after a login that succeeded: to log in again if the session is lost
	refused  bool   // the token refused the PIN: no automatic tries
	absent   bool
	points   map[string][]byte
}

// OpenPKCS11 loads the module. The token is looked for at the first call, so the service can start with the card out.
func OpenPKCS11(cfg PKCS11Config) (*PKCS11, error) {
	ctx := pkcs11.New(cfg.Module)
	if ctx == nil {
		return nil, fmt.Errorf("cannot load %s", cfg.Module)
	}
	if err := ctx.Initialize(); err != nil {
		if e, ok := err.(pkcs11.Error); !ok || e != pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
			return nil, fmt.Errorf("C_Initialize: %w", err)
		}
	}
	return newPKCS11(cfg, ctx), nil
}

func newPKCS11(cfg PKCS11Config, m module) *PKCS11 {
	return &PKCS11{cfg: cfg, m: m, points: map[string][]byte{}}
}

func (p *PKCS11) State() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case p.absent:
		return "absent"
	case !p.loggedIn:
		return "locked"
	}
	return "ready"
}

// Unlock logs in with the PIN: one attempt. After a refusal the service stays locked until an operator calls this again.
func (p *PKCS11) Unlock(pin []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.refused = false
	if err := p.ensureSession(); err != nil {
		return err
	}
	return p.login(pin)
}

func (p *PKCS11) login(pin []byte) error {
	err := p.m.Login(p.sh, pkcs11.CKU_USER, string(pin))
	switch {
	case err == nil || isErr(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN):
		p.loggedIn = true
		p.pin = append(p.pin[:0], pin...)
		return nil
	case isErr(err, pkcs11.CKR_PIN_INCORRECT), isErr(err, pkcs11.CKR_PIN_LOCKED), isErr(err, pkcs11.CKR_PIN_LEN_RANGE):
		p.refused = true
		p.pin = nil
		return fmt.Errorf("%w: %v", ErrPINRefused, err)
	}
	p.dropSession()
	return unavailable(err)
}

// Close logs out and forgets the PIN.
func (p *PKCS11) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.open {
		p.m.Logout(p.sh)
		p.dropSession()
	}
	for i := range p.pin {
		p.pin[i] = 0
	}
	p.pin = nil
}

func isErr(err error, want pkcs11.Error) bool {
	e, ok := err.(pkcs11.Error)
	return ok && e == want
}

func unavailable(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }

func (p *PKCS11) dropSession() {
	if p.open {
		p.m.CloseSession(p.sh)
	}
	p.open, p.loggedIn = false, false
}

// ensureSession opens a session on the token (a removed token or a closed session is opened again), and logs in again with the remembered PIN if there is one.
func (p *PKCS11) ensureSession() error {
	if p.open {
		return nil
	}
	slots, err := p.m.GetSlotList(true)
	if err != nil {
		return unavailable(err)
	}
	found := false
	for _, s := range slots {
		info, err := p.m.GetTokenInfo(s)
		if err != nil {
			continue
		}
		label, serial := strings.TrimSpace(info.Label), strings.TrimSpace(info.SerialNumber)
		if (p.cfg.TokenSerial != "" && serial == p.cfg.TokenSerial) ||
			(p.cfg.TokenSerial == "" && (p.cfg.TokenLabel == "" || label == p.cfg.TokenLabel || strings.HasPrefix(label, p.cfg.TokenLabel+" "))) {
			p.slot, found = s, true
			break
		}
	}
	if !found {
		p.absent = true
		return fmt.Errorf("%w: no matching token in the reader", ErrUnavailable)
	}
	sh, err := p.m.OpenSession(p.slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return unavailable(err)
	}
	p.sh, p.open, p.absent, p.loggedIn = sh, true, false, false
	if len(p.pin) > 0 && !p.refused {
		return p.login(p.pin)
	}
	return nil
}

func (p *PKCS11) find(label string, class uint) (pkcs11.ObjectHandle, error) {
	id, ok := p.cfg.Keys[label]
	if !ok {
		return 0, fmt.Errorf("no key %q", label)
	}
	raw, err := hex.DecodeString(id)
	if err != nil {
		return 0, fmt.Errorf("key %q: id is not hex", label)
	}
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class), pkcs11.NewAttribute(pkcs11.CKA_ID, raw)}
	if err := p.m.FindObjectsInit(p.sh, tmpl); err != nil {
		return 0, p.sessionErr(err)
	}
	objs, _, err := p.m.FindObjects(p.sh, 1)
	p.m.FindObjectsFinal(p.sh)
	if err != nil {
		return 0, p.sessionErr(err)
	}
	if len(objs) == 0 {
		return 0, fmt.Errorf("the token has no such key (id %s)", id)
	}
	return objs[0], nil
}

// sessionErr: errors that mean the session, the login or the token is gone are "unavailable"; the session is dropped so that the next call opens it again.
func (p *PKCS11) sessionErr(err error) error {
	for _, c := range []pkcs11.Error{pkcs11.CKR_SESSION_CLOSED, pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_USER_NOT_LOGGED_IN, pkcs11.CKR_DEVICE_REMOVED,
		pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_DEVICE_ERROR, pkcs11.CKR_TOKEN_NOT_RECOGNIZED, pkcs11.CKR_DEVICE_MEMORY} {
		if isErr(err, c) {
			if isErr(err, pkcs11.CKR_DEVICE_REMOVED) || isErr(err, pkcs11.CKR_TOKEN_NOT_PRESENT) {
				p.absent = true
			}
			p.dropSession()
			return unavailable(err)
		}
	}
	return err
}

// Point reads the public key (no PIN) and keeps it.
func (p *PKCS11) Point(label string) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if pt, ok := p.points[label]; ok {
		return pt, nil
	}
	if err := p.ensureSession(); err != nil {
		return nil, err
	}
	o, err := p.find(label, pkcs11.CKO_PUBLIC_KEY)
	if err != nil {
		return nil, err
	}
	a, err := p.m.GetAttributeValue(p.sh, o, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil)})
	if err != nil {
		return nil, p.sessionErr(err)
	}
	pt := a[0].Value
	// CKA_EC_POINT is a DER OCTET STRING around the point (04 41 04 ...); some modules give the point itself
	if len(pt) == 67 && pt[0] == 0x04 && pt[1] == 0x41 {
		pt = pt[2:]
	}
	if len(pt) != 65 || pt[0] != 0x04 {
		return nil, fmt.Errorf("key %q is not an uncompressed P-256 point", label)
	}
	p.points[label] = append([]byte{}, pt...)
	return p.points[label], nil
}

// Derive is ECDH1-DERIVE on the token with no KDF: the 32 bytes of the shared secret. A point the token refuses is final (not ErrUnavailable).
func (p *PKCS11) Derive(label string, peer []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.refused {
		return nil, fmt.Errorf("%w: %v (not tried again; an operator must unlock)", ErrLocked, ErrPINRefused)
	}
	if err := p.ensureSession(); err != nil {
		return nil, err
	}
	if !p.loggedIn {
		return nil, ErrLocked
	}
	o, err := p.find(label, pkcs11.CKO_PRIVATE_KEY)
	if err != nil {
		return nil, err
	}
	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDH1_DERIVE, pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peer))}
	tmpl := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
	}
	k, err := p.m.DeriveKey(p.sh, mech, o, tmpl)
	if err != nil {
		err = p.sessionErr(err)
		if errors.Is(err, ErrUnavailable) {
			return nil, err
		}
		return nil, fmt.Errorf("the token refused the point: %w", err)
	}
	defer p.m.DestroyObject(p.sh, k)
	a, err := p.m.GetAttributeValue(p.sh, k, []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil)})
	if err != nil {
		return nil, p.sessionErr(err)
	}
	if len(a[0].Value) != 32 {
		return nil, unavailable(fmt.Errorf("the token gave a shared secret of %d bytes, not 32", len(a[0].Value)))
	}
	return a[0].Value, nil
}

// SetKeys replaces the label -> CKA_ID map (a reload that adds a key for a rotation). Public keys already read are kept for labels whose id did not change.
func (p *PKCS11) SetKeys(keys map[string]string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for label := range p.points {
		if keys[label] != p.cfg.Keys[label] {
			delete(p.points, label)
		}
	}
	p.cfg.Keys = keys
}
