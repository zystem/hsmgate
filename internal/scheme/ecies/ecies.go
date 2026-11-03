// Package ecies is the sealed format of the service: ECDH-ES on P-256, then HKDF, then an AEAD. The text is
//
//	<suite>.<fingerprint hex>.<ephemeral point, 65 bytes hex>.<nonce || ciphertext || tag, hex>
//
// The fingerprint is the SHA-256 of the DER SubjectPublicKeyInfo of the master public key. The suite names the hash of HKDF and the AEAD, so that either can be replaced if it is
// ever broken, and every suite is always read:
//
//	ecies2  HKDF-SHA-256, AES-256-GCM            the default; every algorithm is approved in a FIPS 140-3 module
//	ecies3  HKDF-SHA-512, AES-256-GCM            another hash
//	ecies4  HKDF-SHA-256, XChaCha20-Poly1305     another cipher (not approved in a FIPS 140-3 module: refused while that mode is on)
//
// What is written is chosen by the configuration (seal_suite); what is read is whatever the text says. The earlier format `ecies1` (XChaCha20-Poly1305 with the key derivation of
// the first implementation) is no longer written or read: its last user, CiNim, moved to ecies2.
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"sort"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// FormatTag is the tag of the default suite.
	FormatTag = "ecies2"
	// DefaultSuite is what is written when the configuration says nothing.
	DefaultSuite = FormatTag
	pointLen     = 65
	tagLen       = 16
)

type suite struct {
	hash     func() hash.Hash
	aead     func(key []byte) (cipher.AEAD, error)
	nonce    int
	approved bool // every algorithm of the suite is approved in a FIPS 140-3 module
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

var suites = map[string]suite{
	"ecies2": {hash: sha256.New, aead: gcm, nonce: 12, approved: true},
	"ecies3": {hash: sha512.New, aead: gcm, nonce: 12, approved: true},
	"ecies4": {hash: sha256.New, aead: func(k []byte) (cipher.AEAD, error) { return chacha20poly1305.NewX(k) }, nonce: chacha20poly1305.NonceSizeX, approved: false},
}

// Suites lists the tags of the suites, in order.
func Suites() []string {
	out := make([]string, 0, len(suites))
	for t := range suites {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// Approved says whether every algorithm of the suite is approved in a FIPS 140-3 module.
func Approved(tag string) bool { return suites[tag].approved }

// Valid says whether text begins with the tag of a suite and a dot: a face uses it to tell a sealed text from garbage before it asks anything more.
func Valid(text string) bool {
	tag, _, ok := strings.Cut(text, ".")
	_, known := suites[tag]
	return ok && known
}

// ErrSuiteRefused says that the text is in a suite that is not approved and the process runs in FIPS 140-3 mode. It is a kind of damaged text for the callers (the text cannot be opened here).
var ErrSuiteRefused = fmt.Errorf("%w: the suite uses an algorithm that is not approved in the FIPS 140-3 mode of this process", ErrDamaged)

// ErrSuiteNotApproved says that a text is asked for in a suite that is not approved while the process runs in FIPS 140-3 mode. It is a fault of the configuration (the server refuses to start
// with such a seal_suite), not of the request.
var ErrSuiteNotApproved = errors.New("the suite uses an algorithm that is not approved in the FIPS 140-3 mode of this process")

var spkiPrefix = []byte{0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00}

// Errors; Unwrap's callers map them to the API codes.
var (
	ErrWrongKey = errors.New("wrapped for another key")        // final
	ErrDamaged  = errors.New("damaged, or not for this place") // final
)

// Deriver is the private half of the master key: ECDH with a peer point, on the token.
// A failure of the token itself (locked, removed) is returned as is, so the caller can tell it from ErrDamaged.
type Deriver interface {
	Derive(peerPoint []byte) ([]byte, error)
}

// Fingerprint names a master public key (65 bytes, uncompressed).
func Fingerprint(masterPoint []byte) string {
	sum := sha256.Sum256(append(append([]byte{}, spkiPrefix...), masterPoint...))
	return hex.EncodeToString(sum[:])
}

func deriveKey(st suite, tag string, secret []byte, fp string, ephPoint []byte) ([]byte, error) {
	return hkdf.Key(st.hash, secret, []byte("hsmgate/"+tag), fp+"|"+hex.EncodeToString(ephPoint), 32)
}

// Wrap seals plain under the master public key in the default suite; no token is needed.
func Wrap(masterPoint, plain, aad []byte) (string, error) {
	return WrapSuite(DefaultSuite, masterPoint, plain, aad)
}

// WrapSuite seals in the named suite ("" is the default); no token is needed. A suite that is not approved is refused in FIPS 140-3 mode.
func WrapSuite(tag string, masterPoint, plain, aad []byte) (string, error) {
	if tag == "" {
		tag = DefaultSuite
	}
	st, ok := suites[tag]
	if !ok {
		return "", fmt.Errorf("unknown suite %q", tag)
	}
	if !st.approved && fips140.Enabled() {
		return "", ErrSuiteNotApproved
	}
	pub, err := ecdh.P256().NewPublicKey(masterPoint)
	if err != nil {
		return "", err
	}
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	z, err := eph.ECDH(pub)
	if err != nil {
		return "", err
	}
	fp := Fingerprint(masterPoint)
	ephPoint := eph.PublicKey().Bytes()
	k, err := deriveKey(st, tag, z, fp, ephPoint)
	if err != nil {
		return "", err
	}
	a, err := st.aead(k)
	if err != nil {
		return "", err
	}
	// a key is made for this one text (a fresh ephemeral key), so a random nonce cannot repeat under it
	nonce := make([]byte, st.nonce)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	body := a.Seal(nonce, nonce, plain, aad)
	return tag + "." + fp + "." + hex.EncodeToString(ephPoint) + "." + hex.EncodeToString(body), nil
}

// Unwrap opens a wrapped text of any suite. The point is checked to be on the curve before the token is asked.
func Unwrap(masterPoint []byte, d Deriver, wrapped string, aad []byte) ([]byte, error) {
	parts := strings.Split(wrapped, ".")
	if len(parts) != 4 {
		return nil, ErrDamaged
	}
	tag := parts[0]
	st, ok := suites[tag]
	if !ok {
		return nil, ErrDamaged
	}
	if !st.approved && fips140.Enabled() {
		return nil, ErrSuiteRefused
	}
	fp := Fingerprint(masterPoint)
	if parts[1] != fp {
		return nil, ErrWrongKey
	}
	eph, err := hex.DecodeString(parts[2])
	if err != nil || len(eph) != pointLen {
		return nil, ErrDamaged
	}
	if _, err := ecdh.P256().NewPublicKey(eph); err != nil { // not on the curve
		return nil, ErrDamaged
	}
	body, err := hex.DecodeString(parts[3])
	if err != nil || len(body) < st.nonce+tagLen {
		return nil, ErrDamaged
	}
	z, err := d.Derive(eph)
	if err != nil {
		return nil, err
	}
	k, err := deriveKey(st, tag, z, fp, eph)
	if err != nil {
		return nil, err
	}
	a, err := st.aead(k)
	if err != nil {
		return nil, err
	}
	plain, err := a.Open(nil, body[:st.nonce], body[st.nonce:], aad)
	if err != nil {
		return nil, ErrDamaged
	}
	return plain, nil
}

// SoftKey is a Deriver on a software P-256 key: for tests and the `soft` backend.
type SoftKey struct{ Key *ecdh.PrivateKey }

func (s SoftKey) Derive(peer []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, ErrDamaged
	}
	return s.Key.ECDH(pub)
}
