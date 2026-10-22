// Package ecies is the `ecies1` sealed format of the CiNim key service (kekd), carried over to Go:
// ECDH-ES on P-256, HKDF-SHA256, XChaCha20-Poly1305. The text is
//
//	ecies1.<fingerprint hex>.<ephemeral point, 65 bytes hex>.<nonce(24) || ciphertext || tag(16), hex>
//
// The fingerprint is the SHA-256 of the DER SubjectPublicKeyInfo of the master public key.
// The format is read for ever; testdata/vectors/ecies1.json was made by the Nim implementation.
//
// ecies2 is the same with algorithms that are all approved for use in a FIPS 140-3 module (ECDH P-256, HKDF-SHA256, AES-256-GCM); see docs/specs/ecies1.md. Sealing writes ecies1
// unless Configure says otherwise; opening reads both unless Configure refuses the older one.
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FormatTag  = "ecies1"
	FormatTag2 = "ecies2"
	kdfLabel   = "cinim/kek/v1"
	kdfSalt2   = "hsmgate/ecies2"
	pointLen   = 65
	nonceLen2  = 12
	tagLen2    = 16
)

var (
	sealV2   atomic.Bool
	noLegacy atomic.Bool
)

// Configure sets what the package seals and what it opens: v2 seals ecies2; refuseV1 refuses to open ecies1 (its cipher is not approved in a FIPS 140-3 module). Set it at start, and
// at a reload.
func Configure(v2, refuseV1 bool) {
	sealV2.Store(v2)
	noLegacy.Store(refuseV1)
}

// ErrLegacyRefused: the text is ecies1 and the service is set to open approved algorithms only.
var ErrLegacyRefused = fmt.Errorf("%w: ecies1 is refused, its cipher is not approved in this mode", ErrDamaged)

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

func deriveKey(secret []byte, fp string, ephPoint []byte) []byte {
	m := hmac.New(sha256.New, []byte(kdfLabel))
	m.Write(secret)
	prk := m.Sum(nil)
	m = hmac.New(sha256.New, prk)
	m.Write([]byte(kdfLabel + "|" + fp + "|" + hex.EncodeToString(ephPoint)))
	m.Write([]byte{1})
	return m.Sum(nil)
}

func deriveKey2(secret []byte, fp string, ephPoint []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, []byte(kdfSalt2), fp+"|"+hex.EncodeToString(ephPoint), 32)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Wrap seals plain under the master public key; no token is needed.
func Wrap(masterPoint, plain, aad []byte) (string, error) {
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
	if sealV2.Load() {
		k, err := deriveKey2(z, fp, ephPoint)
		if err != nil {
			return "", err
		}
		a, err := gcm(k)
		if err != nil {
			return "", err
		}
		// a key is made for this one text (a fresh ephemeral key), so a random nonce cannot repeat under it
		nonce := make([]byte, nonceLen2)
		if _, err := rand.Read(nonce); err != nil {
			return "", err
		}
		body := a.Seal(nonce, nonce, plain, aad)
		return FormatTag2 + "." + fp + "." + hex.EncodeToString(ephPoint) + "." + hex.EncodeToString(body), nil
	}
	aead, err := chacha20poly1305.NewX(deriveKey(z, fp, ephPoint))
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	body := aead.Seal(nonce, nonce, plain, aad)
	return FormatTag + "." + fp + "." + hex.EncodeToString(ephPoint) + "." + hex.EncodeToString(body), nil
}

// Unwrap opens a wrapped text. The point is checked to be on the curve before the token is asked.
func Unwrap(masterPoint []byte, d Deriver, wrapped string, aad []byte) ([]byte, error) {
	parts := strings.Split(wrapped, ".")
	if len(parts) != 4 || (parts[0] != FormatTag && parts[0] != FormatTag2) {
		return nil, ErrDamaged
	}
	v2 := parts[0] == FormatTag2
	if !v2 && noLegacy.Load() {
		return nil, ErrLegacyRefused
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
	min := chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if v2 {
		min = nonceLen2 + tagLen2
	}
	if err != nil || len(body) < min {
		return nil, ErrDamaged
	}
	z, err := d.Derive(eph)
	if err != nil {
		return nil, err
	}
	if v2 {
		k, err := deriveKey2(z, fp, eph)
		if err != nil {
			return nil, err
		}
		a, err := gcm(k)
		if err != nil {
			return nil, err
		}
		plain, err := a.Open(nil, body[:nonceLen2], body[nonceLen2:], aad)
		if err != nil {
			return nil, ErrDamaged
		}
		return plain, nil
	}
	aead, err := chacha20poly1305.NewX(deriveKey(z, fp, eph))
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, body[:aead.NonceSize()], body[aead.NonceSize():], aad)
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
