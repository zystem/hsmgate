// Package ecies is the sealed format `ecies2`: ECDH-ES on P-256, HKDF-SHA256, AES-256-GCM, all approved algorithms of a FIPS 140-3 module. The text is
//
//	ecies2.<fingerprint hex>.<ephemeral point, 65 bytes hex>.<nonce(12) || ciphertext || tag(16), hex>
//
// The fingerprint is the SHA-256 of the DER SubjectPublicKeyInfo of the master public key. The earlier format (`ecies1`, XChaCha20-Poly1305) is no longer written or read: its last
// user, CiNim, moved to this one.
package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	FormatTag = "ecies2"
	kdfSalt   = "hsmgate/ecies2"
	pointLen  = 65
	nonceLen  = 12
	tagLen    = 16
)

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

func deriveKey(secret []byte, fp string, ephPoint []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, []byte(kdfSalt), fp+"|"+hex.EncodeToString(ephPoint), 32)
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
	k, err := deriveKey(z, fp, ephPoint)
	if err != nil {
		return "", err
	}
	a, err := gcm(k)
	if err != nil {
		return "", err
	}
	// a key is made for this one text (a fresh ephemeral key), so a random nonce cannot repeat under it
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	body := a.Seal(nonce, nonce, plain, aad)
	return FormatTag + "." + fp + "." + hex.EncodeToString(ephPoint) + "." + hex.EncodeToString(body), nil
}

// Unwrap opens a wrapped text. The point is checked to be on the curve before the token is asked.
func Unwrap(masterPoint []byte, d Deriver, wrapped string, aad []byte) ([]byte, error) {
	parts := strings.Split(wrapped, ".")
	if len(parts) != 4 || parts[0] != FormatTag {
		return nil, ErrDamaged
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
	if err != nil || len(body) < nonceLen+tagLen {
		return nil, ErrDamaged
	}
	z, err := d.Derive(eph)
	if err != nil {
		return nil, err
	}
	k, err := deriveKey(z, fp, eph)
	if err != nil {
		return nil, err
	}
	a, err := gcm(k)
	if err != nil {
		return nil, err
	}
	plain, err := a.Open(nil, body[:nonceLen], body[nonceLen:], aad)
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
