// Package ecies is the `ecies1` sealed format of the CiNim key service (kekd), carried over to Go:
// ECDH-ES on P-256, HKDF-SHA256, XChaCha20-Poly1305. The text is
//
//	ecies1.<fingerprint hex>.<ephemeral point, 65 bytes hex>.<nonce(24) || ciphertext || tag(16), hex>
//
// The fingerprint is the SHA-256 of the DER SubjectPublicKeyInfo of the master public key.
// The format is read for ever; testdata/vectors/ecies1.json was made by the Nim implementation.
package ecies

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FormatTag = "ecies1"
	kdfLabel  = "cinim/kek/v1"
	pointLen  = 65
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

func deriveKey(secret []byte, fp string, ephPoint []byte) []byte {
	m := hmac.New(sha256.New, []byte(kdfLabel))
	m.Write(secret)
	prk := m.Sum(nil)
	m = hmac.New(sha256.New, prk)
	m.Write([]byte(kdfLabel + "|" + fp + "|" + hex.EncodeToString(ephPoint)))
	m.Write([]byte{1})
	return m.Sum(nil)
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
	if err != nil || len(body) < chacha20poly1305.NonceSizeX+chacha20poly1305.Overhead {
		return nil, ErrDamaged
	}
	z, err := d.Derive(eph)
	if err != nil {
		return nil, err
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
