// Package backend is the token's side: public keys and ECDH. The PIN, the module and the sessions live here (P3); this file is the seam.
package backend

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	// ErrUnavailable: the token could not answer now (locked, removed, busy); asking later may work.
	ErrUnavailable = errors.New("token unavailable")
	ErrLocked      = fmt.Errorf("%w: locked", ErrUnavailable)
)

type Token interface {
	// Point is the public key (65 bytes) of the key with this label. It needs no login.
	Point(label string) ([]byte, error)
	// Derive is ECDH with a peer point on the token.
	Derive(label string, peer []byte) ([]byte, error)
	// Sign is ECDSA (P-256) over a digest of 32 bytes: the signature as ASN.1 DER. A key is used for signing or for ECDH, never both (config.Validate).
	Sign(label string, digest []byte) ([]byte, error)
	// State is "ready", "locked" or "absent"; it never touches the card.
	State() string
}

type Soft struct {
	keys map[string]*ecdh.PrivateKey
	sig  map[string]*ecdsa.PrivateKey
}

// decodeKey turns the hex text of a key file into the bytes of the key and clears the text. It makes no Go string of it: a string cannot be cleared.
func decodeKey(text []byte) ([]byte, error) {
	defer clear(text)
	h := bytes.TrimSpace(text)
	b := make([]byte, hex.DecodedLen(len(h)))
	if _, err := hex.Decode(b, h); err != nil {
		clear(b)
		return nil, err
	}
	return b, nil
}

// NewSoft reads keys of 64 hex digits from files.
func NewSoft(files map[string]string) (*Soft, error) {
	s := &Soft{keys: map[string]*ecdh.PrivateKey{}, sig: map[string]*ecdsa.PrivateKey{}}
	for label, path := range files {
		raw, err := ReadSecretFile(path, 4096)
		if err != nil {
			return nil, err
		}
		b, err := decodeKey(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		defer clear(b) // the key objects below keep their own copies
		k, err := ecdh.P256().NewPrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.keys[label] = k
		sk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.sig[label] = sk
	}
	return s, nil
}

func (s *Soft) Point(label string) ([]byte, error) {
	k, ok := s.keys[label]
	if !ok {
		return nil, fmt.Errorf("no key %q", label)
	}
	return k.PublicKey().Bytes(), nil
}

func (s *Soft) Derive(label string, peer []byte) ([]byte, error) {
	k, ok := s.keys[label]
	if !ok {
		return nil, fmt.Errorf("no key %q", label)
	}
	pub, err := ecdh.P256().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return k.ECDH(pub)
}

func (s *Soft) Sign(label string, digest []byte) ([]byte, error) {
	k, ok := s.sig[label]
	if !ok {
		return nil, fmt.Errorf("no key %q", label)
	}
	if len(digest) != 32 {
		return nil, errors.New("the digest must be 32 bytes")
	}
	return ecdsa.SignASN1(rand.Reader, k, digest)
}

func (s *Soft) State() string { return "ready" }

func (s *Soft) Identity() any { return s }
