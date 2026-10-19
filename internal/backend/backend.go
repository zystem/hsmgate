// Package backend is the token's side: public keys and ECDH. The PIN, the module and the sessions live here (P3); this file is the seam.
package backend

import (
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
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
	// State is "ready", "locked" or "absent"; it never touches the card.
	State() string
}

type Soft struct{ keys map[string]*ecdh.PrivateKey }

// NewSoft reads keys of 64 hex digits from files.
func NewSoft(files map[string]string) (*Soft, error) {
	s := &Soft{keys: map[string]*ecdh.PrivateKey{}}
	for label, path := range files {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%s: a key file must not be readable by group or others (mode %o)", path, st.Mode().Perm())
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		k, err := ecdh.P256().NewPrivateKey(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.keys[label] = k
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

func (s *Soft) State() string { return "ready" }
