// Package keyops is what the faces share about a key version: which holder answers, the pinned fingerprint, and the ECDH on the token.
// A version has one or more holders (a spare card); the next is tried only when the previous could not answer, never when it refused.
package keyops

import (
	"fmt"
	"strings"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

// Pinned: a version with a fingerprint is served only by holders of that key. A card that was swapped for another one is "unavailable", not trusted.
func Pinned(v config.Version, point []byte) error {
	if v.Fingerprint != "" && !strings.EqualFold(v.Fingerprint, ecies.Fingerprint(point)) {
		return fmt.Errorf("%w: the holder's key is not the pinned one", backend.ErrUnavailable)
	}
	return nil
}

// PointOf is the public key of a version (65 bytes), from the first holder that answers.
func PointOf(tokens map[string]backend.Token, v config.Version) ([]byte, error) {
	var last error
	for _, h := range v.Holders() {
		pt, err := tokens[h.Token].Point(h.Label)
		if err == nil {
			if err = Pinned(v, pt); err == nil {
				return pt, nil
			}
		}
		last = err
	}
	return nil, last
}

// Derive is the ECDH of the private key of a version with a peer point (65 bytes): the 32 bytes of the shared secret.
func Derive(tokens map[string]backend.Token, v config.Version, peer []byte) ([]byte, error) {
	var last error
	for _, h := range v.Holders() {
		tok := tokens[h.Token]
		pt, err := tok.Point(h.Label)
		if err == nil {
			err = Pinned(v, pt)
		}
		if err == nil {
			var z []byte
			if z, err = tok.Derive(h.Label, peer); err == nil {
				return z, nil
			}
		}
		if !isUnavailable(err) {
			return nil, err
		}
		last = err
	}
	return nil, last
}

// Open opens an ecies1 text sealed to a version: the holders in order, the next only when this one could not answer (locked, removed), never when it said the text is bad.
func Open(tokens map[string]backend.Token, v config.Version, text string, aad []byte) ([]byte, error) {
	var last error
	for _, h := range v.Holders() {
		tok := tokens[h.Token]
		point, err := tok.Point(h.Label)
		if err == nil {
			err = Pinned(v, point)
		}
		if err == nil {
			var plain []byte
			if plain, err = ecies.Unwrap(point, deriver{tok, h.Label}, text, aad); err == nil {
				return plain, nil
			}
		}
		if !isUnavailable(err) {
			return nil, err
		}
		last = err
	}
	return nil, last
}

type deriver struct {
	t     backend.Token
	label string
}

func (d deriver) Derive(peer []byte) ([]byte, error) { return d.t.Derive(d.label, peer) }

func isUnavailable(err error) bool { return err != nil && errorsIs(err, backend.ErrUnavailable) }
