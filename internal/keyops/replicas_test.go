package keyops

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

// locked answers the public key and nothing else, as a card that is present and not unlocked does.
type locked struct{ backend.Token }

func (locked) Derive(string, []byte) ([]byte, error) { return nil, backend.ErrLocked }
func (locked) Sign(string, []byte) ([]byte, error)   { return nil, backend.ErrLocked }

func tokens(t *testing.T) (map[string]backend.Token, config.Version) {
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	os.WriteFile(p, []byte(strings.Repeat("07", 32)), 0o600)
	a, err := backend.NewSoft(map[string]string{"m": p})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := backend.NewSoft(map[string]string{"m": p}) // the spare card: the same key
	toks := map[string]backend.Token{"primary": locked{a}, "spare": b}
	return toks, config.Version{Token: "primary", Label: "m", Replicas: []config.Replica{{Token: "spare", Label: "m"}}}
}

// The operations that the KMS-JSON face adds (sign, MAC key, open) ask the next holder only when the first one could not answer.
func TestTheSpareAnswersWhenThePrimaryIsLocked(t *testing.T) {
	toks, v := tokens(t)
	digest := sha256.Sum256([]byte("m"))
	if sig, err := Sign(toks, v, digest[:]); err != nil || len(sig) < 8 {
		t.Errorf("Sign: %v", err)
	}
	k1, err := MacKey(toks, v)
	if err != nil || len(k1) != 32 {
		t.Fatalf("MacKey: %v", err)
	}
	// the spare gives the key that the primary would: the same on every holder of the key
	only := map[string]backend.Token{"primary": toks["spare"]}
	k2, err := MacKey(only, config.Version{Token: "primary", Label: "m"})
	if err != nil || !bytes.Equal(k1, k2) {
		t.Errorf("the MAC key of a holder differs from that of its spare: %v", err)
	}
	pt, _ := PointOf(toks, v)
	text, _ := ecies.Wrap(pt, []byte("data"), []byte("aad"))
	if plain, err := Open(toks, v, text, []byte("aad")); err != nil || string(plain) != "data" {
		t.Errorf("Open: %v", err)
	}
}

// A refusal is final: a damaged text is not tried on the next holder, and a spare with another key is never used.
func TestARefusalIsNotRetriedAndAWrongSpareIsNotUsed(t *testing.T) {
	toks, v := tokens(t)
	pt, _ := PointOf(toks, v)
	text, _ := ecies.Wrap(pt, []byte("data"), []byte("aad"))
	if _, err := Open(toks, v, text, []byte("other aad")); !errors.Is(err, ecies.ErrDamaged) {
		t.Errorf("a wrong context: %v", err)
	}
	// a spare that holds another key: the version is pinned to the primary's fingerprint
	dir := t.TempDir()
	p := filepath.Join(dir, "k")
	os.WriteFile(p, []byte(strings.Repeat("09", 32)), 0o600)
	other, _ := backend.NewSoft(map[string]string{"m": p})
	toks["spare"] = other
	v.Fingerprint = ecies.Fingerprint(pt)
	digest := sha256.Sum256([]byte("m"))
	if _, err := Sign(toks, v, digest[:]); !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("a spare with another key signed: %v", err)
	}
	if _, err := MacKey(toks, v); !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("a spare with another key gave a MAC key: %v", err)
	}
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	if _, err := Derive(toks, v, peer.PublicKey().Bytes()); !errors.Is(err, backend.ErrUnavailable) {
		t.Errorf("a spare with another key derived: %v", err)
	}
}
