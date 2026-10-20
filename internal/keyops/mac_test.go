package keyops

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

// The point P is part of the format of every MAC ever made: its value is pinned. It is on the curve, its y is even, and it is not the generator (whose discrete logarithm is known).
func TestMacPointIsPinned(t *testing.T) {
	const want = "04e47aa3b3cca6ed6e2441921fb7fb84b8766bbfe353a28c0e7b84b656d310daa73ceee4772792e7bfb4607b3d6b52bb26413f83613cc2429b69d8f535aeb08e22"
	p := MacPoint()
	if got := hex.EncodeToString(p); got != want {
		t.Fatalf("the point changed: %s", got)
	}
	if _, err := ecdh.P256().NewPublicKey(p); err != nil {
		t.Fatalf("not a point of the curve: %v", err)
	}
	if p[64]&1 != 0 {
		t.Error("y is not even")
	}
	g := elliptic.P256().Params()
	if hex.EncodeToString(p[1:33]) == hex.EncodeToString(g.Gx.Bytes()) {
		t.Error("the point is the generator")
	}
}
