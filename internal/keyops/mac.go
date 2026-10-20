package keyops

// The MAC key of a key version. A token that has ECDH but no HMAC (a SmartCard-HSM through OpenSC) still holds a MAC key without storing one: the key is derived from the
// ECDH of the private key with a fixed point P, K = HKDF-SHA256(ECDH(priv, P), salt, info = the fingerprint of the public key). P comes from a hash by try-and-increment, so
// nobody knows its discrete logarithm; the shared secret priv*P then cannot be computed without the private key. The same key gives the same MAC key on every start and on
// every replica of it. A private key does this or signs or does other ECDH, not both: the configuration refuses a token key that is shared (config.Validate).

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sync"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

const macLabel = "hsmgate/mac/v1"

var (
	macPointOnce sync.Once
	macPointVal  []byte
)

// MacPoint is the point P (65 bytes, uncompressed): the first x = SHA-256(label || counter) that is on the curve, with an even y.
func MacPoint() []byte {
	macPointOnce.Do(func() {
		c := elliptic.P256().Params()
		three := big.NewInt(3)
		for ctr := uint32(0); ; ctr++ {
			h := sha256.New()
			h.Write([]byte(macLabel + "/point"))
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], ctr)
			h.Write(b[:])
			x := new(big.Int).SetBytes(h.Sum(nil))
			if x.Cmp(c.P) >= 0 {
				continue
			}
			// y^2 = x^3 - 3x + b
			rhs := new(big.Int).Exp(x, three, c.P)
			rhs.Sub(rhs, new(big.Int).Mul(three, x))
			rhs.Add(rhs, c.B)
			rhs.Mod(rhs, c.P)
			y := new(big.Int).ModSqrt(rhs, c.P)
			if y == nil {
				continue
			}
			if y.Bit(0) == 1 {
				y.Sub(c.P, y)
			}
			pt := make([]byte, 65)
			pt[0] = 4
			x.FillBytes(pt[1:33])
			y.FillBytes(pt[33:])
			if _, err := ecdh.P256().NewPublicKey(pt); err != nil { // on the curve, by the library's own check
				continue
			}
			macPointVal = pt
			return
		}
	})
	return macPointVal
}

// MacKey derives the MAC key (32 bytes) of a key version: one ECDH on the token.
func MacKey(tokens map[string]backend.Token, v config.Version) ([]byte, error) {
	point, err := PointOf(tokens, v)
	if err != nil {
		return nil, err
	}
	z, err := Derive(tokens, v, MacPoint())
	if err != nil {
		return nil, err
	}
	defer func() {
		for i := range z {
			z[i] = 0
		}
	}()
	return hkdf.Key(sha256.New, z, []byte(macLabel), "mac|"+ecies.Fingerprint(point), 32)
}
