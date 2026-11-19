package card

import (
	"crypto/elliptic"
	"crypto/sha1" // #nosec G505 -- the key identifier of PKCS#15 is the SHA-1 of the public key: a name, not a protection
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Generating a key on the card. The command is `00 46 key 00` with a specification of the key in the form of a certificate request that the card completes: it answers with the
// request, signed by the key and by the device (the "authenticated request"), whose public key is the one of the new key. The page then writes the description of the key (the file
// C4nn: label, identifier, usage), as the card manager of the vendor does.

// the algorithms that a key may be used for, as the card numbers them (the byte list of the specification); the names are those the page shows
const (
	AlgECDSARaw    = 0x70
	AlgECDSASHA1   = 0x71
	AlgECDSASHA224 = 0x72
	AlgECDSASHA256 = 0x73
	AlgECDSASHA384 = 0x74
	AlgECDSASHA512 = 0x75
	AlgECDH        = 0x80
	AlgWrap        = 0x92
	AlgDerive      = 0x98
)

// GenSpec says what key to make.
type GenSpec struct {
	Kind       string // "EC" (P-256) or "RSA"
	Bits       int    // for RSA: 2048, 3072 or 4096; for EC: 256
	Label      string
	Algorithms []byte // what the key may be used for; empty: the card's default
	Domain     int    // the key domain the key belongs to; -1: not said (the card chooses)
}

var (
	oidECDSASHA256  = []byte{0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x02, 0x03} // id-TA-ECDSA-SHA-256
	oidRSAv15SHA256 = []byte{0x06, 0x0A, 0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x02, 0x01, 0x02} // id-TA-RSA-v1-5-SHA-256
	dummyRef        = []byte("UTDUMMY00001")                                                         // the reference the card manager gives a key that has no certificate yet
)

func (g GenSpec) validate() error {
	if len(g.Label) == 0 || len(g.Label) > 60 {
		return errors.New("a key needs a label of 1 to 60 characters")
	}
	switch g.Kind {
	case "EC":
		if g.Bits != 256 {
			return errors.New("only EC P-256 is made here")
		}
	case "RSA":
		if g.Bits != 2048 && g.Bits != 3072 && g.Bits != 4096 {
			return errors.New("RSA keys of 2048, 3072 or 4096 bits only")
		}
	default:
		return errors.New("a key is EC or RSA")
	}
	return nil
}

// ecKeySpec is the 7F49 object of an EC key: the algorithm and the domain parameters of P-256.
func ecKeySpec() []byte {
	c := elliptic.P256().Params()
	be := func(n *big.Int) []byte { return n.FillBytes(make([]byte, 32)) }
	a := new(big.Int).Sub(c.P, big.NewInt(3)) // y² = x³ − 3x + b
	g := append([]byte{0x04}, append(be(c.Gx), be(c.Gy)...)...)
	var body []byte
	body = append(body, oidECDSASHA256...)
	body = append(body, der(0x81, be(c.P))...)
	body = append(body, der(0x82, be(a))...)
	body = append(body, der(0x83, be(c.B))...)
	body = append(body, der(0x84, g)...)
	body = append(body, der(0x85, be(c.N))...)
	body = append(body, der(0x87, []byte{0x01})...)
	return derTag2(0x7F49, body)
}

func rsaKeySpec(bits int) []byte {
	var body []byte
	body = append(body, oidRSAv15SHA256...)
	body = append(body, der(0x82, []byte{0x01, 0x00, 0x01})...)
	body = append(body, der(0x02, []byte{byte(bits >> 8), byte(bits)})...) // #nosec G115 -- 2048 to 4096 fits two bytes
	return derTag2(0x7F49, body)
}

// derTag2 writes an element with a tag of two bytes.
func derTag2(tag int, v []byte) []byte {
	e := der(byte(tag&0xFF), v) // #nosec G115 -- the low byte of the tag
	return append([]byte{byte(tag >> 8)}, e...)
}

// encode is the body of the generation command.
func (g GenSpec) encode() []byte {
	var b []byte
	b = append(b, 0x5F, 0x29, 0x01, 0x00) // certificate profile identifier
	b = append(b, der(0x42, dummyRef)...) // authority reference
	if g.Kind == "EC" {
		b = append(b, ecKeySpec()...)
	} else {
		b = append(b, rsaKeySpec(g.Bits)...)
	}
	b = append(b, 0x5F, 0x20, byte(len(dummyRef))) // #nosec G115 -- 12
	b = append(b, dummyRef...)                     // holder reference
	if len(g.Algorithms) > 0 {
		b = append(b, der(0x91, g.Algorithms)...)
	}
	if g.Domain >= 0 {
		b = append(b, der(0x92, []byte{byte(g.Domain)})...) // #nosec G115 -- a key domain number
	}
	return b
}

// GenerateKey makes a key under the lowest free number and writes its description. Needs the User PIN. It returns the number, the authenticated request the card made, and the
// identifier of the key (the SHA-1 of its public key, which PKCS#11 shows as CKA_ID).
func (s *Session) GenerateKey(g GenSpec) (id byte, request, keyID []byte, err error) {
	if err = g.validate(); err != nil {
		return
	}
	if id, err = s.FreeKeyID(); err != nil {
		return
	}
	request, err = s.do(fmt.Sprintf("generating the key %d (a %s key of %d bits: an RSA key takes up to a minute; the User PIN must be given)", id, g.Kind, g.Bits), 0x00, 0x46, id, 0x00, g.encode(), true)
	if err != nil {
		return 0, nil, nil, err
	}
	keyID, err = requestKeyID(request)
	if err != nil {
		return id, request, nil, fmt.Errorf("the key %d is made but its public key could not be read from the request: %w", id, err)
	}
	if err = s.WriteFile(0xC400|uint16(id), prkdFor(g, keyID)); err != nil {
		return id, request, keyID, fmt.Errorf("the key %d is made but its description was not written: %w", id, err)
	}
	return id, request, keyID, nil
}

// requestKeyID makes the identifier of a key from the request that the card answered: the SHA-1 of the public point (EC) or of the RSAPublicKey (RSA).
func requestKeyID(req []byte) ([]byte, error) {
	pk := find(req, 0x7F49)
	if pk == nil {
		return nil, errors.New("no public key in the answer of the card")
	}
	if pt := find(pk, 0x86); pt != nil {
		h := sha1.Sum(pt) // #nosec G401 -- an identifier
		return h[:], nil
	}
	n, e := find(pk, 0x81), find(pk, 0x82)
	if n == nil || e == nil {
		return nil, errors.New("neither a point nor a modulus in the public key")
	}
	if n[0] >= 0x80 {
		n = append([]byte{0}, n...)
	}
	rsaPub := der(0x30, append(der(0x02, n), der(0x02, e)...))
	h := sha1.Sum(rsaPub) // #nosec G401
	return h[:], nil
}

// prkdFor is the description of a private key as the card manager writes it: the label, the identifier and usage, and the size.
func prkdFor(g GenSpec, keyID []byte) []byte {
	label := der(0x30, der(0x0C, []byte(g.Label)))
	usage := []byte{0x03, 0x03, 0x07, 0x20, 0x80} // EC: sign, derive
	tag := byte(0xA0)
	if g.Kind == "RSA" {
		usage, tag = []byte{0x03, 0x02, 0x02, 0x74}, 0x30
	}
	common := der(0x30, append(der(0x04, keyID), usage...))
	size := der(0x02, []byte{byte(g.Bits >> 8), byte(g.Bits)}) // #nosec G115 -- 256 to 4096
	typ := der(0xA1, der(0x30, append(der(0x30, der(0x04, nil)), size...)))
	return der(tag, append(append(label, common...), typ...))
}

// AlgorithmByName turns names such as "sign" or "wrap" into the bytes of the specification.
func AlgorithmByName(kind string, names ...string) []byte {
	var out []byte
	for _, n := range names {
		switch strings.ToLower(n) {
		case "sign":
			if kind == "EC" {
				out = append(out, AlgECDSARaw, AlgECDSASHA1, AlgECDSASHA224, AlgECDSASHA256, AlgECDSASHA384, AlgECDSASHA512)
			} else {
				out = append(out, 0x20, 0x31, 0x33, 0x35, 0x40, 0x41, 0x43, 0x45)
			}
		case "derive", "ecdh":
			out = append(out, AlgECDH)
		case "decrypt":
			out = append(out, 0x21, 0x22, 0x23)
		case "wrap":
			out = append(out, AlgWrap)
		}
	}
	return out
}
