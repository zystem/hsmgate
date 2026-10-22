package ecies

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type vectors struct {
	Master struct {
		PrivateHex  string `json:"private_hex"`
		PublicHex   string `json:"public_hex"`
		Fingerprint string `json:"fingerprint"`
	} `json:"master"`
	Valid []struct {
		Name     string `json:"name"`
		PlainHex string `json:"plain_hex"`
		AAD      string `json:"aad"`
		Wrapped  string `json:"wrapped"`
	} `json:"valid"`
	Invalid []struct {
		Name    string `json:"name"`
		Wrapped string `json:"wrapped"`
		AAD     string `json:"aad"`
		Error   string `json:"error"`
	} `json:"invalid"`
}

const vectorFile = "../../../testdata/vectors/ecies2.json"

func load(t testing.TB) (vectors, SoftKey, []byte) {
	t.Helper()
	raw, err := os.ReadFile(vectorFile)
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	privB, _ := hex.DecodeString(v.Master.PrivateHex)
	priv, err := ecdh.P256().NewPrivateKey(privB)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(v.Master.PublicHex)
	if !bytes.Equal(priv.PublicKey().Bytes(), pub) {
		t.Fatal("vector key pair does not match")
	}
	return v, SoftKey{priv}, pub
}

func TestFingerprintMatchesVector(t *testing.T) {
	v, _, pub := load(t)
	if got := Fingerprint(pub); got != v.Master.Fingerprint {
		t.Fatalf("fingerprint %s, want %s", got, v.Master.Fingerprint)
	}
}

func TestVectorsOpen(t *testing.T) {
	v, key, pub := load(t)
	for _, c := range v.Valid {
		plain, err := Unwrap(pub, key, c.Wrapped, []byte(c.AAD))
		if err != nil || hex.EncodeToString(plain) != c.PlainHex {
			t.Errorf("%s: %x, %v", c.Name, plain, err)
		}
	}
}

func TestInvalidVectors(t *testing.T) {
	v, key, pub := load(t)
	want := map[string]error{"damaged": ErrDamaged, "wrong_key": ErrWrongKey}
	for _, c := range v.Invalid {
		if _, err := Unwrap(pub, key, c.Wrapped, []byte(c.AAD)); !errors.Is(err, want[c.Error]) {
			t.Errorf("%s: %v, want %s", c.Name, err, c.Error)
		}
	}
}

func TestRoundTripAndFreshEphemeral(t *testing.T) {
	_, key, pub := load(t)
	a, err := Wrap(pub, []byte("data key"), []byte("ctx"))
	if err != nil || !strings.HasPrefix(a, "ecies2.") {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := Wrap(pub, []byte("data key"), []byte("ctx"))
	if a == b {
		t.Error("two wraps gave the same text")
	}
	if p, err := Unwrap(pub, key, a, []byte("ctx")); err != nil || string(p) != "data key" {
		t.Errorf("%q %v", p, err)
	}
	if _, err := Unwrap(pub, key, a, []byte("other")); !errors.Is(err, ErrDamaged) {
		t.Errorf("another context: %v", err)
	}
}

func TestTamperOffCurveAndTag(t *testing.T) {
	_, key, pub := load(t)
	w, _ := Wrap(pub, []byte("k"), nil)
	p := strings.Split(w, ".")
	body := []byte(p[3])
	body[len(body)/2] ^= 1 // flips between hex digits of the same class mostly; any change must fail
	if body[len(body)/2] > 'f' {
		body[len(body)/2] = '0'
	}
	if _, err := Unwrap(pub, key, strings.Join([]string{p[0], p[1], p[2], string(body)}, "."), nil); !errors.Is(err, ErrDamaged) {
		t.Errorf("tamper: %v", err)
	}
	off := "04" + strings.Repeat("11", 64)
	if _, err := Unwrap(pub, key, strings.Join([]string{p[0], p[1], off, p[3]}, "."), nil); !errors.Is(err, ErrDamaged) {
		t.Errorf("off curve: %v", err)
	}
	// the format that this one replaced is not read, even with the same fields
	if _, err := Unwrap(pub, key, strings.Join([]string{"ecies1", p[1], p[2], p[3]}, "."), nil); !errors.Is(err, ErrDamaged) {
		t.Errorf("the earlier format tag: %v", err)
	}
}

// Fuzzing: whatever text arrives, Unwrap neither panics nor opens it, except the genuine ones.
func FuzzUnwrap(f *testing.F) {
	v, key, pub := load(f)
	for _, c := range v.Valid {
		f.Add(c.Wrapped, []byte(c.AAD))
	}
	f.Add("ecies2.x.y.z", []byte("a"))
	f.Fuzz(func(t *testing.T, wrapped string, aad []byte) {
		plain, err := Unwrap(pub, key, wrapped, aad)
		if err == nil {
			// the only texts that open are ones sealed to this key with this aad: seal the result again and check it is consistent
			again, err := Wrap(pub, plain, aad)
			if err != nil {
				t.Fatal(err)
			}
			back, err := Unwrap(pub, key, again, aad)
			if err != nil || !bytes.Equal(back, plain) {
				t.Fatalf("inconsistent: %v", err)
			}
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("k"), []byte("aad"))
	_, key, pub := load(f)
	f.Fuzz(func(t *testing.T, plain, aad []byte) {
		w, err := Wrap(pub, plain, aad)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Unwrap(pub, key, w, aad)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%v", err)
		}
		if len(aad) > 0 {
			if _, err := Unwrap(pub, key, w, append([]byte{}, aad[1:]...)); err == nil {
				t.Fatal("a different aad opened the text")
			}
		}
	})
}
