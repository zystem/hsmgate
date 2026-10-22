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

func load(t *testing.T) (vectors, SoftKey, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/vectors/ecies1.json")
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

func TestNimVectorsOpen(t *testing.T) {
	v, key, pub := load(t)
	for _, c := range v.Valid {
		plain, err := Unwrap(pub, key, c.Wrapped, []byte(c.AAD))
		if err != nil || hex.EncodeToString(plain) != c.PlainHex {
			t.Errorf("%s: %x, %v", c.Name, plain, err)
		}
	}
}

func TestNimInvalidVectors(t *testing.T) {
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
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Wrap(pub, []byte("data key"), []byte("ctx"))
	if a == b {
		t.Error("two wraps gave the same text")
	}
	p, err := Unwrap(pub, key, a, []byte("ctx"))
	if err != nil || string(p) != "data key" {
		t.Errorf("%q %v", p, err)
	}
}

func TestTamperAndOffCurve(t *testing.T) {
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
}

// Fuzzing: whatever text arrives, Unwrap neither panics nor opens it, except the genuine ones.
func FuzzUnwrap(f *testing.F) {
	raw, _ := os.ReadFile("../../../testdata/vectors/ecies1.json")
	var v vectors
	json.Unmarshal(raw, &v)
	for _, c := range v.Valid {
		f.Add(c.Wrapped, []byte(c.AAD))
	}
	f.Add("ecies1.x.y.z", []byte("a"))
	privB, _ := hex.DecodeString(v.Master.PrivateHex)
	priv, _ := ecdh.P256().NewPrivateKey(privB)
	pub := priv.PublicKey().Bytes()
	f.Fuzz(func(t *testing.T, wrapped string, aad []byte) {
		plain, err := Unwrap(pub, SoftKey{priv}, wrapped, aad)
		if err == nil {
			// the only texts that open are ones sealed to this key with this aad: seal the result again and check it is consistent
			again, err := Wrap(pub, plain, aad)
			if err != nil {
				t.Fatal(err)
			}
			back, err := Unwrap(pub, SoftKey{priv}, again, aad)
			if err != nil || !bytes.Equal(back, plain) {
				t.Fatalf("inconsistent: %v", err)
			}
		}
	})
}

func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte("k"), []byte("aad"))
	f.Fuzz(func(t *testing.T, plain, aad []byte) {
		_, key, pub := load(t)
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

func TestV2RoundTripAndWhatItBinds(t *testing.T) {
	_, key, pub := load(t)
	Configure(true, false)
	defer Configure(false, false)
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
	// another place, a changed byte, a text made into the older format by relabelling
	if _, err := Unwrap(pub, key, a, []byte("other")); err != ErrDamaged {
		t.Errorf("another context: %v", err)
	}
	parts := strings.Split(a, ".")
	bad := []byte(parts[3])
	bad[10] ^= 1
	parts[3] = string(bad)
	if _, err := Unwrap(pub, key, strings.Join(parts, "."), []byte("ctx")); err == nil {
		t.Error("a changed byte opened")
	}
	parts[0], parts[3] = "ecies1", strings.Split(a, ".")[3]
	if _, err := Unwrap(pub, key, strings.Join(parts, "."), []byte("ctx")); err == nil {
		t.Error("a relabelled text opened")
	}
	// both formats open while the older one is allowed; only the newer when it is not
	Configure(false, false)
	old, _ := Wrap(pub, []byte("x"), nil)
	if !strings.HasPrefix(old, "ecies1.") {
		t.Fatal("the default is not ecies1")
	}
	if _, err := Unwrap(pub, key, a, []byte("ctx")); err != nil {
		t.Errorf("ecies2 under the default: %v", err)
	}
	Configure(true, true)
	if _, err := Unwrap(pub, key, old, nil); err != ErrLegacyRefused {
		t.Errorf("ecies1 when refused: %v", err)
	}
	if _, err := Unwrap(pub, key, a, []byte("ctx")); err != nil {
		t.Errorf("ecies2 when ecies1 is refused: %v", err)
	}
}
