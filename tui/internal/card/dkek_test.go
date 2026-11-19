package card

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// The key derivation of a share file is the one of OpenSSL's EVP_BytesToKey with MD5 and a count. With the count 1 `openssl enc -aes-256-cbc -md md5 -S 3132333435363738 -P
// -pass pass:pw` prints the answer below, which is an independent check of the three rounds; the count that is used for real (10 000 000) is the same loop, longer.
func TestShareKeyIsEVPBytesToKey(t *testing.T) {
	defer func(c int) { kdfCount = c }(kdfCount)
	kdfCount = 1
	key, iv := shareKey([]byte("pw"), []byte("12345678"))
	if got := strings.ToUpper(hex.EncodeToString(key)); got != "B55A2901D68927617F9C2F962AD9302BD0DC8B99FC2C9678CB2AF0C6246CBDB1" {
		t.Errorf("key %s", got)
	}
	if got := strings.ToUpper(hex.EncodeToString(iv)); got != "FAF51D5B5BA9D900ACF04DE4A73D767A" {
		t.Errorf("iv %s", got)
	}
}

func TestShareFileRoundTripInBothFormats(t *testing.T) {
	defer SetKDFCount(50)()
	for _, format := range []ShareFormat{Strong, Compatible} {
		t.Run(format.String(), func(t *testing.T) {
			share, err := NewShare(nil)
			if err != nil || len(share) != ShareLen {
				t.Fatal(err)
			}
			file, err := EncryptShare(format, share, []byte("a password"), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := FormatOf(file); !ok || got != format {
				t.Fatalf("the format of the file: %v %v", got, ok)
			}
			wantLen, magic := 88, "HGDKEKS1"
			if format == Compatible {
				wantLen, magic = 64, "Salted__"
			}
			if len(file) != wantLen || !bytes.HasPrefix(file, []byte(magic)) {
				t.Fatalf("%d bytes, starts with %q", len(file), file[:8])
			}
			got, err := DecryptShare(file, []byte("a password"))
			if err != nil || !bytes.Equal(got, share) {
				t.Fatalf("%v", err)
			}
			if _, err := DecryptShare(file, []byte("another")); err != ErrWrongPassword {
				t.Errorf("a wrong password: %v", err)
			}
			if _, err := DecryptShare(file[:len(file)-1], []byte("a password")); err == nil {
				t.Error("a short file was opened")
			}
			if _, err := DecryptShare(append([]byte("X"), file[1:]...), []byte("a password")); err == nil {
				t.Error("a file without the mark was opened")
			}
			// two files of the same share differ (the salt), and neither shows the share
			f2, _ := EncryptShare(format, share, []byte("a password"), nil)
			if bytes.Equal(file, f2) || bytes.Contains(file, share) {
				t.Error("the file is not salted or shows the share")
			}
			if _, err := EncryptShare(format, share[:31], []byte("x"), nil); err == nil {
				t.Error("a share of 31 bytes was accepted")
			}
			if _, err := EncryptShare(format, share, nil, nil); err == nil {
				t.Error("no password was accepted")
			}
		})
	}
}

// The strong format authenticates its header: a changed byte anywhere, in the number of iterations, the salt, the nonce, the text or the tag, is refused and nothing is opened.
func TestStrongShareFileRefusesAnyChange(t *testing.T) {
	defer SetKDFCount(50)()
	share, _ := NewShare(nil)
	file, _ := EncryptShare(Strong, share, []byte("pw long enough"), nil)
	for i := 8; i < len(file); i++ { // after the magic, which says what the file is
		if i == 8 || i == 9 {
			continue // the high bytes of the count: a flipped bit asks for millions of iterations (the bound for a count is tested below)
		}
		bad := append([]byte{}, file...)
		bad[i] ^= 1
		if got, err := DecryptShare(bad, []byte("pw long enough")); err == nil {
			t.Fatalf("a file changed at byte %d was opened: %x", i, got)
		}
	}
	// the number of iterations a file may ask for is bounded
	bad := append([]byte{}, file...)
	bad[8], bad[9], bad[10], bad[11] = 0xFF, 0xFF, 0xFF, 0xFF
	if _, err := DecryptShare(bad, []byte("pw long enough")); err == nil || err == ErrWrongPassword {
		t.Errorf("an absurd count: %v", err)
	}
	bad[8], bad[9], bad[10], bad[11] = 0, 0, 0, 0
	if _, err := DecryptShare(bad, []byte("pw long enough")); err == nil || err == ErrWrongPassword {
		t.Errorf("a zero count: %v", err)
	}
}

// A new strong file asks for the count that is used for real: a million iterations of PBKDF2-HMAC-SHA-256, and the compatible one for ten million (the counts are variables, so a
// test of the format can use small ones; this reads what they are when nothing changed them). Making a file with them takes seconds, more under the race detector: not done here.
func TestTheCountsUsedForReal(t *testing.T) {
	if pbkdf2Iter != 1_000_000 || kdfCount != 10_000_000 {
		t.Errorf("PBKDF2 %d iterations, MD5 count %d", pbkdf2Iter, kdfCount)
	}
}

func TestKCVAndCombine(t *testing.T) {
	a, b := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{3}, 32)
	if !bytes.Equal(Combine(a, b), bytes.Repeat([]byte{2}, 32)) || !bytes.Equal(Combine(a), a) {
		t.Error("the XOR of shares")
	}
	// the check value is the first 8 bytes of the SHA-256: the one the real card gave for a share was this
	if got := hex.EncodeToString(KCV(make([]byte, 32))); got != "66687aadf862bd77" {
		t.Errorf("%s", got)
	}
	w := []byte{1, 2, 3}
	Wipe(w)
	if !bytes.Equal(w, []byte{0, 0, 0}) {
		t.Error("Wipe")
	}
}
