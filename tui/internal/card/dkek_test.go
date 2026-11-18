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

func TestShareFileRoundTrip(t *testing.T) {
	defer func(c int) { kdfCount = c }(kdfCount)
	kdfCount = 50
	share, err := NewShare(nil)
	if err != nil || len(share) != ShareLen {
		t.Fatal(err)
	}
	file, err := EncryptShare(share, []byte("a password"), nil)
	if err != nil || len(file) != 64 || !bytes.HasPrefix(file, []byte("Salted__")) {
		t.Fatalf("%v %d", err, len(file))
	}
	got, err := DecryptShare(file, []byte("a password"))
	if err != nil || !bytes.Equal(got, share) {
		t.Fatalf("%v", err)
	}
	if _, err := DecryptShare(file, []byte("another")); err != ErrWrongPassword {
		t.Errorf("a wrong password: %v", err)
	}
	if _, err := DecryptShare(file[:60], []byte("a password")); err == nil {
		t.Error("a short file was opened")
	}
	if _, err := DecryptShare(append([]byte("Xalted__"), file[8:]...), []byte("a password")); err == nil {
		t.Error("a file without the mark was opened")
	}
	// two files of the same share differ (the salt), and neither shows the share
	f2, _ := EncryptShare(share, []byte("a password"), nil)
	if bytes.Equal(file, f2) || bytes.Contains(file, share) {
		t.Error("the file is not salted or shows the share")
	}
	if _, err := EncryptShare(share[:31], []byte("x"), nil); err == nil {
		t.Error("a share of 31 bytes was accepted")
	}
	if _, err := EncryptShare(share, nil, nil); err == nil {
		t.Error("no password was accepted")
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
