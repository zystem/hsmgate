package card

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec G501 -- the file format of a DKEK share (OpenSSL's EVP_BytesToKey with MD5), which the card managers of the vendor read; it is not chosen here
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

// A DKEK (device key encryption key) is made of shares: each share is 32 random bytes, kept in a file under a password, and the card combines the shares it is given by XOR.
// The file is the one the vendor's card managers write and read: "Salted__", a salt of 8 bytes and 48 bytes of AES-256-CBC (the share and 16 bytes of 0x10), with the key and the
// initialisation vector made from the password and the salt by the key derivation of OpenSSL's `EVP_BytesToKey` (MD5, three rounds) with the count 10 000 000. That count makes a
// guess at the password slow on purpose, and makes opening a file take a few seconds.

// ShareLen is the length of a DKEK share.
const ShareLen = 32

// kdfCount is the count of the key derivation; it is a variable so that a test can use a small one for the cases that do not test the count.
var kdfCount = 10_000_000

// SetKDFCount changes the count of the key derivation and returns what restores it. It is for tests, which cannot wait for the count that is used for real.
func SetKDFCount(n int) (restore func()) {
	old := kdfCount
	kdfCount = n
	return func() { kdfCount = old }
}

// ErrWrongPassword is what DecryptShare says when the password does not open the file.
var ErrWrongPassword = errors.New("the password does not open this DKEK share (or the file is not a DKEK share)")

// shareKey makes the key (32 bytes) and the initialisation vector (16 bytes) of a share file.
func shareKey(password, salt []byte) (key, iv []byte) {
	var prev []byte
	out := make([]byte, 0, 48)
	for len(out) < 48 {
		h := md5.New() // #nosec G401 -- see above
		h.Write(prev)
		h.Write(password)
		h.Write(salt)
		var sum [16]byte
		h.Sum(sum[:0])
		for i := 1; i < kdfCount; i++ {
			sum = md5.Sum(sum[:]) // #nosec G401
		}
		prev = sum[:]
		out = append(out, sum[:]...)
	}
	return out[:32], out[32:48]
}

// NewShare makes a share of random bytes. rnd is where they come from (crypto/rand when nil).
func NewShare(rnd io.Reader) ([]byte, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	s := make([]byte, ShareLen)
	if _, err := io.ReadFull(rnd, s); err != nil {
		return nil, err
	}
	return s, nil
}

// EncryptShare makes the content of a share file (64 bytes) from a share and a password.
func EncryptShare(share, password []byte, rnd io.Reader) ([]byte, error) {
	if len(share) != ShareLen {
		return nil, fmt.Errorf("a DKEK share is %d bytes, not %d", ShareLen, len(share))
	}
	if len(password) == 0 {
		return nil, errors.New("a DKEK share needs a password")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	salt := make([]byte, 8)
	if _, err := io.ReadFull(rnd, salt); err != nil {
		return nil, err
	}
	key, iv := shareKey(password, salt)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := append(append([]byte{}, share...), bytes.Repeat([]byte{0x10}, 16)...)
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(blk, iv).CryptBlocks(ct, plain)
	return append(append([]byte("Salted__"), salt...), ct...), nil
}

// DecryptShare opens a share file.
func DecryptShare(file, password []byte) ([]byte, error) {
	if len(file) != 64 || !bytes.HasPrefix(file, []byte("Salted__")) {
		return nil, errors.New("this is not a DKEK share file (it must be 64 bytes and start with Salted__)")
	}
	key, iv := shareKey(password, file[8:16])
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, 48)
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, file[16:])
	if subtle.ConstantTimeCompare(plain[32:], bytes.Repeat([]byte{0x10}, 16)) != 1 {
		return nil, ErrWrongPassword
	}
	return plain[:32], nil
}

// KCV is the key check value of a DKEK: the first 8 bytes of its SHA-256. The card gives it for the shares it has been given, so two cards (or a card and the shares on paper)
// can be compared without showing the key.
func KCV(dkek []byte) []byte {
	h := sha256.Sum256(dkek)
	return h[:8]
}

// Combine is the DKEK that shares make: their XOR.
func Combine(shares ...[]byte) []byte {
	out := make([]byte, ShareLen)
	for _, s := range shares {
		for i := range out {
			out[i] ^= s[i]
		}
	}
	return out
}

// Wipe overwrites secret bytes (what a program can do: the garbage collector may have copied them).
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
