package card

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec G501 -- the compatible share file (OpenSSL's EVP_BytesToKey with MD5) that the card managers of the vendor read; the strong format below is the default
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// A DKEK (device key encryption key) is made of shares: each share is 32 random bytes, kept in a file under a password, and the card combines the shares it is given by XOR. A share
// file comes in two formats, and the page opens both (the file says which it is):
//
//   - Strong (the default): the magic "HGDKEKS1", the number of iterations (4 bytes), a salt of 16 bytes, a nonce of 12 bytes and the share under AES-256-GCM (48 bytes with the tag),
//     the key made from the password by PBKDF2-HMAC-SHA-256 with that many iterations (1 000 000 for a new file). The header is authenticated, so a changed file is refused, not
//     opened wrongly. Only this program reads it.
//   - Compatible: the file that the vendor's card managers (Smart Card Shell, sc-hsm-tool) write and read: "Salted__", a salt of 8 bytes and 48 bytes of AES-256-CBC (the share and
//     16 bytes of 0x10), the key and the initialisation vector made by OpenSSL's `EVP_BytesToKey` (MD5, three rounds, the count 10 000 000). MD5 is weak for a password, and the
//     count is what protects the file: use it only when another tool has to read the file.

// ShareFormat is the format of a share file.
type ShareFormat int

const (
	// Strong is the default format (AES-256-GCM, PBKDF2-HMAC-SHA-256).
	Strong ShareFormat = iota
	// Compatible is the format of the vendor's card managers (AES-256-CBC, MD5 key derivation).
	Compatible
)

func (f ShareFormat) String() string {
	if f == Compatible {
		return "compatible"
	}
	return "strong"
}

// ShareLen is the length of a DKEK share.
const ShareLen = 32

// kdfCount is the count of the key derivation of the compatible format and pbkdf2Iter the number of iterations of the strong one; they are variables so that a test can use small
// ones for the cases that do not test the count.
var (
	kdfCount   = 10_000_000
	pbkdf2Iter = 1_000_000
)

const (
	strongMagic   = "HGDKEKS1"
	strongHeader  = 8 + 4 + 16 + 12 // magic, iterations, salt, nonce
	strongSize    = strongHeader + ShareLen + 16
	compatSize    = 64
	maxIterations = 100_000_000 // what a file may ask for: a bound for a file that is not ours
)

// SetKDFCount changes the count of the key derivation and returns what restores it. It is for tests, which cannot wait for the count that is used for real.
func SetKDFCount(n int) (restore func()) {
	oldK, oldP := kdfCount, pbkdf2Iter
	kdfCount, pbkdf2Iter = n, n
	return func() { kdfCount, pbkdf2Iter = oldK, oldP }
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

// EncryptShare makes the content of a share file from a share and a password, in the format asked for.
func EncryptShare(format ShareFormat, share, password []byte, rnd io.Reader) ([]byte, error) {
	if len(share) != ShareLen {
		return nil, fmt.Errorf("a DKEK share is %d bytes, not %d", ShareLen, len(share))
	}
	if len(password) == 0 {
		return nil, errors.New("a DKEK share needs a password")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	if format == Compatible {
		return encryptCompatible(share, password, rnd)
	}
	return encryptStrong(share, password, rnd)
}

func encryptCompatible(share, password []byte, rnd io.Reader) ([]byte, error) {
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

// strongKey makes the key of a strong file from the password, the salt and the number of iterations.
func strongKey(password, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), salt, iter, 32)
}

func encryptStrong(share, password []byte, rnd io.Reader) ([]byte, error) {
	hdr := make([]byte, strongHeader)
	copy(hdr, strongMagic)
	binary.BigEndian.PutUint32(hdr[8:], uint32(pbkdf2Iter)) // #nosec G115 -- 1 000 000, or a small number in a test
	if _, err := io.ReadFull(rnd, hdr[12:]); err != nil {   // the salt and the nonce
		return nil, err
	}
	key, err := strongKey(password, hdr[12:28], pbkdf2Iter)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(hdr, hdr[28:40], share, hdr[:28]), nil // the header up to the nonce is authenticated
}

// FormatOf says which format a share file is, by what it starts with.
func FormatOf(file []byte) (ShareFormat, bool) {
	switch {
	case len(file) == strongSize && bytes.HasPrefix(file, []byte(strongMagic)):
		return Strong, true
	case len(file) == compatSize && bytes.HasPrefix(file, []byte("Salted__")):
		return Compatible, true
	}
	return 0, false
}

// DecryptShare opens a share file of either format.
func DecryptShare(file, password []byte) ([]byte, error) {
	f, ok := FormatOf(file)
	if !ok {
		return nil, errors.New("this is not a DKEK share file (the strong format is 88 bytes and starts with HGDKEKS1, the compatible one 64 bytes and starts with Salted__)")
	}
	if f == Compatible {
		return decryptCompatible(file, password)
	}
	iter := int(binary.BigEndian.Uint32(file[8:12]))
	if iter < 1 || iter > maxIterations {
		return nil, errors.New("this share file asks for a number of iterations that is not accepted")
	}
	key, err := strongKey(password, file[12:28], iter)
	if err != nil {
		return nil, err
	}
	defer Wipe(key)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	share, err := gcm.Open(nil, file[28:40], file[40:], file[:28])
	if err != nil {
		return nil, ErrWrongPassword // a wrong password and a changed file look the same, as they must
	}
	return share, nil
}

func decryptCompatible(file, password []byte) ([]byte, error) {
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
