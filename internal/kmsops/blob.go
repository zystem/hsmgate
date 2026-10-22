package kmsops

import (
	"encoding/binary"
	"errors"
	"strings"

	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

// The blob that Encrypt gives and Decrypt takes (on every face): "HGK2", the length of the name, the name of the key, the version as two bytes, the ecies2 text. The name and the version
// are in the clear so that a Decrypt without a key id finds the key, and they are also authenticated: BindAAD puts them into the additional data of the AEAD, so a blob cannot be
// relabelled to another key (even one with the same material and context) or to another version (the audit of 2026-10-21, CR-02).
const blobMagic = "HGK2"

// BindAAD is what the AEAD authenticates for a blob: the domain, the name, the version and the additional data of the request. The name has at most 128 characters and a key at most
// 1000 versions (config.Validate), so the conversions lose nothing.
func BindAAD(name string, ver int, aad []byte) []byte {
	b := append([]byte("hsmgate/kmsjson/blob/v2\x00"), byte(len(name))) // #nosec G115
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(ver)) // #nosec G115
	return append(b, aad...)
}

// MakeBlob puts a name, a version and an ecies2 text into the blob.
func MakeBlob(name string, ver int, text string) []byte {
	b := append([]byte(blobMagic), byte(len(name))) // #nosec G115 -- bounded by config.Validate
	b = append(b, name...)
	b = binary.BigEndian.AppendUint16(b, uint16(ver)) // #nosec G115 -- bounded by config.Validate
	return append(b, text...)
}

var errBlob = errors.New("the ciphertext is not valid")

// ParseBlob reads a blob strictly.
func ParseBlob(b []byte) (name string, ver int, text string, err error) {
	if len(b) < len(blobMagic)+1+1+2+1 || string(b[:len(blobMagic)]) != blobMagic {
		return "", 0, "", errBlob
	}
	n := int(b[len(blobMagic)])
	rest := b[len(blobMagic)+1:]
	if n == 0 || len(rest) < n+2+1 {
		return "", 0, "", errBlob
	}
	name = string(rest[:n])
	ver = int(binary.BigEndian.Uint16(rest[n : n+2]))
	text = string(rest[n+2:])
	if ver < 1 || !strings.HasPrefix(text, ecies.FormatTag+".") {
		return "", 0, "", errBlob
	}
	return name, ver, text, nil
}

// Wipe zeroes a buffer that held a secret.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
