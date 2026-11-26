package kmsrest

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestSecretDigestClearsTheFileContent(t *testing.T) {
	secret := strings.Repeat("s", 32)
	for name, text := range map[string]string{"a secret": " " + secret + "\n", "too short": " short\n"} {
		in := []byte(text)
		sum, err := secretDigest(in)
		if (err == nil) != (name == "a secret") {
			t.Errorf("%s: %v", name, err)
		}
		if name == "a secret" && sum != sha256.Sum256([]byte(secret)) {
			t.Errorf("%s: the digest is not of the secret without the white space", name)
		}
		if !bytes.Equal(in, make([]byte, len(in))) {
			t.Errorf("%s: the content is still there: %q", name, in)
		}
	}
}
