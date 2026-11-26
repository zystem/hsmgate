package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestSigningSecretClearsTheFileContent(t *testing.T) {
	secret := strings.Repeat("s", 20)
	for name, text := range map[string]string{"a secret": " " + secret + "\n", "too short": " short\n"} {
		in := []byte(text)
		got, err := signingSecret(in, 20)
		if (err == nil) != (name == "a secret") {
			t.Errorf("%s: %v", name, err)
		}
		if name == "a secret" && string(got) != secret { // a copy of its own: it outlives the clearing of the content
			t.Errorf("%s: %q", name, got)
		}
		if !bytes.Equal(in, make([]byte, len(in))) {
			t.Errorf("%s: the content is still there: %q", name, in)
		}
	}
}
