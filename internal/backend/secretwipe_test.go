package backend

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// brokenReader hands out a part of a secret and then fails; it keeps the buffer it was given, so a test can look at it afterwards.
type brokenReader struct {
	buf  []byte
	done bool
}

func (r *brokenReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, errors.New("input/output error")
	}
	r.buf, r.done = p, true
	return copy(p, "half-a-secret"), nil
}

func TestReadSecretClearsItsBufferOnAnError(t *testing.T) {
	r := &brokenReader{}
	if _, err := readSecret(r, "k", 64); err == nil {
		t.Fatal("a failed read was accepted")
	}
	if !bytes.Equal(r.buf, make([]byte, len(r.buf))) {
		t.Errorf("the part that was read is still in the buffer: %q", r.buf[:16])
	}
	if b, err := readSecret(bytes.NewReader([]byte("abcd")), "k", 4); err != nil || string(b) != "abcd" {
		t.Errorf("exactly max bytes: %q, %v", b, err)
	}
	if _, err := readSecret(bytes.NewReader([]byte("abcde")), "k", 4); err == nil {
		t.Error("more than max bytes was accepted")
	}
	if b, err := readSecret(io.LimitReader(nil, 0), "k", 4); err != nil || len(b) != 0 {
		t.Errorf("empty: %q, %v", b, err)
	}
}

func TestDecodeKeyClearsTheText(t *testing.T) {
	for name, text := range map[string]string{"a key": " 0102ff\n", "not hex": "01zz\n", "odd": "010\n"} {
		in := []byte(text)
		b, err := decodeKey(in)
		if (err == nil) != (name == "a key") {
			t.Errorf("%s: %v", name, err)
		}
		if name == "a key" && !bytes.Equal(b, []byte{1, 2, 255}) {
			t.Errorf("%s: %x", name, b)
		}
		if !bytes.Equal(in, make([]byte, len(in))) {
			t.Errorf("%s: the text is still there: %q", name, in)
		}
	}
}
