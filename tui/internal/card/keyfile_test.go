package card

import (
	"bytes"
	"testing"
)

func TestKeyFileRoundTrip(t *testing.T) {
	desc := []byte{0xA0, 0x0E, 0x30, 0x09, 0x0C, 0x07, 'm', 'y', ' ', 'k', 'e', 'y', 's', 0x30, 0x01, 0x04}
	k := KeyFile{Blob: bytes.Repeat([]byte{7}, 400), Description: desc, Certs: [][]byte{{0x7F, 0x21, 0x02, 1, 2}, {0x7F, 0x21, 0x01, 9}}}
	got, err := ParseKeyFile(k.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Blob, k.Blob) || !bytes.Equal(got.Description, desc) || len(got.Certs) != 2 || !bytes.Equal(got.Certs[1], k.Certs[1]) {
		t.Errorf("%+v", got)
	}
	if got.Label() != "my keys" {
		t.Errorf("label %q", got.Label())
	}
	// a blob alone (what sc-hsm-tool writes) is read as the blob, also when it starts with a byte that looks like a tag
	for _, raw := range [][]byte{bytes.Repeat([]byte{0x55}, 100), append([]byte{0x30, 0x04}, bytes.Repeat([]byte{1}, 98)...)} {
		g, err := ParseKeyFile(raw)
		if err != nil || !bytes.Equal(g.Blob, raw) || len(g.Description) != 0 {
			t.Errorf("a blob alone: %v %+v", err, g)
		}
	}
	if _, err := ParseKeyFile(nil); err == nil {
		t.Error("an empty file")
	}
	// a file cut in the middle of the certificates is refused, not read as a blob
	enc := k.Encode()
	cut := append([]byte{}, enc...)
	cut = cut[:len(cut)-1]
	if g, err := ParseKeyFile(cut); err == nil && bytes.Equal(g.Blob, k.Blob) && len(g.Certs) == 2 {
		t.Error("a cut file was read whole")
	}
}
