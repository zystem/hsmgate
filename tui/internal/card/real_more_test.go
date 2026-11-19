package card

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
)

// More tests on a real card, gated like those of real_session_test.go: HSMGATE_REAL_CARD=1, HSMGATE_REAL_CARD_WRITE=1 and HSMGATE_REAL_PIN_FILE. They are for a card that holds nothing
// that is not backed up.

// completeDomain is the number of a complete DKEK domain other than the first, or -1.
func completeDomain(t *testing.T, r Reader) int {
	t.Helper()
	tree, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range tree.Domains {
		if d.Created && !d.XKEK && d.Outstanding == 0 && d.Number > 0 {
			return d.Number
		}
	}
	return -1
}

// TestRealRSAGenerateWrapUnwrap makes an RSA-2048 key (the card takes up to a minute), wraps it, unwraps it as a second key, checks the tree and deletes both.
func TestRealRSAGenerateWrapUnwrap(t *testing.T) {
	pinv := userPIN(t)
	s, r := realSession(t)
	dom := completeDomain(t, r)
	if dom < 0 {
		t.Skip("no complete key domain other than the first")
	}
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	realLogin(t, s, pinv)
	id, _, kid, err := s.GenerateKey(GenSpec{Kind: "RSA", Bits: 2048, Label: "rsa-test", Algorithms: AlgorithmByName("RSA", rsaUses()...), Domain: dom})
	if err != nil {
		if id != 0 {
			t.Logf("the key %d may be on the card: delete it", id)
		}
		t.Fatal(err)
	}
	t.Logf("the RSA key %d, identifier %X", id, kid)
	var copyID byte
	defer func() {
		if err := s.Select(); err != nil {
			t.Errorf("%v (delete the keys %d and %d by hand)", err, id, copyID)
			return
		}
		realLogin(t, s, pinv)
		for _, k := range []byte{copyID, id} {
			if k == 0 {
				continue
			}
			if err := s.DeleteKey(k); err != nil {
				t.Errorf("deleting the key %d: %v (delete it by hand)", k, err)
			}
		}
	}()
	kf, err := s.ExportKey(id)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wrapped: blob %d bytes, description %d bytes, %d certificates", len(kf.Blob), len(kf.Description), len(kf.Certs))
	desc := append([]byte{}, kf.Description...)
	if i := bytes.Index(desc, []byte("rsa-test")); i >= 0 {
		desc[i] ^= 0x20
	}
	if i := bytes.Index(desc, kid); i >= 0 {
		desc[i] ^= 0xFF
	}
	kf.Description = desc
	copyID, err = s.ImportKey(kf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("unwrapped as the key %d", copyID)
	tree, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]string{}
	for _, d := range tree.Domains {
		for _, k := range d.Keys {
			if k.ID == int(id) || k.ID == int(copyID) {
				seen[k.ID] = k.Label + " " + k.Algo
			}
		}
	}
	t.Logf("in the tree: %v", seen)
	if len(seen) != 2 || !strings.Contains(seen[int(id)], "RSA-2048") || !strings.Contains(seen[int(copyID)], "RSA-2048") {
		t.Errorf("the two RSA-2048 keys are not both in the tree: %v", seen)
	}
}

// TestRealChangeUserPIN changes the User PIN to another one, takes the new one, and changes it back; if the way back fails the log says what the PIN is now.
func TestRealChangeUserPIN(t *testing.T) {
	pinv := userPIN(t)
	s, _ := realSession(t)
	temp := bytes.Repeat([]byte("7"), len(pinv)) // as long as the PIN there is; a PIN of another length may be refused, which the test shows
	if v := os.Getenv("HSMGATE_REAL_TEMP_PIN"); v != "" {
		temp = []byte(v)
	}
	if bytes.Equal(temp, pinv) {
		temp = bytes.Repeat([]byte("8"), len(pinv))
	}
	realLogin(t, s, pinv)
	if err := s.ChangeUserPIN(pinv, temp); err != nil {
		t.Fatal(err)
	}
	back := func() {
		if err := s.Select(); err != nil {
			t.Fatalf("%v: THE USER PIN IS NOW %s", err, temp)
		}
		got, err := s.VerifyUserPIN(temp)
		if err != nil || !got.Verified {
			t.Fatalf("the new PIN is not taken (%v, %+v): THE USER PIN MAY BE %s", err, got, temp)
		}
		if err := s.ChangeUserPIN(temp, pinv); err != nil {
			t.Fatalf("%v: THE USER PIN IS NOW %s", err, temp)
		}
	}
	back()
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifyUserPIN(pinv)
	if err != nil || !got.Verified {
		t.Fatalf("the old PIN is not back: %v %+v", err, got)
	}
	// a wrong PIN is refused and costs a try, which the state shows; one try is spent here on purpose, the right PIN gives it back
	st, _ := s.PINState("User PIN", refUserPIN)
	t.Logf("after the way back: %s", st.Text())
}

// TestRealTwoShares makes a key domain of two shares on a free number, gives both and checks that the key check value is that of their XOR, then removes it.
func TestRealTwoShares(t *testing.T) {
	pinv := userPIN(t)
	s, _ := realSession(t)
	var free byte = 255
	for n := byte(0); n < 8; n++ {
		d, err := s.DomainStatus(n)
		if err != nil {
			break
		}
		if !d.Created {
			free = n
			break
		}
	}
	if free == 255 {
		t.Skip("no free key domain on this card")
	}
	realLogin(t, s, pinv)
	d, err := s.CreateDKEKDomain(free, 2, "two-shares")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DeleteKEK(free); err != nil {
			t.Logf("deleting the KEK: %v", err)
		}
		if err := s.DeleteDomain(free); err != nil {
			t.Errorf("deleting the key domain: %v (delete it by hand)", err)
		}
	}()
	if d.Shares != 2 || d.Outstanding != 2 {
		t.Fatalf("a new domain of 2 shares: %+v", d)
	}
	a, _ := NewShare(nil)
	b, _ := NewShare(nil)
	d, err = s.ImportShare(free, a)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("after the first share: outstanding=%d kcv=%q", d.Outstanding, d.KCV)
	if d.Outstanding != 1 {
		t.Errorf("one share is still to come: %+v", d)
	}
	d, err = s.ImportShare(free, b)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ToUpper(bytesHex(KCV(Combine(a, b))))
	t.Logf("after both: outstanding=%d kcv=%s (computed %s)", d.Outstanding, d.KCV, want)
	if d.Outstanding != 0 || d.KCV != want {
		t.Errorf("the key check value is not that of the XOR of the shares: %+v want %s", d, want)
	}
}

// rsaUses is what the RSA key of the test may be used for (HSMGATE_REAL_RSA_USES, comma separated; default sign and wrap).
func rsaUses() []string {
	if v := os.Getenv("HSMGATE_REAL_RSA_USES"); v != "" {
		return strings.Split(v, ",")
	}
	return []string{"sign", "wrap"}
}
