package card

import (
	"bytes"
	"context"
	"fmt"
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

func soPIN(t *testing.T) []byte {
	t.Helper()
	f := os.Getenv("HSMGATE_REAL_SO_PIN_FILE")
	if f == "" {
		t.Skip("set HSMGATE_REAL_SO_PIN_FILE to a file that holds the SO PIN")
	}
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b)
}

// TestRealSOPIN changes the SO PIN to another of the same length and back, then sets the User PIN with the SO PIN: to a PIN of another length (what the rule of the length of a
// new User PIN is for this command) and back to the PIN it was. If a way back fails the log says what the PIN is now.
func TestRealSOPIN(t *testing.T) {
	pinv := userPIN(t)
	so := soPIN(t)
	s, _ := realSession(t)
	st, err := s.PINState("SO PIN", refSOPIN)
	if err != nil {
		t.Fatal(err)
	}
	if st.Tries < 3 {
		t.Fatalf("only %d tries of the SO PIN are left: not trying", st.Tries)
	}
	temp := bytes.Repeat([]byte("5"), len(so))
	if bytes.Equal(temp, so) {
		temp = bytes.Repeat([]byte("6"), len(so))
	}
	if err := s.ChangeSOPIN(so, temp); err != nil {
		t.Fatalf("changing the SO PIN: %v (a new SO PIN of another length than the current one is refused, perhaps)", err)
	}
	if err := s.Select(); err != nil {
		t.Fatalf("%v: THE SO PIN IS NOW %s", err, temp)
	}
	if err := s.ChangeSOPIN(temp, so); err != nil {
		t.Fatalf("the way back: %v: THE SO PIN IS NOW %s", err, temp)
	}
	t.Log("the SO PIN was changed and put back")
	// the unblocking: the SO PIN and a new User PIN
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	other := []byte("1234567890")
	if err := s.UnblockUserPIN(so, other); err != nil {
		t.Logf("unblocking with a new User PIN of %d characters (the current one has %d): %v", len(other), len(pinv), err)
	} else {
		t.Logf("unblocking with a new User PIN of %d characters (the current one has %d): taken", len(other), len(pinv))
		if err := s.Select(); err != nil {
			t.Fatalf("%v: THE USER PIN IS NOW %s", err, other)
		}
		if err := s.UnblockUserPIN(so, pinv); err != nil {
			t.Fatalf("the way back: %v: THE USER PIN IS NOW %s", err, other)
		}
	}
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	if err := s.UnblockUserPIN(so, pinv); err != nil {
		t.Fatalf("unblocking with the same PIN: %v", err)
	}
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifyUserPIN(pinv)
	if err != nil || !got.Verified {
		t.Fatalf("the User PIN does not open: %v %+v", err, got)
	}
	t.Logf("User PIN: %s", got.Text())
}

// TestRealAESKey makes an AES-256 key (encrypt, decrypt and wrap) and an AES-128 key that may do CMAC (named by a check value), looks at both in the tree, wraps the first and unwraps
// it as a third key, and deletes all of them.
func TestRealAESKey(t *testing.T) {
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
	var made []byte
	defer func() {
		if err := s.Select(); err != nil {
			t.Errorf("%v (delete the keys %v by hand)", err, made)
			return
		}
		realLogin(t, s, pinv)
		for _, k := range made {
			if err := s.DeleteKey(k); err != nil {
				t.Errorf("deleting the key %d: %v (delete it by hand)", k, err)
			}
		}
	}()
	id1, _, kid1, err := s.GenerateKey(GenSpec{Kind: "AES", Bits: 256, Label: "aes-test", Algorithms: AlgorithmByName("AES", "encrypt", "wrap"), Domain: dom})
	if id1 != 0 {
		made = append(made, id1)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the AES-256 key %d, identifier %X", id1, kid1)
	id2, _, kid2, err := s.GenerateKey(GenSpec{Kind: "AES", Bits: 128, Label: "aes-mac", Algorithms: AlgorithmByName("AES", "cmac"), Domain: dom})
	if id2 != 0 {
		made = append(made, id2)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("the AES-128 CMAC key %d, identifier %X", id2, kid2)
	kf, err := s.ExportKey(id1)
	if err != nil {
		t.Fatalf("wrapping the AES key: %v", err)
	}
	t.Logf("wrapped: blob %d bytes, description %d bytes", len(kf.Blob), len(kf.Description))
	desc := append([]byte{}, kf.Description...)
	if i := bytes.Index(desc, []byte("aes-test")); i >= 0 {
		desc[i] ^= 0x20
	}
	kf.Description = desc
	id3, err := s.ImportKey(kf)
	if id3 != 0 {
		made = append(made, id3)
	}
	if err != nil {
		t.Fatalf("unwrapping: %v", err)
	}
	t.Logf("unwrapped as the key %d", id3)
	tree, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[int]string{}
	for _, d := range tree.Domains {
		for _, k := range d.Keys {
			for _, m := range made {
				if k.ID == int(m) {
					seen[k.ID] = fmt.Sprintf("%s %s id=%X %v", k.Label, k.Algo, k.CKAID, k.Algorithms)
				}
			}
		}
	}
	for _, m := range made {
		t.Logf("in the tree: %d: %s", m, seen[int(m)])
	}
	if len(seen) != len(made) {
		t.Errorf("not all the keys are in the tree: %v", seen)
	}
	if !strings.Contains(seen[int(id1)], "AES-256") || !strings.Contains(seen[int(id2)], "AES-128") {
		t.Errorf("the keys are not shown as AES: %v", seen)
	}
}
