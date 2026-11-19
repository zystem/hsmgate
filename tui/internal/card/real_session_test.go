package card

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// The tests of this file talk to a real SmartCard-HSM through opensc-explorer. They are skipped unless HSMGATE_REAL_CARD=1. The first reads only. The second changes the card (it makes a key
// domain, a key and deletes them again) and is skipped unless HSMGATE_REAL_CARD_WRITE=1 and HSMGATE_REAL_PIN_FILE names a file that holds the User PIN: the PIN is read from that file
// and never printed. Build the test program with `go test -c ./internal/card` and run it on the machine that has the reader.

func realSession(t *testing.T) (*Session, Reader) {
	t.Helper()
	if os.Getenv("HSMGATE_REAL_CARD") != "1" {
		t.Skip("set HSMGATE_REAL_CARD=1 to use a card in a reader")
	}
	rs, err := Readers(context.Background(), run)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.HasCard {
			c, err := OpenExplorer(context.Background(), nil, r)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			s := NewSession(c)
			if err := s.Select(); err != nil {
				t.Fatal(err)
			}
			return s, r
		}
	}
	t.Skip("no card in a reader")
	return nil, Reader{}
}

func TestRealSessionReads(t *testing.T) {
	s, r := realSession(t)
	t.Logf("reader %d: %s", r.Nr, r.Name)
	for _, p := range []struct {
		name string
		ref  byte
	}{{"User PIN", refUserPIN}, {"SO PIN", refSOPIN}} {
		st, err := s.PINState(p.name, p.ref)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(st.Text())
	}
	for n := byte(0); n < 5; n++ {
		d, err := s.DomainStatus(n)
		if err != nil {
			t.Logf("domain %d: %v", n, err)
			break
		}
		t.Logf("domain %d: created=%v kcv=%s shares=%d outstanding=%d xkek=%v", n, d.Created, d.KCV, d.Shares, d.Outstanding, d.XKEK)
	}
	objs, err := s.Objects()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("objects: % X", objs)
	for _, fid := range []uint16{0xC700, 0xC400 | 1} {
		if s.HasFile(fid) {
			b, err := s.ReadFile(fid)
			t.Logf("file %04X: % X %v", fid, b, err)
		}
	}
}

func userPIN(t *testing.T) []byte {
	t.Helper()
	if os.Getenv("HSMGATE_REAL_CARD_WRITE") != "1" {
		t.Skip("set HSMGATE_REAL_CARD_WRITE=1 and HSMGATE_REAL_PIN_FILE to change a card")
	}
	b, err := os.ReadFile(os.Getenv("HSMGATE_REAL_PIN_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(b)
}

// login gives the card the PIN, after looking at how many tries are left; one wrong PIN stops the test.
func realLogin(t *testing.T, s *Session, pinv []byte) {
	t.Helper()
	st, err := s.PINState("User PIN", refUserPIN)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Verified && st.Tries < 2 {
		t.Fatalf("only %d tries of the User PIN are left: not trying", st.Tries)
	}
	got, err := s.VerifyUserPIN(pinv)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Verified {
		t.Fatalf("the card did not take the PIN: %s", got.Text())
	}
}

// TestRealDomainAndShare makes a key domain on a free number, gives it a share and checks the key check value, then removes it.
func TestRealDomainAndShare(t *testing.T) {
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
	d, err := s.CreateDKEKDomain(free, 1, "test-domain")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("created the key domain %d: shares=%d outstanding=%d", free, d.Shares, d.Outstanding)
	cleanup := func() {
		if err := s.DeleteKEK(free); err != nil {
			t.Logf("deleting the KEK: %v", err)
		}
		if err := s.DeleteDomain(free); err != nil {
			t.Errorf("deleting the key domain: %v (delete it by hand)", err)
		}
	}
	defer cleanup()
	if d.Shares != 1 || d.Outstanding != 1 {
		t.Errorf("a new domain of 1 share: %+v", d)
	}
	share, _ := NewShare(nil)
	d, err = s.ImportShare(free, share)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.ToUpper(bytesHex(KCV(Combine(share))))
	t.Logf("after the share: outstanding=%d kcv=%s (computed %s)", d.Outstanding, d.KCV, want)
	if d.Outstanding != 0 || d.KCV != want {
		t.Errorf("the key check value of the card is not the SHA-256 of the share: %+v want %s", d, want)
	}
	// the label is in the file C7nn
	b, err := s.ReadFile(0xC700 | uint16(free))
	if err != nil || string(find(b, 0x0C)) != "test-domain" {
		t.Errorf("the label file: % X %v", b, err)
	}
}

func bytesHex(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, h[c>>4], h[c&15])
	}
	return string(out)
}

// TestRealWrapAndUnwrap wraps the first key of a domain with a complete DKEK that allows wrapping, brings it back as a second key with another label and id (so that the key of a
// service is not duplicated) and deletes that copy.
func TestRealWrapAndUnwrap(t *testing.T) {
	pinv := userPIN(t)
	s, r := realSession(t)
	tree, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	var src *Key
	for _, d := range tree.Domains {
		if d.Created && !d.XKEK && d.Outstanding == 0 {
			for i := range d.Keys {
				for _, a := range d.Keys[i].Algorithms {
					if a == "wrap" { // the last one: not the key a service uses
						src = &d.Keys[i]
					}
				}
			}
		}
	}
	if src == nil {
		t.Skip("no key that allows wrapping")
	}
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	realLogin(t, s, pinv)
	kf, err := s.ExportKey(byte(src.ID)) // #nosec G115 -- a key number
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("wrapped the key %d (%s): the blob is %d bytes, description %d bytes, %d certificates", src.ID, src.Label, len(kf.Blob), len(kf.Description), len(kf.Certs))
	parsed, err := ParseKeyFile(kf.Encode())
	if err != nil || !bytes.Equal(parsed.Blob, kf.Blob) || !bytes.Equal(parsed.Description, kf.Description) || len(parsed.Certs) != len(kf.Certs) {
		t.Fatalf("the file does not read back as it was written: %v", err)
	}
	// another label and another id in the description
	desc := append([]byte{}, kf.Description...)
	if i := bytes.Index(desc, []byte(src.Label)); i >= 0 && len(src.Label) > 0 {
		desc[i] ^= 0x20 // 'c' to 'C': a label of its own
	}
	if i := bytes.Index(desc, src.CKAID); i >= 0 && len(src.CKAID) > 0 {
		desc[i] ^= 0xFF
	}
	kf.Description = desc
	id, err := s.ImportKey(kf)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("unwrapped as the key %d", id)
	defer func() {
		// the reading of the tree below selects the application again, which ends the login: log in again to delete
		if err := s.Select(); err != nil {
			t.Errorf("%v (delete the key %d by hand)", err, id)
			return
		}
		realLogin(t, s, pinv)
		if err := s.DeleteKey(id); err != nil {
			t.Errorf("deleting the copy: %v (delete the key %d by hand)", err, id)
		}
	}()
	tree2, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range tree2.Domains {
		for _, k := range d.Keys {
			if k.ID == int(id) {
				found = true
				t.Logf("the copy: %s (%d, %s) in the key domain %d, id %X", k.Label, k.ID, k.Algo, d.Number, k.CKAID)
			}
		}
	}
	if !found {
		t.Error("the key that was unwrapped is not in the tree")
	}
}

// TestRealDeleteKey deletes the key whose number is in HSMGATE_REAL_DELETE_KEY (a leftover of a test that stopped halfway).
func TestRealDeleteKey(t *testing.T) {
	pinv := userPIN(t)
	n := os.Getenv("HSMGATE_REAL_DELETE_KEY")
	if n == "" {
		t.Skip("set HSMGATE_REAL_DELETE_KEY to a key number")
	}
	var id int
	if _, err := fmt.Sscanf(n, "%d", &id); err != nil || id < 1 || id > 255 {
		t.Fatal("not a key number")
	}
	s, _ := realSession(t)
	realLogin(t, s, pinv)
	if err := s.DeleteKey(byte(id)); err != nil { // #nosec G115 -- 1 to 255
		t.Fatal(err)
	}
}

// TestRealGenerateKey makes an EC key in the first complete key domain other than the first, checks what the card answered and the tree, and deletes it.
func TestRealGenerateKey(t *testing.T) {
	pinv := userPIN(t)
	s, r := realSession(t)
	tree, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	dom := -1
	for _, d := range tree.Domains {
		if d.Created && !d.XKEK && d.Outstanding == 0 && d.Number > 0 {
			dom = d.Number
			break
		}
	}
	if dom < 0 {
		t.Skip("no complete key domain other than the first")
	}
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	realLogin(t, s, pinv)
	id, req, kid, err := s.GenerateKey(GenSpec{Kind: "EC", Bits: 256, Label: "gen-test", Algorithms: AlgorithmByName("EC", "sign"), Domain: dom})
	if err != nil {
		if id != 0 {
			t.Logf("the key %d may be on the card: delete it", id)
		}
		t.Fatal(err)
	}
	t.Logf("the key %d, request of %d bytes, identifier %X", id, len(req), kid)
	defer func() {
		if err := s.Select(); err == nil {
			realLogin(t, s, pinv)
			if err := s.DeleteKey(id); err != nil {
				t.Errorf("deleting the key %d: %v (delete it by hand)", id, err)
			}
		}
	}()
	tree2, err := Read(context.Background(), run, r)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range tree2.Domains {
		for _, k := range d.Keys {
			if k.ID == int(id) {
				found = true
				t.Logf("in the tree: %s (%d, %s) in domain %d, id %X, algorithms %v", k.Label, k.ID, k.Algo, d.Number, k.CKAID, k.Algorithms)
				if k.Label != "gen-test" || k.Algo != "EC-256" || d.Number != dom || !bytes.Equal(k.CKAID, kid) {
					t.Errorf("the key is not as asked")
				}
			}
		}
	}
	if !found {
		t.Error("the new key is not in the tree")
	}
}

// TestRealXKEKDomain makes an XKEK key domain on a free number with a group signer key on the same card (a group of one card: the card is its own member), looks at it, and
// removes the domain and the key.
func TestRealXKEKDomain(t *testing.T) {
	pinv := userPIN(t)
	s, _ := realSession(t)
	var free, signerDomain byte = 255, 255
	for n := byte(0); n < 8; n++ {
		d, err := s.DomainStatus(n)
		if err != nil {
			break
		}
		if !d.Created && free == 255 {
			free = n
		}
		if d.Created && !d.XKEK && d.Outstanding == 0 && n > 0 && signerDomain == 255 {
			signerDomain = n
		}
	}
	if free == 255 || signerDomain == 255 {
		t.Skip("no free key domain, or no complete one for the group signer")
	}
	realLogin(t, s, pinv)
	id, req, _, err := s.GenerateKey(GenSpec{Kind: "EC", Bits: 256, Label: "xkek-signer", Algorithms: AlgorithmByName("EC", "sign"), Domain: int(signerDomain)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DeleteKey(id); err != nil {
			t.Errorf("deleting the group signer key %d: %v (delete it by hand)", id, err)
		}
	}()
	certs, err := s.DeviceCertificates()
	if err != nil {
		t.Fatal(err)
	}
	x, err := certs.DevicePointX()
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Membership(id, x)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("device certificate %d bytes, issuer %d bytes, membership %d bytes", len(certs.Device), len(certs.DICA), len(m))
	d, err := s.CreateXKEKDomain(free, req, m, certs, "xkek-test")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DeleteKEK(free); err != nil {
			t.Logf("deleting the KEK: %v", err)
		}
		if err := s.DeleteDomain(free); err != nil {
			t.Errorf("deleting the key domain %d: %v (delete it by hand)", free, err)
		}
	}()
	t.Logf("the XKEK domain %d: xkek=%v kcv=%s domain id %s", free, d.XKEK, d.KCV, d.DomainID)
	if !d.XKEK || d.DomainID == "" {
		t.Errorf("the card does not say it is an XKEK domain: %+v", d)
	}
	got, err := s.DomainStatus(free)
	if err != nil || !got.XKEK || got.DomainID != d.DomainID {
		t.Errorf("asked again: %v %+v", err, got)
	}
}

// TestRealXKEKFiles is the whole way through the files of the card manager on one card: the device id file, a group signer key, the membership file, and the XKEK domain made
// from what was read back from the files.
func TestRealXKEKFiles(t *testing.T) {
	pinv := userPIN(t)
	s, _ := realSession(t)
	var free, signerDomain byte = 255, 255
	for n := byte(0); n < 8; n++ {
		d, err := s.DomainStatus(n)
		if err != nil {
			break
		}
		if !d.Created && free == 255 {
			free = n
		}
		if d.Created && !d.XKEK && d.Outstanding == 0 && n > 0 && signerDomain == 255 {
			signerDomain = n
		}
	}
	if free == 255 || signerDomain == 255 {
		t.Skip("no free key domain, or no complete one for the group signer")
	}
	realLogin(t, s, pinv)
	id, _, _, err := s.GenerateKey(GenSpec{Kind: "EC", Bits: 256, Label: "xkek-signer", Algorithms: AlgorithmByName("EC", "sign"), Domain: int(signerDomain)})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DeleteKey(id); err != nil {
			t.Errorf("deleting the key %d: %v (delete it by hand)", id, err)
		}
	}()
	certs, err := s.DeviceCertificates()
	if err != nil {
		t.Fatal(err)
	}
	idFile := EncodeDeviceID(certs) // what the device id file holds
	dev, err := ParseDeviceID(idFile)
	if err != nil || !bytes.Equal(dev.Device, certs.Device) || !bytes.Equal(dev.DICA, certs.DICA) {
		t.Fatalf("the device id file does not read back: %v", err)
	}
	mf, err := s.SignMembership(id, dev)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseMembershipFile(mf.Encode())
	if err != nil || !bytes.Equal(back.GroupRequest, mf.GroupRequest) || !bytes.Equal(back.Membership, mf.Membership) {
		t.Fatalf("the membership file does not read back: %v", err)
	}
	t.Logf("the membership file is %d bytes, the key domain id %X", len(mf.Encode()), back.DomainUID())
	d, err := s.CreateXKEKDomain(free, back.GroupRequest, back.Membership, back.Signer, "from-files")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.DeleteDomain(free); err != nil {
			t.Errorf("deleting the key domain %d: %v (delete it by hand)", free, err)
		}
	}()
	if !d.XKEK || !strings.HasPrefix(strings.ToUpper(bytesHex(back.DomainUID())), d.DomainID) {
		t.Errorf("the domain: %+v, the id of the file %X", d, back.DomainUID())
	}
}
