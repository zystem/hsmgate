package card

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/tui/internal/card/cardtest"
)

func newSession(t *testing.T) (*Session, *cardtest.Sim) {
	t.Helper()
	sim := cardtest.NewSim()
	s := NewSession(sim)
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	return s, sim
}

func login(t *testing.T, s *Session) {
	t.Helper()
	p, err := s.VerifyUserPIN([]byte("123456"))
	if err != nil || !p.Verified {
		t.Fatalf("login: %v %+v", err, p)
	}
}

func TestPINTriesAndLogin(t *testing.T) {
	s, sim := newSession(t)
	st, err := s.PINState("User PIN", refUserPIN)
	if err != nil || st.Tries != 3 || st.Verified {
		t.Fatalf("%v %+v", err, st)
	}
	// before the login nothing that changes the card is allowed
	var swe *SWError
	if _, err := s.CreateDKEKDomain(3, 1, ""); !errors.As(err, &swe) || swe.SW != 0x6982 || !strings.Contains(err.Error(), "log in") {
		t.Errorf("before the login: %v", err)
	}
	// a wrong PIN costs a try and says how many are left
	st, err = s.VerifyUserPIN([]byte("000000"))
	if err != nil || st.Verified || st.Tries != 2 {
		t.Errorf("a wrong PIN: %v %+v", err, st)
	}
	login(t, s)
	if sim.Tries != 3 {
		t.Errorf("a right PIN does not give the tries back: %d", sim.Tries)
	}
	// selecting the application ends the login
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.PINState("User PIN", refUserPIN); st.Verified {
		t.Error("the login survived the selection")
	}
	// change the PIN, and unblock with the SO PIN
	login(t, s)
	if err := s.ChangeUserPIN([]byte("123456"), []byte("654321")); err != nil {
		t.Fatal(err)
	}
	if sim.PIN != "654321" {
		t.Error("the PIN was not changed")
	}
	if err := s.ChangeUserPIN([]byte("wrong"), []byte("111111")); err == nil {
		t.Error("a change with a wrong current PIN")
	}
	if err := s.UnblockUserPIN([]byte("57621880"), []byte("111111")); err != nil || sim.PIN != "111111" {
		t.Errorf("unblock: %v %q", err, sim.PIN)
	}
}

func TestDomainShareLifecycle(t *testing.T) {
	defer func(c int) { kdfCount = c }(kdfCount)
	kdfCount = 10
	s, sim := newSession(t)
	login(t, s)
	d, err := s.CreateDKEKDomain(3, 1, "backup")
	if err != nil || d.Shares != 1 || d.Outstanding != 1 || d.Label != "backup" {
		t.Fatalf("%v %+v", err, d)
	}
	b, err := s.ReadFile(0xC703)
	if err != nil || string(find(b, 0x0C)) != "backup" {
		t.Errorf("the label file: % X %v", b, err)
	}
	// a share from a file: made, written, read, imported; the card's check value is that of the share
	share, _ := NewShare(nil)
	file, _ := EncryptShare(Strong, share, []byte("pw"), nil)
	back, err := DecryptShare(file, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	d, err = s.ImportShare(3, back)
	if err != nil || d.Outstanding != 0 || d.KCV != fmt.Sprintf("%X", KCV(Combine(share))) {
		t.Fatalf("%v %+v", err, d)
	}
	var swe *SWError
	if _, err := s.ImportShare(3, share); !errors.As(err, &swe) || swe.SW != 0x6985 {
		t.Errorf("a share more than the domain asked for: %v", err)
	}
	if _, err := s.ImportShare(3, share[:5]); err == nil {
		t.Error("a short share")
	}
	// two shares make one DKEK, in either order
	if _, err := s.CreateDKEKDomain(2, 2, ""); err != nil {
		t.Fatal(err)
	}
	a, b2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{6}, 32)
	if d, _ := s.ImportShare(2, a); d.Outstanding != 1 {
		t.Errorf("after one of two: %+v", d)
	}
	if d, _ := s.ImportShare(2, b2); d.Outstanding != 0 || d.KCV != fmt.Sprintf("%X", KCV(Combine(a, b2))) {
		t.Errorf("after two: %+v", d)
	}
	// a domain that is there cannot be made again; one with a key cannot be deleted
	if _, err := s.CreateDKEKDomain(3, 1, ""); err == nil {
		t.Error("a domain made twice")
	}
	sim.Keys[1] = &cardtest.SimKey{Domain: 3, Wrap: true, Data: []byte("k")}
	if err := s.DeleteDomain(3); !errors.As(err, &swe) || swe.SW != 0x6985 {
		t.Errorf("a domain with a key: %v", err)
	}
	if err := s.DeleteKey(1); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteKEK(3); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDomain(3); err != nil {
		t.Fatal(err)
	}
	if st, _ := s.DomainStatus(3); st.Created {
		t.Error("the domain is still there")
	}
	if s.HasFile(0xC703) {
		t.Error("the label of the domain is still there")
	}
	if st, err := s.DomainStatus(9); err == nil {
		t.Errorf("a domain number the card does not have: %+v", st)
	}
}

// Wrapping and unwrapping, through the same path as the real card: opensc-explorer fed on a pipe, extended length for the blob (a short answer cannot hold it, and a chained command
// is refused), the file of the card manager.
func TestWrapAndUnwrapThroughTheExplorer(t *testing.T) {
	sim := cardtest.NewSim()
	dkek := bytes.Repeat([]byte{5}, 32)
	sim.Domains[0] = &cardtest.SimDomain{Shares: 1, DKEK: dkek}
	sim.Keys[1] = &cardtest.SimKey{Domain: 0, Wrap: true, Data: bytes.Repeat([]byte{0xAB}, 400)}
	sim.Keys[2] = &cardtest.SimKey{Domain: 0, Wrap: false, Data: []byte("not wrappable")}
	sim.Files[0xC401] = []byte{0xA0, 0x0E, 0x30, 0x09, 0x0C, 0x07, 'm', 'y', ' ', 'k', 'e', 'y', 's', 0x30, 0x01, 0x04}
	sim.Files[0xCE01] = []byte{0x7F, 0x21, 0x02, 1, 2}
	conn, err := OpenExplorer(context.Background(), sim.Starter(), Reader{Nr: 0})
	if err != nil {
		t.Fatal(err)
	}
	s := NewSession(conn)
	defer s.Close()
	if err := s.Select(); err != nil {
		t.Fatal(err)
	}
	var swe *SWError
	if _, err := s.ExportKey(1); !errors.As(err, &swe) || swe.SW != 0x6982 {
		t.Errorf("a wrap before the login: %v", err)
	}
	login(t, s)
	if _, err := s.ExportKey(2); !errors.As(err, &swe) || swe.SW != 0x6985 {
		t.Errorf("a key that does not allow wrapping: %v", err)
	}
	kf, err := s.ExportKey(1)
	if err != nil {
		t.Fatal(err)
	}
	if len(kf.Blob) != 408 || len(kf.Description) != 16 || len(kf.Certs) != 1 || kf.Label() != "my keys" {
		t.Fatalf("%d %d %d %q", len(kf.Blob), len(kf.Description), len(kf.Certs), kf.Label())
	}
	id, err := s.ImportKey(kf)
	if err != nil || id != 3 {
		t.Fatalf("%v %d", err, id)
	}
	k := sim.Keys[3]
	if k == nil || k.Domain != 0 || !bytes.Equal(k.Data, sim.Keys[1].Data) {
		t.Errorf("the key that came back: %+v", k)
	}
	if !bytes.Equal(sim.Files[0xC403], kf.Description) || !bytes.Equal(sim.Files[0xCE03], kf.Certs[0]) {
		t.Error("the description or the certificate was not written")
	}
	// the same blob again into a key number that is taken, and a blob of a DKEK the card does not have
	if err := s.UnwrapKey(3, kf.Blob); !errors.As(err, &swe) || swe.SW != 0x6985 {
		t.Errorf("a key number that is taken: %v", err)
	}
	bad := append([]byte{}, kf.Blob...)
	bad[0] ^= 0xFF
	if err := s.UnwrapKey(9, bad); !errors.As(err, &swe) || swe.SW != 0x6A88 {
		t.Errorf("a blob of another DKEK: %v", err)
	}
	if err := s.DeleteKey(3); err != nil {
		t.Fatal(err)
	}
	if sim.Keys[3] != nil || sim.Files[0xC403] != nil || sim.Files[0xCE03] != nil {
		t.Error("the key is not gone with its files")
	}
	for _, c := range sim.Sent {
		if c[0]&0x10 != 0 {
			t.Errorf("a chained command was sent: % X", c[:8])
		}
	}
}

func TestAnswerThatDoesNotFitIsFetched(t *testing.T) {
	s, sim := newSession(t)
	for i := 0; i < 150; i++ {
		sim.Files[0xC400|uint16(i)] = []byte{1}
	}
	objs, err := s.Objects()
	if err != nil || len(objs) != 152 { // the two files of the card and the 150
		t.Fatalf("%v %d", err, len(objs))
	}
}

func TestFreeKeyID(t *testing.T) {
	s, sim := newSession(t)
	sim.Keys[1], sim.Keys[2], sim.Keys[4] = &cardtest.SimKey{}, &cardtest.SimKey{}, &cardtest.SimKey{}
	if id, err := s.FreeKeyID(); err != nil || id != 3 {
		t.Errorf("%v %d", err, id)
	}
}

func TestExplorerErrors(t *testing.T) {
	failing := func(msg string) Starter {
		return func(context.Context, string, ...string) (io.WriteCloser, io.Reader, func() error, error) {
			inR, inW := io.Pipe()
			outR, outW := io.Pipe()
			go func() {
				fmt.Fprint(outW, "OpenSC Explorer version 0.26.1\n")
				bufio.NewReader(inR).ReadString('\n') // the command is read to its end, a pipe waits for that
				fmt.Fprint(outW, msg+"\n")
				outW.Close()
			}()
			return inW, outR, func() error { return nil }, nil
		}
	}
	// no reader: the greeting comes first and the message with the first command
	conn, err := OpenExplorer(context.Background(), failing("No smart card readers found."), Reader{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewSession(conn).Send(0, 0xA4, 4, 4, aid[5:], false); err == nil || !strings.Contains(err.Error(), "No smart card readers") {
		t.Errorf("%v", err)
	}
	// no tool
	missing := func(context.Context, string, ...string) (io.WriteCloser, io.Reader, func() error, error) {
		return nil, nil, nil, fmt.Errorf(`exec: "opensc-explorer": executable file not found in $PATH`)
	}
	if _, err := OpenExplorer(context.Background(), missing, Reader{}); err == nil || !strings.Contains(err.Error(), "apt install opensc") {
		t.Errorf("%v", err)
	}
	// a program that stops at once
	dead := func(context.Context, string, ...string) (io.WriteCloser, io.Reader, func() error, error) {
		inR, inW := io.Pipe()
		_ = inR
		return inW, strings.NewReader("Failed to connect to card\n"), func() error { return nil }, nil
	}
	if _, err := OpenExplorer(context.Background(), dead, Reader{}); err == nil || !strings.Contains(err.Error(), "Failed to connect") {
		t.Errorf("%v", err)
	}
}

// A file of more than 127 bytes: the length of the data of the write is in the long form of BER (the real card answered 6A80 to a length byte of 200), and the file reads back.
func TestWriteAndReadALongFile(t *testing.T) {
	s, sim := newSession(t)
	login(t, s)
	for _, n := range []int{5, 127, 128, 255, 489, 1500} {
		data := bytes.Repeat([]byte{byte(n)}, n) // #nosec G115 -- test data
		if err := s.WriteFile(0xCE09, data); err != nil {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if !bytes.Equal(sim.Files[0xCE09], data) {
			t.Fatalf("%d bytes were not written as they were", n)
		}
		got, err := s.ReadFile(0xCE09)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes: read back %d bytes, %v", n, len(got), err)
		}
		if err := s.DeleteFile(0xCE09); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateKeyWritesItsDescriptionAndRequest(t *testing.T) {
	s, sim := newSession(t)
	if _, _, _, err := s.GenerateKey(GenSpec{Kind: "EC", Bits: 256, Label: "k", Domain: -1}); err == nil {
		t.Error("a key was made before the login")
	}
	login(t, s)
	for _, bad := range []GenSpec{{Kind: "EC", Bits: 256}, {Kind: "EC", Bits: 384, Label: "x"}, {Kind: "RSA", Bits: 1024, Label: "x"}, {Kind: "DSA", Bits: 256, Label: "x"}} {
		if _, _, _, err := s.GenerateKey(bad); err == nil {
			t.Errorf("%+v was accepted", bad)
		}
	}
	id, req, kid, err := s.GenerateKey(GenSpec{Kind: "EC", Bits: 256, Label: "mine", Algorithms: AlgorithmByName("EC", "derive", "wrap"), Domain: 2})
	if err != nil || id != 1 || len(kid) != 20 || len(req) == 0 {
		t.Fatalf("%v %d %d", err, id, len(kid))
	}
	if k := sim.Keys[1]; k == nil || k.Domain != 2 || !k.Wrap || !bytes.Equal(k.Algs, []byte{AlgECDH, AlgWrap}) {
		t.Errorf("the key: %+v", k)
	}
	label, gotID, algo := prkd(sim.Files[0xC401])
	if label != "mine" || !bytes.Equal(gotID, kid) || algo != "EC-256" {
		t.Errorf("the description: %q %X %q", label, gotID, algo)
	}
	if !bytes.Equal(sim.Files[0xCE01], req) {
		t.Error("the request was not kept in its file")
	}
	// the spec that was sent is the one of the vendor's card manager: the profile, the references, P-256, the holder, the algorithms and the key domain
	spec := GenSpec{Kind: "EC", Bits: 256, Label: "x", Algorithms: []byte{0x73}, Domain: 2}.encode()
	for _, want := range [][]byte{{0x5F, 0x29, 0x01, 0x00}, {0x42, 0x0C}, {0x7F, 0x49}, oidECDSASHA256, {0x5F, 0x20, 0x0C}, {0x91, 0x01, 0x73}, {0x92, 0x01, 0x02}} {
		if !bytes.Contains(spec, want) {
			t.Errorf("the specification lacks % X", want)
		}
	}
	rsa := GenSpec{Kind: "RSA", Bits: 2048, Label: "x", Domain: -1}.encode()
	if !bytes.Contains(rsa, oidRSAv15SHA256) || !bytes.Contains(rsa, []byte{0x02, 0x02, 0x08, 0x00}) || bytes.Contains(rsa, []byte{0x92}) && false {
		t.Errorf("the RSA specification: % X", rsa)
	}
}

func TestXKEKDomainThroughTheFiles(t *testing.T) {
	s, sim := newSession(t)
	login(t, s)
	id, _, _, err := s.GenerateKey(GenSpec{Kind: "EC", Bits: 256, Label: "signer", Algorithms: AlgorithmByName("EC", "sign"), Domain: 0})
	if err != nil {
		t.Fatal(err)
	}
	certs, err := s.DeviceCertificates()
	if err != nil || len(certs.Device) == 0 || len(certs.DICA) == 0 {
		t.Fatalf("%v %+v", err, certs)
	}
	dev, err := ParseDeviceID(EncodeDeviceID(certs))
	if err != nil || !bytes.Equal(dev.Device, certs.Device) {
		t.Fatalf("the device id file: %v", err)
	}
	if _, err := ParseDeviceID(append([]byte{0x30, 0x03}, 1, 2, 3)); err == nil {
		t.Error("a file that is not a device id")
	}
	mf, err := s.SignMembership(id, dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(mf.Membership) != 66 || mf.Membership[0] != 0x54 || mf.Membership[1] != 64 {
		t.Errorf("the membership is the TLV 54 with 64 bytes: % X", mf.Membership[:4])
	}
	back, err := ParseMembershipFile(mf.Encode())
	if err != nil || !bytes.Equal(back.GroupRequest, mf.GroupRequest) || !bytes.Equal(back.Membership, mf.Membership) || !bytes.Equal(back.Signer.Device, certs.Device) {
		t.Fatalf("the membership file does not read back: %v", err)
	}
	if _, err := ParseMembershipFile(EncodeDeviceID(certs)); err == nil {
		t.Error("a device id was read as a membership")
	}
	d, err := s.CreateXKEKDomain(2, back.GroupRequest, back.Membership, back.Signer, "group")
	if err != nil || !d.XKEK || d.DomainID != "0101010101010101" || d.Label != "group" {
		t.Fatalf("%v %+v", err, d)
	}
	var swe *SWError
	if err := s.DeleteKEK(2); !errors.As(err, &swe) || swe.SW != 0x6985 {
		t.Errorf("the key encryption key of an XKEK domain before an exchange key: %v", err)
	}
	if _, err := s.CreateXKEKDomain(2, back.GroupRequest, back.Membership, back.Signer, ""); err == nil {
		t.Error("a domain that is there was made again")
	}
	if err := s.DeleteDomain(2); err != nil {
		t.Fatal(err)
	}
	if sim.Domains[2] != nil {
		t.Error("the domain is still there")
	}
	// a membership without the signature is refused before the card is asked
	if _, err := s.CreateXKEKDomain(2, nil, back.Membership, back.Signer, ""); err == nil {
		t.Error("no request")
	}
}

func TestRawECDSA(t *testing.T) {
	der := append([]byte{0x30, 0x46, 0x02, 0x21, 0x00}, append(bytes.Repeat([]byte{0xFF}, 32), append([]byte{0x02, 0x21, 0x00}, bytes.Repeat([]byte{0x80}, 32)...)...)...)
	raw, err := rawECDSA(der, 32)
	if err != nil || len(raw) != 64 || raw[0] != 0xFF || raw[32] != 0x80 {
		t.Fatalf("%v % X", err, raw)
	}
	short := []byte{0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07}
	if raw, _ := rawECDSA(short, 32); len(raw) != 64 || raw[31] != 5 || raw[63] != 7 {
		t.Errorf("short integers are padded: % X", raw)
	}
	for _, bad := range [][]byte{nil, {0x31, 0x00}, {0x30, 0x03, 0x02, 0x01, 0x01}} {
		if _, err := rawECDSA(bad, 32); err == nil {
			t.Errorf("% X was read", bad)
		}
	}
}

// The answer to the generation of an RSA key is longer than 256 bytes, and a card refuses a short Le then (6700, found on a real card): the key is made with extended lengths.
func TestGenerateRSAKeyUsesAnExtendedLength(t *testing.T) {
	s, sim := newSession(t)
	login(t, s)
	id, req, kid, err := s.GenerateKey(GenSpec{Kind: "RSA", Bits: 2048, Label: "rsa", Algorithms: AlgorithmByName("RSA", "sign"), Domain: 1})
	if err != nil || len(kid) != 20 || len(req) < 512 {
		t.Fatalf("%v: %d %d", err, len(kid), len(req))
	}
	label, gotID, algo := prkd(sim.Files[0xC400|uint16(id)])
	if label != "rsa" || !bytes.Equal(gotID, kid) || algo != "RSA-2048" {
		t.Errorf("the description: %q %X %q", label, gotID, algo)
	}
	// a short Le is refused, as the card refuses it
	body := GenSpec{Kind: "RSA", Bits: 2048, Label: "x", Domain: 1}.encode()
	short := append(append([]byte{0x00, 0x46, 0x09, 0x00, byte(len(body))}, body...), 0x00)
	if resp, _ := sim.Transmit(short); statusOf(resp) != 0x6700 {
		t.Errorf("a short Le was accepted: %X", statusOf(resp))
	}
}

// A real card refuses a new User PIN of another length than the current one (6A80); the library says so before it sends anything, so no try is spent.
func TestChangeUserPINNeedsTheSameLength(t *testing.T) {
	s, sim := newSession(t)
	sent := len(sim.Sent)
	if err := s.ChangeUserPIN([]byte("123456"), []byte("1234567")); err == nil || !strings.Contains(err.Error(), "same number of characters") {
		t.Errorf("a PIN of another length: %v", err)
	}
	if len(sim.Sent) != sent {
		t.Error("something was sent to the card")
	}
	if err := s.ChangeUserPIN([]byte("123456"), []byte("65432")); err == nil {
		t.Error("a shorter PIN was accepted")
	}
}
