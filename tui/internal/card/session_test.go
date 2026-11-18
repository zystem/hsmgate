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
	file, _ := EncryptShare(share, []byte("pw"), nil)
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
