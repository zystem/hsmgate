package card

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/tui/internal/card/cardtest"
)

func TestDumpLineAcceptsWhatTheToolPrints(t *testing.T) {
	cases := [][]byte{
		{0x00, 0x01, 0x00, 0x01, 0xC1, 0x68, 0x06, 0x04, 0x01},
		[]byte("0123456789abcdef"),
		{0x41, 0x42},                   // the text "AB" looks like two more bytes
		{0x30, 0x20, 0x20, 0x20, 0x41}, // a text with spaces
		{0xFF},
	}
	for _, c := range cases {
		for _, long := range []bool{false, true} {
			in := c
			if long { // a longer answer: this is its last line, padded
				in = append(make([]byte, 16), c...)
			}
			var got []byte
			for _, l := range strings.Split(strings.TrimRight(cardtest.Dump(in), "\n"), "\n") {
				b, ok := dumpLine(l)
				if !ok {
					t.Fatalf("line %q was not read", l)
				}
				got = append(got, b...)
			}
			if hex.EncodeToString(got) != hex.EncodeToString(in) {
				t.Errorf("got % X, want % X", got, in)
			}
		}
	}
	if _, ok := dumpLine("Sending: 00 A4"); ok {
		t.Error("a message was taken for data")
	}
}

func TestParseReaders(t *testing.T) {
	out := "# Detected readers (pcsc)\nNr.  Card  Features  Name\n0    Yes             HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] (X) 00 00\n1    No              Other Reader 01 00\n"
	rs := parseReaders(out)
	if len(rs) != 2 || rs[0].Nr != 0 || !rs[0].HasCard || rs[1].HasCard || !strings.HasPrefix(rs[0].Name, "HID Global OMNIKEY") || rs[1].Name != "Other Reader 01 00" {
		t.Errorf("%+v", rs)
	}
	if len(parseReaders("No smart card readers found.\n")) != 0 {
		t.Error("a message was taken for a reader")
	}
}

func TestReadTheTreeOfACard(t *testing.T) {
	f := cardtest.New(t)
	rs, err := Readers(context.Background(), f.Run)
	if err != nil || len(rs) != 1 || !rs[0].HasCard {
		t.Fatalf("%v %+v", err, rs)
	}
	tree, err := Read(context.Background(), f.Run, rs[0])
	if err != nil {
		t.Fatal(err)
	}
	if tree.Label != "demo" || tree.DeviceID != "DECC1800263" || tree.Version != "4.1" || tree.FreeMemory != 115048 || tree.Platform != 6 {
		t.Errorf("%+v", tree)
	}
	if got := tree.UserPIN.Text(); got != "User PIN not verified, 3 tries remaining (63C3)" {
		t.Error(got)
	}
	if got := tree.SOPIN.Text(); got != "SO PIN not verified, 15 tries remaining (63CF)" {
		t.Error(got)
	}
	if len(tree.Domains) != 4 { // 0 and 1 are there, 2 and 3 are not, and the card answers 6A86 for 4: the end
		t.Fatalf("%d domains: %+v", len(tree.Domains), tree.Domains)
	}
	d0, d1, d2 := tree.Domains[0], tree.Domains[1], tree.Domains[2]
	if !d0.Created || d0.KCV != "AA02030405060708" || d0.Label != "first" || d0.Shares != 1 || d0.Outstanding != 0 {
		t.Errorf("%+v", d0)
	}
	if d1.Shares != 2 || d1.Outstanding != 1 || d1.Label != "second" {
		t.Errorf("%+v", d1)
	}
	if d2.Created || d2.Number != 2 {
		t.Errorf("%+v", d2)
	}
	if len(d0.Keys) != 1 || d0.Keys[0].Label != "signer" || d0.Keys[0].Algo != "EC-256" || d0.Keys[0].ID != 1 || d0.Keys[0].Uses != -1 || strings.Join(d0.Keys[0].Algorithms, ",") != "ECDH,wrap" || len(d0.Keys[0].CKAID) != 20 {
		t.Errorf("%+v", d0.Keys)
	}
	if len(d1.Keys) != 1 || d1.Keys[0].Algo != "RSA-4096" || d1.Keys[0].Uses != 7 || d1.Keys[0].Label != "rsa key" {
		t.Errorf("%+v", d1.Keys)
	}
	if len(tree.Loose) != 0 {
		t.Errorf("%+v", tree.Loose)
	}
	// nothing but reading: no command that verifies a PIN (INS 20 with data) or writes
	for _, call := range f.Calls {
		for _, c := range call {
			b, _ := hex.DecodeString(strings.ReplaceAll(c, ":", ""))
			switch b[1] {
			case 0xA4, 0x50, 0x52, 0x58, 0xB1:
			case 0x20:
				if len(b) != 4 {
					t.Errorf("a PIN was sent: %s", c)
				}
			default:
				t.Errorf("a command that is not a read: %s", c)
			}
			if b[1] == 0x52 && b[2] != 0x00 {
				t.Errorf("a key domain command that is not a status: %s", c)
			}
		}
	}
}

func TestKeyOfADomainThatIsGoneIsLoose(t *testing.T) {
	f := cardtest.New(t)
	f.FCPs["CC02"] = cardtest.KeyFCP(3, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0x21)
	tree, err := Read(context.Background(), f.Run, Reader{Name: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Loose) != 1 || tree.Loose[0].ID != 2 {
		t.Errorf("%+v", tree.Loose)
	}
}

func TestPINStates(t *testing.T) {
	for sw, want := range map[uint16]string{
		0x9000: "User PIN verified (9000)",
		0x63C1: "User PIN not verified, 1 try remaining (63C1)",
		0x6983: "User PIN blocked, no tries remaining (6983)",
		0x6A88: "User PIN: the card answered 6A88",
	} {
		if got := pin("User PIN", sw).Text(); got != want {
			t.Errorf("%04X: %q, want %q", sw, got, want)
		}
	}
}

func TestNotACard(t *testing.T) {
	run := func(context.Context, string, ...string) (string, error) {
		return "Sending: 00 A4 04 04\nReceived (SW1=0x6A, SW2=0x82)\n", nil
	}
	if _, err := Exchange(context.Background(), run, 0, []byte{0, 0xA4, 4, 4}, []byte{0, 0}); err == nil || !strings.Contains(err.Error(), "1 answers to 2") {
		t.Errorf("%v", err)
	}
	wrong := func(ctx context.Context, name string, args ...string) (string, error) {
		return "Sending: 00 A4 04 04\nReceived (SW1=0x6A, SW2=0x82)\n" + strings.Repeat("Sending: 00\nReceived (SW1=0x6D, SW2=0x00)\n", len(args)/2-2), nil
	}
	if _, err := Read(context.Background(), wrong, Reader{Name: "x"}); err == nil || !strings.Contains(err.Error(), "not a SmartCard-HSM") {
		t.Errorf("%v", err)
	}
}

func TestNoTool(t *testing.T) {
	run := func(context.Context, string, ...string) (string, error) {
		return "", fmt.Errorf(`exec: "opensc-tool": executable file not found in $PATH`)
	}
	if _, err := Readers(context.Background(), run); err == nil || !strings.Contains(err.Error(), "apt install opensc") {
		t.Errorf("%v", err)
	}
}

func TestTLV(t *testing.T) {
	long := append([]byte{0x7F, 0x21, 0x81, 0xE4}, make([]byte, 0xE4)...)
	if tag, val, _, ok := tlv(long); !ok || tag != 0x7F21 || len(val) != 0xE4 {
		t.Errorf("%X %d %v", tag, len(val), ok)
	}
	for _, bad := range [][]byte{nil, {0x30}, {0x30, 0x05, 1}, {0x30, 0x85}, {0x7F}, {0x7F, 0x21}} {
		if _, _, _, ok := tlv(bad); ok {
			t.Errorf("% X was read", bad)
		}
	}
	if find(nil, 1) != nil || find([]byte{0x30, 0x03, 0x80, 0x05}, 0x80) != nil {
		t.Error("a broken text gave a value")
	}
}

// A key domain with an XKEK is told from one with a DKEK by what follows the check value: the identifier of a key domain.
func TestXKEKDomain(t *testing.T) {
	f := cardtest.New(t)
	f.Domains[2] = []byte{0, 0, 0xCC, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	tree, err := Read(context.Background(), f.Run, Reader{Name: "r"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Domains) != 4 || tree.Domains[0].XKEK || tree.Domains[1].XKEK {
		t.Fatalf("%+v", tree.Domains)
	}
	x := tree.Domains[2]
	if !x.Created || !x.XKEK || x.KCV != "CC02030405060708" || x.DomainID != "0102030405060708" {
		t.Errorf("%+v", x)
	}
	if tree.Domains[3].Created {
		t.Errorf("%+v", tree.Domains[3])
	}
}
