// Package cardtest is a SmartCard-HSM made of bytes, behind the interface of opensc-tool: it answers the commands of package card as the card of a test would, and prints them as
// the program does. It is for tests only.
package cardtest

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func printable(b []byte) string {
	s := make([]byte, len(b))
	for i, c := range b {
		if c >= 0x20 && c < 0x7f {
			s[i] = c
		} else {
			s[i] = '.'
		}
	}
	return string(s)
}

// Dump writes bytes as opensc-tool does: 16 to a line, "XX " each and then the same bytes as text; the last line of a longer answer is padded to the column of the text.
func Dump(b []byte) string {
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		var hx strings.Builder
		for _, c := range b[i:end] {
			fmt.Fprintf(&hx, "%02X ", c)
		}
		line := hx.String()
		if len(b) > 16 {
			line += strings.Repeat(" ", 48-len(line))
		}
		sb.WriteString(line + printable(b[i:end]) + "\n")
	}
	return sb.String()
}

func tl(tag byte, v ...[]byte) []byte {
	var body []byte
	for _, x := range v {
		body = append(body, x...)
	}
	return append([]byte{tag, byte(len(body))}, body...)
}

func ec(label string, id byte, bits int) []byte {
	idb := make([]byte, 20)
	idb[0] = id
	return tl(0xA0, tl(0x30, tl(0x0C, []byte(label))), tl(0x30, tl(0x04, idb), tl(0x03, []byte{7, 0x20, 0x80})), tl(0xA1, tl(0x30, tl(0x30, tl(0x04)), tl(0x02, []byte{byte(bits >> 8), byte(bits)}))))
}

// KeyFCP is the answer to selecting a key file: no use counter when uses is FFFFFFFF, the algorithms and the key domain.
func KeyFCP(domain byte, uses []byte, algs ...byte) []byte {
	return tl(0x62, tl(0x80, []byte{0, 0}), tl(0x83, []byte{0xCC, 1}), tl(0xA5, tl(0x90, uses), tl(0x91, algs), tl(0x92, []byte{domain})))
}

// ReaderInfo is a reader of the fake: with a card or without, and the label of the card in it ("" : the label of the Card).
type ReaderInfo struct {
	Name    string
	HasCard bool
	Label   string
}

type Card struct {
	t       *testing.T
	Readers []ReaderInfo // the readers `opensc-tool -l` lists; nil: one reader with a card
	cur     int          // the reader of the run
	Label   string
	Domains map[byte][]byte   // number -> the answer; absent: 6A88 up to `limit`, then 6A86
	Limit   byte              // the number of domains the card was made with
	Files   map[string][]byte // "C401" -> content
	FCPs    map[string][]byte // "CC01" -> the answer of selecting it
	SW      map[string]uint16 // the PINs: "81" or "88"
	Calls   [][]string
}

func (f *Card) Run(_ context.Context, name string, args ...string) (string, error) {
	if name != "opensc-tool" {
		f.t.Fatalf("a program that is not opensc-tool: %s", name)
	}
	if args[0] == "-l" {
		rs := f.Readers
		if rs == nil {
			rs = []ReaderInfo{{Name: "Test Reader 00 00", HasCard: true}}
		}
		out := "# Detected readers (pcsc)\nNr.  Card  Features  Name\n"
		for i, r := range rs {
			card := "No "
			if r.HasCard {
				card = "Yes"
			}
			out += fmt.Sprintf("%d    %s             %s\n", i, card, r.Name)
		}
		return out, nil
	}
	if args[0] == "-r" && len(args) > 1 {
		fmt.Sscanf(args[1], "%d", &f.cur)
	}
	var sb strings.Builder
	var call []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] != "-s" {
			continue
		}
		call = append(call, args[i+1])
		b, _ := hex.DecodeString(strings.ReplaceAll(args[i+1], ":", ""))
		data, sw := f.card(b)
		sb.WriteString("Sending: " + strings.ReplaceAll(args[i+1], ":", " ") + " \n")
		if len(data) == 0 {
			fmt.Fprintf(&sb, "Received (SW1=0x%02X, SW2=0x%02X)\n", sw>>8, sw&0xFF)
		} else {
			fmt.Fprintf(&sb, "Received (SW1=0x%02X, SW2=0x%02X):\n%s", sw>>8, sw&0xFF, Dump(data))
		}
	}
	f.Calls = append(f.Calls, call)
	return sb.String(), nil
}

func (f *Card) card(b []byte) ([]byte, uint16) {
	switch {
	case b[0] == 0x00 && b[1] == 0xA4 && b[2] == 0x04:
		return []byte{0x62, 0x0A, 0x82, 0x01, 0x78, 0x85, 0x05, 0x00, 0x01, 0x06, 0x04, 0x01}, 0x9000
	case b[0] == 0x80 && b[1] == 0x50:
		return []byte{0x00, 0x01, 0x00, 0x01, 0xC1, 0x68, 0x06, 0x04, 0x01}, 0x9000
	case b[0] == 0x00 && b[1] == 0x20:
		return nil, f.SW[fmt.Sprintf("%02X", b[3])]
	case b[0] == 0x00 && b[1] == 0xB1 && b[2] == 0x2F && b[3] == 0x03:
		label := f.Label
		if f.cur < len(f.Readers) && f.Readers[f.cur].Label != "" {
			label = f.Readers[f.cur].Label
		}
		return tl(0x30, tl(0x02, []byte{0}), tl(0x80, []byte(label))), 0x9000
	case b[0] == 0x00 && b[1] == 0xB1 && b[2] == 0x2F && b[3] == 0x02:
		chr := append([]byte{0x5F, 0x20, 0x10}, []byte("DECC180026300000")...)
		inner := append(append([]byte{0x42, 0x0D}, []byte("DEDICC1800001")...), chr...)
		body := append([]byte{0x7F, 0x4E, byte(len(inner))}, inner...)
		return append([]byte{0x7F, 0x21, byte(len(body))}, body...), 0x9000
	case b[0] == 0x80 && b[1] == 0x52:
		if d, ok := f.Domains[b[3]]; ok {
			return d, 0x9000
		}
		if b[3] < f.Limit {
			return nil, 0x6A88
		}
		return nil, 0x6A86
	case b[0] == 0x80 && b[1] == 0x58:
		var ids []byte
		for _, k := range []string{"C700", "C401", "CC01", "C701", "C402", "CC02", "CC00"} {
			if _, ok := f.Files[k]; ok {
				v, _ := hex.DecodeString(k)
				ids = append(ids, v...)
			}
		}
		return ids, 0x9000
	case b[0] == 0x00 && b[1] == 0xA4 && b[2] == 0x00:
		if d, ok := f.FCPs[fmt.Sprintf("%02X%02X", b[5], b[6])]; ok {
			return d, 0x9000
		}
		return nil, 0x6A82
	case b[0] == 0x00 && b[1] == 0xB1:
		if d, ok := f.Files[fmt.Sprintf("%02X%02X", b[2], b[3])]; ok {
			return d, 0x9000
		}
		return nil, 0x6A82
	}
	return nil, 0x6D00
}

func New(t *testing.T) *Card {
	kcv := func(shares, out byte, k byte) []byte { return []byte{shares, out, k, 2, 3, 4, 5, 6, 7, 8} }
	return &Card{
		t: t, Label: "demo", Limit: 4,
		Domains: map[byte][]byte{0: kcv(1, 0, 0xAA), 1: kcv(2, 1, 0xBB)},
		Files: map[string][]byte{
			"C700": tl(0x30, tl(0x30, tl(0x0C, []byte("first")))),
			"C701": tl(0x30, tl(0x30, tl(0x0C, []byte("second")))),
			"C401": ec("signer", 1, 256),
			"C402": tl(0x30, tl(0x30, tl(0x0C, []byte("rsa key"))), tl(0x30, tl(0x04, make([]byte, 20))), tl(0xA1, tl(0x30, tl(0x30, tl(0x04)), tl(0x02, []byte{0x10, 0x00})))),
			"CC01": nil, "CC02": nil, "CC00": nil,
		},
		FCPs: map[string][]byte{
			"CC01": KeyFCP(0, []byte{0xFF, 0xFF, 0xFF, 0xFF}, 0x80, 0x92),
			"CC02": KeyFCP(1, []byte{0, 0, 0, 7}, 0x21, 0x23),
		},
		SW: map[string]uint16{"81": 0x63C3, "88": 0x63CF},
	}
}
