// Package card reads a SmartCard-HSM the way the tree of a card manager shows it: the PINs and their tries, the key domains with their key check values, the keys.
//
// It talks to the card with the `opensc-tool` program (package opensc, which a card needs anyway) and sends only commands that read: no PIN is verified, nothing is written.
// Nothing here is linked to a PC/SC library, so the setup tool stays one static program. The commands are the SmartCard-HSM's own (the identifiers were learned from the scripts of its vendor's card
// manager and are answered by the card); what they answer was checked on one card, see docs/setup-tool.md.
package card

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// Run runs a program and returns what it printed (standard output and error together). sys.Run is one.
type Run func(ctx context.Context, name string, args ...string) (string, error)

// Reader is a card reader as `opensc-tool -l` lists it.
type Reader struct {
	Nr      int
	HasCard bool
	Name    string
}

// Readers lists the readers that PC/SC shows. An empty list is not an error: say so to the person.
func Readers(ctx context.Context, run Run) ([]Reader, error) {
	out, err := run(ctx, "opensc-tool", "-l")
	if err != nil {
		return nil, noTool(err)
	}
	return parseReaders(out), nil
}

func parseReaders(out string) []Reader {
	var rs []Reader
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 {
			continue
		}
		nr, err := strconv.Atoi(f[0])
		if err != nil || (f[1] != "Yes" && f[1] != "No") {
			continue // the heading, or a message
		}
		name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), f[0]))
		name = strings.TrimSpace(strings.TrimPrefix(name, f[1]))
		rs = append(rs, Reader{Nr: nr, HasCard: f[1] == "Yes", Name: name})
	}
	return rs
}

func noTool(err error) error {
	if strings.Contains(err.Error(), "executable file not found") {
		return fmt.Errorf("opensc-tool is not installed: it comes with the package opensc (apt install opensc, dnf install opensc)")
	}
	return err
}

// Response is the answer to one command: the data and the status word.
type Response struct {
	Data []byte
	SW   uint16
}

// OK says whether the card answered 9000.
func (r Response) OK() bool { return r.SW == 0x9000 }

// Exchange sends commands to the card in a reader, in one run of opensc-tool (so that the application stays selected between them), and returns one response for each.
func Exchange(ctx context.Context, run Run, reader int, apdus ...[]byte) ([]Response, error) {
	args := []string{"-r", strconv.Itoa(reader)}
	for _, a := range apdus {
		parts := make([]string, len(a))
		for i, b := range a {
			parts[i] = fmt.Sprintf("%02X", b)
		}
		args = append(args, "-s", strings.Join(parts, ":"))
	}
	out, err := run(ctx, "opensc-tool", args...)
	if err != nil {
		return nil, noTool(err)
	}
	rs, err := parseExchange(out)
	if err != nil {
		return nil, err
	}
	if len(rs) != len(apdus) {
		return nil, fmt.Errorf("the card gave %d answers to %d commands:\n%s", len(rs), len(apdus), strings.TrimSpace(out))
	}
	return rs, nil
}

// parseExchange reads what `opensc-tool -s` prints for each command: "Sending: …", then "Received (SW1=0x90, SW2=0x00):" and, when there is data, lines of hexadecimal bytes
// followed by the same bytes as text (after the last byte, or, on the last line of a longer answer, in a column of its own).
func parseExchange(out string) ([]Response, error) {
	var rs []Response
	var cur *Response
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, "\r")
		switch {
		case strings.HasPrefix(l, "Sending:"):
			if cur != nil {
				rs = append(rs, *cur)
				cur = nil
			}
		case strings.HasPrefix(l, "Received (SW1=0x"):
			sw, ok := parseSW(l)
			if !ok {
				return nil, fmt.Errorf("cannot read the status of %q", l)
			}
			cur = &Response{SW: sw}
		default:
			if cur == nil {
				continue // a line of the command, or a message before the first one
			}
			if b, ok := dumpLine(l); ok {
				cur.Data = append(cur.Data, b...)
			}
		}
	}
	if cur != nil {
		rs = append(rs, *cur)
	}
	return rs, nil
}

func parseSW(l string) (uint16, bool) {
	var sw1, sw2 uint8
	if _, err := fmt.Sscanf(l, "Received (SW1=0x%02X, SW2=0x%02X", &sw1, &sw2); err != nil {
		return 0, false
	}
	return uint16(sw1)<<8 | uint16(sw2), true
}

// dumpLine reads one line of a hexadecimal dump: up to 16 bytes written as "XX " and then the same bytes as text (a dot for what cannot be printed). The text may be cut short
// and may itself look like hexadecimal, so the number of bytes is the one for which the text matches.
func dumpLine(l string) ([]byte, bool) {
	for k := 16; k >= 1; k-- {
		if len(l) < 3*k {
			continue
		}
		b := make([]byte, 0, k)
		ok := true
		for i := 0; i < k; i++ {
			g := l[3*i : 3*i+2]
			v, err := strconv.ParseUint(g, 16, 8)
			if err != nil || (3*i+2 < len(l) && l[3*i+2] != ' ') {
				ok = false
				break
			}
			b = append(b, byte(v))
		}
		if !ok {
			continue
		}
		want := strings.TrimRight(printable(b), " ")
		if strings.TrimRight(l[3*k:], " ") == want { // the text follows the last byte
			return b, true
		}
		if len(l) >= 48 && strings.TrimRight(l[48:], " ") == want { // or it is in the column after 16 bytes (the last line of a longer answer is padded)
			return b, true
		}
	}
	return nil, false
}

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
