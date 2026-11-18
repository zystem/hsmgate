package cardtest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Sim is a SmartCard-HSM made of bytes that can be changed: PINs with tries, key domains with DKEK shares, keys that can be wrapped and unwrapped, files. It answers the commands of
// package card the way the real card did when it was tried (extended length for long bodies and answers, 6884 for a chained command, 6982 until the User PIN is given), and it ends
// a login when the application is selected. It is for tests only.
type Sim struct {
	mu      sync.Mutex
	PIN     string
	Tries   int
	SOTries int
	Logged  bool
	Limit   int // the number of key domains the card was made with
	Domains map[byte]*SimDomain
	Keys    map[byte]*SimKey
	Files   map[uint16][]byte
	Calls   []string // the instruction bytes of the commands, "A4", "20", for a test to look at
	Sent    [][]byte // every command, as it came
	pending []byte
}

// SimDomain is a key domain of the simulated card.
type SimDomain struct {
	Shares, Outstanding int
	DKEK                []byte
}

// SimKey is a key of the simulated card.
type SimKey struct {
	Domain int
	Wrap   bool
	Data   []byte
}

// NewSim is a card with the User PIN 123456 (3 tries), 4 key domains, none created.
func NewSim() *Sim {
	return &Sim{PIN: "123456", Tries: 3, SOTries: 15, Limit: 4, Domains: map[byte]*SimDomain{}, Keys: map[byte]*SimKey{}, Files: map[uint16][]byte{}}
}

func kcvOf(dkek []byte) []byte {
	h := sha256.Sum256(dkek)
	return h[:8]
}

func (s *Sim) status(n byte) []byte {
	d := s.Domains[n]
	return append([]byte{byte(d.Shares), byte(d.Outstanding)}, kcvOf(d.DKEK)...) // #nosec G115 -- sizes and numbers of the test data
}

func (s *Sim) pinSW(tries int) uint16 { return 0x63C0 | uint16(tries) } // #nosec G115 -- sizes and numbers of the test data

// Transmit is the connection: one command in, the answer with its status word out.
func (s *Sim) Transmit(apdu []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Sent = append(s.Sent, append([]byte{}, apdu...))
	data, sw := s.handle(apdu)
	return append(data, byte(sw>>8), byte(sw)), nil // #nosec G115 -- sizes and numbers of the test data
}

// Close ends the connection.
func (s *Sim) Close() error { return nil }

func (s *Sim) handle(a []byte) ([]byte, uint16) {
	if len(a) < 4 {
		return nil, 0x6700
	}
	cla, ins, p1, p2 := a[0], a[1], a[2], a[3]
	var body []byte
	le := -1
	switch rest := a[4:]; {
	case len(rest) == 0:
	case rest[0] == 0 && len(rest) >= 3: // extended length
		if len(rest) == 3 {
			le = int(rest[1])<<8 | int(rest[2])
			if le == 0 {
				le = 65536
			}
			break
		}
		n := int(rest[1])<<8 | int(rest[2])
		if 3+n > len(rest) {
			return nil, 0x6700
		}
		body = rest[3 : 3+n]
		if len(rest) == 3+n+2 {
			le = int(rest[3+n])<<8 | int(rest[3+n+1])
			if le == 0 {
				le = 65536
			}
		}
	case len(rest) == 1:
		le = int(rest[0])
		if le == 0 {
			le = 256
		}
	default:
		n := int(rest[0])
		if 1+n > len(rest) {
			return nil, 0x6700
		}
		body = rest[1 : 1+n]
		if len(rest) == 1+n+1 {
			le = int(rest[1+n])
			if le == 0 {
				le = 256
			}
		}
	}
	s.Calls = append(s.Calls, fmt.Sprintf("%02X", ins))
	if cla&0x10 != 0 {
		return nil, 0x6884 // command chaining is not supported
	}
	data, sw := s.run(cla, ins, p1, p2, body, le)
	if sw == 0x9000 && le > 0 && len(data) > le { // more than the answer can hold: the rest comes with GET RESPONSE
		s.pending = data[le:]
		n := len(s.pending)
		if n > 255 {
			n = 0
		}
		return data[:le], 0x6100 | uint16(n)
	}
	return data, sw
}

func (s *Sim) run(cla, ins, p1, p2 byte, body []byte, le int) ([]byte, uint16) {
	switch {
	case ins == 0xC0: // GET RESPONSE
		out := s.pending
		s.pending = nil
		return out, 0x9000
	case ins == 0xA4 && p1 == 0x04: // select the application: ends the login
		s.Logged = false
		return []byte{0x62, 0x0A, 0x82, 0x01, 0x78, 0x85, 0x05, 0x00, 0x01, 0x06, 0x04, 0x01}, 0x9000
	case ins == 0xA4 && p1 == 0x00: // select a file by its identifier
		if len(body) != 2 {
			return nil, 0x6700
		}
		fid := uint16(body[0])<<8 | uint16(body[1])
		if fid>>8 == 0xCC {
			k, ok := s.Keys[byte(fid)] // #nosec G115 -- sizes and numbers of the test data
			if !ok {
				return nil, 0x6A82
			}
			algs := []byte{0x80, 0x92}
			if !k.Wrap {
				algs = []byte{0x80}
			}
			return append([]byte{0x62, byte(14 + len(algs))}, append([]byte{0x80, 0x02, 0, 0, 0x83, 0x02, 0xCC, byte(fid), 0xA5, byte(7 + len(algs)), 0x90, 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x91, byte(len(algs))}, append(algs, 0x92, 0x01, byte(k.Domain))...)...), 0x9000 // #nosec G115 -- sizes and numbers of the test data
		}
		if _, ok := s.Files[fid]; ok {
			return []byte{0x62, 0x00}, 0x9000
		}
		return nil, 0x6A82
	case ins == 0xB1: // read binary of a file
		fid := uint16(p1)<<8 | uint16(p2)
		f, ok := s.Files[fid]
		if !ok {
			return nil, 0x6A82
		}
		if len(body) != 4 || body[0] != 0x54 {
			return nil, 0x6700
		}
		off := int(body[2])<<8 | int(body[3])
		if off > len(f) {
			return nil, 0x6B00
		}
		return f[off:], 0x9000
	case ins == 0xD7: // update binary
		if !s.Logged {
			return nil, 0x6982
		}
		fid := uint16(p1)<<8 | uint16(p2)
		if len(body) < 6 || body[0] != 0x54 || body[4] != 0x53 {
			return nil, 0x6A80
		}
		off := int(body[2])<<8 | int(body[3])
		f := s.Files[fid]
		if off > len(f) {
			return nil, 0x6B00
		}
		s.Files[fid] = append(f[:off:off], body[6:6+int(body[5])]...)
		return nil, 0x9000
	case ins == 0xE4: // delete a file
		if !s.Logged {
			return nil, 0x6982
		}
		fid := uint16(body[0])<<8 | uint16(body[1])
		if fid>>8 == 0xCC {
			if _, ok := s.Keys[byte(fid)]; !ok { // #nosec G115 -- sizes and numbers of the test data
				return nil, 0x6A82
			}
			delete(s.Keys, byte(fid)) // #nosec G115 -- sizes and numbers of the test data
			return nil, 0x9000
		}
		if _, ok := s.Files[fid]; !ok {
			return nil, 0x6A82
		}
		delete(s.Files, fid)
		return nil, 0x9000
	case ins == 0x20: // verify a PIN, or ask for its state
		if p2 == 0x88 {
			return nil, s.pinSW(s.SOTries)
		}
		if len(body) == 0 {
			if s.Logged {
				return nil, 0x9000
			}
			if s.Tries == 0 {
				return nil, 0x6983
			}
			return nil, s.pinSW(s.Tries)
		}
		if s.Tries == 0 {
			return nil, 0x6983
		}
		if string(body) == s.PIN {
			s.Tries, s.Logged = 3, true
			return nil, 0x9000
		}
		s.Tries--
		return nil, s.pinSW(s.Tries)
	case ins == 0x24 && p2 == 0x81: // change the PIN
		if !bytes.HasPrefix(body, []byte(s.PIN)) || len(body) == len(s.PIN) {
			s.Tries--
			return nil, s.pinSW(s.Tries)
		}
		s.PIN = string(body[len(s.PIN):])
		return nil, 0x9000
	case ins == 0x2C && p2 == 0x81: // unblock with the SO PIN (the SO PIN of the simulated card is 3537363231383830)
		if !bytes.HasPrefix(body, []byte("57621880")) {
			s.SOTries--
			return nil, s.pinSW(s.SOTries)
		}
		s.PIN, s.Tries = string(body[8:]), 3
		return nil, 0x9000
	case ins == 0x52: // key domains
		return s.domainCommand(p1, p2, body)
	case ins == 0x58: // list of objects
		var ids []uint16
		ids = append(ids, 0x2F02, 0x2F03)
		for fid := range s.Files {
			ids = append(ids, fid)
		}
		for id := range s.Keys {
			ids = append(ids, 0xCC00|uint16(id))
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		var out []byte
		for _, id := range ids {
			out = append(out, byte(id>>8), byte(id)) // #nosec G115 -- sizes and numbers of the test data
		}
		return out, 0x9000
	case ins == 0x72 && p2 == 0x92: // wrap a key
		if !s.Logged {
			return nil, 0x6982
		}
		k, ok := s.Keys[p1]
		if !ok {
			return nil, 0x6A88
		}
		if !k.Wrap {
			return nil, 0x6985
		}
		d := s.Domains[byte(k.Domain)] // #nosec G115 -- sizes and numbers of the test data
		return append(append([]byte{}, kcvOf(d.DKEK)...), k.Data...), 0x9000
	case ins == 0x74 && p2 == 0x93: // unwrap a key
		if !s.Logged {
			return nil, 0x6982
		}
		if _, ok := s.Keys[p1]; ok {
			return nil, 0x6985
		}
		if len(body) < 9 {
			return nil, 0x6A80
		}
		for n, d := range s.Domains {
			if d.Outstanding == 0 && bytes.Equal(kcvOf(d.DKEK), body[:8]) {
				s.Keys[p1] = &SimKey{Domain: int(n), Wrap: true, Data: append([]byte{}, body[8:]...)}
				return nil, 0x9000
			}
		}
		return nil, 0x6A88
	case ins == 0x84: // random
		return make([]byte, le), 0x9000
	}
	return nil, 0x6D00
}

func (s *Sim) domainCommand(p1, p2 byte, body []byte) ([]byte, uint16) {
	n := p2
	if int(n) >= s.Limit {
		return nil, 0x6A86
	}
	d := s.Domains[n]
	switch p1 {
	case 0x00: // the status, or a share
		if d == nil {
			return nil, 0x6A88
		}
		if len(body) == 0 {
			return s.status(n), 0x9000
		}
		if !s.Logged {
			return nil, 0x6982
		}
		if d.Outstanding == 0 || len(body) != 32 {
			return nil, 0x6985
		}
		for i := range d.DKEK {
			d.DKEK[i] ^= body[i]
		}
		d.Outstanding--
		return s.status(n), 0x9000
	case 0x01: // create
		if !s.Logged {
			return nil, 0x6982
		}
		if d != nil || len(body) != 1 || body[0] == 0 {
			return nil, 0x6A80
		}
		s.Domains[n] = &SimDomain{Shares: int(body[0]), Outstanding: int(body[0]), DKEK: make([]byte, 32)}
		return s.status(n), 0x9000
	case 0x03: // delete the domain
		if !s.Logged {
			return nil, 0x6982
		}
		if d == nil {
			return nil, 0x6A88
		}
		for _, k := range s.Keys {
			if k.Domain == int(n) {
				return nil, 0x6985
			}
		}
		delete(s.Domains, n)
		return nil, 0x9000
	case 0x04: // delete the key encryption key
		if !s.Logged {
			return nil, 0x6982
		}
		if d == nil {
			return nil, 0x6A88
		}
		d.DKEK, d.Outstanding = make([]byte, 32), d.Shares
		return s.status(n), 0x9000
	}
	return nil, 0x6A86
}

// ---- opensc-explorer -----------------------------------------------------------------------------------------------------------------------------------

// Starter is the program opensc-explorer made of a Sim: it reads "apdu XX:XX…" lines and prints what the real one prints (the command, "Sending:", "Received (SW1=…)", the bytes and
// their text, then "Success!" or "Failure: …"). It is what OpenExplorer is given in a test.
func (s *Sim) Starter() func(ctx context.Context, name string, args ...string) (io.WriteCloser, io.Reader, func() error, error) {
	return func(ctx context.Context, name string, args ...string) (io.WriteCloser, io.Reader, func() error, error) {
		inR, inW := io.Pipe()
		outR, outW := io.Pipe()
		go func() {
			defer outW.Close()
			fmt.Fprint(outW, "OpenSC Explorer version 0.26.1\n")
			sc := bufio.NewScanner(inR)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				fmt.Fprintf(outW, "OpenSC [3F00]> %s\n", line)
				if line == "quit" {
					return
				}
				hx, ok := strings.CutPrefix(line, "apdu ")
				if !ok {
					fmt.Fprint(outW, "Unknown command\n")
					continue
				}
				b, err := hex.DecodeString(strings.ReplaceAll(hx, ":", ""))
				if err != nil {
					fmt.Fprint(outW, "Invalid data\n")
					continue
				}
				resp, _ := s.Transmit(b)
				sw := binary.BigEndian.Uint16(resp[len(resp)-2:])
				data := resp[:len(resp)-2]
				fmt.Fprintf(outW, "Sending: %s \n", strings.ReplaceAll(hx, ":", " "))
				if len(data) == 0 {
					fmt.Fprintf(outW, "Received (SW1=0x%02X, SW2=0x%02X)\n", sw>>8, sw&0xFF)
				} else {
					fmt.Fprintf(outW, "Received (SW1=0x%02X, SW2=0x%02X):\n%s", sw>>8, sw&0xFF, Dump(data))
				}
				if sw == 0x9000 {
					fmt.Fprint(outW, "Success!\n")
				} else {
					fmt.Fprint(outW, "Failure: the card answered an error\n")
				}
			}
		}()
		return inW, outR, func() error { return nil }, nil
	}
}
