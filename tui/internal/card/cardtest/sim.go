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
	mu       sync.Mutex
	PIN      string
	Tries    int
	SOTries  int
	Logged   bool
	Limit    int // the number of key domains the card was made with
	Domains  map[byte]*SimDomain
	Keys     map[byte]*SimKey
	Files    map[uint16][]byte
	Calls    []string // the instruction bytes of the commands, "A4", "20", for a test to look at
	Sent     [][]byte // every command, as it came
	pending  []byte
	verified map[string]bool // the certificates the card has verified
}

// SimDomain is a key domain of the simulated card.
type SimDomain struct {
	Shares, Outstanding int
	DKEK                []byte
	XKEK                []byte // the identifier of an XKEK key domain (8 bytes); nil for a DKEK domain
}

// SimKey is a key of the simulated card.
type SimKey struct {
	Domain int
	Wrap   bool
	Data   []byte
	Algs   []byte // the algorithms of a key that was generated (empty: ECDH, and wrap when Wrap)
}

// NewSim is a card with the User PIN 123456 (3 tries), 4 key domains, none created.
func NewSim() *Sim {
	s := &Sim{PIN: "123456", Tries: 3, SOTries: 15, Limit: 4, Domains: map[byte]*SimDomain{}, Keys: map[byte]*SimKey{}, Files: map[uint16][]byte{}}
	pt := func(b byte) []byte { return append([]byte{0x04}, bytes.Repeat([]byte{b}, 64)...) }
	cert := func(car, chr string, point []byte) []byte {
		inner := tlvBytes(0x5F29, []byte{0}) // profile
		inner = append(inner, tlvBytes(0x42, []byte(car))...)
		inner = append(inner, tlvBytes(0x7F49, append([]byte{0x06, 0x01, 0x01}, tlvBytes(0x86, point)...))...)
		inner = append(inner, tlvBytes(0x5F20, []byte(chr))...)
		return tlvBytes(0x7F21, append(tlvBytes(0x7F4E, inner), tlvBytes(0x5F37, bytes.Repeat([]byte{9}, 64))...))
	}
	s.Files[0x2F02] = append(cert("SIMDICA00001", "SIMDEVICE0001", pt(7)), cert("SIMROOT00001", "SIMDICA00001", pt(8))...)
	return s
}

// tlvBytes writes a tag (one or two bytes), a length in BER and a value.
func tlvBytes(tag int, v []byte) []byte {
	var t []byte
	if tag > 0xFF {
		t = []byte{byte(tag >> 8), byte(tag)} // #nosec G115 -- a tag of two bytes
	} else {
		t = []byte{byte(tag)} // #nosec G115 -- a tag of one byte
	}
	switch {
	case len(v) < 0x80:
		t = append(t, byte(len(v))) // #nosec G115 -- below 128
	case len(v) < 0x100:
		t = append(t, 0x81, byte(len(v))) // #nosec G115 -- below 256
	default:
		t = append(t, 0x82, byte(len(v)>>8), byte(len(v))) // #nosec G115 -- a few kilobytes
	}
	return append(t, v...)
}

// findTag looks for the first element with a tag among siblings and inside constructed ones (what the simulator needs of a parser).
func findTag(b []byte, want int) []byte {
	for len(b) > 1 {
		tag, i := int(b[0]), 1
		if tag&0x1F == 0x1F {
			tag, i = tag<<8|int(b[1]), 2
		}
		if len(b) <= i {
			return nil
		}
		n := int(b[i])
		i++
		if n == 0x81 && len(b) > i {
			n, i = int(b[i]), i+1
		} else if n == 0x82 && len(b) > i+1 {
			n, i = int(b[i])<<8|int(b[i+1]), i+2
		}
		if i+n > len(b) {
			return nil
		}
		val := b[i : i+n]
		if tag == want {
			return val
		}
		first := tag
		if tag > 0xFF {
			first = tag >> 8
		}
		if first&0x20 != 0 {
			if v := findTag(val, want); v != nil {
				return v
			}
		}
		b = b[i+n:]
	}
	return nil
}

func kcvOf(dkek []byte) []byte {
	h := sha256.Sum256(dkek)
	return h[:8]
}

func (s *Sim) status(n byte) []byte {
	d := s.Domains[n]
	out := append([]byte{byte(d.Shares), byte(d.Outstanding)}, kcvOf(d.DKEK)...) // #nosec G115 -- sizes and numbers of the test data
	if d.XKEK != nil {
		out = append(out, d.XKEK...) // the identifier of the key domain follows the check value
	}
	return out
}

func (s *Sim) pinSW(tries int) uint16 { return 0x63C0 | uint16(tries) } // #nosec G115 -- sizes and numbers of the test data

// Transmit is the connection: one command in, the answer with its status word out.
func (s *Sim) Transmit(apdu []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Sent = append(s.Sent, append([]byte{}, apdu...))
	data, sw := s.handle(apdu)
	return append(append([]byte{}, data...), byte(sw>>8), byte(sw)), nil // #nosec G115 -- a copy: the data may be a part of a file, and appending would write into it
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
			if len(k.Algs) > 0 {
				algs = k.Algs
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
		n, hdr := int(body[5]), 6
		switch {
		case body[5] == 0x81 && len(body) > 6:
			n, hdr = int(body[6]), 7
		case body[5] == 0x82 && len(body) > 7:
			n, hdr = int(body[6])<<8|int(body[7]), 8
		case body[5] >= 0x80:
			return nil, 0x6A80 // the length of the data is not in the form of BER: what the real card refused
		}
		if hdr+n > len(body) {
			return nil, 0x6A80
		}
		f := s.Files[fid]
		if off > len(f) {
			return nil, 0x6B00
		}
		s.Files[fid] = append(f[:off:off], body[hdr:hdr+n]...)
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
		set := map[uint16]bool{0x2F02: true, 0x2F03: true}
		for fid := range s.Files {
			set[fid] = true
		}
		var ids []uint16
		for fid := range set {
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
	case ins == 0x46: // generate a key pair: the request answers
		if !s.Logged {
			return nil, 0x6982
		}
		if _, ok := s.Keys[p1]; ok {
			return nil, 0x6985
		}
		k := &SimKey{Domain: 0, Wrap: true}
		if d := findTag(body, 0x92); len(d) == 1 {
			k.Domain = int(d[0])
		}
		if a := findTag(body, 0x91); len(a) > 0 {
			k.Algs, k.Wrap = append([]byte{}, a...), bytes.Contains(a, []byte{0x92})
		}
		x := bytes.Repeat([]byte{p1}, 32)
		point := append(append([]byte{0x04}, x...), bytes.Repeat([]byte{0x77}, 32)...)
		s.Keys[p1] = k
		inner := tlvBytes(0x5F29, []byte{0})
		inner = append(inner, tlvBytes(0x42, []byte("UTDUMMY00001"))...)
		inner = append(inner, tlvBytes(0x7F49, append([]byte{0x06, 0x01, 0x01}, tlvBytes(0x86, point)...))...)
		inner = append(inner, tlvBytes(0x5F20, []byte("UTDUMMY00001"))...)
		req := append(tlvBytes(0x7F21, append(tlvBytes(0x7F4E, inner), tlvBytes(0x5F37, bytes.Repeat([]byte{5}, 64))...)), tlvBytes(0x42, []byte("SIMDEVICE0001"))...)
		req = append(req, tlvBytes(0x5F37, bytes.Repeat([]byte{6}, 64))...)
		return tlvBytes(0x67, req), 0x9000
	case ins == 0x68: // sign
		if !s.Logged {
			return nil, 0x6982
		}
		if _, ok := s.Keys[p1]; !ok {
			return nil, 0x6A88
		}
		r := bytes.Repeat([]byte{0x11}, 32)
		sg := bytes.Repeat([]byte{0x22}, 32)
		return append(append([]byte{0x30, 0x44, 0x02, 0x20}, r...), append([]byte{0x02, 0x20}, sg...)...), 0x9000
	case ins == 0x22 && p1 == 0x81 && p2 == 0xB6: // select the key for the command that follows: a certificate that is not verified yet is asked for again with its authority
		ref := string(findTag(body, 0x83))
		if s.verified[ref] {
			return nil, 0x9000
		}
		if ref == "SIMDEVICE0001" || ref == "SIMDICA00001" {
			return nil, 0x6A88 // the holder is not known yet
		}
		return nil, 0x9000
	case ins == 0x2A && p1 == 0x00 && p2 == 0xBE: // verify a certificate: its holder is known from now on
		if chr := findTag(body, 0x5F20); len(chr) > 0 {
			if s.verified == nil {
				s.verified = map[string]bool{}
			}
			s.verified[string(chr)] = true
		}
		return nil, 0x9000
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
	case 0x02: // create an XKEK domain
		if !s.Logged {
			return nil, 0x6982
		}
		if d != nil {
			return nil, 0x6A80
		}
		pt := findTag(body, 0x86)
		if len(pt) != 65 || findTag(body, 0x54) == nil {
			return nil, 0x6A80
		}
		s.Domains[n] = &SimDomain{DKEK: make([]byte, 32), XKEK: append([]byte{}, pt[1:9]...)}
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
		if d.XKEK != nil {
			return nil, 0x6985 // an XKEK domain has no key encryption key until an exchange key is made
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
