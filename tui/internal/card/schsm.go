package card

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// the application of the SmartCard-HSM
var aid = []byte{0x00, 0xA4, 0x04, 0x04, 0x0B, 0xE8, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x02, 0x01}

// the most key domains asked for (a card is initialised for a number of them; the one that is not there answers 6A88, and the first other answer ends the search)
const maxDomains byte = 8

// PIN is what the card says about a PIN without being given it.
type PIN struct {
	Name     string // "User PIN" or "SO PIN"
	Verified bool   // the card is open with it now (the service that holds the card has given it)
	Blocked  bool   // no tries left
	Tries    int    // tries left; -1 when the card did not say
	SW       uint16
}

// Text is the line of the tree: "User PIN not verified, 3 tries remaining (63C3)".
func (p PIN) Text() string {
	switch {
	case p.Verified:
		return fmt.Sprintf("%s verified (%04X)", p.Name, p.SW)
	case p.Blocked:
		return fmt.Sprintf("%s blocked, no tries remaining (%04X)", p.Name, p.SW)
	case p.Tries >= 0:
		word := "tries"
		if p.Tries == 1 {
			word = "try"
		}
		return fmt.Sprintf("%s not verified, %d %s remaining (%04X)", p.Name, p.Tries, word, p.SW)
	}
	return fmt.Sprintf("%s: the card answered %04X", p.Name, p.SW)
}

// Key is a private key on the card.
type Key struct {
	ID         int      // the number of the key on the card (the file CCnn)
	Label      string   // from the PKCS#15 description ("" when it has none)
	Algo       string   // "EC-256", "RSA-4096", or "" when the description is not one of those
	CKAID      []byte   // the PKCS#15 id, which PKCS#11 shows as CKA_ID: what hsmgate calls the label of a key on a card
	Algorithms []string // what the key may be used for, by name
	Domain     int      // the key domain it belongs to; -1 when the card did not say
	Uses       int64    // the use counter; -1 when there is none
}

// Domain is a key domain: a set of keys that share a key encryption key (DKEK) and can be copied to another card that holds the same one.
type Domain struct {
	Number      int
	Created     bool
	XKEK        bool   // the domain has an XKEK (the card says so by giving the identifier of a key domain after the check value), not a DKEK made of shares
	DomainID    string // of an XKEK domain: the first 8 bytes of the identifier of the key domain, in hexadecimal
	Shares      int    // DKEK shares in all
	Outstanding int    // shares still to be imported
	KCV         string // the key check value of the DKEK or XKEK, 16 hexadecimal digits
	Label       string
	Keys        []Key
}

// Tree is what the card shows.
type Tree struct {
	Reader     Reader
	Label      string // the label of the token
	DeviceID   string // from the device certificate, such as DECC1800263
	Version    string // "4.1"
	Platform   int
	FreeMemory int
	UserPIN    PIN
	SOPIN      PIN
	Domains    []Domain
	Loose      []Key // keys that belong to no domain the card named
}

// Read reads the tree of the card in a reader. It sends commands that only read, and no PIN.
func Read(ctx context.Context, run Run, r Reader) (*Tree, error) {
	t := &Tree{Reader: r}

	// first: the application, what the card says about itself, the PINs, the key domains, the list of objects
	apdus := [][]byte{aid, {0x80, 0x50, 0x00, 0x00, 0x00}, {0x00, 0x20, 0x00, 0x81}, {0x00, 0x20, 0x00, 0x88}, {0x00, 0xB1, 0x2F, 0x03, 0x04, 0x54, 0x02, 0x00, 0x00, 0x00}, {0x00, 0xB1, 0x2F, 0x02, 0x04, 0x54, 0x02, 0x00, 0x00, 0x00}}
	for d := byte(0); d < maxDomains; d++ {
		apdus = append(apdus, []byte{0x80, 0x52, 0x00, d, 0x00})
	}
	apdus = append(apdus, []byte{0x80, 0x58, 0x00, 0x00, 0x00})
	rs, err := Exchange(ctx, run, r.Nr, apdus...)
	if err != nil {
		return nil, err
	}
	if !rs[0].OK() {
		return nil, fmt.Errorf("the card in %q is not a SmartCard-HSM (selecting its application answered %04X)", r.Name, rs[0].SW)
	}
	if info := rs[1]; info.OK() && len(info.Data) >= 9 {
		d := info.Data
		t.FreeMemory = int(d[len(d)-7])<<24 | int(d[len(d)-6])<<16 | int(d[len(d)-5])<<8 | int(d[len(d)-4])
		t.Platform, t.Version = int(d[len(d)-3]), fmt.Sprintf("%d.%d", d[len(d)-2], d[len(d)-1])
	}
	t.UserPIN, t.SOPIN = pin("User PIN", rs[2].SW), pin("SO PIN", rs[3].SW)
	if rs[4].OK() {
		t.Label = string(find(rs[4].Data, 0x80))
	}
	if rs[5].OK() {
		t.DeviceID = deviceID(rs[5].Data)
	}
	last := len(rs) - 1
	for d := 0; d < int(maxDomains); d++ {
		resp := rs[6+d]
		switch {
		case resp.OK() && len(resp.Data) >= 10:
			t.Domains = append(t.Domains, parseDomain(d, resp.Data))
		case resp.SW == 0x6A88:
			t.Domains = append(t.Domains, Domain{Number: d})
		default:
			d = int(maxDomains) // the end of the domains this card was made with
		}
	}
	files := fileIDs(rs[last].Data)

	// second: what each object says. Keys: the file CCnn (the use counter, the algorithms, the domain) and the description C4nn; domains: the label C7nn.
	var ask [][]byte
	var kinds []string
	var nums []int
	for _, f := range files { // f[0] is the kind of the file, f[1] its number
		switch f[0] {
		case 0xCC:
			if f[1] > 0 { // key 0 is the key of the device
				ask = append(ask, []byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0xCC, f[1], 0x00})
				kinds, nums = append(kinds, "key"), append(nums, int(f[1]))
			}
		case 0xC4:
			ask = append(ask, []byte{0x00, 0xB1, 0xC4, f[1], 0x04, 0x54, 0x02, 0x00, 0x00, 0x00})
			kinds, nums = append(kinds, "desc"), append(nums, int(f[1]))
		case 0xC7:
			ask = append(ask, []byte{0x00, 0xB1, 0xC7, f[1], 0x04, 0x54, 0x02, 0x00, 0x00, 0x00})
			kinds, nums = append(kinds, "label"), append(nums, int(f[1]))
		}
	}
	keys := map[int]*Key{}
	if len(ask) > 0 {
		rs2, err := Exchange(ctx, run, r.Nr, append([][]byte{aid}, ask...)...)
		if err != nil {
			return nil, err
		}
		for i, resp := range rs2[1:] {
			n := nums[i]
			if !resp.OK() {
				continue
			}
			switch kinds[i] {
			case "key":
				k := keys[n]
				if k == nil {
					k = &Key{ID: n, Domain: -1, Uses: -1}
					keys[n] = k
				}
				fcp(resp.Data, k)
			case "desc":
				k := keys[n]
				if k == nil {
					k = &Key{ID: n, Domain: -1, Uses: -1}
					keys[n] = k
				}
				k.Label, k.CKAID, k.Algo = prkd(resp.Data)
			case "label":
				for j := range t.Domains {
					if t.Domains[j].Number == n {
						t.Domains[j].Label = string(find(resp.Data, 0x0C))
					}
				}
			}
		}
	}
	ids := make([]int, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		k := *keys[id]
		placed := false
		for j := range t.Domains {
			if t.Domains[j].Created && t.Domains[j].Number == k.Domain {
				t.Domains[j].Keys = append(t.Domains[j].Keys, k)
				placed = true
			}
		}
		if !placed {
			t.Loose = append(t.Loose, k)
		}
	}
	return t, nil
}

// parseDomain reads the answer of the card to the status of a key domain: the shares in all, the shares still to import, the check value of 8 bytes, and for an XKEK the identifier of a
// key domain.
func parseDomain(n int, data []byte) Domain {
	dm := Domain{Number: n, Created: true, Shares: int(data[0]), Outstanding: int(data[1]), KCV: strings.ToUpper(hex.EncodeToString(data[2:10]))}
	if len(data) > 10 { // more than the check value: the identifier of a key domain, which only an XKEK has
		id := data[10:]
		if len(id) > 8 {
			id = id[:8]
		}
		dm.XKEK, dm.DomainID = true, strings.ToUpper(hex.EncodeToString(id))
	}
	return dm
}

func pin(name string, sw uint16) PIN {
	p := PIN{Name: name, SW: sw, Tries: -1}
	switch {
	case sw == 0x9000:
		p.Verified = true
	case sw>>4 == 0x63C:
		p.Tries = int(sw & 0xF)
	case sw == 0x6983:
		p.Blocked, p.Tries = true, 0
	}
	return p
}

// fileIDs reads the answer to ENUMERATE OBJECTS: pairs of bytes, each a file identifier (the first byte says what kind of file, the second is its number).
func fileIDs(b []byte) [][2]byte {
	var ids [][2]byte
	for i := 0; i+1 < len(b); i += 2 {
		ids = append(ids, [2]byte{b[i], b[i+1]})
	}
	return ids
}

// fcp reads the answer to selecting a key file: the use counter (90), the algorithms (91) and the key domain (92) in the proprietary part (A5).
func fcp(b []byte, k *Key) {
	a5 := find(b, 0xA5)
	if a5 == nil {
		return
	}
	if v := find(a5, 0x90); len(v) == 4 {
		if n := int64(v[0])<<24 | int64(v[1])<<16 | int64(v[2])<<8 | int64(v[3]); n != 0xFFFFFFFF {
			k.Uses = n
		}
	}
	for _, a := range find(a5, 0x91) {
		k.Algorithms = append(k.Algorithms, algorithmName(a))
	}
	if v := find(a5, 0x92); len(v) == 1 {
		k.Domain = int(v[0])
	}
}

// prkd reads the PKCS#15 description of a private key: the label, the id, and the kind and size (A0: an EC key, 30: an RSA key).
func prkd(b []byte) (label string, id []byte, algo string) {
	tag, val, _, ok := tlv(b)
	if !ok {
		return
	}
	label = string(find(val, 0x0C))
	id = find(val, 0x04)
	bits := 0
	if a1 := find(val, 0xA1); a1 != nil {
		for _, c := range find(a1, 0x02) {
			bits = bits<<8 | int(c)
		}
	}
	switch tag {
	case 0xA0:
		algo = fmt.Sprintf("EC-%d", bits)
	case 0x30:
		algo = fmt.Sprintf("RSA-%d", bits)
	}
	return
}

// deviceID is the holder reference of the device certificate, in the form the card manager shows: the first 11 characters of the 16 (the rest is a counter).
func deviceID(b []byte) string {
	chr := string(find(b, 0x5F20))
	if len(chr) == 16 {
		return chr[:11]
	}
	return chr
}

// the algorithms a key may be used for, by the identifier the card gives them; what is not here is shown as its number
var algorithms = map[byte]string{
	0x20: "RSA sign raw", 0x21: "RSA decrypt raw", 0x22: "RSA decrypt PKCS#1 v1.5", 0x23: "RSA decrypt OAEP",
	0x31: "RSA sign SHA-1", 0x33: "RSA sign SHA-256", 0x35: "RSA sign SHA-512",
	0x40: "RSA-PSS", 0x41: "RSA-PSS SHA-1", 0x43: "RSA-PSS SHA-256", 0x45: "RSA-PSS SHA-512",
	0x70: "ECDSA raw", 0x71: "ECDSA SHA-1", 0x72: "ECDSA SHA-224", 0x73: "ECDSA SHA-256", 0x74: "ECDSA SHA-384", 0x75: "ECDSA SHA-512",
	0x80: "ECDH", 0x84: "ECDH XKEK", 0x92: "wrap", 0x93: "unwrap", 0x94: "replace", 0x98: "derive EC key", 0x99: "derive SP800-56C",
	0xA0: "sign (default)",
}

func algorithmName(a byte) string {
	if n, ok := algorithms[a]; ok {
		return n
	}
	return fmt.Sprintf("0x%02X", a)
}

// ---- TLV -----------------------------------------------------------------------------------------------------------------------------------------------

// tlv reads one tag, length and value (tags of one or two bytes, lengths of one to three bytes).
func tlv(b []byte) (tag int, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, b = int(b[0]), b[1:]
	if tag&0x1F == 0x1F {
		tag, b = tag<<8|int(b[0]), b[1:]
		if len(b) < 1 {
			return 0, nil, nil, false
		}
	}
	n := int(b[0])
	b = b[1:]
	switch {
	case n == 0x81 && len(b) >= 1:
		n, b = int(b[0]), b[1:]
	case n == 0x82 && len(b) >= 2:
		n, b = int(b[0])<<8|int(b[1]), b[2:]
	case n >= 0x80:
		return 0, nil, nil, false
	}
	if n > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[:n], b[n:], true
}

// find returns the value of the first element with a tag, looking inside the elements that hold others (the tags whose class bits say constructed).
func find(b []byte, want int) []byte {
	for len(b) > 0 {
		tag, val, rest, ok := tlv(b)
		if !ok {
			return nil
		}
		if tag == want {
			return val
		}
		first := tag
		if tag > 0xFF {
			first = tag >> 8
		}
		if first&0x20 != 0 {
			if v := find(val, want); v != nil {
				return v
			}
		}
		b = rest
	}
	return nil
}
