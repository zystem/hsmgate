package card

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Conn is a connection to a card: it sends one command and returns the answer with its status word at the end. The PC/SC one is OpenPCSC; a test gives a card made of bytes.
type Conn interface {
	Transmit(apdu []byte) ([]byte, error)
	Close() error
}

// Session talks to the application of a SmartCard-HSM over a Conn. The commands that change the card (and the PINs) go through it, and the PIN goes down a pipe, never in the
// arguments of a command line. Commands with a body or an answer longer than 255 bytes use the extended length that the card (and the reader) accept.
type Session struct{ c Conn }

// NewSession wraps a connection. Select must come first (it also ends a login that an earlier session left).
func NewSession(c Conn) *Session { return &Session{c: c} }

// Close ends the connection.
func (s *Session) Close() error { return s.c.Close() }

// SWError is a status word that the card answered where 9000 was expected.
type SWError struct {
	SW   uint16
	What string // what was asked, in words
}

func (e *SWError) Error() string {
	return fmt.Sprintf("%s: the card answered %04X, %s", e.What, e.SW, swText(e.SW))
}

func swText(sw uint16) string {
	switch {
	case sw == 0x6982:
		return "the security status is not satisfied (log in with the User PIN first)"
	case sw == 0x6983:
		return "the PIN is blocked"
	case sw>>4 == 0x63C:
		return fmt.Sprintf("the PIN is wrong, %d tries remain", sw&0xF)
	case sw == 0x6985:
		return "the conditions of use are not satisfied (for a key domain: the DKEK is not complete, or the domain still holds keys; for a key: it may not be wrapped)"
	case sw == 0x6A88:
		return "the object is not there"
	case sw == 0x6A80:
		return "the data is not right"
	case sw == 0x6A82:
		return "the file is not there"
	case sw == 0x6A84:
		return "there is not enough memory on the card"
	case sw == 0x6A86:
		return "the parameters are not right"
	case sw == 0x6700:
		return "the length is not right"
	case sw == 0x6D00 || sw == 0x6E00:
		return "the card does not know this command"
	}
	return "an answer this program has no words for"
}

// Send sends a command. A body longer than 255 bytes goes in one command with an extended length (the card answers 6884, "command chaining not supported", to the pieces of a chained
// one). expect asks for data back; an answer that does not fit in one piece is fetched with GET RESPONSE. The status word is returned, not turned into an error: the caller knows
// which ones are fine.
func (s *Session) Send(cla, ins, p1, p2 byte, data []byte, expect bool) ([]byte, uint16, error) {
	apdu := []byte{cla, ins, p1, p2}
	switch {
	case len(data) > 255:
		apdu = append(apdu, 0x00, byte(len(data)>>8), byte(len(data))) // #nosec G115 -- a body of a few kilobytes
		apdu = append(apdu, data...)
		if expect {
			apdu = append(apdu, 0x00, 0x00)
		}
	case len(data) > 0:
		apdu = append(apdu, byte(len(data))) // #nosec G115 -- 1 to 255, by the case
		apdu = append(apdu, data...)
		if expect {
			apdu = append(apdu, 0x00)
		}
	case expect:
		apdu = append(apdu, 0x00)
	}
	return s.answer(apdu)
}

// SendExtended sends a command with extended lengths whatever the size of the body: for a command whose answer is longer than 256 bytes, which a short Le makes the card refuse
// (6700), as the answer to the generation of an RSA key is.
func (s *Session) SendExtended(cla, ins, p1, p2 byte, data []byte) ([]byte, uint16, error) {
	apdu := []byte{cla, ins, p1, p2}
	if len(data) > 0 {
		apdu = append(apdu, 0x00, byte(len(data)>>8), byte(len(data))) // #nosec G115 -- a body of a few hundred bytes
		apdu = append(apdu, data...)
		apdu = append(apdu, 0x00, 0x00)
	} else {
		apdu = append(apdu, 0x00, 0x00, 0x00)
	}
	return s.answer(apdu)
}

func statusOf(resp []byte) uint16 {
	if len(resp) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(resp[len(resp)-2:])
}

// answer transmits the last command and collects the data of the answer.
func (s *Session) answer(apdu []byte) ([]byte, uint16, error) {
	var out []byte
	for i := 0; i < 64; i++ { // a bound: a card that never stops is not a card
		resp, err := s.c.Transmit(apdu)
		if err != nil {
			return nil, 0, err
		}
		if len(resp) < 2 {
			return nil, 0, errors.New("the card gave no status word")
		}
		out = append(out, resp[:len(resp)-2]...)
		sw := statusOf(resp)
		switch sw >> 8 {
		case 0x61: // more data: ask for it
			n := byte(sw & 0xFF)
			apdu = []byte{0x00, 0xC0, 0x00, 0x00, n}
			continue
		case 0x6C: // the length that was asked for was not right: ask again with the right one
			apdu = append(apdu[:len(apdu)-1:len(apdu)-1], byte(sw&0xFF))
			out = out[:0]
			continue
		}
		return out, sw, nil
	}
	return nil, 0, errors.New("the card kept saying there was more data")
}

// do is Send that turns a status word other than 9000 into an error that says what was asked.
func (s *Session) do(what string, cla, ins, p1, p2 byte, data []byte, expect bool) ([]byte, error) {
	out, sw, err := s.Send(cla, ins, p1, p2, data, expect)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if sw != 0x9000 {
		return nil, &SWError{SW: sw, What: what}
	}
	return out, nil
}

// Select selects the application of the SmartCard-HSM. It ends a login that was there.
func (s *Session) Select() error {
	_, err := s.do("selecting the SmartCard-HSM application", aid[0], aid[1], aid[2], aid[3], aid[5:], false)
	return err
}

// ---- PINs ----------------------------------------------------------------------------------------------------------------------------------------------

const (
	refUserPIN = 0x81
	refSOPIN   = 0x88
)

// PINState asks what the card says about a PIN, which does not cost a try.
func (s *Session) PINState(name string, ref byte) (PIN, error) {
	_, sw, err := s.Send(0x00, 0x20, 0x00, ref, nil, false)
	if err != nil {
		return PIN{}, err
	}
	return pin(name, sw), nil
}

// VerifyUserPIN gives the card the User PIN. A wrong PIN costs a try: the state that comes back says how many are left. The caller has looked at PINState first.
func (s *Session) VerifyUserPIN(p []byte) (PIN, error) {
	_, sw, err := s.Send(0x00, 0x20, 0x00, refUserPIN, p, false)
	if err != nil {
		return PIN{}, err
	}
	return pin("User PIN", sw), nil
}

// ChangeUserPIN replaces the User PIN (the card needs the current one given in the same command).
func (s *Session) ChangeUserPIN(current, next []byte) error {
	if len(current) != len(next) { // found on a real card: the command is the two PINs one after the other and the card cuts it in the middle; any other length gives 6A80
		return fmt.Errorf("the new User PIN must have the same number of characters as the current one (%d): the card refuses another length", len(current))
	}
	_, err := s.do("changing the User PIN", 0x00, 0x24, 0x00, refUserPIN, append(append([]byte{}, current...), next...), false)
	return err
}

// UnblockUserPIN sets the User PIN with the SO PIN (the initialization code), when the User PIN is blocked or forgotten.
func (s *Session) UnblockUserPIN(so, next []byte) error {
	_, err := s.do("unblocking the User PIN", 0x00, 0x2C, 0x00, refUserPIN, append(append([]byte{}, so...), next...), false)
	return err
}

// ChangeSOPIN replaces the SO PIN.
func (s *Session) ChangeSOPIN(current, next []byte) error {
	_, err := s.do("changing the SO PIN", 0x00, 0x24, 0x00, refSOPIN, append(append([]byte{}, current...), next...), false)
	return err
}

// ---- files ---------------------------------------------------------------------------------------------------------------------------------------------

// HasFile says whether a file is there.
func (s *Session) HasFile(fid uint16) bool {
	_, sw, err := s.Send(0x00, 0xA4, 0x00, 0x04, []byte{byte(fid >> 8), byte(fid)}, true) // #nosec G115 -- the two bytes of a file identifier
	return err == nil && sw == 0x9000
}

// DeleteFile deletes a file.
func (s *Session) DeleteFile(fid uint16) error {
	_, err := s.do(fmt.Sprintf("deleting the file %04X", fid), 0x00, 0xE4, 0x02, 0x00, []byte{byte(fid >> 8), byte(fid)}, false) // #nosec G115
	return err
}

// ReadFile reads a whole file, a block of up to 256 bytes at a time (a longer file, such as the device certificates, needs more than one).
func (s *Session) ReadFile(fid uint16) ([]byte, error) {
	var out []byte
	for {
		off := len(out)
		body := []byte{0x54, 0x02, byte(off >> 8), byte(off)}                    // #nosec G115 -- an offset in a file of a few kilobytes
		data, sw, err := s.Send(0x00, 0xB1, byte(fid>>8), byte(fid), body, true) // #nosec G115
		if err != nil {
			return nil, err
		}
		if sw != 0x9000 && sw != 0x6282 { // the end of the file (6B00: the offset is past it) or an error at the start
			if len(out) == 0 {
				return nil, &SWError{SW: sw, What: fmt.Sprintf("reading the file %04X", fid)}
			}
			return out, nil
		}
		out = append(out, data...)
		if len(data) < 256 {
			return out, nil
		}
	}
}

// WriteFile writes a file from its first byte (the card makes it when it is not there). The data goes as the object 53 after the offset (54), with its length in the form of BER
// (a block of more than 127 bytes needs the long form). A certificate file is checked by the card as a whole, so a file of a few hundred bytes goes in one command.
func (s *Session) WriteFile(fid uint16, data []byte) error {
	const block = 900
	off := 0
	for {
		n := len(data) - off
		if n > block {
			n = block
		}
		body := append([]byte{0x54, 0x02, byte(off >> 8), byte(off)}, der(0x53, data[off:off+n])...)                                 // #nosec G115 -- an offset in a file of a few kilobytes
		if _, err := s.do(fmt.Sprintf("writing the file %04X", fid), 0x00, 0xD7, byte(fid>>8), byte(fid), body, false); err != nil { // #nosec G115
			return err
		}
		off += n
		if off >= len(data) {
			return nil
		}
	}
}

// ---- key domains ---------------------------------------------------------------------------------------------------------------------------------------

// DomainStatus asks for a key domain: Created is false when it is not there.
func (s *Session) DomainStatus(n byte) (Domain, error) {
	data, sw, err := s.Send(0x80, 0x52, 0x00, n, nil, true)
	if err != nil {
		return Domain{}, err
	}
	return domainFrom(int(n), data, sw)
}

func domainFrom(n int, data []byte, sw uint16) (Domain, error) {
	switch {
	case sw == 0x6A88:
		return Domain{Number: n}, nil
	case sw == 0x9000 && len(data) >= 10:
		return parseDomain(n, data), nil
	}
	return Domain{}, &SWError{SW: sw, What: fmt.Sprintf("asking for the key domain %d", n)}
}

// CreateDKEKDomain makes a key domain whose DKEK will be made of the given number of shares (1 to 255, imported one by one), and gives it a label. Needs the User PIN.
func (s *Session) CreateDKEKDomain(n, shares byte, label string) (Domain, error) {
	data, err := s.do(fmt.Sprintf("creating the key domain %d", n), 0x80, 0x52, 0x01, n, []byte{shares}, true)
	if err != nil {
		return Domain{}, err
	}
	d, err := domainFrom(int(n), data, 0x9000)
	if err != nil {
		return Domain{}, err
	}
	if label != "" {
		fid := uint16(0xC700) | uint16(n)
		if s.HasFile(fid) {
			if err := s.DeleteFile(fid); err != nil {
				return d, err
			}
		}
		if err := s.WriteFile(fid, domainLabelFile(label)); err != nil {
			return d, fmt.Errorf("the key domain is made but its label was not written: %w", err)
		}
		d.Label = label
	}
	return d, nil
}

// domainLabelFile is the description of a key domain that holds its label: SEQUENCE { SEQUENCE { UTF8String } }.
func domainLabelFile(label string) []byte {
	inner := append([]byte{0x0C, byte(len(label))}, label...) // #nosec G115 -- a label is checked to be short
	mid := append([]byte{0x30, byte(len(inner))}, inner...)   // #nosec G115
	return append([]byte{0x30, byte(len(mid))}, mid...)       // #nosec G115
}

// ImportShare gives the card a share of the DKEK of a key domain. The answer says how many shares are still to come and the check value of what the card holds so far.
func (s *Session) ImportShare(n byte, share []byte) (Domain, error) {
	if len(share) != ShareLen {
		return Domain{}, fmt.Errorf("a DKEK share is %d bytes", ShareLen)
	}
	data, err := s.do(fmt.Sprintf("importing a share into the key domain %d", n), 0x80, 0x52, 0x00, n, share, true)
	if err != nil {
		return Domain{}, err
	}
	return domainFrom(int(n), data, 0x9000)
}

// DeleteKEK deletes the key encryption key of a key domain (the keys in it can no longer be wrapped or unwrapped).
func (s *Session) DeleteKEK(n byte) error {
	_, err := s.do(fmt.Sprintf("deleting the key encryption key of the key domain %d", n), 0x80, 0x52, 0x04, n, nil, false)
	return err
}

// DeleteDomain deletes an empty key domain with its label.
func (s *Session) DeleteDomain(n byte) error {
	if _, err := s.do(fmt.Sprintf("deleting the key domain %d", n), 0x80, 0x52, 0x03, n, nil, false); err != nil {
		return err
	}
	if fid := uint16(0xC700) | uint16(n); s.HasFile(fid) {
		return s.DeleteFile(fid)
	}
	return nil
}

// ---- keys ----------------------------------------------------------------------------------------------------------------------------------------------

// Objects lists the files of the card (the keys CCnn, their descriptions C4nn and so on).
func (s *Session) Objects() ([][2]byte, error) {
	data, err := s.do("listing the objects of the card", 0x80, 0x58, 0x00, 0x00, nil, true)
	if err != nil {
		return nil, err
	}
	return fileIDs(data), nil
}

// FreeKeyID is the lowest number from 1 that no key on the card has.
func (s *Session) FreeKeyID() (byte, error) {
	objs, err := s.Objects()
	if err != nil {
		return 0, err
	}
	used := map[byte]bool{}
	for _, o := range objs {
		if o[0] == 0xCC {
			used[o[1]] = true
		}
	}
	for id := 1; id < 256; id++ {
		if !used[byte(id)] { // #nosec G115 -- 1 to 255
			return byte(id), nil // #nosec G115
		}
	}
	return 0, errors.New("the card has no free key number")
}

// DeleteKey deletes a key: its file, its description and its certificates. Needs the User PIN.
func (s *Session) DeleteKey(id byte) error {
	if err := s.DeleteFile(0xCC00 | uint16(id)); err != nil {
		return err
	}
	for _, prefix := range []uint16{0xC400, 0xCE00} {
		if fid := prefix | uint16(id); s.HasFile(fid) {
			if err := s.DeleteFile(fid); err != nil {
				return err
			}
		}
	}
	return nil
}

// WrapKey makes the blob of a key encrypted under the DKEK of its key domain. The key must have been made with wrapping allowed. The blob is longer than a short answer can be, so
// the command asks for it with an extended length.
func (s *Session) WrapKey(id byte) ([]byte, error) {
	what := fmt.Sprintf("wrapping the key %d (the key must allow wrapping, and the User PIN must be given)", id)
	out, sw, err := s.answer([]byte{0x80, 0x72, id, 0x92, 0x00, 0x00, 0x00})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if sw != 0x9000 {
		return nil, &SWError{SW: sw, What: what}
	}
	return out, nil
}

// UnwrapKey puts a wrapped key onto the card as the key with a number. The card looks for the key domain whose DKEK has the check value that the blob names.
func (s *Session) UnwrapKey(id byte, blob []byte) error {
	_, err := s.do(fmt.Sprintf("unwrapping a key as the key %d (the card needs the User PIN, and the DKEK that wrapped the key)", id), 0x80, 0x74, id, 0x93, blob, false)
	return err
}
