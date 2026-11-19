package card

import (
	"bytes"
	"errors"
	"fmt"
)

// The files of an XKEK group, in the form the vendor's card manager writes and reads. All are a SEQUENCE that starts with an OBJECT IDENTIFIER under 1.3.6.1.4.1.24991 (4.1.1: the
// device id, 4.2.1: the key domain membership), and carries the certificates in elements 61 (the issuer of the device), 62 (the device) and 63 (the request of the group signer key).
var (
	oidDeviceID   = []byte{0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x04, 0x01, 0x01}
	oidMembership = []byte{0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x81, 0xC3, 0x1F, 0x04, 0x02, 0x01}
)

// EncodeDeviceID makes the file that says which card a membership is for (what the card manager calls "Export Device ID", .id).
func EncodeDeviceID(c DeviceCerts) []byte {
	body := append([]byte{}, oidDeviceID...)
	body = append(body, der(0x61, c.DICA)...)
	body = append(body, der(0x62, c.Device)...)
	return der(0x30, body)
}

// ParseDeviceID reads such a file.
func ParseDeviceID(b []byte) (DeviceCerts, error) {
	top, err := sequenceWithOID(b, oidDeviceID, "a device id")
	if err != nil {
		return DeviceCerts{}, err
	}
	dica, dev := find(top, 0x61), find(top, 0x62)
	if len(dica) == 0 || len(dev) == 0 {
		return DeviceCerts{}, errors.New("the device id lacks a certificate")
	}
	return DeviceCerts{DICA: dica, Device: dev}, nil
}

// sequenceWithOID checks that b is a SEQUENCE that starts with the identifier and returns what follows the identifier.
func sequenceWithOID(b, oid []byte, what string) ([]byte, error) {
	tag, val, rest, ok := tlv(b)
	if !ok || tag != 0x30 || len(rest) != 0 || !bytes.HasPrefix(val, oid) {
		return nil, fmt.Errorf("the file is not %s of the card manager", what)
	}
	return val[len(oid):], nil
}

// MembershipFile is the key domain membership of one device: who signed it (the certificates of the group signer's card and the request of its key) and the signature.
type MembershipFile struct {
	Signer       DeviceCerts
	GroupRequest []byte
	Membership   []byte // the TLV 54 with the signature
}

// Encode makes the content of the file (.kdm).
func (m MembershipFile) Encode() []byte {
	body := append([]byte{}, oidMembership...)
	body = append(body, der(0x61, m.Signer.DICA)...)
	body = append(body, der(0x62, m.Signer.Device)...)
	body = append(body, der(0x63, m.GroupRequest)...)
	body = append(body, m.Membership...)
	return der(0x30, body)
}

// ParseMembershipFile reads a .kdm file.
func ParseMembershipFile(b []byte) (MembershipFile, error) {
	top, err := sequenceWithOID(b, oidMembership, "a key domain membership")
	if err != nil {
		return MembershipFile{}, err
	}
	m := MembershipFile{Signer: DeviceCerts{DICA: find(top, 0x61), Device: find(top, 0x62)}, GroupRequest: find(top, 0x63)}
	// the signature is the element 54 (or 53) at the top, after the certificates
	for rest := top; len(rest) > 0; {
		tag, _, next, ok := tlv(rest)
		if !ok {
			return MembershipFile{}, errors.New("the membership file is cut short")
		}
		if tag == 0x54 || tag == 0x53 {
			m.Membership = append([]byte{}, rest[:len(rest)-len(next)]...)
		}
		rest = next
	}
	if len(m.Signer.DICA) == 0 || len(m.Signer.Device) == 0 || len(m.GroupRequest) == 0 || len(m.Membership) == 0 {
		return MembershipFile{}, errors.New("the membership file lacks a certificate or the signature")
	}
	return m, nil
}

// SignMembership signs the membership of a device (its id file) with a group signer key on this card, and gathers the file. The key must have been made with ECDSA allowed; the
// request of the key is the one the card kept when it made it (the file CEnn). Needs the User PIN.
func (s *Session) SignMembership(signerKey byte, device DeviceCerts) (MembershipFile, error) {
	req, err := s.ReadFile(0xCE00 | uint16(signerKey))
	if err != nil {
		return MembershipFile{}, fmt.Errorf("the request of the key %d (a key made on a card has one): %w", signerKey, err)
	}
	signer, err := s.DeviceCertificates()
	if err != nil {
		return MembershipFile{}, err
	}
	x, err := device.DevicePointX()
	if err != nil {
		return MembershipFile{}, err
	}
	m, err := s.Membership(signerKey, x)
	if err != nil {
		return MembershipFile{}, err
	}
	return MembershipFile{Signer: signer, GroupRequest: req, Membership: m}, nil
}

// DomainUID is the identifier of the key domain a membership is for: the X of the public key of the group signer, as the first 8 bytes the card shows.
func (m MembershipFile) DomainUID() []byte {
	if pt := find(m.GroupRequest, 0x86); len(pt) == 65 {
		return pt[1:33]
	}
	return nil
}
