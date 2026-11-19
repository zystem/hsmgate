package card

import (
	"errors"
	"fmt"
	"math/big"
)

// An XKEK key domain is made for a group of cards that exchange wrapped keys without sharing DKEK shares. A key of a card (the group signer) signs, for each card that is to belong
// to the group, a key domain membership; the card checks it and makes the domain, whose identifier is the public key of the group signer. This file is the card's side: reading the
// certificates of the device, verifying them for the card, signing a membership with a key on the card, and making the domain. The commands are those of the vendor's card manager.

// DeviceCerts are the two certificates a SmartCard-HSM carries, each a complete TLV: its own (the device) and the one that signed it (the device issuer, "DICA").
type DeviceCerts struct {
	Device, DICA []byte
}

// cvcPart finds a part of a card verifiable certificate: the reference of its authority (42), of its holder (5F20), and the public point (86 inside 7F49).
func cvcPart(cert []byte, tag int) []byte { return find(cert, tag) }

// DeviceCertificates reads the file that holds the certificates of the device (EF.C_DevAut, 2F02).
func (s *Session) DeviceCertificates() (DeviceCerts, error) {
	raw, err := s.ReadFile(0x2F02)
	if err != nil {
		return DeviceCerts{}, err
	}
	var certs [][]byte
	for len(raw) > 0 {
		_, _, rest, ok := tlv(raw)
		if !ok {
			break
		}
		certs = append(certs, raw[:len(raw)-len(rest)])
		raw = rest
	}
	if len(certs) < 2 {
		return DeviceCerts{}, errors.New("the card does not hold a device certificate and its issuer")
	}
	// the device certificate is the one whose authority is the holder of the other
	for i, c := range certs {
		for j, d := range certs {
			if i != j && string(cvcPart(c, 0x42)) == string(cvcPart(d, 0x5F20)) && len(cvcPart(c, 0x42)) > 0 {
				return DeviceCerts{Device: c, DICA: d}, nil
			}
		}
	}
	return DeviceCerts{}, errors.New("the certificates of the card do not form a chain")
}

// DevicePointX is the X coordinate of the public key of a device certificate: what a membership is made for.
func (d DeviceCerts) DevicePointX() ([]byte, error) {
	pt := cvcPart(d.Device, 0x86)
	if len(pt) != 65 || pt[0] != 0x04 {
		return nil, errors.New("the device certificate has no public point of a P-256 key")
	}
	return pt[1:33], nil
}

// VerifyCertificate has the card check a certificate and keep its public key for the commands that follow (the card knows the root of the vendor). A certificate the card already
// knows is not sent again.
func (s *Session) VerifyCertificate(cert []byte) error {
	chr := cvcPart(cert, 0x5F20)
	if _, sw, err := s.Send(0x00, 0x22, 0x81, 0xB6, der(0x83, chr), false); err != nil {
		return err
	} else if sw == 0x9000 {
		return nil
	}
	car := cvcPart(cert, 0x42)
	if _, err := s.do("selecting the authority of a certificate", 0x00, 0x22, 0x81, 0xB6, der(0x83, car), false); err != nil {
		return err
	}
	_, body, _, ok := tlv(cert)
	if !ok {
		return errors.New("a certificate that cannot be read")
	}
	_, err := s.do("verifying a certificate", 0x00, 0x2A, 0x00, 0xBE, body, false)
	return err
}

// SignWithKey signs data with a key of the card: ECDSA with SHA-256, the signature as r followed by s (64 bytes). Needs the User PIN.
func (s *Session) SignWithKey(id byte, data []byte) ([]byte, error) {
	sig, err := s.do(fmt.Sprintf("signing with the key %d (the key must allow ECDSA-SHA-256, and the User PIN must be given)", id), 0x80, 0x68, id, AlgECDSASHA256, data, true)
	if err != nil {
		return nil, err
	}
	return rawECDSA(sig, 32)
}

// rawECDSA turns the DER of an ECDSA signature (SEQUENCE of two INTEGERs) into r and s of a fixed size.
func rawECDSA(sig []byte, size int) ([]byte, error) {
	tag, val, _, ok := tlv(sig)
	if !ok || tag != 0x30 {
		return nil, errors.New("the signature is not a DER sequence")
	}
	out := make([]byte, 0, 2*size)
	for i := 0; i < 2; i++ {
		t, v, rest, ok := tlv(val)
		if !ok || t != 0x02 {
			return nil, errors.New("the signature is not two integers")
		}
		n := new(big.Int).SetBytes(v)
		if n.BitLen() > size*8 {
			return nil, errors.New("an integer of the signature is too large")
		}
		out = append(out, n.FillBytes(make([]byte, size))...)
		val = rest
	}
	return out, nil
}

// Membership signs, with the group signer key on the card, the membership of a device: the signature over 0x54 and the X of the public key of the device, as the TLV 54.
func (s *Session) Membership(signerKey byte, deviceX []byte) ([]byte, error) {
	sig, err := s.SignWithKey(signerKey, append([]byte{0x54}, deviceX...))
	if err != nil {
		return nil, err
	}
	return der(0x54, sig), nil
}

// CreateXKEKDomain makes an XKEK key domain from the request of the group signer key (what GenerateKey returned), the membership of this device and the certificates of the device
// (which the card must have verified: this does it). The label is written like the label of any key domain. Needs the User PIN.
func (s *Session) CreateXKEKDomain(n byte, groupRequest, membership []byte, certs DeviceCerts, label string) (Domain, error) {
	if err := s.VerifyCertificate(certs.DICA); err != nil {
		return Domain{}, err
	}
	if err := s.VerifyCertificate(certs.Device); err != nil {
		return Domain{}, err
	}
	_, body, _, ok := tlv(groupRequest)
	if !ok {
		return Domain{}, errors.New("the request of the group signer key cannot be read")
	}
	outerCAR := cvcPart(groupRequest, 0x45)
	if len(outerCAR) == 0 {
		// an authenticated request carries the reference of the device that signed it after the inner certificate
		_, inner, rest, ok := tlv(body)
		_ = inner
		if ok {
			if t, v, _, ok := tlv(rest); ok && t == 0x42 {
				outerCAR = v
			}
		}
	}
	if len(outerCAR) == 0 {
		return Domain{}, errors.New("the request of the group signer key names no device that signed it")
	}
	if _, err := s.do("selecting the group signer for the key domain", 0x00, 0x22, 0x81, 0xB6, der(0x83, outerCAR), false); err != nil {
		return Domain{}, err
	}
	data, err := s.do(fmt.Sprintf("creating the XKEK key domain %d", n), 0x80, 0x52, 0x02, n, append(append([]byte{}, body...), membership...), true)
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
