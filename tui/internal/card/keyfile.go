package card

import (
	"errors"
	"fmt"
)

// KeyFile is what a file of a wrapped key holds, in the form the vendor's card manager writes (.wky): SEQUENCE { OCTET STRING (the key under the DKEK of its key domain), the
// description of the key as the card keeps it (label, id, usage: the file C4nn), the certificates (the file CEnn, each as its own element) }. A file from `sc-hsm-tool --wrap-key`
// is the blob alone; ParseKeyFile reads that too.
type KeyFile struct {
	Blob        []byte
	Description []byte   // may be empty (a blob alone)
	Certs       [][]byte // each a complete TLV
}

// der writes a tag, a length and a value.
func der(tag byte, v []byte) []byte {
	n := len(v)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)} // #nosec G115 -- below 128
	case n < 0x100:
		l = []byte{0x81, byte(n)} // #nosec G115
	default:
		l = []byte{0x82, byte(n >> 8), byte(n)} // #nosec G115 -- a key file is a few kilobytes
	}
	return append(append([]byte{tag}, l...), v...)
}

// Encode makes the content of the file.
func (k KeyFile) Encode() []byte {
	body := der(0x04, k.Blob)
	body = append(body, k.Description...)
	for _, c := range k.Certs {
		body = append(body, c...)
	}
	return der(0x30, body)
}

// ParseKeyFile reads a key file of the card manager, or a blob alone.
func ParseKeyFile(b []byte) (KeyFile, error) {
	if len(b) == 0 {
		return KeyFile{}, errors.New("the file is empty")
	}
	if tag, val, rest, ok := tlv(b); ok && tag == 0x30 && len(rest) == 0 {
		if t2, blob, more, ok := tlv(val); ok && t2 == 0x04 {
			k := KeyFile{Blob: append([]byte{}, blob...)}
			if len(more) > 0 {
				if _, _, after, ok := tlv(more); ok {
					k.Description = append([]byte{}, more[:len(more)-len(after)]...)
					for len(after) > 0 {
						_, _, next, ok := tlv(after)
						if !ok {
							return KeyFile{}, errors.New("the certificates in the file are cut short")
						}
						k.Certs = append(k.Certs, append([]byte{}, after[:len(after)-len(next)]...))
						after = next
					}
				} else {
					return KeyFile{}, errors.New("the description of the key in the file is cut short")
				}
			}
			return k, nil
		}
	}
	return KeyFile{Blob: append([]byte{}, b...)}, nil // a blob alone
}

// Label is the label that the description of the key holds ("" when there is none).
func (k KeyFile) Label() string {
	if len(k.Description) == 0 {
		return ""
	}
	_, val, _, ok := tlv(k.Description)
	if !ok {
		return ""
	}
	return string(find(val, 0x0C))
}

// Algo is the kind and size of the key by its description ("EC-256", "RSA-4096"), "" when it is not told.
func (k KeyFile) Algo() string {
	if len(k.Description) == 0 {
		return ""
	}
	_, _, algo := prkd(k.Description)
	return algo
}

// ExportKey wraps a key and gathers what goes into its file. Needs the User PIN, and the key must allow wrapping.
func (s *Session) ExportKey(id byte) (KeyFile, error) {
	blob, err := s.WrapKey(id)
	if err != nil {
		return KeyFile{}, err
	}
	k := KeyFile{Blob: blob}
	if d, err := s.ReadFile(0xC400 | uint16(id)); err == nil && len(d) > 2 {
		k.Description = d
	}
	if s.HasFile(0xCE00 | uint16(id)) {
		if c, err := s.ReadFile(0xCE00 | uint16(id)); err == nil {
			for len(c) > 0 {
				_, _, rest, ok := tlv(c)
				if !ok {
					break
				}
				k.Certs = append(k.Certs, append([]byte{}, c[:len(c)-len(rest)]...))
				c = rest
			}
		}
	}
	return k, nil
}

// ImportKey puts the key of a file onto the card under the lowest free number and writes its description and certificates. Needs the User PIN and a key domain with the DKEK
// that wrapped the key. It returns the number the key got.
func (s *Session) ImportKey(k KeyFile) (byte, error) {
	id, err := s.FreeKeyID()
	if err != nil {
		return 0, err
	}
	if err := s.UnwrapKey(id, k.Blob); err != nil {
		return 0, err
	}
	if len(k.Description) > 0 {
		if err := s.WriteFile(0xC400|uint16(id), k.Description); err != nil {
			return id, fmt.Errorf("the key is on the card as the key %d but its description was not written: %w", id, err)
		}
	}
	if len(k.Certs) > 0 {
		var all []byte
		for _, c := range k.Certs {
			all = append(all, c...)
		}
		if err := s.WriteFile(0xCE00|uint16(id), all); err != nil {
			return id, fmt.Errorf("the key is on the card as the key %d but its certificates were not written: %w", id, err)
		}
	}
	return id, nil
}
