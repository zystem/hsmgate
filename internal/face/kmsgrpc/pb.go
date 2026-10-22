package kmsgrpc

// A small reader and writer of the protobuf wire format for the few messages this face speaks, on top of protowire (the encoding library of the protobuf project, with no other
// dependency). Messages are not generated: the field numbers below are those of the public definitions of the service (google/cloud/kms/v1/service.proto and resources.proto,
// Apache-2.0) and are checked by the tests against the client library of the service.

import (
	"hash/crc32"

	"google.golang.org/protobuf/encoding/protowire"
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// crc32c is the checksum that the clients of the service send and expect back.
func crc32c(b []byte) int64 { return int64(crc32.Checksum(b, castagnoli)) }

// reader holds the fields of one message, by number; a repeated field keeps all its values.
type reader struct {
	bytes map[protowire.Number][][]byte
	ints  map[protowire.Number][]uint64
}

func parse(b []byte) (*reader, bool) {
	r := &reader{bytes: map[protowire.Number][][]byte{}, ints: map[protowire.Number][]uint64{}}
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, false
		}
		b = b[n:]
		switch typ {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return nil, false
			}
			r.ints[num] = append(r.ints[num], v)
			b = b[n:]
		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, false
			}
			r.bytes[num] = append(r.bytes[num], v)
			b = b[n:]
		default: // fixed32, fixed64, groups: not in the messages of this face; skip what is skippable
			n := protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return nil, false
			}
			b = b[n:]
		}
	}
	return r, true
}

func (r *reader) str(n protowire.Number) string {
	if v := r.bytes[n]; len(v) > 0 {
		return string(v[len(v)-1])
	}
	return ""
}

func (r *reader) raw(n protowire.Number) []byte {
	if v := r.bytes[n]; len(v) > 0 {
		return v[len(v)-1]
	}
	return nil
}

func (r *reader) has(n protowire.Number) bool { return len(r.bytes[n]) > 0 || len(r.ints[n]) > 0 }

func (r *reader) u64(n protowire.Number) uint64 {
	if v := r.ints[n]; len(v) > 0 {
		return v[len(v)-1]
	}
	return 0
}

func (r *reader) msg(n protowire.Number) (*reader, bool) {
	b := r.raw(n)
	if b == nil {
		return nil, false
	}
	return parse(b)
}

// int64Value reads a google.protobuf.Int64Value field (a message with the value as field 1); present says whether the field was sent at all.
func (r *reader) int64Value(n protowire.Number) (v int64, present bool) {
	m, ok := r.msg(n)
	if !ok {
		return 0, r.has(n)
	}
	return int64(m.u64(1)), true // #nosec G115 -- a protobuf int64 is the two's complement of the varint
}

// writer builds one message.
type writer struct{ b []byte }

func (w *writer) str(n protowire.Number, s string) *writer {
	if s == "" {
		return w
	}
	w.b = protowire.AppendTag(w.b, n, protowire.BytesType)
	w.b = protowire.AppendString(w.b, s)
	return w
}

func (w *writer) bytes(n protowire.Number, v []byte) *writer {
	if len(v) == 0 {
		return w
	}
	w.b = protowire.AppendTag(w.b, n, protowire.BytesType)
	w.b = protowire.AppendBytes(w.b, v)
	return w
}

func (w *writer) u64(n protowire.Number, v uint64) *writer {
	if v == 0 {
		return w
	}
	w.b = protowire.AppendTag(w.b, n, protowire.VarintType)
	w.b = protowire.AppendVarint(w.b, v)
	return w
}

func (w *writer) boolean(n protowire.Number, v bool) *writer {
	if !v {
		return w
	}
	return w.u64(n, 1)
}

func (w *writer) msg(n protowire.Number, m *writer) *writer {
	w.b = protowire.AppendTag(w.b, n, protowire.BytesType)
	w.b = protowire.AppendBytes(w.b, m.b)
	return w
}

// int64Value writes a google.protobuf.Int64Value field (also for zero: the field is then present).
func (w *writer) int64Value(n protowire.Number, v int64) *writer {
	inner := &writer{}
	if v != 0 {
		inner.u64(1, uint64(v)) // #nosec G115 -- two's complement, as the format has it
	}
	return w.msg(n, inner)
}

// timestamp writes a google.protobuf.Timestamp field.
func (w *writer) timestamp(n protowire.Number, seconds int64, nanos int32) *writer {
	inner := &writer{}
	inner.u64(1, uint64(seconds)) // #nosec G115
	inner.u64(2, uint64(nanos))   // #nosec G115
	return w.msg(n, inner)
}
