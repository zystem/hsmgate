package kmsops

import "testing"

// Benchmarks of the shared operations on a soft token: what the service itself costs, without the card (the card's ECDH, about 37 ms, is not here).

func BenchmarkSeal(b *testing.B) {
	s := rig(b)
	plain := make([]byte, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, e := s.Seal(bg, "app", "seal", 0, plain, nil, AADBytes, 4096); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkOpen(b *testing.B) {
	s := rig(b)
	blob, _, e := s.Seal(bg, "app", "seal", 0, make([]byte, 32), nil, AADBytes, 4096)
	if e != nil {
		b.Fatal(e)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, e := s.Open(bg, "app", "", blob, nil, AADBytes); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkSign(b *testing.B) {
	s := rig(b)
	d := make([]byte, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, e := s.Sign(bg, "app", "sig", 0, d); e != nil {
			b.Fatal(e)
		}
	}
}

func BenchmarkMacGenerate(b *testing.B) {
	s := rig(b)
	msg := make([]byte, 256)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, e := s.MacGenerate(bg, "app", "mac", 0, msg); e != nil {
			b.Fatal(e)
		}
	}
}
