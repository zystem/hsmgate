package ecies

import "testing"

func BenchmarkWrap(b *testing.B) {
	_, _, pub := load(b)
	plain := make([]byte, 32)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Wrap(pub, plain, []byte("ctx")); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkUnwrap(b *testing.B) {
	_, key, pub := load(b)
	w, err := Wrap(pub, make([]byte, 32), []byte("ctx"))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Unwrap(pub, key, w, []byte("ctx")); err != nil {
			b.Fatal(err)
		}
	}
}
