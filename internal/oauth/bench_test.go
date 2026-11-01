package oauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"
)

func BenchmarkVerifyJWT(b *testing.B) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	tok := sign(b, key, "RS256", map[string]any{"iss": "me", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := VerifyJWT(tok, &key.PublicKey, now); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTokensIssueLookup(b *testing.B) {
	ts := NewTokens()
	now := time.Now()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		tok, _ := ts.Issue("me", now)
		if _, ok := ts.Lookup(tok, now); !ok {
			b.Fatal("lost")
		}
	}
}
