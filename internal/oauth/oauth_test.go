package oauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func sign(t *testing.T, key *rsa.PrivateKey, alg string, c map[string]any) string {
	e := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": alg})
	p, _ := json.Marshal(c)
	in := e.EncodeToString(h) + "." + e.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + e.EncodeToString(sig)
}

func TestVerifyJWT(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	claims := func(iat, exp time.Time) map[string]any {
		return map[string]any{"iss": "me", "iat": iat.Unix(), "exp": exp.Unix()}
	}
	ok := sign(t, key, "RS256", claims(now, now.Add(time.Hour)))
	if c, err := VerifyJWT(ok, &key.PublicKey, now); err != nil || c.Iss != "me" {
		t.Fatalf("%v", err)
	}
	if iss, good := PeekIssuer(ok); !good || iss != "me" {
		t.Error("PeekIssuer")
	}
	for name, tok := range map[string]string{
		"another key": sign(t, other, "RS256", claims(now, now.Add(time.Hour))),
		"alg none":    sign(t, key, "none", claims(now, now.Add(time.Hour))),
		"alg HS256":   sign(t, key, "HS256", claims(now, now.Add(time.Hour))),
		"expired":     sign(t, key, "RS256", claims(now.Add(-2*time.Hour), now.Add(-time.Hour))),
		"from future": sign(t, key, "RS256", claims(now.Add(time.Hour), now.Add(2*time.Hour))),
		"too long":    sign(t, key, "RS256", claims(now, now.Add(48*time.Hour))),
		"no expiry":   sign(t, key, "RS256", map[string]any{"iss": "me"}),
		"garbage":     "a.b.c",
		"two parts":   "a.b",
	} {
		if _, err := VerifyJWT(tok, &key.PublicKey, now); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTokens(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	tok, exp := ts.Issue("me", now)
	if iss, ok := ts.Lookup(tok, now.Add(time.Minute)); !ok || iss != "me" || exp.Sub(now) != time.Hour {
		t.Fatal("lookup")
	}
	if _, ok := ts.Lookup(tok, now.Add(2*time.Hour)); ok {
		t.Error("an expired token was found")
	}
	if _, ok := ts.Lookup("hg.nope", now); ok {
		t.Error("an unknown token was found")
	}
}
