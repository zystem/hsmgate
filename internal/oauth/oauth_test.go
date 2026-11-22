package oauth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sign(t testing.TB, key *rsa.PrivateKey, alg string, c map[string]any) string {
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
	if c, err := VerifyJWT(ok, &key.PublicKey, now, Expect{}); err != nil || c.Iss != "me" {
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
		if _, err := VerifyJWT(tok, &key.PublicKey, now, Expect{}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestTokens(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	tok, exp := ts.Issue("me", "s", now)
	if iss, stamp, ok := ts.Lookup(tok, now.Add(time.Minute)); !ok || iss != "me" || stamp != "s" || exp.Sub(now) != time.Hour {
		t.Fatal("lookup")
	}
	if _, _, ok := ts.Lookup(tok, now.Add(2*time.Hour)); ok {
		t.Error("an expired token was found")
	}
	if _, _, ok := ts.Lookup("hg.nope", now); ok {
		t.Error("an unknown token was found")
	}
}

func TestReadRSAPublic(t *testing.T) {
	dir := t.TempDir()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	pkix, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o644)
		return p
	}
	smallDER, _ := x509.MarshalPKIXPublicKey(&small.PublicKey)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix2("c"), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	certDER, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDER, _ := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	for name, c := range map[string]struct {
		file string
		ok   bool
	}{
		"pkix":        {write("a.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkix})), true},
		"pkcs1":       {write("b.pub", pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})), true},
		"certificate": {write("c.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})), true},
		"too small":   {write("d.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: smallDER})), false},
		"not rsa":     {write("e.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER})), false},
		"unknown":     {write("f.pub", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkix})), false},
		"no pem":      {write("g.pub", []byte("junk")), false},
		"garbage der": {write("h.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1, 2}})), false},
		"too large":   {write("i.pub", bytes.Repeat([]byte("a"), 20<<10)), false},
		"missing":     {filepath.Join(dir, "none"), false},
	} {
		if _, err := ReadRSAPublic(c.file); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func pkix2(cn string) pkix.Name { return pkix.Name{CommonName: cn} }

func FuzzVerifyJWT(f *testing.F) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	good := sign(f, key, "RS256", map[string]any{"iss": "me", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	f.Add(good)
	f.Add("a.b.c")
	f.Add("..")
	f.Add(good[:len(good)-4] + "AAAA")
	f.Fuzz(func(t *testing.T, tok string) {
		PeekIssuer(tok)
		if c, err := VerifyJWT(tok, &key.PublicKey, now, Expect{}); err == nil && tok != good && c.Iss != "me" {
			t.Fatalf("a token that this key did not sign was accepted: %q", tok)
		}
	})
}

// A token that is signed and alive is still for somebody: the audience says for whom, the subject for what.
func TestJWTAudienceAndSubject(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	mk := func(extra map[string]any) string {
		c := map[string]any{"iss": "me", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
		for k, v := range extra {
			c[k] = v
		}
		return sign(t, key, "RS256", c)
	}
	const endpoint, api = "https://kms.example.org/oauth2/token", "https://cloudkms.googleapis.com/"
	for _, tc := range []struct {
		name string
		tok  string
		exp  Expect
		want error
	}{
		{"no expectation, no aud", mk(nil), Expect{}, nil},
		{"aud as a string", mk(map[string]any{"aud": endpoint}), Expect{Audiences: []string{endpoint}}, nil},
		{"aud as a list", mk(map[string]any{"aud": []string{"x", endpoint}}), Expect{Audiences: []string{endpoint}}, nil},
		{"one of several expected", mk(map[string]any{"aud": api}), Expect{Audiences: []string{endpoint, api}}, nil},
		{"the other service", mk(map[string]any{"aud": api}), Expect{Audiences: []string{endpoint}}, ErrAudience},
		{"no aud when one is asked", mk(nil), Expect{Audiences: []string{endpoint}}, ErrAudience},
		{"empty aud list", mk(map[string]any{"aud": []string{}}), Expect{Audiences: []string{endpoint}}, ErrAudience},
		{"aud is a prefix only", mk(map[string]any{"aud": endpoint + "/x"}), Expect{Audiences: []string{endpoint}}, ErrAudience},
		{"aud of another case", mk(map[string]any{"aud": "HTTPS://KMS.example.org/oauth2/token"}), Expect{Audiences: []string{endpoint}}, ErrAudience},
		{"aud of a wrong type", mk(map[string]any{"aud": 7}), Expect{Audiences: []string{endpoint}}, ErrJWT},
		{"sub absent, optional", mk(nil), Expect{Sub: SubjectOptional}, nil},
		{"sub the issuer, optional", mk(map[string]any{"sub": "me"}), Expect{Sub: SubjectOptional}, nil},
		{"sub another, optional", mk(map[string]any{"sub": "you"}), Expect{Sub: SubjectOptional}, ErrSubject},
		{"sub absent, required", mk(nil), Expect{Sub: SubjectIssuer}, ErrSubject},
		{"sub the issuer, required", mk(map[string]any{"sub": "me"}), Expect{Sub: SubjectIssuer}, nil},
		{"sub another, required", mk(map[string]any{"sub": "you"}), Expect{Sub: SubjectIssuer}, ErrSubject},
		{"sub another, not checked", mk(map[string]any{"sub": "you"}), Expect{}, nil},
	} {
		_, err := VerifyJWT(tc.tok, &key.PublicKey, now, tc.exp)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// A stamp changes with every part of a credential, and the parts cannot be shifted into each other.
func TestStamp(t *testing.T) {
	base := Stamp("app", "id", []byte("material"))
	if base != Stamp("app", "id", []byte("material")) {
		t.Error("a stamp is not stable")
	}
	for name, other := range map[string]string{
		"another client":   Stamp("app2", "id", []byte("material")),
		"another id":       Stamp("app", "id2", []byte("material")),
		"other material":   Stamp("app", "id", []byte("materiaL")),
		"a shifted split":  Stamp("ap", "pid", []byte("material")),
		"a shifted split2": Stamp("app", "idm", []byte("aterial")),
	} {
		if other == base {
			t.Errorf("%s has the same stamp", name)
		}
	}
}

// The table is bounded, and a client that asks for many tokens ends only its own (the review of 2026-11-21, finding 4).
func TestTokensOfOneIssuerAreBounded(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	other, _ := ts.Issue("other", "s", now)
	var mine []string
	for i := 0; i < maxPerIssuer+50; i++ {
		tok, _ := ts.Issue("busy", "s", now.Add(time.Duration(i)*time.Millisecond))
		mine = append(mine, tok)
	}
	at := now.Add(time.Second)
	if _, _, ok := ts.Lookup(other, at); !ok {
		t.Fatal("the token of another issuer was given up")
	}
	for i, tok := range mine {
		_, _, ok := ts.Lookup(tok, at)
		if want := i >= 50; ok != want {
			t.Fatalf("token %d of the busy issuer: live %v, want %v", i, ok, want)
		}
	}
	if len(ts.m) != maxPerIssuer+1 {
		t.Errorf("the table holds %d tokens", len(ts.m))
	}
}

func TestTokensTableFullKeepsTheSessionsOfOthers(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	var all []string
	for i := 0; i < maxTokens/maxPerIssuer; i++ { // the table full: every issuer at its limit
		for j := 0; j < maxPerIssuer; j++ {
			tok, _ := ts.Issue(fmt.Sprintf("client-%03d", i), "s", now)
			all = append(all, tok)
		}
	}
	if len(ts.m) != maxTokens {
		t.Fatalf("the table holds %d tokens, not %d", len(ts.m), maxTokens)
	}
	fresh, _ := ts.Issue("newcomer", "s", now.Add(time.Second))
	at := now.Add(2 * time.Second)
	if _, _, ok := ts.Lookup(fresh, at); !ok {
		t.Fatal("the new token is not good")
	}
	gone := 0
	for _, tok := range all {
		if _, _, ok := ts.Lookup(tok, at); !ok {
			gone++
		}
	}
	if gone != 1 {
		t.Errorf("%d of %d tokens were given up for one new one, want 1", gone, len(all))
	}
	if len(ts.m) > maxTokens {
		t.Errorf("the table holds %d tokens", len(ts.m))
	}
}

func TestTokensExpiredAreDroppedFirst(t *testing.T) {
	ts := NewTokens()
	now := time.Now()
	for i := 0; i < maxTokens/maxPerIssuer; i++ {
		for j := 0; j < maxPerIssuer; j++ {
			ts.Issue(fmt.Sprintf("client-%03d", i), "s", now)
		}
	}
	later := now.Add(2 * time.Hour) // all of them have expired
	fresh, _ := ts.Issue("newcomer", "s", later)
	if _, _, ok := ts.Lookup(fresh, later); !ok {
		t.Fatal("the new token is not good")
	}
	if len(ts.m) != 1 {
		t.Errorf("the table holds %d tokens, the expired ones were not dropped", len(ts.m))
	}
}

func signPSS(t testing.TB, key *rsa.PrivateKey, alg string, salt int, c map[string]any) string {
	e := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": alg})
	p, _ := json.Marshal(c)
	in := e.EncodeToString(h) + "." + e.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: salt})
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + e.EncodeToString(sig)
}

// PS256 is taken only where a face asks for it, and only as RFC 7518 section 3.5 says (salt as long as the hash); the Azure libraries sign a client assertion with it.
func TestPS256(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	cl := map[string]any{"iss": "me", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	ps := signPSS(t, key, "PS256", rsa.PSSSaltLengthEqualsHash, cl)
	if _, err := VerifyJWT(ps, &key.PublicKey, now, Expect{PS256: true}); err != nil {
		t.Errorf("PS256 where it is asked for: %v", err)
	}
	if _, err := VerifyJWT(ps, &key.PublicKey, now, Expect{}); err == nil {
		t.Error("PS256 was taken where it is not asked for")
	}
	for name, tok := range map[string]string{
		"PS256 header, PKCS1 signature":  sign(t, key, "PS256", cl),
		"RS256 header, PSS signature":    signPSS(t, key, "RS256", rsa.PSSSaltLengthEqualsHash, cl),
		"PSS with another salt length":   signPSS(t, key, "PS256", 10, cl),
		"PS384 (a hash of another size)": signPSS(t, key, "PS384", rsa.PSSSaltLengthEqualsHash, cl),
	} {
		if _, err := VerifyJWT(tok, &key.PublicKey, now, Expect{PS256: true}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := VerifyJWT(signPSS(t, other, "PS256", rsa.PSSSaltLengthEqualsHash, cl), &key.PublicKey, now, Expect{PS256: true}); err == nil {
		t.Error("PS256 of another key was accepted")
	}
}

// "nbf" stands for "iat" when there is no "iat" (the Azure libraries write the one and not the other); with neither the life cannot be bounded.
func TestNotBefore(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	now := time.Now()
	mk := func(c map[string]any) string {
		c["iss"] = "me"
		return sign(t, key, "RS256", c)
	}
	u := func(d time.Duration) int64 { return now.Add(d).Unix() }
	for name, tc := range map[string]struct {
		tok string
		ok  bool
	}{
		"nbf and exp, no iat":       {mk(map[string]any{"nbf": u(0), "exp": u(10 * time.Minute)}), true},
		"nbf a little ahead (skew)": {mk(map[string]any{"nbf": u(2 * time.Minute), "exp": u(10 * time.Minute)}), true},
		"nbf well ahead":            {mk(map[string]any{"nbf": u(time.Hour), "exp": u(2 * time.Hour)}), false},
		"neither iat nor nbf":       {mk(map[string]any{"exp": u(10 * time.Minute)}), false},
		"nbf, a life of 48 hours":   {mk(map[string]any{"nbf": u(0), "exp": u(48 * time.Hour)}), false},
		"iat and nbf, both good":    {mk(map[string]any{"iat": u(0), "nbf": u(0), "exp": u(time.Hour)}), true},
		"iat good, nbf ahead":       {mk(map[string]any{"iat": u(0), "nbf": u(time.Hour), "exp": u(2 * time.Hour)}), false},
	} {
		_, err := VerifyJWT(tc.tok, &key.PublicKey, now, Expect{})
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, accepted %v, want %v", name, err, err == nil, tc.ok)
		}
	}
}
