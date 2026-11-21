// Package oauth is what the faces with a token endpoint share: the check of a JWT signed by a client (RS256 only), the table of access tokens a service gives, and the reading
// of a public key of a credential. A face decides what an issuer is and what a token may do.
package oauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	tokenTTL   = time.Hour
	maxTokens  = 10000
	maxJWTLife = 24 * time.Hour
	skew       = 5 * time.Minute
)

var (
	ErrJWT      = errors.New("the token is not valid")
	ErrExpired  = errors.New("the token has expired")
	ErrAudience = errors.New("the token is for another audience")
	ErrSubject  = errors.New("the subject of the token is not its issuer")
)

// Audience is the "aud" claim: a string or a list of strings (RFC 7519 section 4.1.3).
type Audience []string

func (a *Audience) UnmarshalJSON(b []byte) error {
	var one string
	if json.Unmarshal(b, &one) == nil {
		*a = Audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type Claims struct {
	Iss string   `json:"iss"`
	Sub string   `json:"sub"`
	Aud Audience `json:"aud"`
	Iat int64    `json:"iat"`
	Exp int64    `json:"exp"`
}

// Subject says what the "sub" claim of a token must be.
type Subject int

const (
	// SubjectAny: not checked (what a token without a claim "sub" is).
	SubjectAny Subject = iota
	// SubjectOptional: absent, or the issuer itself (a token for another subject is a request to act for someone else, which the service does not do).
	SubjectOptional
	// SubjectIssuer: present and equal to the issuer (RFC 7523 section 3 for the authentication of a client).
	SubjectIssuer
)

// Expect is what a face asks of a token besides the signature and the dates. Audiences: when not empty, the token must name one of them in "aud" (an exact match, no
// normalisation); empty: not checked. The audience is the part of a token that says for whom it was made: without it a token made for one service is good for every
// service that trusts the same issuer.
type Expect struct {
	Audiences []string
	Sub       Subject
}

// PeekIssuer reads the issuer of a token without trusting it (to find the key to check it with).
func PeekIssuer(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var c Claims
	if json.Unmarshal(raw, &c) != nil || c.Iss == "" {
		return "", false
	}
	return c.Iss, true
}

// VerifyJWT checks a token against the public key of its issuer: RS256 only, within its life, issued no later than now (plus the skew), and what is asked in exp (the audience
// and the subject).
func VerifyJWT(tok string, pub *rsa.PublicKey, now time.Time, exp Expect) (Claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Claims{}, ErrJWT
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, ErrJWT
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "RS256" { // never "none", never a symmetric algorithm
		return Claims{}, ErrJWT
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, ErrJWT
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return Claims{}, ErrJWT
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, ErrJWT
	}
	var c Claims
	if json.Unmarshal(raw, &c) != nil {
		return Claims{}, ErrJWT
	}
	end, iat := time.Unix(c.Exp, 0), time.Unix(c.Iat, 0)
	if c.Exp == 0 || !now.Before(end.Add(skew)) {
		return Claims{}, ErrExpired
	}
	if iat.After(now.Add(skew)) || end.Sub(iat) > maxJWTLife || end.Before(iat) {
		return Claims{}, ErrJWT
	}
	if len(exp.Audiences) > 0 && !c.Aud.hasAny(exp.Audiences) {
		return c, ErrAudience
	}
	switch exp.Sub {
	case SubjectOptional:
		if c.Sub != "" && c.Sub != c.Iss {
			return c, ErrSubject
		}
	case SubjectIssuer:
		if c.Sub == "" || c.Sub != c.Iss {
			return c, ErrSubject
		}
	}
	return c, nil
}

func (a Audience) hasAny(want []string) bool {
	for _, have := range a {
		for _, w := range want {
			if have == w {
				return true
			}
		}
	}
	return false
}

type tokenInfo struct {
	issuer  string
	stamp   string
	expires time.Time
}

// Stamp is a short name of a credential as it is now: the client it belongs to, the issuer (or client id) and the material that proves it (the public key, or the secret).
// A face writes it into every access token it gives and compares it again at every call, so that a token does not outlive the credential it was given for: a new key or secret,
// another client behind the same issuer, are another stamp. The material is hashed with its length, so that two different splits of the same bytes are not the same stamp.
func Stamp(client, issuer string, material []byte) string {
	h := sha256.New()
	for _, p := range [][]byte{[]byte("hsmgate/credential/v1"), []byte(client), []byte(issuer), material} {
		fmt.Fprintf(h, "%d:", len(p))
		h.Write(p)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Tokens are the access tokens this service has given: opaque, random, in memory only (a restart ends them; a client then asks again).
type Tokens struct {
	mu sync.Mutex
	m  map[string]tokenInfo
}

func NewTokens() *Tokens { return &Tokens{m: map[string]tokenInfo{}} }

// Issue gives a token to an issuer whose credential has the stamp.
func (t *Tokens) Issue(issuer, stamp string, now time.Time) (string, time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.m) >= maxTokens {
		for k, v := range t.m { // drop the expired; if that is not enough, the whole table: clients ask again
			if !now.Before(v.expires) {
				delete(t.m, k)
			}
		}
		if len(t.m) >= maxTokens {
			t.m = map[string]tokenInfo{}
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("oauth: no randomness: " + err.Error())
	}
	tok := "hg." + strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
	exp := now.Add(tokenTTL)
	t.m[tok] = tokenInfo{issuer: issuer, stamp: stamp, expires: exp}
	return tok, exp
}

// Lookup gives the issuer of a token and the stamp of the credential it was given for; the caller compares the stamp with the one of the credential now.
func (t *Tokens) Lookup(tok string, now time.Time) (issuer, stamp string, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[tok]
	if !ok {
		return "", "", false
	}
	if !now.Before(v.expires) {
		delete(t.m, tok)
		return "", "", false
	}
	return v.issuer, v.stamp, true
}

// ReadRSAPublic reads a PEM file with an RSA public key (PKIX or PKCS#1) or a certificate, of 2048 bits or more.
func ReadRSAPublic(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is from the configuration; it holds a public key
	if err != nil {
		return nil, err
	}
	if len(b) > 16<<10 {
		return nil, errors.New("the file is too large")
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("the file holds no PEM block")
	}
	var pub *rsa.PublicKey
	switch blk.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		pub, _ = k.(*rsa.PublicKey)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
	case "CERTIFICATE":
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		pub, _ = c.PublicKey.(*rsa.PublicKey)
	}
	if pub == nil || pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("an RSA public key of 2048 bits or more is needed")
	}
	return pub, nil
}
