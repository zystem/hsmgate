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
	ErrJWT     = errors.New("the token is not valid")
	ErrExpired = errors.New("the token has expired")
)

type Claims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Iat int64           `json:"iat"`
	Exp int64           `json:"exp"`
}

// aud reads the audience: a string, or a list of strings.
func (c Claims) Audiences() []string {
	var one string
	if json.Unmarshal(c.Aud, &one) == nil {
		return []string{one}
	}
	var many []string
	if json.Unmarshal(c.Aud, &many) == nil {
		return many
	}
	return nil
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

// VerifyJWT checks a token against the public key of its issuer: RS256 only, within its life, issued no later than now (plus the skew).
func VerifyJWT(tok string, pub *rsa.PublicKey, now time.Time) (Claims, error) {
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
	exp, iat := time.Unix(c.Exp, 0), time.Unix(c.Iat, 0)
	if c.Exp == 0 || !now.Before(exp.Add(skew)) {
		return Claims{}, ErrExpired
	}
	if iat.After(now.Add(skew)) || exp.Sub(iat) > maxJWTLife || exp.Before(iat) {
		return Claims{}, ErrJWT
	}
	return c, nil
}

type tokenInfo struct {
	issuer  string
	expires time.Time
}

// Tokens are the access tokens this service has given: opaque, random, in memory only (a restart ends them; a client then asks again).
type Tokens struct {
	mu sync.Mutex
	m  map[string]tokenInfo
}

func NewTokens() *Tokens { return &Tokens{m: map[string]tokenInfo{}} }

func (t *Tokens) Issue(issuer string, now time.Time) (string, time.Time) {
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
	t.m[tok] = tokenInfo{issuer: issuer, expires: exp}
	return tok, exp
}

func (t *Tokens) Lookup(tok string, now time.Time) (string, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.m[tok]
	if !ok {
		return "", false
	}
	if !now.Before(v.expires) {
		delete(t.m, tok)
		return "", false
	}
	return v.issuer, true
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
