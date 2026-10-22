package kmsgrpc

// Authentication of the gRPC face. A client holds a service account: the private key of an RSA pair, which the service knows by its public half. Like the client libraries of the
// service do, it can (1) send a token that it signed itself (a JWT, RS256) as the bearer, or (2) trade a signed assertion for an opaque access token at the token endpoint of this
// service (the grant "urn:ietf:params:oauth:grant-type:jwt-bearer") and send that. Either way the bearer is bound to the client of the credential; the address, the client certificate
// (if one is shown it must be the client's) and the rule about calls without a certificate are judged on every request, so that a removed credential or a changed list of addresses
// ends access at once.

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
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zystem/hsmgate/internal/config"
)

// Cred is a service account of a client.
type Cred struct {
	Client string
	Issuer string
	Key    *rsa.PublicKey
	NoCert bool
	From   []netip.Prefix
}

const (
	tokenTTL   = time.Hour
	maxTokens  = 10000
	maxJWTLife = 24 * time.Hour
	skew       = 5 * time.Minute
)

var (
	errJWT     = errors.New("the token is not valid")
	errExpired = errors.New("the token has expired")
)

type claims struct {
	Iss string          `json:"iss"`
	Sub string          `json:"sub"`
	Aud json.RawMessage `json:"aud"`
	Iat int64           `json:"iat"`
	Exp int64           `json:"exp"`
}

// aud reads the audience: a string, or a list of strings.
func (c claims) audiences() []string {
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

// splitJWT reads the issuer of a token without trusting it (to find the key to check it with).
func peekIssuer(tok string) (string, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	var c claims
	if json.Unmarshal(raw, &c) != nil || c.Iss == "" {
		return "", false
	}
	return c.Iss, true
}

// verifyJWT checks a token against the public key of its issuer: RS256 only, within its life, issued no later than now (plus the skew).
func verifyJWT(tok string, pub *rsa.PublicKey, now time.Time) (claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return claims{}, errJWT
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims{}, errJWT
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdr, &h) != nil || h.Alg != "RS256" { // never "none", never a symmetric algorithm
		return claims{}, errJWT
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims{}, errJWT
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return claims{}, errJWT
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, errJWT
	}
	var c claims
	if json.Unmarshal(raw, &c) != nil {
		return claims{}, errJWT
	}
	exp, iat := time.Unix(c.Exp, 0), time.Unix(c.Iat, 0)
	if c.Exp == 0 || !now.Before(exp.Add(skew)) {
		return claims{}, errExpired
	}
	if iat.After(now.Add(skew)) || exp.Sub(iat) > maxJWTLife || exp.Before(iat) {
		return claims{}, errJWT
	}
	return c, nil
}

type tokenInfo struct {
	issuer  string
	expires time.Time
}

// tokens are the access tokens this service has given: opaque, random, in memory only (a restart ends them; a client then asks again).
type tokens struct {
	mu sync.Mutex
	m  map[string]tokenInfo
}

func newTokens() *tokens { return &tokens{m: map[string]tokenInfo{}} }

func (t *tokens) issue(issuer string, now time.Time) (string, time.Time) {
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
		panic("kmsgrpc: no randomness: " + err.Error())
	}
	tok := "hg." + strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
	exp := now.Add(tokenTTL)
	t.m[tok] = tokenInfo{issuer: issuer, expires: exp}
	return tok, exp
}

func (t *tokens) lookup(tok string, now time.Time) (string, bool) {
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

// LoadCreds reads the public keys of the service accounts of the clients that have a jwt credential, by issuer.
func LoadCreds(cfg *config.Config) (map[string]Cred, error) {
	creds := map[string]Cred{}
	for _, c := range cfg.Clients {
		if c.JWT == nil {
			continue
		}
		pemBytes, err := os.ReadFile(c.JWT.PublicKeyFile) // #nosec G304,G304 -- the path is from the configuration; it holds a public key
		if err != nil {
			return nil, fmt.Errorf("client %s: jwt.public_key_file: %w", c.Name, err)
		}
		if len(pemBytes) > 16<<10 {
			return nil, fmt.Errorf("client %s: jwt.public_key_file is too large", c.Name)
		}
		blk, _ := pem.Decode(pemBytes)
		if blk == nil {
			return nil, fmt.Errorf("client %s: jwt.public_key_file holds no PEM block", c.Name)
		}
		var pub *rsa.PublicKey
		switch blk.Type {
		case "PUBLIC KEY":
			k, err := x509.ParsePKIXPublicKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("client %s: jwt.public_key_file: %w", c.Name, err)
			}
			pub, _ = k.(*rsa.PublicKey)
		case "RSA PUBLIC KEY":
			pub, err = x509.ParsePKCS1PublicKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("client %s: jwt.public_key_file: %w", c.Name, err)
			}
		}
		if pub == nil || pub.N.BitLen() < 2048 {
			return nil, fmt.Errorf("client %s: jwt.public_key_file must hold an RSA public key of 2048 bits or more", c.Name)
		}
		from, err := (config.SigV4{AllowFrom: c.JWT.AllowFrom}).Prefixes()
		if err != nil {
			return nil, fmt.Errorf("client %s: %w", c.Name, err)
		}
		creds[c.JWT.Issuer] = Cred{Client: c.Name, Issuer: c.JWT.Issuer, Key: pub, NoCert: c.JWT.NoCert, From: from}
	}
	return creds, nil
}
