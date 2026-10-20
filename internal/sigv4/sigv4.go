// Package sigv4 verifies the signature of a request signed with the scheme named "AWS4-HMAC-SHA256" (the request-signing scheme that SDKs of the cloud key services use,
// "Signature Version 4"). The name is the wire name of the scheme; this package is independent of any SDK and of any service.
//
// What is checked: the Authorization header (credential scope: date, region, service), the date (X-Amz-Date within MaxSkew of now), the signed headers (the ones in Require
// must be among them: the signature must cover the target of the call), the payload hash, and the signature itself, in constant time. The secret of an access key comes from
// the Secrets function. There is no replay cache: the requests travel inside TLS with a client certificate, so a recorded request cannot be sent again by anyone who is not already
// on the connection, and a retry of the same request within a second would be refused by such a cache for no reason.
package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	algorithm  = "AWS4-HMAC-SHA256"
	terminator = "aws4_request"
	dateLayout = "20060102T150405Z"
)

// Errors; Kind says which answer the face gives.
var (
	ErrMissing   = errors.New("the request is not signed")
	ErrMalformed = errors.New("the authorization header is malformed")
	ErrUnknown   = errors.New("unknown access key")
	ErrSignature = errors.New("the signature does not match")
	ErrExpired   = errors.New("the request time is too far from the time of the service")
	ErrScope     = errors.New("the credential scope is not for this service")
	ErrHeaders   = errors.New("a header that must be signed is not")
	ErrPayload   = errors.New("the payload hash does not match the body")
)

type Verifier struct {
	Region, Service string
	Secrets         func(accessKeyID string) (secret []byte, ok bool)
	MaxSkew         time.Duration // default 5 minutes
	Require         []string      // lowercase names of headers that must be signed; default host, x-amz-date, x-amz-target
	Now             func() time.Time
}

// Verify returns the access key id of a request whose signature is good. body is the whole body of the request.
func (v *Verifier) Verify(r *http.Request, body []byte) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ErrMissing
	}
	if !strings.HasPrefix(auth, algorithm+" ") {
		return "", fmt.Errorf("%w: not %s", ErrMalformed, algorithm)
	}
	fields := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, algorithm+" "), ",") {
		k, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			return "", ErrMalformed
		}
		fields[k] = val
	}
	cred, signed, sig := fields["Credential"], fields["SignedHeaders"], fields["Signature"]
	if cred == "" || signed == "" || sig == "" {
		return "", ErrMalformed
	}
	scope := strings.Split(cred, "/")
	if len(scope) != 5 || scope[4] != terminator {
		return "", ErrMalformed
	}
	akid, date, region, service := scope[0], scope[1], scope[2], scope[3]
	if region != v.Region || service != v.Service {
		return "", ErrScope
	}
	amzDate := r.Header.Get("X-Amz-Date")
	t, err := time.Parse(dateLayout, amzDate)
	if err != nil || !strings.HasPrefix(amzDate, date) {
		return "", fmt.Errorf("%w: X-Amz-Date", ErrMalformed)
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	skew := v.MaxSkew
	if skew == 0 {
		skew = 5 * time.Minute
	}
	if d := now.Sub(t); d > skew || d < -skew {
		return "", ErrExpired
	}
	names := strings.Split(signed, ";")
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	req := v.Require
	if req == nil {
		req = []string{"host", "x-amz-date", "x-amz-target"}
	}
	for _, n := range req {
		if !have[n] {
			return "", fmt.Errorf("%w: %s", ErrHeaders, n)
		}
	}
	secret, ok := v.Secrets(akid)
	if !ok {
		return "", ErrUnknown
	}
	// The signature must cover the body: the hash of the body is what the canonical request holds. A header that claims another payload mode (UNSIGNED-PAYLOAD, STREAMING-...) would
	// leave the body outside the signature, so a body could be exchanged under a valid Authorization: it is refused; a header with the real hash is accepted.
	payload := hex.EncodeToString(sum(body))
	if h := r.Header.Get("X-Amz-Content-Sha256"); h != "" && !strings.EqualFold(h, payload) {
		return "", ErrPayload
	}
	canon, err := canonicalRequest(r, names, payload)
	if err != nil {
		return "", err
	}
	toSign := algorithm + "\n" + amzDate + "\n" + date + "/" + region + "/" + service + "/" + terminator + "\n" + hex.EncodeToString(sum([]byte(canon)))
	want := hex.EncodeToString(hmacSHA256(signingKey(secret, date, region, service), []byte(toSign)))
	if !hmac.Equal([]byte(want), []byte(strings.ToLower(sig))) {
		return "", ErrSignature
	}
	return akid, nil
}

func canonicalRequest(r *http.Request, names []string, payload string) (string, error) {
	if !sort.StringsAreSorted(names) {
		return "", fmt.Errorf("%w: SignedHeaders are not sorted", ErrMalformed)
	}
	var h strings.Builder
	for _, n := range names {
		var val string
		if n == "host" {
			val = r.Host
		} else {
			vals := r.Header.Values(http.CanonicalHeaderKey(n))
			if len(vals) == 0 {
				return "", fmt.Errorf("%w: %s is signed but absent", ErrHeaders, n)
			}
			trimmed := make([]string, len(vals))
			for i, x := range vals {
				trimmed[i] = strings.Join(strings.Fields(x), " ")
			}
			val = strings.Join(trimmed, ",")
		}
		h.WriteString(n + ":" + strings.Join(strings.Fields(val), " ") + "\n")
	}
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	return r.Method + "\n" + path + "\n" + canonicalQuery(r.URL) + "\n" + h.String() + "\n" + strings.Join(names, ";") + "\n" + payload, nil
}

func canonicalQuery(u *url.URL) string {
	q := u.Query()
	var parts []string
	for k, vals := range q {
		for _, v := range vals {
			parts = append(parts, uriEncode(k)+"="+uriEncode(v))
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "&")
}

func uriEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func signingKey(secret []byte, date, region, service string) []byte {
	k := hmacSHA256(append([]byte("AWS4"), secret...), []byte(date))
	k = hmacSHA256(k, []byte(region))
	k = hmacSHA256(k, []byte(service))
	return hmacSHA256(k, []byte(terminator))
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// Sign adds the headers of a signed request (for tests and for a client that has no SDK). It signs host, x-amz-date and x-amz-target, and content-type if present.
func Sign(r *http.Request, body []byte, akid string, secret []byte, region, service string, now time.Time) {
	amz := now.UTC().Format(dateLayout)
	date := amz[:8]
	r.Header.Set("X-Amz-Date", amz)
	names := []string{"host", "x-amz-date"}
	if r.Header.Get("X-Amz-Target") != "" {
		names = append(names, "x-amz-target")
	}
	if r.Header.Get("Content-Type") != "" {
		names = append(names, "content-type")
	}
	sort.Strings(names)
	canon, _ := canonicalRequest(r, names, hex.EncodeToString(sum(body)))
	toSign := algorithm + "\n" + amz + "\n" + date + "/" + region + "/" + service + "/" + terminator + "\n" + hex.EncodeToString(sum([]byte(canon)))
	sig := hex.EncodeToString(hmacSHA256(signingKey(secret, date, region, service), []byte(toSign)))
	r.Header.Set("Authorization", fmt.Sprintf("%s Credential=%s/%s/%s/%s/%s, SignedHeaders=%s, Signature=%s", algorithm, akid, date, region, service, terminator, strings.Join(names, ";"), sig))
}
