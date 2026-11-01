package main

// The clients of the four faces: each does one round, encrypt then decrypt of a random plaintext, and says whether what came back is what went in.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/zystem/hsmgate/internal/sigv4"
)

const (
	akid       = "AKIDSOAKSOAKSOAK0001"
	sigSecret  = "a-signing-secret-of-the-soak-0123456789"
	restID     = "soak-rest-client"
	restSecret = "a-client-secret-of-the-soak-0123456789abcdef"
	jwtIssuer  = "soak@example.test"
	grpcPath   = "/google.cloud.kms.v1.KeyManagementService/"
	ringName   = "projects/hsmgate/locations/global/keyRings/main/cryptoKeys/"
)

type face interface {
	name() string
	round(plain []byte) error
}

func httpDo(c *http.Client, req *http.Request) (int, []byte, http.Header, http.Header, error) {
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, b, resp.Header, resp.Trailer, err
}

// ---- Transit ----

type transit struct {
	c    *http.Client
	base string
}

func (t *transit) name() string { return "transit" }

func (t *transit) call(op, body string) (map[string]any, error) {
	req, _ := http.NewRequest("PUT", t.base+"/v1/transit/"+op+"/t-seal", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	st, b, _, _, err := httpDo(t.c, req)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("%s: HTTP %d %.80s", op, st, b)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	d, _ := m["data"].(map[string]any)
	return d, nil
}

func (t *transit) round(plain []byte) error {
	d, err := t.call("encrypt", `{"plaintext":"`+base64.StdEncoding.EncodeToString(plain)+`"}`)
	if err != nil {
		return err
	}
	ct, _ := d["ciphertext"].(string)
	d, err = t.call("decrypt", `{"ciphertext":"`+ct+`"}`)
	if err != nil {
		return err
	}
	got, _ := base64.StdEncoding.DecodeString(fmt.Sprint(d["plaintext"]))
	if !bytes.Equal(got, plain) {
		return errors.New("transit: the plaintext that came back is not the one that went in")
	}
	return nil
}

// ---- KMS-JSON ----

type kmsjson struct {
	c    *http.Client
	base string
}

func (k *kmsjson) name() string { return "kmsjson" }

func (k *kmsjson) call(op, body string) (map[string]any, error) {
	req, _ := http.NewRequest("POST", k.base+"/", strings.NewReader(body))
	req.Header.Set("X-Amz-Target", "TrentService."+op)
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	sigv4.Sign(req, []byte(body), akid, []byte(sigSecret), "local", "kms", time.Now())
	st, b, _, _, err := httpDo(k.c, req)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("%s: HTTP %d %.80s", op, st, b)
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func (k *kmsjson) round(plain []byte) error {
	m, err := k.call("Encrypt", `{"KeyId":"j-seal","Plaintext":"`+base64.StdEncoding.EncodeToString(plain)+`"}`)
	if err != nil {
		return err
	}
	m, err = k.call("Decrypt", `{"CiphertextBlob":"`+fmt.Sprint(m["CiphertextBlob"])+`"}`)
	if err != nil {
		return err
	}
	got, _ := base64.StdEncoding.DecodeString(fmt.Sprint(m["Plaintext"]))
	if !bytes.Equal(got, plain) {
		return errors.New("kmsjson: the plaintext that came back is not the one that went in")
	}
	return nil
}

// ---- REST ----

type rest struct {
	c    *http.Client
	base string
	mu   sync.Mutex
	tok  string
	exp  time.Time
}

func (r *rest) name() string { return "rest" }

func (r *rest) token() (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tok != "" && time.Now().Before(r.exp) {
		return r.tok, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {restID}, "client_secret": {restSecret}}
	req, _ := http.NewRequest("POST", r.base+"/hsmgate/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	st, b, _, _, err := httpDo(r.c, req)
	if err != nil {
		return "", err
	}
	var m struct {
		AccessToken string `json:"access_token"`
	}
	if st != 200 || json.Unmarshal(b, &m) != nil || m.AccessToken == "" {
		return "", fmt.Errorf("rest token: HTTP %d %.80s", st, b)
	}
	r.tok, r.exp = m.AccessToken, time.Now().Add(40*time.Minute) // a token lasts an hour
	return r.tok, nil
}

func (r *rest) call(op, body string) (map[string]any, error) {
	tok, err := r.token()
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest("POST", r.base+"/keys/r-seal/"+op+"?api-version=7.5", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	st, b, _, _, err := httpDo(r.c, req)
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("rest %s: HTTP %d %.80s", op, st, b)
	}
	var m map[string]any
	return m, json.Unmarshal(b, &m)
}

func (r *rest) round(plain []byte) error {
	m, err := r.call("encrypt", `{"alg":"A256GCM","value":"`+base64.RawURLEncoding.EncodeToString(plain)+`"}`)
	if err != nil {
		return err
	}
	m, err = r.call("decrypt", `{"alg":"A256GCM","value":"`+fmt.Sprint(m["value"])+`"}`)
	if err != nil {
		return err
	}
	got, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(m["value"]))
	if !bytes.Equal(got, plain) {
		return errors.New("rest: the plaintext that came back is not the one that went in")
	}
	return nil
}

// ---- gRPC ----

type grpc struct {
	c    *http.Client
	base string
	key  *rsa.PrivateKey
	mu   sync.Mutex
	jwt  string
	exp  time.Time
}

func (g *grpc) name() string { return "grpc" }

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// bearer is a JWT that the client signed itself (the face accepts it, as the client libraries use it): RS256, an hour long, made again when it is near its end.
func (g *grpc) bearer() (string, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.jwt != "" && time.Now().Before(g.exp) {
		return g.jwt, nil
	}
	now := time.Now()
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	cl, _ := json.Marshal(map[string]any{"iss": jwtIssuer, "sub": jwtIssuer, "aud": "https://soak.test/", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	in := b64u(hdr) + "." + b64u(cl)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	g.jwt, g.exp = in+"."+b64u(sig), now.Add(40*time.Minute)
	return g.jwt, nil
}

func (g *grpc) call(method string, msg []byte) ([]byte, error) {
	tok, err := g.bearer()
	if err != nil {
		return nil, err
	}
	body := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(body[1:], uint32(len(msg))) // #nosec G115 -- small
	body = append(body, msg...)
	req, _ := http.NewRequest("POST", g.base+grpcPath+method, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	req.Header.Set("Authorization", "Bearer "+tok)
	st, b, hdr, tr, err := httpDo(g.c, req)
	if err != nil {
		return nil, err
	}
	status := tr.Get("Grpc-Status")
	if status == "" {
		status = hdr.Get("Grpc-Status")
	}
	if st != 200 || status != "0" || len(b) < 5 {
		return nil, fmt.Errorf("grpc %s: HTTP %d status %q %q", method, st, status, hdr.Get("Grpc-Message"))
	}
	return b[5:], nil
}

// field reads the bytes of field n of a protobuf message.
func field(msg []byte, n protowire.Number) []byte {
	for len(msg) > 0 {
		num, typ, l := protowire.ConsumeTag(msg)
		if l < 0 {
			return nil
		}
		msg = msg[l:]
		l = protowire.ConsumeFieldValue(num, typ, msg)
		if l < 0 {
			return nil
		}
		if num == n && typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(msg)
			return v
		}
		msg = msg[l:]
	}
	return nil
}

func (g *grpc) round(plain []byte) error {
	var req []byte
	req = protowire.AppendTag(req, 1, protowire.BytesType)
	req = protowire.AppendString(req, ringName+"g-seal")
	req = protowire.AppendTag(req, 2, protowire.BytesType)
	req = protowire.AppendBytes(req, plain)
	rep, err := g.call("Encrypt", req)
	if err != nil {
		return err
	}
	ct := field(rep, 2)
	var dreq []byte
	dreq = protowire.AppendTag(dreq, 1, protowire.BytesType)
	dreq = protowire.AppendString(dreq, ringName+"g-seal")
	dreq = protowire.AppendTag(dreq, 2, protowire.BytesType)
	dreq = protowire.AppendBytes(dreq, ct)
	rep, err = g.call("Decrypt", dreq)
	if err != nil {
		return err
	}
	if !bytes.Equal(field(rep, 1), plain) {
		return errors.New("grpc: the plaintext that came back is not the one that went in")
	}
	return nil
}
