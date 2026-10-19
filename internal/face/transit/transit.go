// Package transit is the Vault/OpenBao Transit face: encrypt, decrypt, rewrap, keys/<name>, and the few calls that existing clients make around them
// (sys/health, auth/token/lookup-self and renew-self). It must not break OpenBao's seal `transit`: that sends {"plaintext": base64} to encrypt/<key> and
// {"ciphertext": "vault:v1:..."} to decrypt/<key>, with no context, and reads data.ciphertext / data.plaintext. A token it presents is ignored.
package transit

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/policy"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

// Identify names the client of a request, or says there is none. The server wires it to the verified client certificate.
type Identify func(*http.Request) (string, bool)

type Face struct {
	Cfg      *config.Config
	Tokens   map[string]backend.Token
	Policy   *policy.Policy
	Audit    *audit.Log
	Identify Identify
}

const face = "transit"

func (f *Face) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := "/v1/" + f.Cfg.Transit.Mount + "/"
	path := r.URL.Path
	switch {
	case path == "/v1/sys/health":
		reply(w, 200, map[string]any{"initialized": true, "sealed": false, "standby": false, "version": "hsmgate"})
		return
	case path == "/v1/auth/token/lookup-self" || path == "/v1/auth/token/renew-self":
		// a token is never an authentication here; a client the policy knows gets a token that never expires, so that nothing tries to renew it.
		// A certificate the policy does not know is refused here, so that such a client fails at its start and not at its first key.
		if _, ok := f.Identify(r); !ok {
			f.Audit.Write(audit.Event{RequestID: requestID(r), Face: face, Op: "token-lookup", Result: "unauthenticated"})
			fail(w, 403, "permission denied", false)
			return
		}
		reply(w, 200, map[string]any{"data": map[string]any{"id": "hsmgate", "ttl": 0, "creation_ttl": 0, "renewable": false, "policies": []string{}},
			"auth": map[string]any{"client_token": "hsmgate", "lease_duration": 2764800, "renewable": false}})
		return
	case !strings.HasPrefix(path, prefix):
		fail(w, 404, "unsupported path", false)
		return
	}
	client, ok := f.Identify(r)
	rid := requestID(r)
	w.Header().Set("X-Request-Id", rid)
	parts := strings.Split(strings.TrimPrefix(path, prefix), "/")
	if len(parts) != 2 {
		fail(w, 404, "unsupported path", false)
		return
	}
	op, name := parts[0], parts[1]
	ev := audit.Event{RequestID: rid, Client: client, Face: face, Key: name, Op: op}
	done := func(status int, result string, msg string, retry bool) {
		ev.Result = result
		f.Audit.Write(ev)
		fail(w, status, msg, retry)
	}
	if !ok {
		ev.Client = ""
		done(403, "unauthenticated", "permission denied", false)
		return
	}
	key, known := f.Cfg.Keys[name]
	// a key the client has no grant for looks the same as one that does not exist
	if !known || !f.Policy.Allowed(client, name) {
		done(403, "forbidden", "permission denied", false)
		return
	}
	switch {
	case op == "keys" && r.Method == http.MethodGet:
		// any grant on the key lets a client read its public part
		f.keyInfo(w, name, key)
		ev.Result = "ok"
		f.Audit.Write(ev)
		return
	case (op == "encrypt" || op == "decrypt" || op == "rewrap") && (r.Method == http.MethodPut || r.Method == http.MethodPost):
	default:
		done(404, "unsupported", "unsupported path", false)
		return
	}
	switch f.Policy.Check(client, name, op) {
	case policy.Forbidden:
		done(403, "forbidden", "permission denied", false)
		return
	case policy.Throttled:
		w.Header().Set("Retry-After", "5")
		done(429, "throttled", "rate limit exceeded", true)
		return
	}
	var body struct {
		Plaintext  *string `json:"plaintext"`
		Ciphertext *string `json:"ciphertext"`
		Context    *string `json:"context"`
	}
	max := key.MaxBytes
	if max == 0 {
		max = config.DefaultMaxBytes
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(4*max+4096)))
	if err != nil || json.Unmarshal(raw, &body) != nil {
		done(400, "bad_request", "invalid request body", false)
		return
	}
	aad, msg := f.aadOf(name, key, body.Context)
	if msg != "" {
		done(400, "bad_context", msg, false)
		return
	}
	if key.AAD.Mode == "context" && utf8.Valid(aad) {
		ev.Context = string(aad)
	}
	switch op {
	case "encrypt":
		if body.Plaintext == nil {
			done(400, "bad_request", "missing plaintext", false)
			return
		}
		plain, err := base64.StdEncoding.DecodeString(*body.Plaintext)
		if err != nil {
			done(400, "bad_request", "failed to base64-decode plaintext", false)
			return
		}
		if len(plain) == 0 || len(plain) > max {
			done(400, "bad_request", "invalid plaintext", false)
			return
		}
		ct, ver, err := f.seal(key, plain, aad)
		if err != nil {
			f.failTokenErr(done, err)
			return
		}
		ev.Result = "ok"
		f.Audit.Write(ev)
		reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": ct, "key_version": ver}})
	case "decrypt", "rewrap":
		if body.Ciphertext == nil {
			done(400, "bad_request", "missing ciphertext", false)
			return
		}
		plain, err := f.open(key, *body.Ciphertext, aad)
		if err != nil {
			f.failTokenErr(done, err)
			return
		}
		if op == "decrypt" {
			ev.Result = "ok"
			f.Audit.Write(ev)
			reply(w, 200, map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plain)}})
			return
		}
		ct, ver, err := f.seal(key, plain, aad)
		if err != nil {
			f.failTokenErr(done, err)
			return
		}
		ev.Result = "ok"
		f.Audit.Write(ev)
		reply(w, 200, map[string]any{"data": map[string]any{"ciphertext": ct, "key_version": ver}})
	}
}

func (f *Face) aadOf(name string, k config.Key, ctx *string) ([]byte, string) {
	if k.AAD.Mode == "fixed" {
		if ctx != nil && *ctx != "" {
			return nil, "this key takes no context"
		}
		return []byte(k.FixedAAD(name)), ""
	}
	if ctx == nil || *ctx == "" {
		return nil, "missing context"
	}
	b, err := base64.StdEncoding.DecodeString(*ctx)
	if err != nil || len(b) == 0 {
		return nil, "failed to base64-decode context"
	}
	if !policy.ContextAllowed(k, b) {
		return nil, "context not allowed for this key"
	}
	return b, ""
}

func (f *Face) tokenOf(v config.Version) backend.Token { return f.Tokens[v.Token] }

func (f *Face) seal(k config.Key, plain, aad []byte) (string, int, error) {
	ver := len(k.Versions)
	v := k.Versions[ver-1]
	point, err := f.tokenOf(v).Point(v.Label)
	if err != nil {
		return "", 0, err
	}
	text, err := ecies.Wrap(point, plain, aad)
	if err != nil {
		return "", 0, err
	}
	return "vault:v" + strconv.Itoa(ver) + ":" + base64.StdEncoding.EncodeToString([]byte(text)), ver, nil
}

var errBadCiphertext = errors.New("invalid ciphertext")

func (f *Face) open(k config.Key, ct string, aad []byte) ([]byte, error) {
	p := strings.Split(ct, ":")
	if len(p) != 3 || p[0] != "vault" || !strings.HasPrefix(p[1], "v") {
		return nil, errBadCiphertext
	}
	n, err := strconv.Atoi(p[1][1:])
	if err != nil || n < 1 || n > len(k.Versions) {
		return nil, errBadCiphertext
	}
	text, err := base64.StdEncoding.DecodeString(p[2])
	if err != nil {
		return nil, errBadCiphertext
	}
	v := k.Versions[n-1]
	tok := f.tokenOf(v)
	point, err := tok.Point(v.Label)
	if err != nil {
		return nil, err
	}
	return ecies.Unwrap(point, derive{tok, v.Label}, string(text), aad)
}

type derive struct {
	t     backend.Token
	label string
}

func (d derive) Derive(peer []byte) ([]byte, error) { return d.t.Derive(d.label, peer) }

func (f *Face) failTokenErr(done func(int, string, string, bool), err error) {
	switch {
	case errors.Is(err, backend.ErrLocked):
		done(503, "locked", "token locked", true)
	case errors.Is(err, backend.ErrUnavailable):
		done(503, "unavailable", "token unavailable", true)
	case errors.Is(err, errBadCiphertext), errors.Is(err, ecies.ErrDamaged), errors.Is(err, ecies.ErrWrongKey):
		done(400, "invalid_ciphertext", "invalid ciphertext: cannot be opened with this key", false)
	default:
		done(503, "unavailable", "internal error", true)
	}
}

func (f *Face) keyInfo(w http.ResponseWriter, name string, k config.Key) {
	keys := map[string]any{}
	for i, v := range k.Versions {
		if point, err := f.tokenOf(v).Point(v.Label); err == nil {
			keys[strconv.Itoa(i+1)] = map[string]any{"public_key": base64.StdEncoding.EncodeToString(point), "fingerprint": ecies.Fingerprint(point)}
		}
	}
	state := f.tokenOf(k.Versions[len(k.Versions)-1]).State()
	reply(w, 200, map[string]any{"data": map[string]any{
		"name": name, "type": "ecdh-es-p256", "latest_version": len(k.Versions), "min_decryption_version": 1,
		"supports_encryption": true, "supports_decryption": true, "supports_derivation": k.AAD.Mode == "context",
		"supports_signing": false, "keys": keys, "token_state": state,
	}})
}

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 && utf8.ValidString(id) {
		return id
	}
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string, retry bool) {
	w.Header().Set("X-Hsmgate-Retryable", strconv.FormatBool(retry))
	reply(w, status, map[string]any{"errors": []string{msg}})
}
