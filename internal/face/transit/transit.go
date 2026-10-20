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
	"sync"
	"unicode/utf8"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/keyops"
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

	mu    sync.RWMutex
	gate  *gate.Gate // the line to the tokens, shared with the other face; nil: no bound
	track *tracker   // requests of this generation that are in flight
}

// tracker counts the requests of one generation, so that a reload can tell when the tokens it dropped are no longer in use.
type tracker struct{ wg sync.WaitGroup }

// Limit sets the line to the tokens. The same Gate may be given to another face.
func (f *Face) Limit(g *gate.Gate) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gate = g
}

// Gate is the line to the tokens (nil if none was set).
func (f *Face) Gate() *gate.Gate {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.gate
}

// Reload replaces the whole generation (configuration, tokens, policy and how clients are identified) at once for the requests that come after;
// one in flight finishes with the generation it began with.
// It returns a function that waits until every request that began with the previous generation is done.
func (f *Face) Reload(cfg *config.Config, tokens map[string]backend.Token, pol *policy.Policy, id Identify) (waitOld func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	old := f.track
	f.Cfg, f.Tokens, f.Policy, f.Identify = cfg, tokens, pol, id
	f.track = &tracker{}
	if old == nil {
		return func() {}
	}
	return old.wg.Wait
}

func (f *Face) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.RLock()
	missing := f.track == nil
	f.mu.RUnlock()
	if missing {
		f.mu.Lock()
		if f.track == nil {
			f.track = &tracker{}
		}
		f.mu.Unlock()
	}
	f.mu.RLock()
	g := &Face{Cfg: f.Cfg, Tokens: f.Tokens, Policy: f.Policy, Audit: f.Audit, Identify: f.Identify, gate: f.gate}
	t := f.track
	if t != nil {
		t.wg.Add(1) // under the read lock: Reload swaps the tracker under the write lock, so no request joins a generation that is being waited for
	}
	f.mu.RUnlock()
	if t != nil {
		defer t.wg.Done()
	}
	g.serve(w, r)
}

const (
	face       = "transit"
	maxContext = 1024 // the context is written to the audit: keep a line small
)

// acquire waits for a turn at the tokens; false means the caller was told to come back later.
func (f *Face) acquire(w http.ResponseWriter, r *http.Request) (release func(), ok bool) {
	release, ok = f.gate.Take(r.Context())
	if !ok {
		w.Header().Set("Retry-After", "2")
		fail(w, 503, "busy", true)
	}
	return release, ok
}

func (f *Face) serve(w http.ResponseWriter, r *http.Request) {
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
	// a refusal is written down as well as can be; it has nothing to withhold
	done := func(status int, result string, msg string, retry bool) {
		ev.Result = result
		f.Audit.Write(ev)
		fail(w, status, msg, retry)
	}
	// an answer is given only after the line that says so is written: with no log, nothing leaves
	succeed := func(payload any) {
		ev.Result = "ok"
		if err := f.Audit.Write(ev); err != nil {
			w.Header().Set("Retry-After", "5")
			fail(w, 503, "audit log unavailable", true)
			return
		}
		reply(w, 200, payload)
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
	isOp := (op == "encrypt" || op == "decrypt" || op == "rewrap") && (r.Method == http.MethodPut || r.Method == http.MethodPost)
	isKeys := op == "keys" && r.Method == http.MethodGet
	if !isOp && !isKeys {
		done(404, "unsupported", "unsupported path", false)
		return
	}
	// fail closed: with no way to write the decision down nothing is done (a probe line says when the log works again)
	if !f.Audit.Healthy() && f.Audit.Write(audit.Event{RequestID: rid, Face: face, Op: "audit-probe", Result: "probe"}) != nil {
		w.Header().Set("Retry-After", "5")
		fail(w, 503, "audit log unavailable", true)
		return
	}
	decision := f.Policy.Check(client, name, op)
	if isKeys {
		decision = f.Policy.CheckMeta(client, name) // key information has a small budget of its own
	}
	switch decision {
	case policy.Forbidden:
		done(403, "forbidden", "permission denied", false)
		return
	case policy.Throttled:
		w.Header().Set("Retry-After", "5")
		done(429, "throttled", "rate limit exceeded", true)
		return
	}
	release, got := f.acquire(w, r)
	if !got {
		ev.Result = "busy"
		f.Audit.Write(ev)
		return
	}
	defer release()
	if isKeys {
		f.keyInfo(w, name, key, succeed)
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
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(4*max+4096)))
	if err := dec.Decode(&body); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			done(413, "too_large", "request body too large", false)
			return
		}
		done(400, "bad_request", "invalid request body", false)
		return
	}
	// nothing but whitespace may follow the one JSON value
	if _, err := dec.Token(); err != io.EOF {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			done(413, "too_large", "request body too large", false)
			return
		}
		done(400, "bad_request", "invalid request body", false)
		return
	}
	aad, msg, forbidden := f.aadOf(client, name, key, body.Context)
	if key.AAD.Mode == "context" && utf8.Valid(aad) {
		ev.Context = string(aad) // public by rule; a refused context is written down too
	}
	if forbidden {
		done(403, "forbidden_context", "permission denied", false)
		return
	}
	if msg != "" {
		done(400, "bad_context", msg, false)
		return
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
		succeed(map[string]any{"data": map[string]any{"ciphertext": ct, "key_version": ver}})
	case "decrypt", "rewrap":
		if body.Ciphertext == nil {
			done(400, "bad_request", "missing ciphertext", false)
			return
		}
		if len(*body.Ciphertext) > 3*max+1024 { // the sealed text of max bytes is about 2.7 times as long in base64
			done(400, "too_large", "ciphertext too large for this key", false)
			return
		}
		plain, err := f.open(key, *body.Ciphertext, aad)
		if err != nil {
			f.failTokenErr(done, err)
			return
		}
		defer wipe(plain)
		if len(plain) > max {
			done(400, "too_large", "invalid ciphertext: the data is larger than max_bytes of this key", false)
			return
		}
		if op == "decrypt" {
			succeed(map[string]any{"data": map[string]any{"plaintext": base64.StdEncoding.EncodeToString(plain)}})
			return
		}
		ct, ver, err := f.seal(key, plain, aad)
		if err != nil {
			f.failTokenErr(done, err)
			return
		}
		succeed(map[string]any{"data": map[string]any{"ciphertext": ct, "key_version": ver}})
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// aadOf returns the additional data; forbidden is true when the grant of this client does not cover the context (judged before the rules of the key, so that a client learns nothing about them).
func (f *Face) aadOf(client, name string, k config.Key, ctx *string) (aad []byte, msg string, forbidden bool) {
	if k.AAD.Mode == "fixed" {
		if ctx != nil && *ctx != "" {
			return nil, "this key takes no context", false
		}
		return []byte(k.FixedAAD(name)), "", false
	}
	if ctx == nil || *ctx == "" {
		return nil, "missing context", false
	}
	b, err := base64.StdEncoding.DecodeString(*ctx)
	if err == nil && len(b) > maxContext {
		return nil, "context is too long", false
	}
	if err != nil || len(b) == 0 {
		return nil, "failed to base64-decode context", false
	}
	if !f.Policy.ContextOK(client, name, b) {
		return b, "", true
	}
	if !policy.ContextAllowed(k, b) {
		return nil, "context not allowed for this key", false
	}
	return b, "", false
}

// pointOf is the public key of a version, from the first holder that answers.
func (f *Face) pointOf(v config.Version) ([]byte, error) { return keyops.PointOf(f.Tokens, v) }

func (f *Face) seal(k config.Key, plain, aad []byte) (string, int, error) {
	ver := len(k.Versions)
	point, err := f.pointOf(k.Versions[ver-1])
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
	// the holders in order: the next one is tried only when this one could not answer (locked, removed), never when it said the text is bad
	var last error
	for _, h := range k.Versions[n-1].Holders() {
		tok := f.Tokens[h.Token]
		point, err := tok.Point(h.Label)
		if err == nil {
			err = keyops.Pinned(k.Versions[n-1], point)
		}
		if err == nil {
			var plain []byte
			if plain, err = ecies.Unwrap(point, derive{tok, h.Label}, string(text), aad); err == nil {
				return plain, nil
			}
		}
		if !errors.Is(err, backend.ErrUnavailable) {
			return nil, err
		}
		last = err
	}
	return nil, last
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

func (f *Face) keyInfo(w http.ResponseWriter, name string, k config.Key, succeed func(any)) {
	keys := map[string]any{}
	for i, v := range k.Versions {
		if point, err := f.pointOf(v); err == nil {
			keys[strconv.Itoa(i+1)] = map[string]any{"public_key": base64.StdEncoding.EncodeToString(point), "fingerprint": ecies.Fingerprint(point)}
		}
	}
	// the state of the best holder of the latest version
	state := "absent"
	for _, h := range k.Versions[len(k.Versions)-1].Holders() {
		if st := f.Tokens[h.Token].State(); st == "ready" || state == "absent" {
			state = st
		}
	}
	succeed(map[string]any{"data": map[string]any{
		"name": name, "type": "ecdh-es-p256", "latest_version": len(k.Versions), "min_decryption_version": 1,
		"supports_encryption": true, "supports_decryption": true, "supports_derivation": k.AAD.Mode == "context",
		"supports_signing": false, "keys": keys, "token_state": state,
	}})
}

func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); id != "" && len(id) <= 64 && safeID(id) {
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

func safeID(s string) bool {
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
