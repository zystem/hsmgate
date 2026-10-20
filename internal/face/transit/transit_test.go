package transit

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/gate"
	"github.com/zystem/hsmgate/internal/policy"
)

type vec struct {
	Master struct {
		Priv string `json:"private_hex"`
	} `json:"master"`
	Valid []struct {
		Name     string `json:"name"`
		PlainHex string `json:"plain_hex"`
		AAD      string `json:"aad"`
		Wrapped  string `json:"wrapped"`
	} `json:"valid"`
}

type lockedToken struct{ backend.Token }

func (lockedToken) Derive(string, []byte) ([]byte, error) { return nil, backend.ErrLocked }

type rig struct {
	t     *testing.T
	srv   *httptest.Server
	audit *bytes.Buffer
	vec   vec
	cfg   *config.Config
	face  *Face
}

func newRig(t *testing.T, mutate func(*config.Config, map[string]backend.Token)) *rig {
	t.Helper()
	raw, err := os.ReadFile("../../../testdata/vectors/ecies1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vec
	json.Unmarshal(raw, &v)
	dir := t.TempDir()
	f1 := filepath.Join(dir, "k1")
	os.WriteFile(f1, []byte(v.Master.Priv), 0o600)
	// a second key for version 2 (any other valid scalar)
	f2 := filepath.Join(dir, "k2")
	os.WriteFile(f2, []byte(strings.Repeat("0a", 32)), 0o600)
	cfg := &config.Config{
		Tokens: []config.Token{{Name: "soft", Type: "soft", Keys: map[string]string{"m1": f1, "m2": f2}}},
		Keys: map[string]config.Key{
			"bao-seal": {Versions: []config.Version{{Token: "soft", Label: "m1"}}, AAD: config.AAD{Mode: "fixed"}},
			"cinim":    {Versions: []config.Version{{Token: "soft", Label: "m1"}}, AAD: config.AAD{Mode: "context", Allow: []string{"cinim/dek/v1|"}}},
			"rot":      {Versions: []config.Version{{Token: "soft", Label: "m1"}}, AAD: config.AAD{Mode: "fixed", Fixed: "x"}},
		},
		Clients: []config.Client{
			{Name: "openbao", Identity: config.Identity{CN: "openbao"}, Keys: map[string]config.Grant{
				"bao-seal": {Ops: []string{"encrypt", "decrypt"}}, "rot": {Ops: []string{"encrypt", "decrypt", "rewrap"}}}},
			{Name: "core", Identity: config.Identity{CN: "core"}, Keys: map[string]config.Grant{
				"cinim": {Ops: []string{"encrypt", "decrypt"}}}},
		},
	}
	cfg.Transit.Mount = "transit"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	soft, err := backend.NewSoft(cfg.Tokens[0].Keys)
	if err != nil {
		t.Fatal(err)
	}
	tokens := map[string]backend.Token{"soft": soft}
	if mutate != nil {
		mutate(cfg, tokens)
	}
	buf := &bytes.Buffer{}
	face := &Face{Cfg: cfg, Tokens: tokens, Policy: policy.New(cfg, nil), Audit: audit.New(buf),
		Identify: func(r *http.Request) (string, bool) { c := r.Header.Get("X-Test-Client"); return c, c != "" }}
	s := httptest.NewServer(face)
	t.Cleanup(s.Close)
	return &rig{t, s, buf, v, cfg, face}
}

func (r *rig) call(client, method, path string, body any) (int, map[string]any, http.Header) {
	r.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, r.srv.URL+path, bytes.NewReader(b))
	if client != "" {
		req.Header.Set("X-Test-Client", client)
	}
	req.Header.Set("X-Vault-Token", "ignored")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func data(m map[string]any) map[string]any { d, _ := m["data"].(map[string]any); return d }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// The exact calls OpenBao's seal `transit` makes: PUT encrypt/<key> {"plaintext"}, PUT decrypt/<key> {"ciphertext"}, no context.
func TestOpenBaoSealRoundTrip(t *testing.T) {
	r := newRig(t, nil)
	st, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("root key of the barrier")})
	ct, _ := data(out)["ciphertext"].(string)
	if st != 200 || !strings.HasPrefix(ct, "vault:v1:") || strings.Count(ct, ":") != 2 {
		t.Fatalf("%d %v", st, out)
	}
	st, out, _ = r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct})
	if st != 200 || data(out)["plaintext"] != b64("root key of the barrier") {
		t.Fatalf("%d %v", st, out)
	}
}

// Ciphertexts made by the Nim kekd for OpenBao's seal keep opening: aad "openbao/seal/v1|<key>", wrapped in vault:v1:<base64>.
func TestNimMadeOpenBaoCiphertextOpens(t *testing.T) {
	r := newRig(t, nil)
	for _, c := range r.vec.Valid {
		if c.Name != "openbao-seal" {
			continue
		}
		st, out, _ := r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": "vault:v1:" + b64(c.Wrapped)})
		want, _ := hex.DecodeString(c.PlainHex)
		if st != 200 || data(out)["plaintext"] != base64.StdEncoding.EncodeToString(want) {
			t.Fatalf("%d %v", st, out)
		}
	}
}

// CiNim's wrapped keys (aad "cinim/dek/v1|...") open through the context.
func TestNimMadeCinimCiphertextOpensWithContext(t *testing.T) {
	r := newRig(t, nil)
	c := r.vec.Valid[0]
	ct := "vault:v1:" + b64(c.Wrapped)
	want, _ := hex.DecodeString(c.PlainHex)
	st, out, _ := r.call("core", "PUT", "/v1/transit/decrypt/cinim", map[string]string{"ciphertext": ct, "context": b64(c.AAD)})
	if st != 200 || data(out)["plaintext"] != base64.StdEncoding.EncodeToString(want) {
		t.Fatalf("%d %v", st, out)
	}
	for name, body := range map[string]map[string]string{
		"other context":  {"ciphertext": ct, "context": b64("cinim/dek/v1|t2")},
		"no context":     {"ciphertext": ct},
		"not allowed":    {"ciphertext": ct, "context": b64("other/thing")},
		"bad ciphertext": {"ciphertext": "vault:v1:!!", "context": b64(c.AAD)},
	} {
		if st, out, h := r.call("core", "PUT", "/v1/transit/decrypt/cinim", body); st != 400 || h.Get("X-Hsmgate-Retryable") != "false" {
			t.Errorf("%s: %d %v", name, st, out)
		}
	}
}

func TestDenyByDefault(t *testing.T) {
	r := newRig(t, nil)
	body := map[string]string{"plaintext": b64("x")}
	cases := []struct{ client, path string }{
		{"", "/v1/transit/encrypt/bao-seal"},           // unauthenticated
		{"openbao", "/v1/transit/encrypt/cinim"},       // not granted
		{"core", "/v1/transit/encrypt/bao-seal"},       // not granted
		{"openbao", "/v1/transit/encrypt/nonexistent"}, // same answer as not granted
		{"openbao", "/v1/transit/rewrap/bao-seal"},     // op not granted
	}
	for _, c := range cases {
		if st, _, _ := r.call(c.client, "PUT", c.path, body); st != 403 {
			t.Errorf("%v: %d", c, st)
		}
	}
	if !strings.Contains(r.audit.String(), `"result":"forbidden"`) || !strings.Contains(r.audit.String(), `"result":"unauthenticated"`) {
		t.Error("refusals are not audited")
	}
}

func TestRateLimit(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.Clients[1].Keys["cinim"] = config.Grant{Ops: []string{"encrypt", "decrypt"}, PerMinute: 3}
	body := map[string]string{"plaintext": b64("x"), "context": b64("cinim/dek/v1|a")}
	for i := 0; i < 3; i++ {
		if st, _, _ := r.call("core", "PUT", "/v1/transit/encrypt/cinim", body); st != 200 {
			t.Fatalf("%d: %d", i, st)
		}
	}
	st, _, h := r.call("core", "PUT", "/v1/transit/encrypt/cinim", body)
	if st != 429 || h.Get("Retry-After") == "" || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("%d %v", st, h)
	}
}

func TestLockedTokenIsRetryable(t *testing.T) {
	r := newRig(t, nil)
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("k")})
	ct := data(out)["ciphertext"].(string)
	r2 := newRig(t, func(c *config.Config, tk map[string]backend.Token) { tk["soft"] = lockedToken{tk["soft"]} })
	st, _, h := r2.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct})
	if st != 503 || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("%d %v", st, h)
	}
}

func TestRewrapMovesToLatestVersion(t *testing.T) {
	r := newRig(t, nil)
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/rot", map[string]string{"plaintext": b64("secret")})
	old := data(out)["ciphertext"].(string)
	r.cfg.Keys["rot"] = config.Key{Versions: []config.Version{{Token: "soft", Label: "m1"}, {Token: "soft", Label: "m2"}}, AAD: config.AAD{Mode: "fixed", Fixed: "x"}}
	st, out, _ := r.call("openbao", "PUT", "/v1/transit/rewrap/rot", map[string]string{"ciphertext": old})
	nw, _ := data(out)["ciphertext"].(string)
	if st != 200 || !strings.HasPrefix(nw, "vault:v2:") || nw == old {
		t.Fatalf("%d %v", st, out)
	}
	for _, ct := range []string{old, nw} { // the old version still opens
		st, out, _ = r.call("openbao", "PUT", "/v1/transit/decrypt/rot", map[string]string{"ciphertext": ct})
		if st != 200 || data(out)["plaintext"] != b64("secret") {
			t.Errorf("%s: %d %v", ct[:10], st, out)
		}
	}
}

func TestClientCallsAroundTheSeal(t *testing.T) {
	r := newRig(t, nil)
	for _, p := range []struct{ m, path string }{{"GET", "/v1/sys/health"}, {"GET", "/v1/auth/token/lookup-self"}, {"POST", "/v1/auth/token/renew-self"}} {
		if st, _, _ := r.call("openbao", p.m, p.path, nil); st != 200 {
			t.Errorf("%s: %d", p.path, st)
		}
	}
	// a certificate the policy does not know fails at the token calls, not later
	if st, _, _ := r.call("", "GET", "/v1/auth/token/lookup-self", nil); st != 403 {
		t.Errorf("unknown client at lookup-self: %d", st)
	}
	// vault-kubernetes-kms (v1.4.0) reads data.ttl and data.creation_ttl as numbers from lookup-self, and data.latest_version from keys/<name>
	_, out, _ := r.call("openbao", "GET", "/v1/auth/token/lookup-self", nil)
	if d := data(out); d["ttl"] != float64(0) || d["creation_ttl"] != float64(0) {
		t.Errorf("lookup-self: %v", out)
	}
	st, out, _ := r.call("openbao", "GET", "/v1/transit/keys/bao-seal", nil)
	if st != 200 || data(out)["latest_version"] != float64(1) {
		t.Errorf("%d %v", st, out)
	}
}

func TestAuditNeverHoldsSecrets(t *testing.T) {
	r := newRig(t, nil)
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("topsecretvalue")})
	ct := data(out)["ciphertext"].(string)
	log := r.audit.String()
	if log == "" || strings.Contains(log, "topsecretvalue") || strings.Contains(log, b64("topsecretvalue")) || strings.Contains(log, ct[10:30]) {
		t.Errorf("audit: %s", log)
	}
}

// A spare card: the same key on another token. When the first holder cannot answer, the next one does; a text that is bad is bad on every holder.
func TestReplicaAnswersWhenThePrimaryIsLocked(t *testing.T) {
	r := newRig(t, func(c *config.Config, tk map[string]backend.Token) {
		tk["spare"] = tk["soft"]             // the same key, as a second card restored from the backup
		tk["soft"] = lockedToken{tk["soft"]} // the first card is locked
		c.Keys["bao-seal"] = config.Key{AAD: config.AAD{Mode: "fixed"},
			Versions: []config.Version{{Token: "soft", Label: "m1", Replicas: []config.Replica{{Token: "spare", Label: "m1"}}}}}
	})
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("k")})
	ct, _ := data(out)["ciphertext"].(string)
	st, out, _ := r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct})
	if st != 200 || data(out)["plaintext"] != b64("k") {
		t.Fatalf("%d %v", st, out)
	}
	// damaged text: not retried elsewhere, final
	if st, _, h := r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": "vault:v1:" + b64("ecies1.x")}); st != 400 || h.Get("X-Hsmgate-Retryable") != "false" {
		t.Errorf("damaged: %d", st)
	}
	// both holders locked: retryable
	r2 := newRig(t, func(c *config.Config, tk map[string]backend.Token) {
		tk["spare"] = lockedToken{tk["soft"]}
		tk["soft"] = lockedToken{tk["soft"]}
		c.Keys["bao-seal"] = config.Key{AAD: config.AAD{Mode: "fixed"},
			Versions: []config.Version{{Token: "soft", Label: "m1", Replicas: []config.Replica{{Token: "spare", Label: "m1"}}}}}
	})
	if st, _, h := r2.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct}); st != 503 || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("both locked: %d", st)
	}
}

// Rotation through Reload: a new version is added, new encrypts use it, the old texts still open, rewrap moves them.
func TestRotationWithReload(t *testing.T) {
	r := newRig(t, nil)
	f := r.face
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/rot", map[string]string{"plaintext": b64("secret")})
	old := data(out)["ciphertext"].(string)
	cfg2 := *f.Cfg
	cfg2.Keys = map[string]config.Key{}
	for k, v := range f.Cfg.Keys {
		cfg2.Keys[k] = v
	}
	cfg2.Keys["rot"] = config.Key{AAD: config.AAD{Mode: "fixed", Fixed: "x"}, Versions: []config.Version{{Token: "soft", Label: "m1"}, {Token: "soft", Label: "m2"}}}
	f.Reload(&cfg2, f.Tokens, policy.New(&cfg2, f.Policy.Counters()), f.Identify)
	_, out, _ = r.call("openbao", "PUT", "/v1/transit/encrypt/rot", map[string]string{"plaintext": b64("new")})
	if ct := data(out)["ciphertext"].(string); !strings.HasPrefix(ct, "vault:v2:") {
		t.Errorf("new encrypt not on v2: %s", ct[:12])
	}
	if st, out, _ := r.call("openbao", "PUT", "/v1/transit/decrypt/rot", map[string]string{"ciphertext": old}); st != 200 || data(out)["plaintext"] != b64("secret") {
		t.Errorf("old text: %d %v", st, out)
	}
	_, out, _ = r.call("openbao", "PUT", "/v1/transit/rewrap/rot", map[string]string{"ciphertext": old})
	if ct := data(out)["ciphertext"].(string); !strings.HasPrefix(ct, "vault:v2:") {
		t.Errorf("rewrap: %v", out)
	}
}

func TestContextTooLongAndUnsafeRequestID(t *testing.T) {
	r := newRig(t, nil)
	long := strings.Repeat("a", 2000)
	st, _, _ := r.call("core", "PUT", "/v1/transit/encrypt/cinim", map[string]string{"plaintext": b64("x"), "context": b64("cinim/dek/v1|" + long)})
	if st != 400 {
		t.Errorf("long context: %d", st)
	}
	req, _ := http.NewRequest("PUT", r.srv.URL+"/v1/transit/encrypt/cinim", strings.NewReader(`{}`))
	req.Header.Set("X-Test-Client", "core")
	req.Header.Set("X-Request-Id", "bad id\"},{\"x\":1")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if id := resp.Header.Get("X-Request-Id"); id == "" || strings.ContainsAny(id, " \"{") {
		t.Errorf("request id %q", id)
	}
}

type brokenWriter struct{ broken bool }

func (b *brokenWriter) Write(p []byte) (int, error) {
	if b.broken {
		return 0, os.ErrClosed
	}
	return len(p), nil
}

// With no way to write the decision down, nothing is done; when the log works again the service does too.
func TestAuditFailureFailsClosed(t *testing.T) {
	bw := &brokenWriter{}
	r := newRig(t, nil)
	r.face.Audit = audit.New(bw)
	body := map[string]string{"plaintext": b64("x")}
	if st, _, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", body); st != 200 {
		t.Fatalf("%d", st)
	}
	bw.broken = true
	r.face.Audit.Write(audit.Event{}) // a write that fails marks the log unhealthy
	if st, _, h := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", body); st != 503 || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("broken log: %d", st)
	}
	bw.broken = false
	if st, _, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", body); st != 200 {
		t.Errorf("recovered log: %d", st)
	}
}

// Fuzzing the request: any body to decrypt and rewrap. No panic, no 5xx other than the retryable 503, no plaintext from nonsense.
// The face is built once and called directly (a server per input would exhaust the machine and look like a crash).
func FuzzDecryptRequest(f *testing.F) {
	f.Add([]byte(`{"ciphertext":"vault:v1:aGVsbG8=","context":"Y2luaW0vZGVrL3YxfHQx"}`))
	f.Add([]byte(`{"ciphertext":"vault:v9:x"}`))
	f.Add([]byte(`{"ciphertext":1}`))
	f.Add([]byte(`[`))
	var face *Face
	f.Fuzz(func(t *testing.T, body []byte) {
		if face == nil {
			face = newRig(t, nil).face
		}
		for _, p := range []struct{ client, path string }{{"core", "/v1/transit/decrypt/cinim"}, {"openbao", "/v1/transit/decrypt/bao-seal"}, {"openbao", "/v1/transit/rewrap/rot"}} {
			req := httptest.NewRequest("PUT", p.path, bytes.NewReader(body))
			req.Header.Set("X-Test-Client", p.client)
			rec := httptest.NewRecorder()
			face.ServeHTTP(rec, req)
			if rec.Code == 200 || rec.Code >= 500 && rec.Code != 503 {
				t.Fatalf("%s: %d for %q", p.path, rec.Code, body)
			}
		}
	})
}

// The first write that fails must not let the answer out: the line is written before the plaintext leaves.
func TestFirstFailedAuditWriteWithholdsThePlaintext(t *testing.T) {
	bw := &brokenWriter{}
	r := newRig(t, nil)
	r.face.Audit = audit.New(bw)
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("topsecret")})
	ct := data(out)["ciphertext"].(string)
	bw.broken = true // the log was healthy a moment ago: nothing has marked it broken yet
	st, out, _ := r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct})
	if st != 503 || data(out)["plaintext"] != nil {
		t.Errorf("%d %v", st, out)
	}
}

func TestSizeLimits(t *testing.T) {
	r := newRig(t, nil)
	k := r.cfg.Keys["bao-seal"]
	k.MaxBytes = 8
	r.cfg.Keys["bao-seal"] = k
	// 100 bytes were sealed when the limit was larger (or elsewhere): not opened now
	big := strings.Repeat("x", 100)
	r.cfg.Keys["bao-seal"] = config.Key{Versions: k.Versions, AAD: k.AAD, MaxBytes: 1000}
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64(big)})
	ct := data(out)["ciphertext"].(string)
	r.cfg.Keys["bao-seal"] = config.Key{Versions: k.Versions, AAD: k.AAD, MaxBytes: 8}
	if st, _, _ := r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct}); st != 400 {
		t.Errorf("oversized plaintext on decrypt: %d", st)
	}
	// a valid body followed by anything but whitespace is refused, not silently cut
	req, _ := http.NewRequest("PUT", r.srv.URL+"/v1/transit/encrypt/bao-seal", strings.NewReader(`{"plaintext":"`+b64("x")+`"}   garbage`))
	req.Header.Set("X-Test-Client", "openbao")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Errorf("trailing garbage: %d", resp.StatusCode)
	}
}

func TestKeyInfoHasABudgetAndConcurrencyIsBounded(t *testing.T) {
	r := newRig(t, nil)
	n429 := 0
	for i := 0; i < policy.MetaPerMinute+5; i++ {
		if st, _, _ := r.call("openbao", "GET", "/v1/transit/keys/bao-seal", nil); st == 429 {
			n429++
		}
	}
	if n429 == 0 {
		t.Error("key information reads are not limited")
	}
	// one slot, held: the next operation is told to come back later, not queued for ever
	r2 := newRig(t, nil)
	r2.face.Limit(gate.New(1, 50*time.Millisecond))
	block := make(chan struct{})
	r2.face.Tokens["soft"] = slowToken{r2.face.Tokens["soft"], block}
	body := map[string]string{"ciphertext": "vault:v1:" + b64("ecies1.x.y.z")}
	// the first operation holds the slot: it is sent from another goroutine with plain net/http (a test helper that calls t.Fatal must not run there)
	first := make(chan struct{})
	go func() {
		defer close(first)
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest("PUT", r2.srv.URL+"/v1/transit/decrypt/bao-seal", bytes.NewReader(b))
		req.Header.Set("X-Test-Client", "openbao")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	for i := 0; i < 200 && r2.face.Gate().Running() == 0; i++ { // wait until it really has the slot
		time.Sleep(5 * time.Millisecond)
	}
	st, _, h := r2.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", body)
	close(block)
	<-first
	if st != 503 || h.Get("Retry-After") == "" {
		t.Errorf("second operation: %d", st)
	}
}

type slowToken struct {
	backend.Token
	block chan struct{}
}

func (s slowToken) Point(l string) ([]byte, error) { <-s.block; return s.Token.Point(l) }

// The line is finite: with the slot taken and the waiting places full, the next request is refused at once, not after the queue time.
func TestAdmissionIsAFiniteLine(t *testing.T) {
	r := newRig(t, nil)
	r.face.Limit(gate.New(1, 5*time.Second))
	block := make(chan struct{})
	r.face.Tokens["soft"] = slowToken{r.face.Tokens["soft"], block}
	body, _ := json.Marshal(map[string]string{"ciphertext": "vault:v1:" + b64("ecies1.x.y.z")})
	send := func(wg *sync.WaitGroup) {
		defer wg.Done()
		req, _ := http.NewRequest("PUT", r.srv.URL+"/v1/transit/decrypt/bao-seal", bytes.NewReader(body))
		req.Header.Set("X-Test-Client", "openbao")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}
	var wg sync.WaitGroup
	wg.Add(2) // one runs, one waits: the line (2 places) is full
	go send(&wg)
	go send(&wg)
	for i := 0; i < 400 && r.face.Gate().InLine() < 2; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	st, _, _ := r.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": "vault:v1:" + b64("ecies1.x.y.z")})
	took := time.Since(start)
	close(block)
	wg.Wait()
	if st != 503 || took > time.Second {
		t.Errorf("third request: %d after %v (want 503 at once)", st, took)
	}
}

// A reload hands back a way to wait for the requests of the old generation.
func TestReloadWaitsForRequestsInFlight(t *testing.T) {
	r := newRig(t, nil)
	block := make(chan struct{})
	r.face.Tokens["soft"] = slowToken{r.face.Tokens["soft"], block}
	body, _ := json.Marshal(map[string]string{"ciphertext": "vault:v1:" + b64("ecies1.x.y.z")})
	req, _ := http.NewRequest("PUT", r.srv.URL+"/v1/transit/decrypt/bao-seal", bytes.NewReader(body))
	req.Header.Set("X-Test-Client", "openbao")
	finished := make(chan struct{})
	go func() {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
		close(finished)
	}()
	time.Sleep(100 * time.Millisecond) // the request is inside the old generation, blocked at the token
	wait := r.face.Reload(r.face.Cfg, r.face.Tokens, r.face.Policy, r.face.Identify)
	done := make(chan struct{})
	go func() { wait(); close(done) }()
	select {
	case <-done:
		t.Fatal("the wait returned while a request of the old generation was running")
	case <-time.After(150 * time.Millisecond):
	}
	close(block)
	<-finished
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("the wait did not return after the request was done")
	}
}

// A client's own context prefixes narrow a key in context mode: the certificate of one namespace opens the contexts of that namespace only.
func TestClientContextPrefixes(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.Clients[1].Keys["cinim"] = config.Grant{Ops: []string{"encrypt", "decrypt"}, Contexts: []string{"cinim/dek/v1|org-1"}}
	body := func(ctx string) map[string]string {
		return map[string]string{"plaintext": b64("k"), "context": b64(ctx)}
	}
	if st, _, _ := r.call("core", "PUT", "/v1/transit/encrypt/cinim", body("cinim/dek/v1|org-1/db")); st != 200 {
		t.Errorf("own context: %d", st)
	}
	st, out, h := r.call("core", "PUT", "/v1/transit/encrypt/cinim", body("cinim/dek/v1|org-2/db"))
	if st != 403 || h.Get("X-Hsmgate-Retryable") != "false" {
		t.Errorf("another organisation's context: %d %v", st, out)
	}
	// the answer says nothing about the rules of the key: a context that breaks the key's own rule is also 403 for this client
	if st, _, _ := r.call("core", "PUT", "/v1/transit/encrypt/cinim", body("other/thing")); st != 403 {
		t.Errorf("a context outside everything: %d", st)
	}
	// the refusal is written down with its context
	if !strings.Contains(r.audit.String(), `"result":"forbidden_context"`) || !strings.Contains(r.audit.String(), `org-2/db`) {
		t.Errorf("audit: %s", r.audit.String())
	}
}
