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
	"testing"

	"github.com/zystem/hsmgate/internal/audit"
	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
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
	face := &Face{Cfg: cfg, Tokens: tokens, Policy: policy.New(cfg), Audit: audit.New(buf),
		Identify: func(r *http.Request) (string, bool) { c := r.Header.Get("X-Test-Client"); return c, c != "" }}
	s := httptest.NewServer(face)
	t.Cleanup(s.Close)
	return &rig{t, s, buf, v, cfg}
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
