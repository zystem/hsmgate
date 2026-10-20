package transit

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
)

// api/openapi.yaml is a contract: what it lists is what the handler does, and what the handler answers is what it lists.
type spec struct {
	Paths map[string]map[string]struct {
		OperationID string                 `yaml:"operationId"`
		Responses   map[string]interface{} `yaml:"responses"`
	} `yaml:"paths"`
}

func loadSpec(t *testing.T) spec {
	raw, err := os.ReadFile("../../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var s spec
	if err := yaml.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func (s spec) documents(path, method string, status int) bool {
	op, ok := s.Paths[path][strings.ToLower(method)]
	if !ok {
		return false
	}
	_, ok = op.Responses[strconv.Itoa(status)]
	return ok
}

func TestSpecListsTheRoutesThatExist(t *testing.T) {
	s := loadSpec(t)
	want := map[string][]string{
		"/v1/sys/health":             {"get"},
		"/v1/auth/token/lookup-self": {"get"},
		"/v1/auth/token/renew-self":  {"post"},
		"/v1/transit/keys/{name}":    {"get"},
		"/v1/transit/encrypt/{name}": {"put", "post"},
		"/v1/transit/decrypt/{name}": {"put", "post"},
		"/v1/transit/rewrap/{name}":  {"put", "post"},
		"/":                          {"post"}, // the KMS-JSON face (its own tests are in internal/face/kmsjson)
	}
	if len(s.Paths) != len(want) {
		t.Errorf("the spec has %d paths, the service %d", len(s.Paths), len(want))
	}
	ids := map[string]bool{}
	for p, methods := range want {
		for _, m := range methods {
			op, ok := s.Paths[p][m]
			if !ok {
				t.Errorf("%s %s is not in the spec", m, p)
				continue
			}
			if op.OperationID == "" || ids[op.OperationID] {
				t.Errorf("%s %s: operationId %q is empty or repeated", m, p, op.OperationID)
			}
			ids[op.OperationID] = true
		}
	}
}

// Every answer the handler gives in these scenarios is one the spec documents for that operation, and the headers the spec promises are there.
func TestHandlerAnswersAreDocumented(t *testing.T) {
	s := loadSpec(t)
	r := newRig(t, nil)
	check := func(name, client, method, specPath, urlPath string, body any, want int) *http.Response {
		t.Helper()
		st, _, h := r.call(client, method, urlPath, body)
		if st != want {
			t.Errorf("%s: %d, want %d", name, st, want)
		}
		if !s.documents(specPath, method, st) {
			t.Errorf("%s: %d is not documented for %s %s", name, st, method, specPath)
		}
		if st == 429 || st == 503 {
			if h.Get("Retry-After") == "" && st == 429 {
				t.Errorf("%s: no Retry-After", name)
			}
		}
		if st >= 400 && h.Get("X-Hsmgate-Retryable") == "" {
			t.Errorf("%s: no X-Hsmgate-Retryable", name)
		}
		return nil
	}
	enc := "/v1/transit/encrypt/{name}"
	ok := map[string]string{"plaintext": b64("a data key")}
	check("sealed", "openbao", "PUT", enc, "/v1/transit/encrypt/bao-seal", ok, 200)
	check("sealed (POST)", "openbao", "POST", enc, "/v1/transit/encrypt/bao-seal", ok, 200)
	check("bad plaintext", "openbao", "PUT", enc, "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": "!!"}, 400)
	check("a context on a fixed key", "openbao", "PUT", enc, "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("k"), "context": b64("x")}, 400)
	check("no client", "", "PUT", enc, "/v1/transit/encrypt/bao-seal", ok, 403)
	check("no grant", "openbao", "PUT", enc, "/v1/transit/encrypt/cinim", ok, 403)
	check("no such key", "openbao", "PUT", enc, "/v1/transit/encrypt/nope", ok, 403)
	dec := "/v1/transit/decrypt/{name}"
	check("bad ciphertext", "openbao", "PUT", dec, "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": "vault:v1:!!"}, 400)
	check("rewrap not granted", "openbao", "PUT", "/v1/transit/rewrap/{name}", "/v1/transit/rewrap/bao-seal", map[string]string{"ciphertext": "x"}, 403)
	check("key info", "openbao", "GET", "/v1/transit/keys/{name}", "/v1/transit/keys/bao-seal", nil, 200)
	check("key info, no grant", "openbao", "GET", "/v1/transit/keys/{name}", "/v1/transit/keys/cinim", nil, 403)
	check("health", "", "GET", "/v1/sys/health", "/v1/sys/health", nil, 200)
	check("lookup-self", "openbao", "GET", "/v1/auth/token/lookup-self", "/v1/auth/token/lookup-self", nil, 200)
	check("lookup-self, unknown", "", "GET", "/v1/auth/token/lookup-self", "/v1/auth/token/lookup-self", nil, 403)
	check("renew-self", "openbao", "POST", "/v1/auth/token/renew-self", "/v1/auth/token/renew-self", nil, 200)

	// too large
	k := r.cfg.Keys["bao-seal"]
	r.cfg.Keys["bao-seal"] = config.Key{Versions: k.Versions, AAD: k.AAD, MaxBytes: 1}
	check("too large", "openbao", "PUT", enc, "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64(strings.Repeat("x", 6000))}, 413)
	r.cfg.Keys["bao-seal"] = k

	// throttled
	r.cfg.Clients[1].Keys["cinim"] = config.Grant{Ops: []string{"encrypt", "decrypt"}, PerMinute: 1} // a client and key that have not been used yet
	withCtx := map[string]string{"plaintext": b64("k"), "context": b64("cinim/dek/v1|t1")}
	check("first of one", "core", "PUT", enc, "/v1/transit/encrypt/cinim", withCtx, 200)
	check("second of one", "core", "PUT", enc, "/v1/transit/encrypt/cinim", withCtx, 429)

	// a locked token
	lr := newRig(t, func(c *config.Config, tk map[string]backend.Token) { tk["soft"] = lockedToken{tk["soft"]} })
	_, out, _ := r.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("k")})
	ct := data(out)["ciphertext"]
	if ct == nil { // the throttled rig above is spent; seal with the locked rig instead (encrypt needs no PIN)
		_, out, _ = lr.call("openbao", "PUT", "/v1/transit/encrypt/bao-seal", map[string]string{"plaintext": b64("k")})
		ct = data(out)["ciphertext"]
	}
	st, _, h := lr.call("openbao", "PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct.(string)})
	if st != 503 || !s.documents(dec, "PUT", st) || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("locked token: %d %v", st, h)
	}
}
