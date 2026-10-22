package transit

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/backend"
	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/policy"
)

// A simulator of the Kubernetes KMS v2 plug-in `vault-kubernetes-kms` (v1.4.0), reduced to what it asks of the Transit API. The sequence was read from the plug-in's source
// (pkg/plugin/plugin_v2.go, pkg/vault/transit.go, pkg/vault/lease.go) and seen in the audit log of a real kube-apiserver (docs/specs/kubernetes-kms-v2.md):
//
//	start, then every minute:  GET auth/token/lookup-self            (data.ttl and data.creation_ttl read as numbers: no renewal while ttl >= creation_ttl/2)
//	Status:                    GET keys/K, then a probe: PUT encrypt "health", GET keys/K (the plug-in reads the version after every encrypt), PUT decrypt of that
//	Encrypt (a DEK):           PUT encrypt, then GET keys/K  -> key_id = data.latest_version
//	Decrypt:                   PUT decrypt
//
// It never sends a context, so the key must be in "fixed" mode. A token (X-Vault-Token) is sent and must be ignored.
type plugin struct {
	t   *testing.T
	r   *rig
	cli string
}

func (p *plugin) do(method, path string, body any) (int, map[string]any, http.Header) {
	p.t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, p.r.srv.URL+path, rd)
	req.Header.Set("X-Test-Client", p.cli)
	req.Header.Set("X-Vault-Token", "unused")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		p.t.Fatal(err)
	}
	defer resp.Body.Close()
	dec := json.NewDecoder(resp.Body)
	dec.UseNumber() // as the Vault API client does: latest_version must be a number, not a string
	var out map[string]any
	dec.Decode(&out)
	return resp.StatusCode, out, resp.Header
}

func (p *plugin) lookupSelf() map[string]any {
	st, out, _ := p.do("GET", "/v1/auth/token/lookup-self", nil)
	if st != 200 {
		p.t.Fatalf("lookup-self: %d %v", st, out)
	}
	return out["data"].(map[string]any)
}

// keyVersion is GetKeyVersion: the key_id the apiserver sees.
func (p *plugin) keyVersion(key string) string {
	st, out, _ := p.do("GET", "/v1/transit/keys/"+key, nil)
	if st != 200 {
		p.t.Fatalf("keys: %d %v", st, out)
	}
	n, ok := out["data"].(map[string]any)["latest_version"].(json.Number)
	if !ok {
		p.t.Fatalf("latest_version is not a number: %v", out["data"])
	}
	return n.String()
}

func (p *plugin) encrypt(key string, plain []byte) (ciphertext, keyID string, status int) {
	st, out, _ := p.do("PUT", "/v1/transit/encrypt/"+key, map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plain)})
	if st != 200 {
		return "", "", st
	}
	return out["data"].(map[string]any)["ciphertext"].(string), p.keyVersion(key), 200
}

func (p *plugin) decrypt(key, ciphertext string) ([]byte, int) {
	st, out, _ := p.do("PUT", "/v1/transit/decrypt/"+key, map[string]string{"ciphertext": ciphertext})
	if st != 200 {
		return nil, st
	}
	b, _ := base64.StdEncoding.DecodeString(out["data"].(map[string]any)["plaintext"].(string))
	return b, 200
}

// status is Status(): the version, the probe, the answer.
func (p *plugin) status(key string) (healthz, keyID string) {
	keyID = p.keyVersion(key)
	healthz = "ok"
	ct, _, st := p.encrypt(key, []byte("health"))
	if st != 200 {
		return "err", keyID
	}
	if got, st := p.decrypt(key, ct); st != 200 || string(got) != "health" {
		healthz = "err"
	}
	return healthz, keyID
}

func ops(r *rig) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(r.audit.String()), "\n") {
		var e struct{ Op, Result string }
		if json.Unmarshal([]byte(l), &e) == nil && e.Op != "" {
			out = append(out, e.Op+":"+e.Result)
		}
	}
	return out
}

func TestKMSv2PluginStartAndTokenUpkeep(t *testing.T) {
	r := newRig(t, nil)
	p := &plugin{t, r, "openbao"}
	d := p.lookupSelf()
	ttl, ok1 := d["ttl"].(json.Number)
	creation, ok2 := d["creation_ttl"].(json.Number)
	if !ok1 || !ok2 {
		t.Fatalf("ttl and creation_ttl must be numbers: %v", d)
	}
	// the plug-in renews only when ttl < creation_ttl/2: with 0 and 0 it never does
	tf, _ := ttl.Float64()
	cf, _ := creation.Float64()
	if tf < cf/2 {
		t.Errorf("the plug-in would try to renew the token: ttl %v, creation_ttl %v", tf, cf)
	}
	// a certificate the policy does not know makes the plug-in fail at its start, not at the first Secret
	if st, _, _ := (&plugin{t, r, ""}).do("GET", "/v1/auth/token/lookup-self", nil); st != 403 {
		t.Errorf("an unknown client at lookup-self: %d", st)
	}
}

func TestKMSv2StatusEncryptDecryptSequence(t *testing.T) {
	r := newRig(t, nil)
	p := &plugin{t, r, "openbao"}
	healthz, keyID := p.status("bao-seal")
	if healthz != "ok" || keyID != "1" {
		t.Fatalf("status: %s %s", healthz, keyID)
	}
	// what one Status costs the service: keys, encrypt, keys, decrypt (seen in the audit log of a real apiserver)
	if got := strings.Join(ops(r), " "); got != "keys:ok encrypt:ok keys:ok decrypt:ok" {
		t.Errorf("one Status was: %s", got)
	}
	// a DEK of the apiserver: 32 bytes
	dek := bytes.Repeat([]byte{0xA5}, 32)
	ct, id, st := p.encrypt("bao-seal", dek)
	if st != 200 || id != "1" || !strings.HasPrefix(ct, "vault:v1:") {
		t.Fatalf("%q %q %d", ct, id, st)
	}
	if len(ct) != 441 { // the number in the specification
		t.Errorf("the ciphertext of a 32-byte DEK is %d bytes, the spec says 441", len(ct))
	}
	if got, st := p.decrypt("bao-seal", ct); st != 200 || !bytes.Equal(got, dek) {
		t.Errorf("%x %d", got, st)
	}
}

// KMS v2 requires a ciphertext under 1 kB; the specification says a plaintext of up to 250 bytes fits.
func TestKMSv2CiphertextStaysUnderOneKilobyte(t *testing.T) {
	r := newRig(t, nil)
	p := &plugin{t, r, "openbao"}
	fits, _, st := p.encrypt("bao-seal", bytes.Repeat([]byte{1}, 250))
	if st != 200 || len(fits) >= 1024 {
		t.Errorf("250 bytes: %d bytes of ciphertext, status %d", len(fits), st)
	}
	over, _, st := p.encrypt("bao-seal", bytes.Repeat([]byte{1}, 251))
	if st != 200 || len(over) < 1024 {
		t.Errorf("251 bytes: %d bytes of ciphertext, status %d (the specification's bound is 250)", len(over), st)
	}
}

// A new key version: the key_id the apiserver reads changes, a new DEK is sealed under it, and what was sealed before still opens.
func TestKMSv2RotationChangesTheKeyID(t *testing.T) {
	r := newRig(t, nil)
	p := &plugin{t, r, "openbao"}
	old, id1, _ := p.encrypt("bao-seal", []byte("first DEK"))
	if id1 != "1" {
		t.Fatalf("key_id %s", id1)
	}
	cfg2 := *r.face.Cfg
	cfg2.Keys = map[string]config.Key{}
	for k, v := range r.face.Cfg.Keys {
		cfg2.Keys[k] = v
	}
	cfg2.Keys["bao-seal"] = config.Key{AAD: config.AAD{Mode: "fixed"}, Versions: []config.Version{{Token: "soft", Label: "m1"}, {Token: "soft", Label: "m2"}}}
	r.face.Reload(&cfg2, r.face.Tokens, policy.New(&cfg2, r.face.Policy.Counters()), r.face.Identify)
	if healthz, id := p.status("bao-seal"); healthz != "ok" || id != "2" {
		t.Fatalf("status after the rotation: %s %s", healthz, id)
	}
	fresh, id2, _ := p.encrypt("bao-seal", []byte("second DEK"))
	if id2 != "2" || !strings.HasPrefix(fresh, "vault:v2:") {
		t.Errorf("%q %q", fresh, id2)
	}
	if got, st := p.decrypt("bao-seal", old); st != 200 || string(got) != "first DEK" {
		t.Errorf("the old ciphertext after the rotation: %q %d", got, st)
	}
}

// The token is locked: Encrypt still works (the public key), Decrypt and with it the probe do not, so Status says "err" and the apiserver's health check fails.
func TestKMSv2LockedTokenFailsTheHealthProbeButNotEncrypt(t *testing.T) {
	r := newRig(t, func(c *config.Config, tk map[string]backend.Token) { tk["soft"] = lockedToken{tk["soft"]} })
	p := &plugin{t, r, "openbao"}
	if healthz, id := p.status("bao-seal"); healthz != "err" || id != "1" {
		t.Errorf("status of a locked token: %s %s", healthz, id)
	}
	ct, _, st := p.encrypt("bao-seal", []byte("a DEK"))
	if st != 200 || ct == "" {
		t.Errorf("encrypt while locked: %d", st)
	}
	_, st = p.decrypt("bao-seal", ct)
	st2, _, h := p.do("PUT", "/v1/transit/decrypt/bao-seal", map[string]string{"ciphertext": ct})
	if st != 503 || st2 != 503 || h.Get("X-Hsmgate-Retryable") != "true" {
		t.Errorf("decrypt while locked: %d %d %v", st, st2, h)
	}
}

// The plug-in never sends a context. A key in context mode would refuse it; the key for the plug-in must be in fixed mode.
func TestKMSv2KeyInContextModeIsRefusedWithoutContext(t *testing.T) {
	r := newRig(t, nil)
	p := &plugin{t, r, "core"}
	if _, _, st := p.encrypt("cinim", []byte("a DEK")); st != 400 {
		t.Errorf("a context key without a context: %d", st)
	}
}
