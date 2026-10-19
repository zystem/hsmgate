package config

import (
	"os"
	"testing"
)

func FuzzParse(f *testing.F) {
	ex, _ := os.ReadFile("../../deploy/hsmgate.example.yaml")
	f.Add(ex)
	f.Add([]byte("keys: {a: {aad: {mode: context}}}"))
	f.Add([]byte("{{{{"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		cfg, err := Parse(raw) // must not panic; a configuration that parses is valid
		if err == nil {
			if err := cfg.Validate(); err != nil {
				t.Fatalf("parsed but invalid: %v", err)
			}
		}
	})
}

func TestUnknownFieldIsAnError(t *testing.T) {
	if _, err := Parse([]byte("lisen: :8443")); err == nil {
		t.Error("a misspelt field was ignored")
	}
}

func TestContextModeNeedsAllow(t *testing.T) {
	raw := `
tokens: [{name: t, type: soft, keys: {m: /x}}]
keys: {k: {versions: [{token: t, label: m}], aad: {mode: context}}}
`
	if _, err := Parse([]byte(raw)); err == nil {
		t.Error("a context key with no allowed prefixes was accepted")
	}
}

func TestAmbiguityIsRefused(t *testing.T) {
	base := `
tokens: [{name: t, type: soft, keys: {m: /x}}]
keys: {k: {versions: [{token: t, label: m}], aad: {mode: fixed}}}
clients:
`
	for name, clients := range map[string]string{
		"duplicate name":      "  - {name: a, identity: {cn: x}, keys: {k: {ops: [encrypt]}}}\n  - {name: a, identity: {cn: y}, keys: {k: {ops: [rewrap]}}}\n",
		"same identity":       "  - {name: a, identity: {cn: x}, keys: {}}\n  - {name: b, identity: {cn: x}, keys: {}}\n",
		"two identity fields": "  - {name: a, identity: {cn: x, uri: \"spiffe://a/b\"}, keys: {}}\n",
		"bad sha256":          "  - {name: a, identity: {sha256: abcd}, keys: {}}\n",
		"negative limit":      "  - {name: a, identity: {cn: x}, keys: {k: {ops: [encrypt], per_minute: -1}}}\n",
		"huge limit":          "  - {name: a, identity: {cn: x}, keys: {k: {ops: [encrypt], per_day: 99999999}}}\n",
	} {
		if _, err := Parse([]byte(base + clients)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, keys := range map[string]string{
		"empty allow":     "keys: {k: {versions: [{token: t, label: m}], aad: {mode: context, allow: [\"\"]}}}",
		"max_bytes big":   "keys: {k: {max_bytes: 999999999, versions: [{token: t, label: m}], aad: {mode: fixed}}}",
		"max_bytes below": "keys: {k: {max_bytes: -1, versions: [{token: t, label: m}], aad: {mode: fixed}}}",
		"bad fingerprint": "keys: {k: {versions: [{token: t, label: m, fingerprint: zz}], aad: {mode: fixed}}}",
	} {
		if _, err := Parse([]byte("tokens: [{name: t, type: soft, keys: {m: /x}}]\n" + keys)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	if _, err := Parse([]byte("tokens: [{name: t, type: pkcs11, module: /m, keys: {m: \"\"}}]")); err == nil {
		t.Error("an empty CKA_ID was accepted")
	}
	if _, err := Parse([]byte("tokens: [{name: t, type: soft, keys: {}}, {name: t, type: soft, keys: {}}]")); err == nil {
		t.Error("a token defined twice was accepted")
	}
}
