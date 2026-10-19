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
