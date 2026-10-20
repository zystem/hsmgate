package config

import (
	"os"
	"strings"
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

func TestGrantContextsNeedAContextKey(t *testing.T) {
	base := `
tokens: [{name: t, type: soft, keys: {m: /x}}]
keys:
  fixed: {versions: [{token: t, label: m}], aad: {mode: fixed}}
  ctx: {versions: [{token: t, label: m}], aad: {mode: context, allow: ["a/"]}}
clients:
`
	if _, err := Parse([]byte(base + "  - {name: a, identity: {cn: x}, keys: {ctx: {ops: [encrypt], contexts: [\"a/b/\"]}}}\n")); err != nil {
		t.Errorf("a valid grant: %v", err)
	}
	if _, err := Parse([]byte(base + "  - {name: a, identity: {cn: x}, keys: {fixed: {ops: [encrypt], contexts: [\"a/\"]}}}\n")); err == nil {
		t.Error("contexts on a fixed key were accepted")
	}
	if _, err := Parse([]byte(base + "  - {name: a, identity: {cn: x}, keys: {ctx: {ops: [encrypt], contexts: [\"\"]}}}\n")); err == nil {
		t.Error("an empty context prefix was accepted")
	}
}

func TestKMSJSONRules(t *testing.T) {
	base := `
kmsjson: {enabled: true}
tokens: [{name: t, type: soft, keys: {m: /x}}]
keys:
  d: {kmsjson: true, versions: [{token: t, label: m}], aad: {mode: fixed}}
  c: {versions: [{token: t, label: m}], aad: {mode: context, allow: ["a/"]}}
clients:
`
	ok := "  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {d: {ops: [derive]}}}\n"
	cfg, err := Parse([]byte(base + ok))
	if err != nil {
		t.Fatalf("a valid configuration: %v", err)
	}
	if cfg.KMSJSON.Region != "local" {
		t.Errorf("region default: %q", cfg.KMSJSON.Region)
	}
	for name, clients := range map[string]string{
		"derive on a key without kmsjson": "  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {c: {ops: [derive]}}}\n",
		"derive without a credential":     "  - {name: a, identity: {cn: x}, keys: {d: {ops: [derive]}}}\n",
		"a short access key id":           "  - {name: a, identity: {cn: x}, sigv4: {access_key_id: short, secret_file: /s}, keys: {d: {ops: [derive]}}}\n",
		"an access key id with a dash":    "  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIA-EXAMPLE-EXAMPLE, secret_file: /s}, keys: {d: {ops: [derive]}}}\n",
		"no secret file":                  "  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1}, keys: {d: {ops: [derive]}}}\n",
		"the same access key id twice":    ok + "  - {name: b, identity: {cn: y}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {d: {ops: [derive]}}}\n",
	} {
		if _, err := Parse([]byte(base + clients)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// a key in context mode cannot be opened through the face that has no context
	bad := strings.Replace(base, "d: {kmsjson: true, versions: [{token: t, label: m}], aad: {mode: fixed}}", "d: {kmsjson: true, versions: [{token: t, label: m}], aad: {mode: context, allow: [\"a/\"]}}", 1)
	if _, err := Parse([]byte(bad + ok)); err == nil {
		t.Error("kmsjson on a key in context mode was accepted")
	}
	// enabled with no key to serve, or a credential with the face off
	if _, err := Parse([]byte(strings.Replace(base, "kmsjson: true, ", "", 1))); err == nil {
		t.Error("kmsjson.enabled with no kmsjson key was accepted")
	}
	if _, err := Parse([]byte(strings.Replace(base+ok, "kmsjson: {enabled: true}", "kmsjson: {enabled: false}", 1))); err == nil {
		t.Error("a credential with the face off was accepted")
	}
}

func TestKMSJSONUsage(t *testing.T) {
	base := func(keys string) string {
		return "kmsjson: {enabled: true}\ntokens: [{name: t, type: soft, keys: {m: /x}}]\nkeys:\n" + keys + "clients:\n  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {s: {ops: [encrypt, decrypt]}}}\n"
	}
	v := "versions: [{token: t, label: m}]"
	// a sealing key may be in context mode: the context is checked on this face
	if _, err := Parse([]byte(base("  s: {kmsjson: true, kmsjson_usage: encrypt_decrypt, " + v + ", aad: {mode: context, allow: [\"purpose=dek\"]}}\n"))); err != nil {
		t.Errorf("a sealing key in context mode: %v", err)
	}
	for name, keys := range map[string]string{
		"usage without kmsjson":    "  s: {kmsjson_usage: encrypt_decrypt, " + v + ", aad: {mode: fixed}}\n",
		"an unknown usage":         "  s: {kmsjson: true, kmsjson_usage: sign, " + v + ", aad: {mode: fixed}}\n",
		"key agreement in context": "  s: {kmsjson: true, kmsjson_usage: key_agreement, " + v + ", aad: {mode: context, allow: [\"a\"]}}\n",
	} {
		if _, err := Parse([]byte(base(keys))); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// derive is for key agreement only
	derive := "kmsjson: {enabled: true}\ntokens: [{name: t, type: soft, keys: {m: /x}}]\nkeys:\n  s: {kmsjson: true, kmsjson_usage: encrypt_decrypt, " + v + ", aad: {mode: fixed}}\nclients:\n  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {s: {ops: [derive]}}}\n"
	if _, err := Parse([]byte(derive)); err == nil {
		t.Error("derive on a sealing key was accepted")
	}
}

func TestNoCertRules(t *testing.T) {
	v := "versions: [{token: t, label: m}]"
	base := "kmsjson: {enabled: true}\ntokens: [{name: t, type: soft, keys: {m: /x}}]\nkeys:\n" +
		"  s: {kmsjson: true, kmsjson_usage: encrypt_decrypt, " + v + ", aad: {mode: fixed}}\n" +
		"  e: {kmsjson: true, " + v + ", aad: {mode: fixed}}\n  plain: {" + v + ", aad: {mode: fixed}}\nclients:\n"
	cl := func(sig, keys string) string {
		return "  - {name: a, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s, " + sig + "}, keys: {" + keys + "}}\n"
	}
	if _, err := Parse([]byte(base + cl("no_cert: true, allow_from: [10.0.0.0/8, 192.168.1.5]", "s: {ops: [encrypt, decrypt]}"))); err != nil {
		t.Fatalf("a valid client without a certificate: %v", err)
	}
	for name, c := range map[string]string{
		"no address list":         cl("no_cert: true", "s: {ops: [encrypt]}"),
		"a bad address":           cl("no_cert: true, allow_from: [nonsense]", "s: {ops: [encrypt]}"),
		"a key for key agreement": cl("no_cert: true, allow_from: [10.0.0.0/8]", "e: {ops: [encrypt]}"),
		"a key without kmsjson":   cl("no_cert: true, allow_from: [10.0.0.0/8]", "plain: {ops: [encrypt]}"),
		"the right rewrap":        cl("no_cert: true, allow_from: [10.0.0.0/8]", "s: {ops: [rewrap]}"),
		"no identity and no flag": cl("allow_from: [10.0.0.0/8]", "s: {ops: [encrypt]}"),
	} {
		if _, err := Parse([]byte(base + c)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSignVerifyRules(t *testing.T) {
	v := func(label string) string { return "versions: [{token: t, label: " + label + "}]" }
	base := "kmsjson: {enabled: true}\ntokens: [{name: t, type: soft, keys: {m: /x, n: /y}}]\nkeys:\n"
	sig := "  sig: {kmsjson: true, kmsjson_usage: sign_verify, " + v("m") + ", aad: {mode: fixed}}\n"
	cl := func(ops string) string {
		return "clients:\n  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {sig: {ops: [" + ops + "]}}}\n"
	}
	if _, err := Parse([]byte(base + sig + cl("sign, verify"))); err != nil {
		t.Fatalf("a valid signing key: %v", err)
	}
	for name, c := range map[string]string{
		"encrypt on a signing key":            base + sig + cl("encrypt"),
		"derive on a signing key":             base + sig + cl("derive"),
		"the same private key used for ECDH":  base + sig + "  e: {kmsjson: true, " + v("m") + ", aad: {mode: fixed}}\n" + cl("sign"),
		"the same private key in the Transit": base + sig + "  t: {" + v("m") + ", aad: {mode: fixed}}\n" + cl("sign"),
	} {
		if _, err := Parse([]byte(c)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// sign on a key that is not a signing key
	plain := base + "  e: {kmsjson: true, " + v("m") + ", aad: {mode: fixed}}\nclients:\n  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {e: {ops: [sign]}}}\n"
	if _, err := Parse([]byte(plain)); err == nil {
		t.Error("sign on an ECDH key was accepted")
	}
}

func TestMacRules(t *testing.T) {
	v := func(label string) string { return "versions: [{token: t, label: " + label + "}]" }
	base := "kmsjson: {enabled: true, mac_cache_seconds: 30}\ntokens: [{name: t, type: soft, keys: {m: /x, n: /y}}]\nkeys:\n"
	mac := "  mac: {kmsjson: true, kmsjson_usage: generate_verify_mac, " + v("m") + ", aad: {mode: fixed}}\n"
	cl := func(ops string) string {
		return "clients:\n  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {mac: {ops: [" + ops + "]}}}\n"
	}
	if _, err := Parse([]byte(base + mac + cl("generate_mac, verify_mac"))); err != nil {
		t.Fatalf("a valid MAC key: %v", err)
	}
	for name, c := range map[string]string{
		"encrypt on a MAC key":              base + mac + cl("encrypt"),
		"sign on a MAC key":                 base + mac + cl("sign"),
		"the same token key for ECDH":       base + mac + "  e: {kmsjson: true, " + v("m") + ", aad: {mode: fixed}}\n" + cl("generate_mac"),
		"the same token key for signing":    base + mac + "  s: {kmsjson: true, kmsjson_usage: sign_verify, " + v("m") + ", aad: {mode: fixed}}\n" + cl("generate_mac"),
		"the same token key in the Transit": base + mac + "  tr: {" + v("m") + ", aad: {mode: fixed}}\n" + cl("generate_mac"),
		"a cache for too long":              "kmsjson: {enabled: true, mac_cache_seconds: 99999}\ntokens: [{name: t, type: soft, keys: {m: /x}}]\nkeys:\n" + mac + cl("generate_mac"),
	} {
		if _, err := Parse([]byte(c)); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	plain := base + "  e: {kmsjson: true, " + v("m") + ", aad: {mode: fixed}}\nclients:\n  - {name: a, identity: {cn: x}, sigv4: {access_key_id: AKIAEXAMPLEEXAMPLE1, secret_file: /s}, keys: {e: {ops: [verify_mac]}}}\n"
	if _, err := Parse([]byte(plain)); err == nil {
		t.Error("verify_mac on an ECDH key was accepted")
	}
}

func TestKMSJSONKeyNames(t *testing.T) {
	v := "versions: [{token: t, label: m}], aad: {mode: fixed}"
	mk := func(name string) string {
		return "kmsjson: {enabled: true}\ntokens: [{name: t, type: soft, keys: {m: /x}}]\nkeys:\n  \"" + name + "\": {kmsjson: true, " + v + "}\nclients:\n"
	}
	for _, ok := range []string{"etcd", "app-key_1.v2", strings.Repeat("a", 128)} {
		if _, err := Parse([]byte(mk(ok))); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"a@1", "alias/x", "a:b", "a b", strings.Repeat("a", 129), "ключ"} {
		if _, err := Parse([]byte(mk(bad))); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// the Transit face keeps its freedom of names
	plain := "tokens: [{name: t, type: soft, keys: {m: /x}}]\nkeys:\n  \"cinim shard/1\": {" + v + "}\nclients:\n"
	if _, err := Parse([]byte(plain)); err != nil {
		t.Errorf("a Transit-only key name: %v", err)
	}
}
