package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// docs/configuration.md must name every setting of the file: a setting that is added without a line there fails this test, so the reference does not fall behind.
func TestEveryYAMLSettingIsDocumented(t *testing.T) {
	raw, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	seen := map[string]bool{}
	var walk func(reflect.Type)
	walk = func(ty reflect.Type) {
		for ty.Kind() == reflect.Ptr || ty.Kind() == reflect.Slice || ty.Kind() == reflect.Map {
			ty = ty.Elem()
		}
		if ty.Kind() != reflect.Struct {
			return
		}
		for i := 0; i < ty.NumField(); i++ {
			f := ty.Field(i)
			name := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			if !seen[name] {
				seen[name] = true
				if !strings.Contains(doc, "`"+name+"`") && !strings.Contains(doc, "`"+name+".") && !strings.Contains(doc, "."+name+"`") {
					t.Errorf("the setting %q (%s.%s) is not in docs/configuration.md", name, ty.Name(), f.Name)
				}
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(Config{}))
}

// The defaults the reference states are the ones the code applies.
func TestDocumentedDefaults(t *testing.T) {
	c, err := Parse([]byte("insecure_loopback_client: c\ntokens: []\nkeys: {}\nclients: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Transit.Mount != "transit" || c.SealSuite != "ecies2" || c.Metrics.Detail != "basic" || DefaultMaxBytes != 8192 {
		t.Errorf("the defaults changed: %q %q %q %d: update docs/configuration.md", c.Transit.Mount, c.SealSuite, c.Metrics.Detail, DefaultMaxBytes)
	}
	k := Key{}
	if k.FixedAAD("k") != "openbao/seal/v1|k" || k.Usage() != UsageKeyAgreement || k.MACBits() != 256 {
		t.Error("the defaults of a key changed: update docs/configuration.md")
	}
}
