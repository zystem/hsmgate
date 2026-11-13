// Package apispec holds only a test: the OpenAPI files of api/ are well formed and say what the code does. The Transit file has its own, stricter test (internal/face/transit).
package apispec

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type doc struct {
	OpenAPI string `yaml:"openapi"`
	Info    struct {
		Title   string `yaml:"title"`
		Version string `yaml:"version"`
	} `yaml:"info"`
	Paths map[string]map[string]struct {
		OperationID string         `yaml:"operationId"`
		Responses   map[string]any `yaml:"responses"`
	} `yaml:"paths"`
}

func load(t *testing.T, name string) (doc, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", name))
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := yaml.Unmarshal(raw, &d); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return d, string(raw)
}

func source(t *testing.T, glob string) string {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join("..", "..", glob))
	var b strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(raw)
	}
	if b.Len() == 0 {
		t.Fatalf("no source for %s", glob)
	}
	return b.String()
}

// Every file is OpenAPI 3.1, has unique operation ids, an answer for every operation, and every $ref points at something that exists.
func TestSpecsAreWellFormed(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("..", "..", "api", "*.yaml"))
	if len(files) < 5 {
		t.Fatalf("expected at least 5 specifications, found %d", len(files))
	}
	for _, f := range files {
		name := filepath.Base(f)
		d, raw := load(t, name)
		if !strings.HasPrefix(d.OpenAPI, "3.1") || d.Info.Title == "" || d.Info.Version == "" || len(d.Paths) == 0 {
			t.Errorf("%s: not an OpenAPI 3.1 file with a title, a version and paths", name)
		}
		ids := map[string]bool{}
		for p, methods := range d.Paths {
			for m, op := range methods {
				if op.OperationID == "" || ids[op.OperationID] {
					t.Errorf("%s %s %s: operationId %q is empty or repeated", name, m, p, op.OperationID)
				}
				ids[op.OperationID] = true
				if len(op.Responses) == 0 {
					t.Errorf("%s %s %s: no responses", name, m, p)
				}
			}
		}
		var root map[string]any
		if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
			t.Fatal(err)
		}
		for _, ref := range regexp.MustCompile(`\$ref['"]?:\s*['"]?(#/[^'"}\s,]+)`).FindAllStringSubmatch(raw, -1) {
			var cur any = root
			for _, part := range strings.Split(ref[1][2:], "/") {
				m, ok := cur.(map[string]any)
				if !ok {
					cur = nil
					break
				}
				cur = m[part]
			}
			if cur == nil {
				t.Errorf("%s: %s points at nothing", name, ref[1])
			}
		}
	}
}

func opsOf(d doc) []string {
	var out []string
	for p, methods := range d.Paths {
		for m := range methods {
			out = append(out, strings.ToLower(m)+" "+p)
		}
	}
	sort.Strings(out)
	return out
}

// The KMS-JSON operations of the file are the ones the code dispatches on, and the other way round.
func TestKMSJSONOperations(t *testing.T) {
	d, _ := load(t, "kms-json.yaml")
	src := source(t, "internal/face/kmsjson/*.go")
	have := map[string]bool{}
	for _, o := range opsOf(d) {
		name := strings.TrimPrefix(strings.Fields(o)[1], "/#TrentService.")
		have[name] = true
		if !strings.Contains(src, `"`+name+`"`) {
			t.Errorf("%s is in the spec but the code has no such operation", name)
		}
	}
	for _, name := range []string{"GetPublicKey", "DescribeKey", "ListKeys", "ListAliases", "DeriveSharedSecret", "Encrypt", "Decrypt", "ReEncrypt", "GenerateDataKey", "GenerateDataKeyWithoutPlaintext", "GenerateRandom", "Sign", "Verify", "GenerateMac", "VerifyMac"} {
		if !have[name] {
			t.Errorf("%s is served by the code but not in the spec", name)
		}
	}
}

// The REST routes: the operations of the table in kmsrest.go, each with a path with and without a version.
func TestKMSRESTOperations(t *testing.T) {
	d, _ := load(t, "kms-rest.yaml")
	src := source(t, "internal/face/kmsrest/*.go")
	want := []string{
		"get /keys", "get /keys/{name}", "get /keys/{name}/versions", "get /keys/{name}/{version}", "post /rng",
		"get /{tenant}/v2.0/.well-known/openid-configuration", "post /{tenant}/oauth2/v2.0/token",
	}
	for _, op := range []string{"sign", "verify", "encrypt", "decrypt", "wrapkey", "unwrapkey"} {
		if !strings.Contains(src, `op: "`+op+`"`) {
			t.Errorf("the code has no operation %q any more: update api/kms-rest.yaml", op)
		}
		want = append(want, "post /keys/{name}/"+op, "post /keys/{name}/{version}/"+op)
	}
	sort.Strings(want)
	got := opsOf(d)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the spec lists\n%s\nthe service has\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// The gRPC methods of the file are the ones the code dispatches on.
func TestGRPCMethods(t *testing.T) {
	d, _ := load(t, "kms-grpc.yaml")
	src := source(t, "internal/face/kmsgrpc/*.go")
	prefix := "/google.cloud.kms.v1.KeyManagementService/"
	if !strings.Contains(src, prefix) {
		t.Fatal("the service path changed: update api/kms-grpc.yaml")
	}
	n := 0
	for p := range d.Paths {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		n++
		if m := strings.TrimPrefix(p, prefix); !strings.Contains(src, `"`+m+`"`) {
			t.Errorf("%s is in the spec but the code has no such method", m)
		}
	}
	if n != 11 {
		t.Errorf("the spec lists %d methods, the service serves 11", n)
	}
}

// The admin socket routes.
func TestAdminRoutes(t *testing.T) {
	d, _ := load(t, "admin.yaml")
	src := source(t, "internal/server/admin.go")
	for _, o := range opsOf(d) {
		f := strings.Fields(o)
		if !strings.Contains(src, strings.ToUpper(f[0])+" "+f[1]+`"`) {
			t.Errorf("%s is in the spec but not in the admin handler", o)
		}
	}
	if len(d.Paths) != 3 {
		t.Errorf("the admin spec lists %d paths, the handler has 3", len(d.Paths))
	}
}

// The page names every specification of the directory.
func TestIndexListsEverySpec(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "api", "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "api", "*.yaml"))
	for _, f := range files {
		if !strings.Contains(string(raw), "'"+filepath.Base(f)+"'") {
			t.Errorf("api/index.html does not show %s", filepath.Base(f))
		}
	}
}
