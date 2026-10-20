package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

// the real service in development mode; the client is "shop", who may use contexts of the namespace shop only
func service(t *testing.T) string {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "k"), []byte(strings.Repeat("33", 32)), 0o600)
	cfg, err := config.Parse([]byte("listen: 127.0.0.1:0\ninsecure_loopback_client: shop\naudit: {file: " + filepath.Join(dir, "a.log") + "}\n" +
		"tokens: [{name: soft, type: soft, keys: {m: " + filepath.Join(dir, "k") + "}}]\n" +
		"keys: {apps: {versions: [{token: soft, label: m}], aad: {mode: context, allow: [\"k8s/\"]}}}\n" +
		"clients: [{name: shop, identity: {cn: shop}, keys: {apps: {ops: [encrypt, decrypt], contexts: [\"k8s/shop/\"]}}}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := server.New(cfg, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s.HTTP.Handler)
	t.Cleanup(ts.Close)
	return ts.URL
}

func enc(t *testing.T, addr, stdin string, extra ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = runEncrypt(append([]string{"-addr", addr, "-transit-key", "apps"}, extra...), strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

func dec(t *testing.T, addr string, stdin string, args ...string) (code int, stdout, stderr string) {
	var o, e bytes.Buffer
	code = runDecrypt(append([]string{"-addr", addr, "-transit-key", "apps", "-wait", "1s"}, args...), strings.NewReader(stdin), &o, &e)
	return code, o.String(), e.String()
}

// a Secret volume as the kubelet makes it: the fields are links to ..data, which is a link to a directory named after the time
func secretVolume(t *testing.T, fields map[string]string) string {
	dir := t.TempDir()
	real := filepath.Join(dir, "..2026_10_20_10_00_00.123")
	os.Mkdir(real, 0o755)
	os.Symlink("..2026_10_20_10_00_00.123", filepath.Join(dir, "..data"))
	for k, v := range fields {
		os.WriteFile(filepath.Join(real, k), []byte(v), 0o644)
		os.Symlink(filepath.Join("..data", k), filepath.Join(dir, k))
	}
	return dir
}

func ciphertextFromManifest(t *testing.T, manifest string) string {
	var m struct {
		Kind       string `yaml:"kind"`
		Metadata   struct{ Name, Namespace string }
		StringData map[string]string `yaml:"stringData"`
	}
	if err := yaml.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatalf("%v\n%s", err, manifest)
	}
	if m.Kind != "Secret" || m.Metadata.Name == "" || m.Metadata.Namespace != "shop" {
		t.Fatalf("manifest: %s", manifest)
	}
	for _, v := range m.StringData {
		return v
	}
	t.Fatal("no stringData")
	return ""
}

func TestEncryptMakesASecretManifestAndDecryptFillsTheDirectory(t *testing.T) {
	addr := service(t)
	code, out, errOut := enc(t, addr, "test-password\n", "-k8s", "shop/app-secrets/api-keys-secret")
	if code != 0 || strings.Contains(out, "test-password") || strings.Contains(errOut, "test-password") {
		t.Fatalf("%d\n%s\n%s", code, out, errOut)
	}
	ct := ciphertextFromManifest(t, out)
	if !strings.HasPrefix(ct, "vault:v1:") || !strings.Contains(errOut, `context "k8s/shop/app-secrets/api-keys-secret"`) {
		t.Errorf("%q / %s", ct, errOut)
	}

	in := secretVolume(t, map[string]string{"api-keys-secret": ct + "\n"}) // a newline after the value, as `echo` leaves one
	outDir := filepath.Join(t.TempDir(), "plain")
	code, _, errOut = dec(t, addr, "", "-in-dir", in, "-out-dir", outDir, "-context-prefix", "k8s/shop/app-secrets/")
	if code != 0 {
		t.Fatalf("%d %s", code, errOut)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "api-keys-secret"))
	if err != nil || string(got) != "test-password" { // exactly the value: the newline of the input was removed when it was sealed
		t.Fatalf("%q %v", got, err)
	}
	if st, _ := os.Stat(filepath.Join(outDir, "api-keys-secret")); st.Mode().Perm() != 0o440 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	ents, _ := os.ReadDir(outDir)
	if len(ents) != 1 { // no ..data, no temporary files
		t.Errorf("%d entries in the output: %v", len(ents), ents)
	}
	if strings.Contains(errOut, "test-password") || !strings.Contains(errOut, "api-keys-secret") {
		t.Errorf("stderr: %s", errOut)
	}
}

func TestContextPrefixTakesTheNamespaceFromTheEnvironment(t *testing.T) {
	addr := service(t)
	_, out, _ := enc(t, addr, "v", "-k8s", "shop/app-secrets/f")
	ct := ciphertextFromManifest(t, out)
	in := secretVolume(t, map[string]string{"f": ct})
	t.Setenv("POD_NAMESPACE", "shop")
	outDir := filepath.Join(t.TempDir(), "p")
	if code, _, e := dec(t, addr, "", "-in-dir", in, "-out-dir", outDir, "-context-prefix", "k8s/${POD_NAMESPACE}/app-secrets/"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if b, _ := os.ReadFile(filepath.Join(outDir, "f")); string(b) != "v" {
		t.Errorf("%q", b)
	}
}

// All or nothing: a pod whose init container fails does not start with a half of its files.
func TestOneBadFileWritesNothing(t *testing.T) {
	addr := service(t)
	_, out, _ := enc(t, addr, "one", "-k8s", "shop/app-secrets/good")
	good := ciphertextFromManifest(t, out)
	_, out, _ = enc(t, addr, "two", "-k8s", "shop/another/bad") // sealed for another Secret
	bad := ciphertextFromManifest(t, out)
	in := secretVolume(t, map[string]string{"good": good, "bad": bad})
	outDir := filepath.Join(t.TempDir(), "plain")
	code, _, errOut := dec(t, addr, "", "-in-dir", in, "-out-dir", outDir, "-context-prefix", "k8s/shop/app-secrets/")
	if code != 1 || !strings.Contains(errOut, "bad:") || !strings.Contains(errOut, "cannot be opened") || !strings.Contains(errOut, `"k8s/shop/app-secrets/bad"`) {
		t.Fatalf("%d %s", code, errOut)
	}
	if _, err := os.Stat(outDir); err == nil {
		ents, _ := os.ReadDir(outDir)
		if len(ents) != 0 {
			t.Errorf("files were written: %v", ents)
		}
	}
	if strings.Contains(errOut, "one") && strings.Contains(errOut, "two") {
		t.Errorf("values in the output: %s", errOut)
	}
}

func TestAnotherNamespaceIsRefusedByTheGrant(t *testing.T) {
	addr := service(t)
	code, _, errOut := enc(t, addr, "x", "-k8s", "bank/app-secrets/f") // the certificate of the shop may not even seal for the bank
	if code != 1 || !strings.Contains(errOut, "permission denied") || !strings.Contains(errOut, "k8s/bank/app-secrets/f") {
		t.Errorf("%d %s", code, errOut)
	}
}

func TestSingleModeAndNewlines(t *testing.T) {
	addr := service(t)
	ctx := []string{"-context", "k8s/shop/a/b"}
	_, ct, _ := enc(t, addr, "line\n", ctx...)
	if code, out, e := dec(t, addr, ct, append([]string{"-in", "-"}, ctx...)...); code != 0 || out != "line" {
		t.Errorf("%d %q %s", code, out, e)
	}
	_, ct, _ = enc(t, addr, "line\n", append([]string{"-raw"}, ctx...)...)
	if _, out, _ := dec(t, addr, ct, append([]string{"-in", "-"}, ctx...)...); out != "line\n" {
		t.Errorf("-raw: %q", out)
	}
	if code, _, e := enc(t, addr, "", ctx...); code != 1 || !strings.Contains(e, "empty") {
		t.Errorf("empty value: %d %s", code, e)
	}
	if code, _, e := dec(t, addr, ct, "-in", "-", "-context", "k8s/shop/x/y"); code != 1 || !strings.Contains(e, "cannot be opened") {
		t.Errorf("wrong context: %d %s", code, e)
	}
}

func TestUsageErrorsAreExitCodeTwo(t *testing.T) {
	addr := service(t)
	for name, args := range map[string][]string{
		"neither":    {},
		"both":       {"-in", "-", "-in-dir", "/x"},
		"no out-dir": {"-in-dir", "/x", "-context-prefix", "k8s/a/"},
		"no prefix":  {"-in-dir", "/x", "-out-dir", "/y"},
		"bad mode":   {"-in-dir", "/x", "-out-dir", "/y", "-context-prefix", "k8s/a/", "-mode", "rw"},
	} {
		if code, _, _ := dec(t, addr, "", args...); code != 2 {
			t.Errorf("decrypt %s: exit %d", name, code)
		}
	}
	if code, _, _ := enc(t, addr, "x", "-k8s", "only/two"); code != 2 {
		t.Errorf("encrypt -k8s: exit %d", code)
	}
	if code, _, _ := enc(t, addr, "x", "-k8s", "a/b/c", "-context", "d"); code != 2 {
		t.Errorf("encrypt -k8s with -context: exit %d", code)
	}
	var o, e bytes.Buffer
	if code := runEncrypt([]string{"-transit-key", "apps"}, strings.NewReader("x"), &o, &e); code != 2 || !strings.Contains(e.String(), "address") {
		t.Errorf("no address: %d %s", code, e.String())
	}
	if code, _, e := dec(t, addr, "", "-in-dir", t.TempDir(), "-out-dir", t.TempDir(), "-context-prefix", "k8s/a/"); code != 1 || !strings.Contains(e, "no ciphertext files") {
		t.Errorf("empty directory: %d %s", code, e)
	}
}

// A locked token is a state that passes: the init container waits for it, up to -wait, and then fails with a sentence a person can read.
func TestInitContainerWaitsForALockedToken(t *testing.T) {
	var calls int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.Header().Set("X-Hsmgate-Retryable", "true")
			w.WriteHeader(503)
			io.WriteString(w, `{"errors":["token locked"]}`)
			return
		}
		io.WriteString(w, `{"data":{"plaintext":"c2VjcmV0"}}`)
	}))
	defer ts.Close()
	in := secretVolume(t, map[string]string{"f": "vault:v1:x"})
	outDir := filepath.Join(t.TempDir(), "p")
	var e bytes.Buffer
	code := runDecrypt([]string{"-addr", ts.URL, "-transit-key", "apps", "-wait", "10s", "-in-dir", in, "-out-dir", outDir, "-context-prefix", "k8s/a/b/"}, strings.NewReader(""), io.Discard, &e)
	if code != 0 || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("%d, %d calls: %s", code, calls, e.String())
	}
	if b, _ := os.ReadFile(filepath.Join(outDir, "f")); string(b) != "secret" {
		t.Errorf("%q", b)
	}
	// it stays locked: the failure says so
	always := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Hsmgate-Retryable", "true")
		w.WriteHeader(503)
		io.WriteString(w, `{"errors":["token locked"]}`)
	}))
	defer always.Close()
	e.Reset()
	code = runDecrypt([]string{"-addr", always.URL, "-transit-key", "apps", "-wait", "1s", "-in-dir", in, "-out-dir", filepath.Join(t.TempDir(), "q"), "-context-prefix", "k8s/a/b/"}, strings.NewReader(""), io.Discard, &e)
	if code != 1 || !strings.Contains(e.String(), "token may be locked") {
		t.Errorf("%d %s", code, e.String())
	}
}
