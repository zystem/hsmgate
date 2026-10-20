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
		"-in-dir without -out-dir":      {"-in-dir", "/x", "-context-prefix", "k8s/a/"},
		"-in-dir without a prefix":      {"-in-dir", "/x", "-out-dir", "/y"},
		"-in-files without a place":     {"-in-files", "/x", "-context-prefix", "k8s/a/"},
		"-out-files without -in-files":  {"-out-files", "/y", "-context-prefix", "k8s/a/"},
		"lists of different length":     {"-in-files", "/x,/y", "-out-files", "/z", "-context-prefix", "k8s/a/"},
		"-in with -in-dir":              {"-in", "-", "-in-dir", "/y", "-out-dir", "/z", "-context-prefix", "k8s/a/"},
		"-out with -in-files":           {"-in-files", "/x", "-out", "/z", "-out-files", "/z", "-context-prefix", "k8s/a/"},
		"-context-prefix for one value": {"-in", "-", "-context-prefix", "k8s/a/"},
		"bad mode":                      {"-in-dir", "/x", "-out-dir", "/y", "-context-prefix", "k8s/a/", "-mode", "rw"},
	} {
		if code, _, e := dec(t, addr, "", args...); code != 2 {
			t.Errorf("decrypt %s: exit %d (%s)", name, code, e)
		}
	}
	for name, args := range map[string][]string{
		"-k8s with two parts for one value": {"-k8s", "only/two"},
		"-k8s with -context":                {"-k8s", "a/b/c", "-context", "d"},
		"-k8s with three parts for many":    {"-in-dir", "/x", "-k8s", "a/b/c"},
		"-k8s with -out-dir":                {"-in-dir", "/x", "-k8s", "a/b", "-out-dir", "/y"},
		"many without a prefix or -k8s":     {"-in-dir", "/x", "-out-dir", "/y"},
		"lists of different length":         {"-in-files", "/x,/y", "-out-files", "/z", "-context-prefix", "k8s/a/"},
		"-in with -in-files":                {"-in", "-", "-in-files", "/x", "-k8s", "a/b"},
	} {
		if code, _, e := enc(t, addr, "x", args...); code != 2 {
			t.Errorf("encrypt %s: exit %d (%s)", name, code, e)
		}
	}
	var o, e bytes.Buffer
	if code := runEncrypt([]string{"-transit-key", "apps"}, strings.NewReader("x"), &o, &e); code != 2 || !strings.Contains(e.String(), "address") {
		t.Errorf("no address: %d %s", code, e.String())
	}
	if code, _, e := dec(t, addr, "", "-in-dir", t.TempDir(), "-out-dir", t.TempDir(), "-context-prefix", "k8s/a/"); code != 1 || !strings.Contains(e, "no ciphertext files") {
		t.Errorf("empty directory: %d %s", code, e)
	}
	if code, _, e := dec(t, addr, "", "-in-files", "/no/such/file", "-out-files", filepath.Join(t.TempDir(), "x"), "-context-prefix", "k8s/a/"); code != 1 || !strings.Contains(e, "no such file") {
		t.Errorf("a missing source: %d %s", code, e)
	}
	// the message of the length check says the two numbers
	if code, _, e := dec(t, addr, "", "-in-files", "/x,/y", "-out-files", "/z", "-context-prefix", "k8s/a/"); code != 2 || !strings.Contains(e, "2 element(s)") || !strings.Contains(e, "has 1") {
		t.Errorf("length message: %d %s", code, e)
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

// ---- a directory of files, and individual files ----

func writeFiles(t *testing.T, files map[string][]byte) string {
	dir := t.TempDir()
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func fieldsOf(t *testing.T, manifest string) map[string]string {
	var m struct {
		StringData map[string]string `yaml:"stringData"`
	}
	if err := yaml.Unmarshal([]byte(manifest), &m); err != nil {
		t.Fatalf("%v\n%s", err, manifest)
	}
	return m.StringData
}

// A directory of files becomes one Secret manifest; the whole round trip gives the files back, binary ones too.
func TestEncryptADirectoryAndDecryptItBack(t *testing.T) {
	addr := service(t)
	binary := []byte{0x00, 0xff, 0xfe, 0x01, '\n', 0x80}
	src := writeFiles(t, map[string][]byte{
		"api-keys-secret":  []byte("test-password\n"),
		"application.yaml": []byte("db:\n  password: s3cret\n"),
		"keystore.p12":     binary,
		".hidden":          []byte("not a field"),
	})
	os.Mkdir(filepath.Join(src, "subdir"), 0o755)
	code, out, errOut := enc(t, addr, "", "-in-dir", src, "-k8s", "shop/app-files", "-raw")
	if code != 0 || strings.Contains(out, "s3cret") || strings.Contains(out, "test-password") {
		t.Fatalf("%d\n%s\n%s", code, out, errOut)
	}
	fields := fieldsOf(t, out)
	if len(fields) != 3 || fields[".hidden"] != "" || !strings.Contains(errOut, "sealed 3 file(s)") {
		t.Fatalf("fields: %v / %s", fields, errOut)
	}
	// put the ciphertexts where a Secret volume has them and open the whole directory
	vol := secretVolume(t, fields)
	outDir := filepath.Join(t.TempDir(), "plain")
	if code, _, e := dec(t, addr, "", "-in-dir", vol, "-out-dir", outDir, "-context-prefix", "k8s/shop/app-files/"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	for n, want := range map[string][]byte{"api-keys-secret": []byte("test-password\n"), "application.yaml": []byte("db:\n  password: s3cret\n"), "keystore.p12": binary} {
		got, err := os.ReadFile(filepath.Join(outDir, n))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %q %v", n, got, err)
		}
	}
}

// ---- -in/-out, -in-dir/-out-dir, -in-files/-out-files: the same on both sides ----

// A directory to a directory and back; the middle is a directory of ciphertext files, the form a mounted Secret has.
func TestDirectoryToDirectoryAndBack(t *testing.T) {
	addr := service(t)
	binary := []byte{0x00, 0xff, 0xfe, 0x01, 0x80}
	plain := writeFiles(t, map[string][]byte{"api-keys-secret": []byte("test-password"), "application.yaml": []byte("db: s3cret\n"), "keystore.p12": binary})
	enc1 := filepath.Join(t.TempDir(), "enc")
	code, out, e := enc(t, addr, "", "-in-dir", plain, "-out-dir", enc1, "-context-prefix", "k8s/shop/app/", "-raw")
	if code != 0 || out != "" {
		t.Fatalf("%d %q %s", code, out, e)
	}
	for _, n := range []string{"api-keys-secret", "application.yaml", "keystore.p12"} {
		b, err := os.ReadFile(filepath.Join(enc1, n))
		if err != nil || !strings.HasPrefix(string(b), "vault:v1:") || strings.Contains(string(b), "s3cret") {
			t.Errorf("%s: %q %v", n, b, err)
		}
	}
	back := filepath.Join(t.TempDir(), "plain")
	if code, _, e := dec(t, addr, "", "-in-dir", enc1, "-out-dir", back, "-context-prefix", "k8s/shop/app/"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	for n, want := range map[string][]byte{"api-keys-secret": []byte("test-password"), "application.yaml": []byte("db: s3cret\n"), "keystore.p12": binary} {
		if got, err := os.ReadFile(filepath.Join(back, n)); err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %q %v", n, got, err)
		}
	}
}

// Lists in pairs, by position: the output name decides the context when sealing, the input name when opening.
func TestFilesInPairsByPosition(t *testing.T) {
	addr := service(t)
	src := writeFiles(t, map[string][]byte{"a": []byte("alpha"), "b b": []byte("beta"), "c": []byte("gamma")})
	dst := t.TempDir()
	list := filepath.Join(src, "a") + ", " + filepath.Join(src, "b b") + ",," + filepath.Join(src, "c") // spaces around, an empty element, a path with a space
	outs := filepath.Join(dst, "one") + "," + filepath.Join(dst, "sub", "two") + "," + filepath.Join(dst, "three")
	code, _, e := enc(t, addr, "", "-in-files", list, "-out-files", outs, "-context-prefix", "k8s/shop/list/")
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	// a ciphertext file is named "one", "two", "three": they are the contexts
	back := t.TempDir()
	code, _, e = dec(t, addr, "", "-context-prefix", "k8s/shop/list/",
		"-in-files", filepath.Join(dst, "one")+","+filepath.Join(dst, "sub", "two"), "-in-files", filepath.Join(dst, "three"),
		"-out-files", filepath.Join(back, "x", "alpha.txt")+","+filepath.Join(back, "beta.txt"), "-out-files", filepath.Join(back, "gamma.txt"))
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	for n, want := range map[string]string{filepath.Join("x", "alpha.txt"): "alpha", "beta.txt": "beta", "gamma.txt": "gamma"} {
		if b, err := os.ReadFile(filepath.Join(back, n)); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", n, b, err)
		}
	}
	// the output name is the context: with the wrong prefix nothing opens, and nothing is written
	bad := t.TempDir()
	if code, _, e := dec(t, addr, "", "-context-prefix", "k8s/shop/other/", "-in-files", filepath.Join(dst, "one"), "-out-files", filepath.Join(bad, "x")); code != 1 || !strings.Contains(e, "cannot be opened") {
		t.Errorf("wrong prefix: %d %s", code, e)
	}
	if ents, _ := os.ReadDir(bad); len(ents) != 0 {
		t.Errorf("files were written: %v", ents)
	}
}

// -in-files with -out-dir: the output names are the input names. A directory and files can be given together.
func TestFilesAndDirectoryTogether(t *testing.T) {
	addr := service(t)
	dir := writeFiles(t, map[string][]byte{"from-dir": []byte("one")})
	extra := writeFiles(t, map[string][]byte{"app.yaml": []byte("two"), "other": []byte("three")})
	encDir := filepath.Join(t.TempDir(), "enc")
	code, _, e := enc(t, addr, "", "-in-dir", dir, "-in-files", filepath.Join(extra, "app.yaml")+","+filepath.Join(extra, "other"), "-out-dir", encDir, "-context-prefix", "k8s/shop/mix/")
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	ents, _ := os.ReadDir(encDir)
	if len(ents) != 3 {
		t.Fatalf("%v", ents)
	}
	back := t.TempDir()
	code, _, e = dec(t, addr, "", "-context-prefix", "k8s/shop/mix/", "-in-dir", encDir, "-out-dir", back)
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	for n, want := range map[string]string{"from-dir": "one", "app.yaml": "two", "other": "three"} {
		if b, err := os.ReadFile(filepath.Join(back, n)); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", n, b, err)
		}
	}
	// two inputs with the same name would have the same context, and two outputs would be one file: refused, nothing is done
	other := writeFiles(t, map[string][]byte{"from-dir": []byte("again")})
	if code, _, e := enc(t, addr, "", "-in-dir", dir, "-in-files", filepath.Join(other, "from-dir"), "-out-dir", filepath.Join(t.TempDir(), "x"), "-context-prefix", "k8s/shop/mix/"); code != 2 || !strings.Contains(e, "same") {
		t.Errorf("a name twice: %d %s", code, e)
	}
}

// -k8s with a directory or files prints one manifest; the field names are the names of the input files.
func TestManifestFromFiles(t *testing.T) {
	addr := service(t)
	src := writeFiles(t, map[string][]byte{"a": []byte("alpha"), "b": []byte("beta"), "bad name": []byte("x")})
	code, out, e := enc(t, addr, "", "-in-files", filepath.Join(src, "a")+","+filepath.Join(src, "b"), "-k8s", "shop/files")
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if f := fieldsOf(t, out); len(f) != 2 || f["a"] == "" || f["b"] == "" {
		t.Errorf("fields: %v", f)
	}
	if code, out, e := enc(t, addr, "", "-in-dir", src, "-k8s", "shop/files"); code != 1 || out != "" || !strings.Contains(e, "bad name") {
		t.Errorf("an invalid field name: %d %q %s", code, out, e)
	}
}
