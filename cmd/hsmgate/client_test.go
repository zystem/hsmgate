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

// Individual files, to places that the caller names; the other files of the volume are not touched.
func TestDecryptIndividualFiles(t *testing.T) {
	addr := service(t)
	src := writeFiles(t, map[string][]byte{"a": []byte("alpha"), "b": []byte("beta"), "c": []byte("gamma")})
	_, out, _ := enc(t, addr, "", "-in-dir", src, "-k8s", "shop/files")
	vol := secretVolume(t, fieldsOf(t, out))
	dst := t.TempDir()
	code, _, e := dec(t, addr, "", "-context-prefix", "k8s/shop/files/",
		"-file", filepath.Join(vol, "a")+"="+filepath.Join(dst, "conf", "nested", "a.txt"),
		"-file", filepath.Join(vol, "c"), "-out-dir", filepath.Join(dst, "out"))
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "conf", "nested", "a.txt")); string(b) != "alpha" {
		t.Errorf("a: %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "out", "c")); string(b) != "gamma" {
		t.Errorf("c: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dst, "out", "b")); err == nil {
		t.Error("b was opened although it was not asked for")
	}
	// all or nothing here too: the second file is for another Secret
	_, out, _ = enc(t, addr, "x", "-k8s", "shop/elsewhere/d")
	bad := writeFiles(t, map[string][]byte{"d": []byte(ciphertextFromManifest(t, out))})
	dst2 := t.TempDir()
	code, _, e = dec(t, addr, "", "-context-prefix", "k8s/shop/files/", "-file", filepath.Join(vol, "a")+"="+filepath.Join(dst2, "a"), "-file", filepath.Join(bad, "d")+"="+filepath.Join(dst2, "d"))
	if code != 1 || !strings.Contains(e, "d:") {
		t.Fatalf("%d %s", code, e)
	}
	if ents, _ := os.ReadDir(dst2); len(ents) != 0 {
		t.Errorf("files were written: %v", ents)
	}
}

func TestDirectoryAndFileModesAreChecked(t *testing.T) {
	addr := service(t)
	src := writeFiles(t, map[string][]byte{"ok": []byte("v"), "bad name": []byte("v")})
	if code, out, e := enc(t, addr, "", "-in-dir", src, "-k8s", "shop/s"); code != 1 || out != "" || !strings.Contains(e, "bad name") {
		t.Errorf("an invalid field name: %d %q %s", code, out, e)
	}
	empty := writeFiles(t, map[string][]byte{"e": nil})
	if code, out, e := enc(t, addr, "", "-in-dir", empty, "-k8s", "shop/s"); code != 1 || out != "" || !strings.Contains(e, "empty") {
		t.Errorf("an empty file: %d %q %s", code, out, e)
	}
	for name, args := range map[string][]string{
		"-in-dir with a field in -k8s": {"-in-dir", src, "-k8s", "shop/s/f"},
		"-in-dir without -k8s":         {"-in-dir", src},
		"-in-dir with -context":        {"-in-dir", src, "-k8s", "shop/s", "-context", "x"},
		"-in with -in-dir":             {"-in", "-", "-in-dir", src, "-k8s", "shop/s"},
		"-in with -file":               {"-in", "-", "-file", filepath.Join(src, "ok"), "-k8s", "shop/s"},
		"-file without -k8s":           {"-file", filepath.Join(src, "ok")},
	} {
		if code, _, _ := enc(t, addr, "", args...); code != 2 {
			t.Errorf("encrypt %s: exit %d", name, code)
		}
	}
	for name, args := range map[string][]string{
		"-in with -in-dir":     {"-in", "-", "-in-dir", "/y", "-out-dir", "/z", "-context-prefix", "k8s/a/"},
		"-in with -file":       {"-file", "/x", "-in", "-", "-context-prefix", "k8s/a/"},
		"-file with no place":  {"-file", "/x", "-context-prefix", "k8s/a/"},
		"-file with no prefix": {"-file", "/x=/y"},
	} {
		if code, _, _ := dec(t, addr, "", args...); code != 2 {
			t.Errorf("decrypt %s: exit %d", name, code)
		}
	}
	if code, _, e := dec(t, addr, "", "-file", "/no/such/file=/tmp/x", "-context-prefix", "k8s/a/"); code != 1 || !strings.Contains(e, "no such file") {
		t.Errorf("a missing source: %d %s", code, e)
	}
}

// -in-dir and -file mean the same in both commands and can be given together; "=TARGET" is the other side: the field name when sealing, the path when opening.
func TestInDirAndFileAreUniform(t *testing.T) {
	addr := service(t)
	dir := writeFiles(t, map[string][]byte{"from-dir": []byte("one")})
	extra := writeFiles(t, map[string][]byte{"app.yaml": []byte("two"), "other": []byte("three")})
	code, out, e := enc(t, addr, "", "-in-dir", dir, "-file", filepath.Join(extra, "app.yaml")+"=application.yaml", "-file", filepath.Join(extra, "other"), "-k8s", "shop/mixed")
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	fields := fieldsOf(t, out)
	if len(fields) != 3 || fields["from-dir"] == "" || fields["application.yaml"] == "" || fields["other"] == "" || fields["app.yaml"] != "" {
		t.Fatalf("fields: %v", fields)
	}
	// the same two kinds of source on the way back, together: a directory and two files to places of their choice
	vol := secretVolume(t, map[string]string{"from-dir": fields["from-dir"]})
	vol2 := secretVolume(t, map[string]string{"application.yaml": fields["application.yaml"], "other": fields["other"]})
	dst := t.TempDir()
	code, _, e = dec(t, addr, "", "-context-prefix", "k8s/shop/mixed/", "-out-dir", filepath.Join(dst, "all"),
		"-in-dir", vol, "-file", filepath.Join(vol2, "application.yaml")+"="+filepath.Join(dst, "etc", "app.yaml"), "-file", filepath.Join(vol2, "other"))
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	for path, want := range map[string]string{filepath.Join(dst, "all", "from-dir"): "one", filepath.Join(dst, "etc", "app.yaml"): "two", filepath.Join(dst, "all", "other"): "three"} {
		if b, err := os.ReadFile(path); err != nil || string(b) != want {
			t.Errorf("%s: %q %v", path, b, err)
		}
	}
	// two sources for one field, or for one destination, are an error and nothing is done
	if code, out, e := enc(t, addr, "", "-in-dir", dir, "-file", filepath.Join(extra, "other")+"=from-dir", "-k8s", "shop/mixed"); code != 1 || out != "" || !strings.Contains(e, "twice") {
		t.Errorf("a field twice: %d %q %s", code, out, e)
	}
	dst2 := t.TempDir()
	if code, _, e := dec(t, addr, "", "-context-prefix", "k8s/shop/mixed/", "-in-dir", vol, "-file", filepath.Join(vol2, "other")+"="+filepath.Join(dst2, "from-dir"), "-out-dir", dst2); code != 1 || !strings.Contains(e, "same place") {
		t.Errorf("a destination twice: %d %s", code, e)
	}
	if ents, _ := os.ReadDir(dst2); len(ents) != 0 {
		t.Errorf("files were written: %v", ents)
	}
}
