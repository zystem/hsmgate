package main

// The client side of hsmgate: `hsmgate encrypt` for the person who makes a ciphertext, `hsmgate decrypt` for the init container of a pod that turns ciphertexts
// into files. Neither needs a configuration file of the service; they speak the Transit API (docs/specs/transit.md) with a client certificate.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/zystem/hsmgate/internal/client"
)

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

type common struct {
	addr, mount, key, ca, cert, keyfile string
	wait                                time.Duration
}

func (c *common) add(fs *flag.FlagSet) {
	fs.StringVar(&c.addr, "addr", env("HSMGATE_ADDR", ""), "address of the service, https://host:8443 (env HSMGATE_ADDR)")
	fs.StringVar(&c.mount, "mount", env("HSMGATE_MOUNT", "transit"), "Transit mount (env HSMGATE_MOUNT)")
	fs.StringVar(&c.key, "transit-key", env("HSMGATE_TRANSIT_KEY", ""), "name of the key in the service (env HSMGATE_TRANSIT_KEY)")
	fs.StringVar(&c.ca, "ca", env("HSMGATE_CA", ""), "CA certificate of the service, PEM (env HSMGATE_CA)")
	fs.StringVar(&c.cert, "cert", env("HSMGATE_CERT", ""), "client certificate, PEM (env HSMGATE_CERT)")
	fs.StringVar(&c.keyfile, "keyfile", env("HSMGATE_KEYFILE", ""), "private key of the client certificate, PEM (env HSMGATE_KEYFILE)")
	fs.DurationVar(&c.wait, "wait", time.Minute, "how long to try again when the service says it may pass (locked token, busy, rate)")
}

func (c *common) client() (*client.Client, error) {
	return client.New(client.Config{Addr: c.addr, Mount: c.mount, Key: c.key, CAFile: c.ca, CertFile: c.cert, KeyFile: c.keyfile})
}

// runEncrypt: hsmgate encrypt -transit-key K [-context C | -k8s NS/NAME/FIELD] [-in FILE] [-raw]
func runEncrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.add(fs)
	aadContext := fs.String("context", "", "context (additional data) of the ciphertext; required for a key in context mode")
	k8s := fs.String("k8s", "", "NAMESPACE/SECRET/FIELD (one value) or NAMESPACE/SECRET (with -in-dir): sets the context to k8s/NAMESPACE/SECRET/FIELD and prints a Kubernetes Secret manifest")
	in := fs.String("in", "-", "file with the value, or - for standard input (a terminal is asked without echo)")
	inDir := fs.String("in-dir", "", "a directory of files, one value each; the file name is the field name")
	var files fileList
	fs.Var(&files, "file", "one file, SRC or SRC=FIELD (repeat for more): SRC holds the value, FIELD is the field name (default: the base name of SRC). With -in-dir and -file, -k8s NAMESPACE/SECRET prints one Secret manifest with a field per file")
	raw := fs.Bool("raw", false, "keep a trailing newline of the input (by default one is removed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	explicitIn := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "in" {
			explicitIn = true
		}
	})
	if *inDir != "" || len(files) > 0 {
		if explicitIn {
			fmt.Fprintln(stderr, "hsmgate encrypt: -in (one value) cannot be combined with -in-dir or -file")
			return 2
		}
		return encryptFiles(&c, *inDir, files, *k8s, *aadContext, *raw, stdout, stderr)
	}
	var ns, name, field string
	if *k8s != "" {
		p := strings.Split(*k8s, "/")
		if len(p) != 3 || p[0] == "" || p[1] == "" || p[2] == "" {
			fmt.Fprintln(stderr, "hsmgate encrypt: -k8s wants NAMESPACE/SECRET/FIELD (or NAMESPACE/SECRET with -in-dir)")
			return 2
		}
		ns, name, field = p[0], p[1], p[2]
		if *aadContext != "" {
			fmt.Fprintln(stderr, "hsmgate encrypt: -k8s sets the context itself; do not give -context as well")
			return 2
		}
		*aadContext = contextOf(ns, name, field)
	}
	cl, err := c.client()
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate encrypt:", err)
		return 2
	}
	plain, err := readValue(*in, stdin, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate encrypt:", err)
		return 1
	}
	defer wipe(plain)
	if !*raw {
		plain = trimOneNewline(plain)
	}
	if len(plain) == 0 {
		fmt.Fprintln(stderr, "hsmgate encrypt: the value is empty")
		return 1
	}
	var ct string
	var ver int
	err = client.Retry(context.Background(), c.wait, func() (e error) {
		ct, ver, e = cl.Encrypt(context.Background(), plain, *aadContext)
		return
	}, nil)
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate encrypt:", client.Explain(err, c.key, *aadContext))
		return 1
	}
	if *k8s != "" {
		fmt.Fprintf(stdout, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\nstringData:\n  %s: %q\n", name, ns, field, ct)
	} else {
		fmt.Fprintln(stdout, ct)
	}
	fmt.Fprintf(stderr, "sealed under version %d of key %q with context %q\n", ver, c.key, *aadContext)
	return 0
}

// validField: what Kubernetes accepts as a key of a Secret.
func validField(n string) bool {
	if n == "" || len(n) > 253 || n == "." || n == ".." {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

// source is one value to seal: the file that holds it and the name of its field.
type source struct{ field, path string }

// sealSources lists the files of -in-dir (every regular file that does not start with a dot) and -file; the same field name twice is an error.
func sourcesOf(dir string, files fileList, stderr io.Writer) ([]source, bool) {
	var out []source
	seen := map[string]string{}
	add := func(field, path string) bool {
		if !validField(field) {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: %q is not a valid key of a Secret (letters, digits, - _ .)\n", path, field)
			return false
		}
		if prev, dup := seen[field]; dup {
			fmt.Fprintf(stderr, "hsmgate encrypt: the field %q is given twice (%s and %s)\n", field, prev, path)
			return false
		}
		seen[field] = path
		out = append(out, source{field, path})
		return true
	}
	ok := true
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate encrypt:", err)
			return nil, false
		}
		for _, e := range entries {
			n := e.Name()
			if strings.HasPrefix(n, ".") {
				continue
			}
			if st, err := os.Stat(filepath.Join(dir, n)); err != nil || !st.Mode().IsRegular() {
				continue
			}
			ok = add(n, filepath.Join(dir, n)) && ok
		}
	}
	for _, f := range files {
		path, field := f, ""
		if i := strings.Index(f, "="); i >= 0 {
			path, field = f[:i], f[i+1:]
		}
		if path == "" {
			fmt.Fprintf(stderr, "hsmgate encrypt: -file %q has no source\n", f)
			return nil, false
		}
		if field == "" {
			field = filepath.Base(path)
		}
		ok = add(field, path) && ok
	}
	return out, ok
}

// encryptFiles seals every file (a file is a field) and prints one Secret manifest; nothing is printed unless every file was sealed.
func encryptFiles(c *common, dir string, files fileList, k8s, aadContext string, raw bool, stdout, stderr io.Writer) int {
	p := strings.Split(k8s, "/")
	if len(p) != 2 || p[0] == "" || p[1] == "" || aadContext != "" {
		fmt.Fprintln(stderr, "hsmgate encrypt: -in-dir and -file need -k8s NAMESPACE/SECRET (and no -context): the context of a file is k8s/NAMESPACE/SECRET/<field>")
		return 2
	}
	cl, err := c.client()
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate encrypt:", err)
		return 2
	}
	srcs, ok := sourcesOf(dir, files, stderr)
	if !ok {
		return 1
	}
	type field struct{ name, ct string }
	var fields []field
	failed := false
	for _, src := range srcs {
		plain, err := readValue(src.path, nil, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: %v\n", src.field, err)
			failed = true
			continue
		}
		if !raw {
			plain = trimOneNewline(plain)
		}
		if len(plain) == 0 {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: the file is empty\n", src.field)
			failed = true
			continue
		}
		ctx := contextOf(p[0], p[1], src.field)
		var ct string
		err = client.Retry(context.Background(), c.wait, func() (e error) {
			ct, _, e = cl.Encrypt(context.Background(), plain, ctx)
			return
		}, nil)
		wipe(plain)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: %s\n", src.field, client.Explain(err, c.key, ctx))
			failed = true
			continue
		}
		fields = append(fields, field{src.field, ct})
	}
	if failed {
		return 1
	}
	if len(fields) == 0 {
		fmt.Fprintln(stderr, "hsmgate encrypt: no files to seal")
		return 1
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	fmt.Fprintf(stdout, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\nstringData:\n", p[1], p[0])
	for _, f := range fields {
		fmt.Fprintf(stdout, "  %s: %q\n", f.name, f.ct)
	}
	fmt.Fprintf(stderr, "sealed %d file(s) under key %q, contexts k8s/%s/%s/<field>\n", len(fields), c.key, p[0], p[1])
	return 0
}

// contextOf is the convention that ties a ciphertext to the Secret field it belongs to.
func contextOf(ns, name, field string) string { return "k8s/" + ns + "/" + name + "/" + field }

func readValue(in string, stdin io.Reader, stderr io.Writer) ([]byte, error) {
	const max = 1 << 20
	if in == "-" {
		if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			fmt.Fprint(stderr, "value (not shown): ")
			b, err := term.ReadPassword(int(f.Fd()))
			fmt.Fprintln(stderr)
			return b, err
		}
		b, err := io.ReadAll(io.LimitReader(stdin, max+1))
		if err == nil && len(b) > max {
			err = errors.New("the value is larger than 1 MiB")
		}
		return b, err
	}
	b, err := os.ReadFile(in)
	if err == nil && len(b) > max {
		err = errors.New("the value is larger than 1 MiB")
	}
	return b, err
}

func trimOneNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// runDecrypt: one ciphertext (-in FILE) to a file or standard output, or a whole directory (-in-dir) to a directory (-out-dir).
func runDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.add(fs)
	aadContext := fs.String("context", "", "context of the ciphertext (single mode)")
	in := fs.String("in", "", "file with one ciphertext, or - for standard input (single mode)")
	out := fs.String("out", "-", "where the value goes in single mode: a file, or - for standard output")
	inDir := fs.String("in-dir", "", "directory of ciphertexts, one file each (a mounted Secret): the file name is the field name")
	var files fileList
	fs.Var(&files, "file", "one ciphertext file, SRC or SRC=DST (repeat for more): its context is the prefix followed by the base name of SRC; DST defaults to -out-dir/<base name of SRC>")
	outDir := fs.String("out-dir", "", "directory for the values, one file each (directory and file modes)")
	prefix := fs.String("context-prefix", "", "directory mode: the context of a file is this prefix followed by the file name, e.g. k8s/$(POD_NAMESPACE)/app-secrets/")
	mode := fs.String("mode", "0440", "directory mode: permission bits of the files (octal); use 0440 with the group of the pod's fsGroup")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*in != "") == (*inDir != "" || len(files) > 0) {
		fmt.Fprintln(stderr, "hsmgate decrypt: give either -in (one ciphertext to standard output) or -in-dir and/or -file (several, to files)")
		return 2
	}
	cl, err := c.client()
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate decrypt:", err)
		return 2
	}
	decrypt := func(ct, ctx string) ([]byte, error) {
		var p []byte
		err := client.Retry(context.Background(), c.wait, func() (e error) {
			p, e = cl.Decrypt(context.Background(), ct, ctx)
			return
		}, nil)
		return p, err
	}
	if *in != "" {
		raw, err := readValue(*in, stdin, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", err)
			return 1
		}
		p, err := decrypt(strings.TrimSpace(string(raw)), *aadContext)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", client.Explain(err, c.key, *aadContext))
			return 1
		}
		defer wipe(p)
		if *out == "-" {
			stdout.Write(p)
			return 0
		}
		if err := writeAtomic(*out, p, 0o600); err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", err)
			return 1
		}
		return 0
	}
	if *prefix == "" || (*inDir != "" && *outDir == "") {
		fmt.Fprintln(stderr, "hsmgate decrypt: directory and file modes need -context-prefix, and -in-dir needs -out-dir")
		return 2
	}
	m, err := strconv.ParseUint(*mode, 8, 32)
	if err != nil || m > 0o777 {
		fmt.Fprintln(stderr, "hsmgate decrypt: -mode is octal permission bits like 0440")
		return 2
	}
	if strings.Contains(*prefix, "$") {
		*prefix = os.ExpandEnv(*prefix)
	}
	jobs, code := jobsOf(*inDir, *outDir, files, stderr)
	if code != 0 {
		return code
	}
	return decryptJobs(c.key, decrypt, jobs, *prefix, os.FileMode(m), *inDir, stderr)
}

// fileList is a flag that can be given more than once.
type fileList []string

func (f *fileList) String() string     { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error { *f = append(*f, v); return nil }

// job is one ciphertext file and where its value goes. name is the field name: it ends the context.
type job struct{ name, src, dst string }

// jobsOf lists what to open: the files of -in-dir (every regular file that does not start with a dot) and -file, as in `encrypt`. The same destination twice is an error.
func jobsOf(inDir, outDir string, files fileList, stderr io.Writer) ([]job, int) {
	var jobs []job
	seen := map[string]string{}
	add := func(j job) bool {
		if prev, dup := seen[j.dst]; dup {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s and %s would be written to the same place, %s\n", prev, j.src, j.dst)
			return false
		}
		seen[j.dst] = j.src
		jobs = append(jobs, j)
		return true
	}
	if inDir != "" {
		entries, err := os.ReadDir(inDir)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", err)
			return nil, 1
		}
		for _, e := range entries {
			name := e.Name()
			// a Secret volume holds ..data and ..2026_… (the machinery of atomic updates) next to the symbolic links that are the fields
			if strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(inDir, name)
			if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() { // follows the link
				continue
			}
			if !add(job{name: name, src: path, dst: filepath.Join(outDir, name)}) {
				return nil, 1
			}
		}
	}
	for _, f := range files {
		src, dst := f, ""
		if i := strings.Index(f, "="); i >= 0 {
			src, dst = f[:i], f[i+1:]
		}
		if src == "" || (dst == "" && outDir == "") {
			fmt.Fprintf(stderr, "hsmgate decrypt: -file %q needs a source, and a destination or -out-dir\n", f)
			return nil, 2
		}
		if dst == "" {
			dst = filepath.Join(outDir, filepath.Base(src))
		}
		if !add(job{name: filepath.Base(src), src: src, dst: dst}) {
			return nil, 1
		}
	}
	return jobs, 0
}

// decryptJobs opens every ciphertext first and writes only if all of them opened: a pod either gets all its files or none (the init container fails).
func decryptJobs(key string, decrypt func(ct, ctx string) ([]byte, error), jobs []job, prefix string, mode os.FileMode, inDir string, stderr io.Writer) int {
	type item struct {
		job
		plain []byte
	}
	var items []item
	defer func() {
		for _, it := range items {
			wipe(it.plain)
		}
	}()
	failed := false
	for _, j := range jobs {
		raw, err := os.ReadFile(j.src)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %v\n", j.name, err)
			failed = true
			continue
		}
		ct := strings.TrimSpace(string(raw))
		if ct == "" {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: the file is empty\n", j.name)
			failed = true
			continue
		}
		ctx := prefix + j.name
		p, err := decrypt(ct, ctx)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %s\n", j.name, client.Explain(err, key, ctx))
			failed = true
			continue
		}
		items = append(items, item{j, p})
	}
	if failed {
		return 1
	}
	if len(items) == 0 {
		fmt.Fprintf(stderr, "hsmgate decrypt: no ciphertext files in %s\n", inDir)
		return 1
	}
	var written []string
	for _, it := range items {
		if err := os.MkdirAll(filepath.Dir(it.dst), 0o750); err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %v\n", it.name, err)
			for _, w := range written {
				os.Remove(w)
			}
			return 1
		}
		if err := writeAtomic(it.dst, it.plain, mode); err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %v\n", it.name, err)
			for _, w := range written {
				os.Remove(w)
			}
			return 1
		}
		written = append(written, it.dst)
	}
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.name
	}
	sort.Strings(names)
	fmt.Fprintf(stderr, "decrypted %d value(s): %s\n", len(items), strings.Join(names, ", "))
	return 0
}

// writeAtomic writes next to the target and renames, so that a reader never sees half a value.
func writeAtomic(dst string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), dst)
}
