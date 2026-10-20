package main

// The client side of hsmgate: `hsmgate encrypt` for the person who makes a ciphertext, `hsmgate decrypt` for the init container of a pod that turns ciphertexts
// into files. Neither needs a configuration file of the service; they speak the Transit API (docs/specs/transit.md) with a client certificate.
//
// The two commands have the same flags. What goes in and what comes out:
//
//	-in FILE        -out FILE          one value (default: standard input, standard output)       context: -context
//	-in-dir DIR     -out-dir DIR       every file of DIR to a file of the same name in DIR         context: -context-prefix + the name of the ciphertext file
//	-in-files a,b   -out-files x,y     the files in pairs, by position: a to x, b to y             lists of different length are refused
//
// "The ciphertext file" is the one that holds the ciphertext: the input of `decrypt`, the output of `encrypt`. Its base name is the field name of a Secret, and the
// context is the prefix followed by that name, so that sealing and opening agree. With `encrypt -k8s` there is no ciphertext file: a Secret manifest is printed and
// the field name is the base name of the input file.

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

// fileList is a flag whose value is a comma-separated list; the flag may also be repeated. Empty elements are ignored, spaces around an element are removed.
// (A path with a comma in it cannot be given.)
type fileList []string

func (f *fileList) String() string { return strings.Join(*f, ",") }
func (f *fileList) Set(v string) error {
	for _, e := range strings.Split(v, ",") {
		if e = strings.TrimSpace(e); e != "" {
			*f = append(*f, e)
		}
	}
	return nil
}

// ioFlags are the flags of what goes in and what comes out; both commands have them.
type ioFlags struct {
	in, out, inDir, outDir, context, prefix, mode string
	inFiles, outFiles                             fileList
	sealing                                       bool
}

func (f *ioFlags) add(fs *flag.FlagSet, sealing bool) {
	f.sealing = sealing
	what, other := "a ciphertext", "the value"
	if sealing {
		what, other = "a value", "its ciphertext"
	}
	fs.StringVar(&f.in, "in", "-", "one file with "+what+", or - for standard input")
	fs.StringVar(&f.out, "out", "-", "where "+other+" goes for -in: a file, or - for standard output")
	fs.StringVar(&f.inDir, "in-dir", "", "a directory: every regular file in it (not those starting with a dot) is "+what)
	fs.StringVar(&f.outDir, "out-dir", "", "a directory for "+other+" of -in-dir: a file of the same name each; also the default place for -in-files")
	fs.Var(&f.inFiles, "in-files", "files with "+what+", a comma-separated list (the flag may be repeated)")
	fs.Var(&f.outFiles, "out-files", "where "+other+" of -in-files goes: a comma-separated list as long as -in-files, by position; a different length is refused")
	fs.StringVar(&f.context, "context", "", "context of the single value (-in/-out)")
	fs.StringVar(&f.prefix, "context-prefix", "", "for -in-dir and -in-files: the context of a value is this prefix followed by the name of the ciphertext file, e.g. k8s/$(POD_NAMESPACE)/app-secrets/")
	def := "0440"
	if sealing {
		def = "0644"
	}
	fs.StringVar(&f.mode, "mode", def, "permission bits (octal) of the files that are written")
}

// pair is one value on its way: from in to out. name is the name of the ciphertext file, which ends the context. out is "" when a manifest is printed instead.
type pair struct{ in, out, name string }

// plan turns the flags into pairs. A usage error (exit code 2) is returned as usage=true.
func (f *ioFlags) plan(manifest bool) (pairs []pair, usage bool, err error) {
	if len(f.outFiles) > 0 && len(f.inFiles) == 0 {
		return nil, true, errors.New("-out-files needs -in-files")
	}
	if manifest && (f.outDir != "" || len(f.outFiles) > 0) {
		return nil, true, errors.New("-k8s prints a Secret manifest: it cannot be combined with -out-dir or -out-files")
	}
	if len(f.outFiles) > 0 && len(f.outFiles) != len(f.inFiles) {
		return nil, true, fmt.Errorf("-in-files has %d element(s) and -out-files has %d: the lists must be of the same length", len(f.inFiles), len(f.outFiles))
	}
	needOut := !manifest
	if f.inDir != "" {
		if needOut && f.outDir == "" {
			return nil, true, errors.New("-in-dir needs -out-dir")
		}
		entries, err := os.ReadDir(f.inDir)
		if err != nil {
			return nil, false, err
		}
		for _, e := range entries {
			n := e.Name()
			// a Secret volume holds ..data and ..2026_… (the machinery of atomic updates) next to the symbolic links that are the fields
			if strings.HasPrefix(n, ".") {
				continue
			}
			if st, err := os.Stat(filepath.Join(f.inDir, n)); err != nil || !st.Mode().IsRegular() { // follows the link
				continue
			}
			p := pair{in: filepath.Join(f.inDir, n), name: n}
			if needOut {
				p.out = filepath.Join(f.outDir, n)
			}
			pairs = append(pairs, p)
		}
	}
	for i, in := range f.inFiles {
		p := pair{in: in}
		switch {
		case len(f.outFiles) > 0:
			p.out = f.outFiles[i]
		case needOut && f.outDir != "":
			p.out = filepath.Join(f.outDir, filepath.Base(in))
		case needOut:
			return nil, true, errors.New("-in-files needs -out-files or -out-dir")
		}
		pairs = append(pairs, p)
	}
	// the name of the ciphertext file: the output when sealing to files, the input otherwise
	seenName, seenOut := map[string]string{}, map[string]string{}
	for i := range pairs {
		p := &pairs[i]
		if p.name == "" {
			if f.sealing && p.out != "" {
				p.name = filepath.Base(p.out)
			} else if f.sealing {
				p.name = filepath.Base(p.in)
			} else {
				p.name = filepath.Base(p.in)
			}
		}
		if prev, dup := seenName[p.name]; dup {
			return nil, true, fmt.Errorf("%s and %s have the same name %q, so the same context", prev, p.in, p.name)
		}
		seenName[p.name] = p.in
		if p.out != "" {
			if prev, dup := seenOut[p.out]; dup {
				return nil, true, fmt.Errorf("%s and %s would be written to the same place, %s", prev, p.in, p.out)
			}
			seenOut[p.out] = p.in
		}
	}
	return pairs, false, nil
}

func (f *ioFlags) multi() bool { return f.inDir != "" || len(f.inFiles) > 0 }

func (f *ioFlags) fileMode() (os.FileMode, error) {
	m, err := strconv.ParseUint(f.mode, 8, 32)
	if err != nil || m > 0o777 {
		return 0, errors.New("-mode is octal permission bits like 0440")
	}
	return os.FileMode(m), nil
}

// checkSingle refuses the flags of one value next to those of many.
func (f *ioFlags) checkSingle(fs *flag.FlagSet) error {
	if !f.multi() {
		if f.prefix != "" || f.outDir != "" {
			return errors.New("-context-prefix and -out-dir are for -in-dir and -in-files; for one value use -in, -out and -context")
		}
		return nil
	}
	var bad []string
	fs.Visit(func(fl *flag.Flag) {
		if fl.Name == "in" || fl.Name == "out" || fl.Name == "context" {
			bad = append(bad, "-"+fl.Name)
		}
	})
	if len(bad) > 0 {
		return fmt.Errorf("%s is for one value and cannot be combined with -in-dir or -in-files", strings.Join(bad, ", "))
	}
	return nil
}

// ---- encrypt ----

// runEncrypt: hsmgate encrypt -transit-key K  [-in F -out F -context C | -in-dir D -out-dir O | -in-files a,b -out-files x,y]  -context-prefix P, or -k8s for a Secret manifest.
func runEncrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.add(fs)
	var io_ ioFlags
	io_.add(fs, true)
	k8s := fs.String("k8s", "", "NAMESPACE/SECRET/FIELD for one value, NAMESPACE/SECRET for -in-dir and -in-files: sets the context (k8s/NAMESPACE/SECRET/FIELD) and prints a Kubernetes Secret manifest instead of ciphertext files")
	raw := fs.Bool("raw", false, "keep a trailing newline of the input (by default one is removed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(err error) int { fmt.Fprintln(stderr, "hsmgate encrypt:", err); return 2 }
	if err := io_.checkSingle(fs); err != nil {
		return usage(err)
	}
	mode, err := io_.fileMode()
	if err != nil {
		return usage(err)
	}
	var ns, name, field string
	manifest := *k8s != ""
	if manifest {
		p := strings.Split(*k8s, "/")
		want := 2
		if !io_.multi() {
			want = 3
		}
		if len(p) != want {
			return usage(fmt.Errorf("-k8s wants %s here", map[int]string{2: "NAMESPACE/SECRET (with -in-dir or -in-files)", 3: "NAMESPACE/SECRET/FIELD (for one value)"}[want]))
		}
		for _, x := range p {
			if x == "" {
				return usage(errors.New("-k8s has an empty part"))
			}
		}
		if io_.context != "" || io_.prefix != "" {
			return usage(errors.New("-k8s sets the context itself; do not give -context or -context-prefix as well"))
		}
		ns, name = p[0], p[1]
		if want == 3 {
			field = p[2]
			io_.context = contextOf(ns, name, field)
		} else {
			io_.prefix = contextOf(ns, name, "")
		}
	}
	cl, err := c.client()
	if err != nil {
		return usage(err)
	}
	seal := func(plain []byte, ctx string) (string, int, error) {
		var ct string
		var ver int
		err := client.Retry(context.Background(), c.wait, func() (e error) {
			ct, ver, e = cl.Encrypt(context.Background(), plain, ctx)
			return
		}, nil)
		return ct, ver, err
	}

	if !io_.multi() { // one value
		plain, err := readValue(io_.in, stdin, stderr)
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
		ct, ver, err := seal(plain, io_.context)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate encrypt:", client.Explain(err, c.key, io_.context))
			return 1
		}
		text := ct + "\n"
		if manifest {
			text = fmt.Sprintf("apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\nstringData:\n  %s: %q\n", name, ns, field, ct)
		}
		if err := writeOut(io_.out, text, 0o644, stdout); err != nil {
			fmt.Fprintln(stderr, "hsmgate encrypt:", err)
			return 1
		}
		fmt.Fprintf(stderr, "sealed under version %d of key %q with context %q\n", ver, c.key, io_.context)
		return 0
	}

	// many values: all are sealed first; nothing is written or printed unless all were
	if io_.prefix == "" {
		return usage(errors.New("-in-dir and -in-files need -context-prefix (or -k8s NAMESPACE/SECRET)"))
	}
	prefix := expandPrefix(io_.prefix)
	pairs, isUsage, err := io_.plan(manifest)
	if err != nil {
		if isUsage {
			return usage(err)
		}
		fmt.Fprintln(stderr, "hsmgate encrypt:", err)
		return 1
	}
	type sealed struct {
		pair
		ct string
	}
	var done []sealed
	failed := false
	for _, p := range pairs {
		if manifest && !validField(p.name) {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: %q is not a valid key of a Secret (letters, digits, - _ .)\n", p.in, p.name)
			failed = true
			continue
		}
		plain, err := readValue(p.in, nil, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: %v\n", p.name, err)
			failed = true
			continue
		}
		if !*raw {
			plain = trimOneNewline(plain)
		}
		if len(plain) == 0 {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: the file is empty\n", p.in)
			failed = true
			continue
		}
		ctx := prefix + p.name
		ct, _, err := seal(plain, ctx)
		wipe(plain)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate encrypt: %s: %s\n", p.name, client.Explain(err, c.key, ctx))
			failed = true
			continue
		}
		done = append(done, sealed{p, ct})
	}
	if failed {
		return 1
	}
	if len(done) == 0 {
		fmt.Fprintln(stderr, "hsmgate encrypt: no files to seal")
		return 1
	}
	if manifest {
		sort.Slice(done, func(i, j int) bool { return done[i].name < done[j].name })
		var b strings.Builder
		fmt.Fprintf(&b, "apiVersion: v1\nkind: Secret\nmetadata:\n  name: %s\n  namespace: %s\ntype: Opaque\nstringData:\n", name, ns)
		for _, d := range done {
			fmt.Fprintf(&b, "  %s: %q\n", d.name, d.ct)
		}
		if err := writeOut(io_.out, b.String(), 0o644, stdout); err != nil {
			fmt.Fprintln(stderr, "hsmgate encrypt:", err)
			return 1
		}
		fmt.Fprintf(stderr, "sealed %d file(s) under key %q, contexts %s<field>\n", len(done), c.key, prefix)
		return 0
	}
	var written []string
	for _, d := range done {
		if err := os.MkdirAll(filepath.Dir(d.out), 0o750); err == nil {
			err = writeAtomic(d.out, []byte(d.ct+"\n"), mode)
			if err == nil {
				written = append(written, d.out)
				continue
			}
		}
		for _, w := range written {
			os.Remove(w)
		}
		fmt.Fprintf(stderr, "hsmgate encrypt: %s: cannot be written\n", d.out)
		return 1
	}
	fmt.Fprintf(stderr, "sealed %d file(s) under key %q, contexts %s<name of the ciphertext file>\n", len(done), c.key, prefix)
	return 0
}

// writeOut writes text to a file, or to w when the name is "-".
func writeOut(path, text string, mode os.FileMode, w io.Writer) error {
	if path == "-" || path == "" {
		_, err := io.WriteString(w, text)
		return err
	}
	return writeAtomic(path, []byte(text), mode)
}

func expandPrefix(p string) string {
	if strings.Contains(p, "$") {
		return os.ExpandEnv(p)
	}
	return p
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

// contextOf is the convention that ties a ciphertext to the Secret field it belongs to.
func contextOf(ns, name, field string) string {
	if field == "" {
		return "k8s/" + ns + "/" + name + "/"
	}
	return "k8s/" + ns + "/" + name + "/" + field
}

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
	b, err := os.ReadFile(in) // #nosec G304 -- the file the user of the command named
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

// ---- decrypt ----

// runDecrypt: the same flags as encrypt; the input is ciphertext and the output is the value.
func runDecrypt(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.add(fs)
	var io_ ioFlags
	io_.add(fs, false)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	usage := func(err error) int { fmt.Fprintln(stderr, "hsmgate decrypt:", err); return 2 }
	if err := io_.checkSingle(fs); err != nil {
		return usage(err)
	}
	mode, err := io_.fileMode()
	if err != nil {
		return usage(err)
	}
	cl, err := c.client()
	if err != nil {
		return usage(err)
	}
	open := func(ct, ctx string) ([]byte, error) {
		var p []byte
		err := client.Retry(context.Background(), c.wait, func() (e error) {
			p, e = cl.Decrypt(context.Background(), ct, ctx)
			return
		}, nil)
		return p, err
	}

	if !io_.multi() { // one value
		raw, err := readValue(io_.in, stdin, stderr)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", err)
			return 1
		}
		p, err := open(strings.TrimSpace(string(raw)), io_.context)
		if err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", client.Explain(err, c.key, io_.context))
			return 1
		}
		defer wipe(p)
		if io_.out == "-" {
			stdout.Write(p)
			return 0
		}
		if err := writeAtomic(io_.out, p, 0o600); err != nil {
			fmt.Fprintln(stderr, "hsmgate decrypt:", err)
			return 1
		}
		return 0
	}

	// many values: all are opened first; nothing is written unless all were, so a pod gets all its files or none (the init container fails)
	if io_.prefix == "" {
		return usage(errors.New("-in-dir and -in-files need -context-prefix"))
	}
	prefix := expandPrefix(io_.prefix)
	pairs, isUsage, err := io_.plan(false)
	if err != nil {
		if isUsage {
			return usage(err)
		}
		fmt.Fprintln(stderr, "hsmgate decrypt:", err)
		return 1
	}
	type opened struct {
		pair
		plain []byte
	}
	var items []opened
	defer func() {
		for _, it := range items {
			wipe(it.plain)
		}
	}()
	failed := false
	for _, p := range pairs {
		raw, err := os.ReadFile(p.in)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %v\n", p.name, err)
			failed = true
			continue
		}
		ct := strings.TrimSpace(string(raw))
		if ct == "" {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: the file is empty\n", p.name)
			failed = true
			continue
		}
		ctx := prefix + p.name
		v, err := open(ct, ctx)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %s\n", p.name, client.Explain(err, c.key, ctx))
			failed = true
			continue
		}
		items = append(items, opened{p, v})
	}
	if failed {
		return 1
	}
	if len(items) == 0 {
		fmt.Fprintln(stderr, "hsmgate decrypt: no ciphertext files")
		return 1
	}
	var written []string
	for _, it := range items {
		if err := os.MkdirAll(filepath.Dir(it.out), 0o750); err == nil {
			err = writeAtomic(it.out, it.plain, mode)
			if err == nil {
				written = append(written, it.out)
				continue
			}
		}
		for _, w := range written {
			os.Remove(w)
		}
		fmt.Fprintf(stderr, "hsmgate decrypt: %s: cannot be written\n", it.out)
		return 1
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
