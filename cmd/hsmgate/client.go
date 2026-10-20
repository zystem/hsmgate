package main

// The client side of hsmgate: `hsmgate encrypt` for the person who makes a ciphertext, `hsmgate decrypt` for the init container of a pod that turns ciphertexts
// into files. Neither needs a configuration file of the service; they speak the Transit API (docs/specs/transit.md) with a client certificate.

import (
	"bufio"
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
	k8s := fs.String("k8s", "", "NAMESPACE/SECRET/FIELD: sets the context to k8s/NAMESPACE/SECRET/FIELD and prints a Kubernetes Secret manifest")
	in := fs.String("in", "-", "file with the value, or - for standard input (a terminal is asked without echo)")
	raw := fs.Bool("raw", false, "keep a trailing newline of the input (by default one is removed)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var ns, name, field string
	if *k8s != "" {
		p := strings.Split(*k8s, "/")
		if len(p) != 3 || p[0] == "" || p[1] == "" || p[2] == "" {
			fmt.Fprintln(stderr, "hsmgate encrypt: -k8s wants NAMESPACE/SECRET/FIELD")
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
	outDir := fs.String("out-dir", "", "directory for the values, one file each (directory mode)")
	prefix := fs.String("context-prefix", "", "directory mode: the context of a file is this prefix followed by the file name, e.g. k8s/$(POD_NAMESPACE)/app-secrets/")
	mode := fs.String("mode", "0440", "directory mode: permission bits of the files (octal); use 0440 with the group of the pod's fsGroup")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if (*in == "") == (*inDir == "") {
		fmt.Fprintln(stderr, "hsmgate decrypt: give either -in (one ciphertext) or -in-dir with -out-dir (a directory)")
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
	if *outDir == "" || *prefix == "" {
		fmt.Fprintln(stderr, "hsmgate decrypt: directory mode needs -out-dir and -context-prefix")
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
	return decryptDir(cl, c.key, decrypt, *inDir, *outDir, *prefix, os.FileMode(m), stderr)
}

// decryptDir opens every ciphertext first and writes only if all of them opened: a pod either gets all its files or none (the init container fails).
func decryptDir(_ *client.Client, key string, decrypt func(ct, ctx string) ([]byte, error), inDir, outDir, prefix string, mode os.FileMode, stderr io.Writer) int {
	entries, err := os.ReadDir(inDir)
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate decrypt:", err)
		return 1
	}
	type item struct {
		name  string
		plain []byte
	}
	var items []item
	defer func() {
		for _, it := range items {
			wipe(it.plain)
		}
	}()
	failed := false
	for _, e := range entries {
		name := e.Name()
		// a Secret volume holds ..data and ..2026_… (the machinery of atomic updates) next to the symbolic links that are the fields
		if strings.HasPrefix(name, ".") {
			continue
		}
		path := filepath.Join(inDir, name)
		st, err := os.Stat(path) // follows the link
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %v\n", name, err)
			failed = true
			continue
		}
		ct := strings.TrimSpace(string(raw))
		if ct == "" {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: the file is empty\n", name)
			failed = true
			continue
		}
		ctx := prefix + name
		p, err := decrypt(ct, ctx)
		if err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %s\n", name, client.Explain(err, key, ctx))
			failed = true
			continue
		}
		items = append(items, item{name, p})
	}
	if failed {
		return 1
	}
	if len(items) == 0 {
		fmt.Fprintf(stderr, "hsmgate decrypt: no ciphertext files in %s\n", inDir)
		return 1
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		fmt.Fprintln(stderr, "hsmgate decrypt:", err)
		return 1
	}
	var written []string
	for _, it := range items {
		dst := filepath.Join(outDir, it.name)
		if err := writeAtomic(dst, it.plain, mode); err != nil {
			fmt.Fprintf(stderr, "hsmgate decrypt: %s: %v\n", it.name, err)
			for _, w := range written {
				os.Remove(w)
			}
			return 1
		}
		written = append(written, dst)
	}
	names := make([]string, len(items))
	for i, it := range items {
		names[i] = it.name
	}
	sort.Strings(names)
	w := bufio.NewWriter(stderr)
	fmt.Fprintf(w, "decrypted %d value(s) into %s: %s\n", len(items), outDir, strings.Join(names, ", "))
	w.Flush()
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
