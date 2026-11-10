package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

const devUsage = `usage: hsmgate dev [-listen 127.0.0.1:8443] [-dir DIR]

A throw-away service to try hsmgate in a minute, with no hardware and no files to prepare: a software token with a fresh key, a CA of its own, the certificate of the
service and of one client (demo), and the keys "demo" (no context) and "demo-ctx" (the context must begin with "demo/"). It prints what to type to use it.
NOT for real keys: the key is a file, and without -dir everything is deleted when the service stops (what it sealed can never be opened again).
-dir DIR keeps the files there (the directory must be new or empty) and, run again on the same directory, starts the same service with the same key and address.`

// devConfig is the configuration of the dev service. Every path is in dir; listen is where it listens.
func devConfig(dir, listen string) string {
	return fmt.Sprintf(`listen: %s
tls:
  cert: %[2]s/server.pem
  key: %[2]s/server.key
  client_ca: %[2]s/ca/ca.pem
audit: {file: %[2]s/audit.log}
tokens:
  - name: soft
    type: soft
    keys: {m1: %[2]s/soft-key.hex}
keys:
  demo:
    versions: [{token: soft, label: m1}]
    aad: {mode: fixed}
  demo-ctx:
    versions: [{token: soft, label: m1}]
    aad: {mode: context, allow: ["demo/"]}
clients:
  - name: demo
    identity: {cn: demo}
    keys:
      demo: {ops: [encrypt, decrypt, rewrap]}
      demo-ctx: {ops: [encrypt, decrypt, rewrap]}
`, listen, dir)
}

// devSetup makes what the dev service needs in dir, unless it is there already (a second run with the same -dir): the key, the configuration, the authority and the
// certificates. It returns the path of the configuration.
func devSetup(dir, listen string) (string, error) {
	cfgPath := filepath.Join(dir, "hsmgate.yaml")
	if _, err := os.Stat(cfgPath); err == nil {
		return cfgPath, nil // the same directory again: the same service
	}
	if entries, err := os.ReadDir(dir); err != nil {
		return "", err
	} else if len(entries) > 0 {
		return "", fmt.Errorf("%s is not empty and holds no hsmgate.yaml of a dev service: use a new or empty directory", dir)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(dir, "soft-key.hex"), []byte(hex.EncodeToString(key)), 0o400); err != nil {
		return "", err
	}
	if err := os.WriteFile(cfgPath, []byte(devConfig(dir, listen)), 0o600); err != nil {
		return "", err
	}
	var out strings.Builder
	if code := runCA([]string{"setup", "-config", cfgPath, "-client", "demo"}, &out, &out); code != 0 {
		return "", fmt.Errorf("making the certificates failed: %s", strings.TrimSpace(out.String()))
	}
	return cfgPath, nil
}

// devHelp is what the user is told to type.
func devHelp(w io.Writer, addr net.Addr, dir string, keep bool) {
	url := "https://" + addr.String()
	fmt.Fprintf(w, `
hsmgate dev: a throw-away service with a software token. NOT for real keys.
  address   %s
  files     %s %s

In another terminal:

  export HSMGATE_ADDR=%s HSMGATE_CA=%s/clients/ca.pem \
         HSMGATE_CERT=%s/clients/demo.pem HSMGATE_KEYFILE=%s/clients/demo.key HSMGATE_TRANSIT_KEY=demo
  echo 'my secret' | hsmgate encrypt > sealed.txt      # a ciphertext: vault:v1:...
  hsmgate decrypt < sealed.txt                         # my secret

  # the key "demo-ctx" binds the ciphertext to a context that must begin with demo/
  echo 'x' | hsmgate encrypt -transit-key demo-ctx -context demo/a > c.txt
  hsmgate decrypt -transit-key demo-ctx -context demo/b < c.txt    # refused: another context

  # no certificate, no service (the handshake fails):
  curl --cacert %s/clients/ca.pem %s/v1/transit/keys/demo

What was done is in %s/audit.log. Stop with Ctrl-C.
`, url, dir, map[bool]string{true: "(kept)", false: "(deleted when you stop)"}[keep], url, dir, dir, dir, dir, url, dir)
}

func runDev(args []string) error {
	fs := flag.NewFlagSet("dev", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { fmt.Fprintln(os.Stderr, devUsage) }
	listen := fs.String("listen", "127.0.0.1:8443", "address to listen on (loopback unless you say otherwise)")
	dir := fs.String("dir", "", "keep the files in this new or empty directory (default: a temporary one, deleted at the stop)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keep := *dir != ""
	if !keep {
		d, err := os.MkdirTemp("", "hsmgate-dev-")
		if err != nil {
			return err
		}
		*dir = d
		defer os.RemoveAll(d)
	} else if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cfgPath, err := devSetup(abs, *listen)
	if err != nil {
		return err
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	s, err := server.New(cfg, nil)
	if err != nil {
		return err
	}
	return serve(s, cfg, cfgPath, func(a net.Addr) { devHelp(os.Stdout, a, abs, keep) })
}
