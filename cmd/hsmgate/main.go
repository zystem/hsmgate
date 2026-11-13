// hsmgate: a policy-checked network door in front of a key token. Subcommands: serve, check, unlock, dev (a throw-away service to try it), ca, encrypt, decrypt, ping, version.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

// version is set at build time (-X main.version=...)
var version = "dev"

const usage = `hsmgate: a policy-checked door in front of a key token.

usage: hsmgate <command> [flags]       (hsmgate <command> -h shows the flags of a command)

  dev       start a throw-away service to try hsmgate: no hardware, nothing to prepare
  serve     run the service
  check     load a configuration, open the tokens and list every key version; starts nothing, needs no PIN
  unlock    give a card its PIN (to the running service, over its admin socket)
  encrypt   seal a value (or the files of a directory) with a key of the service
  decrypt   open what encrypt sealed
  ca        make the certificates: the authority, the service, the clients (init, setup, server, client, list)
  ping      connect to the listener (a container health check; needs no certificate)
  version   print the version

Documentation: https://github.com/zystem/hsmgate#readme`

// commandHelp is the line under "usage:" of serve, check and unlock.
var commandHelp = map[string]string{
	"serve":  "Runs the service until SIGINT or SIGTERM (then the tokens are logged out). SIGHUP reloads the configuration, the policy and the certificates.",
	"check":  "Loads the configuration, opens the tokens and prints every key version with its holders, their state and the fingerprint of the public key. Starts nothing and needs no PIN. Exit status 0 means the configuration is good.",
	"unlock": "Hands the PIN of a card to the running service over its admin socket (admin_socket of the configuration). The PIN is read from the terminal without echo, or from standard input with -pin-stdin; it is never an argument and stays in memory only.",
}

func die(err error) {
	fmt.Fprintln(os.Stderr, "hsmgate:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) >= 2 && (os.Args[1] == "encrypt" || os.Args[1] == "decrypt") {
		run := runEncrypt
		if os.Args[1] == "decrypt" {
			run = runDecrypt
		}
		os.Exit(run(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "ca" {
		os.Exit(runCA(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "ping" {
		// a TCP connect to the listener: for a container health check (it must not touch the token or need a certificate)
		fs := flag.NewFlagSet("ping", flag.ExitOnError)
		addr := fs.String("addr", "127.0.0.1:8443", "address to connect to")
		fs.Parse(os.Args[2:])
		c, err := net.DialTimeout("tcp", *addr, 3*time.Second)
		if err != nil {
			die(err)
		}
		c.Close()
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "dev" {
		if err := runDev(os.Args[2:]); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return
			}
			die(err)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("hsmgate", version)
		return
	}
	if len(os.Args) >= 2 && (os.Args[1] == "help" || os.Args[1] == "-h" || os.Args[1] == "-help" || os.Args[1] == "--help") {
		fmt.Println(usage)
		return
	}
	if len(os.Args) < 2 || (os.Args[1] != "serve" && os.Args[1] != "check" && os.Args[1] != "unlock") {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: hsmgate %s -config hsmgate.yaml%s\n\n%s\n\n", cmd, map[string]string{"unlock": " -token NAME [-pin-stdin]"}[cmd], commandHelp[cmd])
		fs.PrintDefaults()
	}
	path := fs.String("config", "hsmgate.yaml", "configuration file")
	var tokenName string
	var pinStdin bool
	if cmd == "unlock" {
		fs.StringVar(&tokenName, "token", "", "the token to unlock (a name in tokens: of the configuration)")
		fs.BoolVar(&pinStdin, "pin-stdin", false, "read the PIN from standard input instead of the terminal")
	}
	fs.Parse(os.Args[2:])
	cfg, err := config.Load(*path)
	if err != nil {
		die(err)
	}
	if os.Args[1] == "unlock" {
		die(unlock(cfg, tokenName, pinStdin))
	}
	s, err := server.New(cfg, nil)
	if err != nil {
		die(err)
	}
	if os.Args[1] == "check" {
		for _, line := range s.Describe() {
			fmt.Println(line)
		}
		fmt.Println("configuration ok")
		return
	}
	if err := serve(s, cfg, *path, nil); err != nil {
		die(err)
	}
}

// serve runs the service until it is told to stop (SIGINT, SIGTERM): the admin socket, the reload on SIGHUP, the listener. It returns nil after a requested stop, once the
// tokens are logged out. listening, when not nil, is called with the address as soon as the listener is open.
func serve(s *server.Server, cfg *config.Config, path string, listening func(net.Addr)) error {
	if cfg.AdminSocket != "" {
		go func() { die(s.ServeAdmin(cfg.AdminSocket)) }()
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := s.ReopenAudit(); err != nil {
				fmt.Fprintln(os.Stderr, "hsmgate: audit file not reopened, the old one stays in use:", err)
			}
			next, err := config.Load(path)
			if err == nil {
				err = s.Reload(next)
			}
			if err != nil {
				fmt.Fprintln(os.Stderr, "hsmgate: reload refused, nothing changed:", err)
			} else {
				fmt.Fprintln(os.Stderr, "hsmgate: configuration reloaded")
			}
		}
	}()
	stop := make(chan os.Signal, 1)
	stopped := make(chan struct{})
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		s.Close() // stops the listener, then logs the tokens out and makes them forget the PIN
		fmt.Fprintln(os.Stderr, "hsmgate: stopped, tokens logged out")
		close(stopped)
	}()
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "hsmgate: listening on", l.Addr())
	if listening != nil {
		listening(l.Addr())
	}
	err = s.Serve(l)
	if errors.Is(err, http.ErrServerClosed) { // a requested stop is not a failure: wait for the tokens to be closed
		<-stopped
		return nil
	}
	return err
}

// unlock hands a PIN to the running service over its admin socket. The PIN is read from the terminal without echo (or from standard input) and is never an argument.
func unlock(cfg *config.Config, token string, fromStdin bool) error {
	if cfg.AdminSocket == "" || token == "" {
		return fmt.Errorf("unlock needs admin_socket in the configuration and -token NAME")
	}
	pin, err := readPIN(token, fromStdin)
	if err != nil {
		return err
	}
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg.AdminSocket)
	}}}
	body, _ := json.Marshal(map[string]string{"token": token, "pin": pin})
	resp, err := cl.Post("http://admin/unlock", "application/json", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	fmt.Print(string(out))
	return nil
}

// readPIN reads a PIN from the terminal without echo, or from standard input. It is never an argument.
func readPIN(token string, fromStdin bool) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, "PIN for "+token+": ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
