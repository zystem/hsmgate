// hsmgate: a policy-checked network door in front of a key token. Subcommands: serve, check, unlock.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, "hsmgate:", err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "serve" && os.Args[1] != "check" && os.Args[1] != "unlock") {
		fmt.Fprintln(os.Stderr, "usage: hsmgate serve|check|unlock -config hsmgate.yaml [-token NAME] [-pin-stdin]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	path := fs.String("config", "hsmgate.yaml", "configuration file")
	tokenName := fs.String("token", "", "unlock: the token to unlock")
	pinStdin := fs.Bool("pin-stdin", false, "unlock: read the PIN from standard input instead of the terminal")
	fs.Parse(os.Args[2:])
	cfg, err := config.Load(*path)
	if err != nil {
		die(err)
	}
	if os.Args[1] == "unlock" {
		die(unlock(cfg, *tokenName, *pinStdin))
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
	if cfg.AdminSocket != "" {
		go func() { die(s.ServeAdmin(cfg.AdminSocket)) }()
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			next, err := config.Load(*path)
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
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		s.Close()
		fmt.Fprintln(os.Stderr, "hsmgate: stopped, tokens logged out")
		os.Exit(0)
	}()
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		die(err)
	}
	fmt.Fprintln(os.Stderr, "hsmgate: listening on", l.Addr())
	die(s.Serve(l))
}

// unlock hands a PIN to the running service over its admin socket. The PIN is read from the terminal without echo (or from standard input) and is never an argument.
func unlock(cfg *config.Config, token string, fromStdin bool) error {
	if cfg.AdminSocket == "" || token == "" {
		return fmt.Errorf("unlock needs admin_socket in the configuration and -token NAME")
	}
	var pin string
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		pin = strings.TrimRight(line, "\r\n")
	} else {
		fmt.Fprint(os.Stderr, "PIN for "+token+": ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pin = string(b)
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
