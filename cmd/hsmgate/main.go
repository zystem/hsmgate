// hsmgate: a policy-checked network door in front of a key token. Subcommands: serve, check.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/server"
)

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "serve" && os.Args[1] != "check") {
		fmt.Fprintln(os.Stderr, "usage: hsmgate serve|check -config hsmgate.yaml")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	path := fs.String("config", "hsmgate.yaml", "configuration file")
	fs.Parse(os.Args[2:])
	cfg, err := config.Load(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsmgate:", err)
		os.Exit(1)
	}
	s, err := server.New(cfg, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsmgate:", err)
		os.Exit(1)
	}
	if os.Args[1] == "check" {
		fmt.Println("configuration ok")
		return
	}
	l, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hsmgate:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "hsmgate: listening on", l.Addr())
	fmt.Fprintln(os.Stderr, "hsmgate:", s.Serve(l))
	os.Exit(1)
}
