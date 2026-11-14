package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

const setupHelp = `usage: hsmgate setup [flags of hsmgate-setup]

Opens hsmgate-setup, the terminal tool: menus to look at and change the tokens, keys, clients, faces and audit settings of the configuration (it edits hsmgate.yaml and checks every change
with the same rules as the service), and a quick setup that goes from nothing to a running service with a first key, a first client and its certificate.

  hsmgate setup                   the menus
  hsmgate setup -first-run        the quick setup when there is no configuration (what a package runs after the installation)
  hsmgate setup -auto             the quick setup with no screen: the defaults and the flags (for unattended installations)

hsmgate-setup is a separate program, installed next to hsmgate by the packages (deb, rpm, AppImage) and the release archive; "hsmgate-setup -h" lists its flags. It is a program of its own so
that the service does not carry a terminal library.`

// runSetup hands the terminal to hsmgate-setup. The process is replaced (exec), so that the terminal, the signals and the exit status are those of the tool.
func runSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "-help" || args[0] == "--help") {
		fmt.Fprintln(stdout, setupHelp)
		return 0
	}
	path := findSetup()
	if path == "" {
		fmt.Fprintln(stderr, "hsmgate: hsmgate-setup is not installed (it is next to hsmgate in the packages and the release archive). Install it, or set HSMGATE_SETUP to its path.")
		return 1
	}
	env := os.Environ()
	if self, err := os.Executable(); err == nil {
		env = append(env, "HSMGATE_BIN="+self) // the tool runs this very program for the certificates
	}
	if err := syscall.Exec(path, append([]string{path}, args...), env); err != nil { // #nosec G204 -- the tool next to this program
		fmt.Fprintln(stderr, "hsmgate:", err)
		return 1
	}
	return 0
}

func findSetup() string {
	if p := os.Getenv("HSMGATE_SETUP"); p != "" {
		return p
	}
	if self, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(self), "hsmgate-setup"); isExecutable(p) {
			return p
		}
	}
	if p, err := exec.LookPath("hsmgate-setup"); err == nil {
		return p
	}
	return ""
}

func isExecutable(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}
