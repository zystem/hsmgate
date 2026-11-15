// Package sys is what the setup tool needs from the machine: the hsmgate binary, the users, systemd and the admin socket of the running service.
package sys

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Binary finds the hsmgate program: $HSMGATE_BIN, the file next to this tool, then the PATH.
func Binary() (string, error) {
	if b := os.Getenv("HSMGATE_BIN"); b != "" {
		return b, nil
	}
	if self, err := os.Executable(); err == nil {
		if p := filepath.Join(filepath.Dir(self), "hsmgate"); isExec(p) {
			return p, nil
		}
	}
	if p, err := exec.LookPath("hsmgate"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("the hsmgate program was not found: put it next to this tool, on the PATH, or name it in HSMGATE_BIN")
}

func isExec(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0
}

// Run runs a program and returns what it printed (standard output and error together). The error carries that text when the program failed.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- the program and its arguments are made by this tool, not typed by a remote party
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w\n%s", filepath.Base(name), strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// RunAs runs a program as another user when this is root and the user is named (the secrets are checked as the user who will own them: a key file owned by the service is "owned by another
// user" for root). Otherwise it is Run.
func RunAs(ctx context.Context, name string, prog string, args ...string) (string, error) {
	if !IsRoot() || name == "" {
		return Run(ctx, prog, args...)
	}
	u, err := user.Lookup(name)
	if err != nil {
		return Run(ctx, prog, args...)
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return Run(ctx, prog, args...)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return Run(ctx, prog, args...)
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, prog, args...) // #nosec G204 -- made by this tool
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}} // #nosec G115 -- the ids were parsed with a 32-bit limit above
	if err := cmd.Run(); err != nil {
		return out.String(), fmt.Errorf("%s %s (as %s): %w\n%s", filepath.Base(prog), strings.Join(args, " "), name, err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}

// ChownGroup gives a file to the group of a user, keeping its owner (the configuration is root's, and read by the service through its group). It does nothing when this is not root.
func ChownGroup(path, name string) {
	if !IsRoot() || name == "" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	gid, _ := strconv.Atoi(u.Gid)
	_ = os.Chown(path, -1, gid)
}

// IsRoot says whether this runs as root.
func IsRoot() bool { return os.Geteuid() == 0 }

// UserExists says whether the account is there.
func UserExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

// Chown gives a file to a user (and its group). It does nothing, and says nothing, when this is not root or the account is not there: the file then stays with whoever made it.
func Chown(path, name string) {
	if !IsRoot() || name == "" {
		return
	}
	u, err := user.Lookup(name)
	if err != nil {
		return
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	_ = os.Chown(path, uid, gid)
}

// HasSystemd says whether this machine runs systemd (the same test sd_booted() makes).
func HasSystemd() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

// Systemctl runs systemctl.
func Systemctl(ctx context.Context, args ...string) (string, error) {
	return Run(ctx, "systemctl", args...)
}

// NewSoftKey writes a new private key for a soft token: 64 hexadecimal digits, a P-256 scalar, mode 0400, never over a file that is there. It returns the hex SHA-less identifier of the key,
// the first 16 digits of the public point, which is enough to tell two keys apart on a screen (`hsmgate check` prints the full fingerprint).
func NewSoftKey(path, owner string) (string, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- a path the operator chose
	if err != nil {
		return "", fmt.Errorf("the key file: %w", err)
	}
	if _, err := fmt.Fprintln(f, hex.EncodeToString(k.Bytes())); err != nil {
		f.Close()
		os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	Chown(path, owner)
	return hex.EncodeToString(k.PublicKey().Bytes())[:16], nil
}

// Shred overwrites a key file with zeros and removes it. On a journalling or flash file system an overwrite is not a guarantee: it is the best a program can do and the text says so.
func Shred(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil { // #nosec G304
		_, _ = f.Write(make([]byte, st.Size()))
		_ = f.Sync()
		f.Close()
	}
	return os.Remove(path)
}

// ---- the admin socket --------------------------------------------------------------------------------------------------------------------------------

func adminClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		}},
	}
}

// Status asks the running service for the state of its tokens.
func Status(sock string) (map[string]string, error) {
	resp, err := adminClient(sock).Get("http://admin/status")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var m map[string]string
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

// Unlock gives a token its PIN. The PIN goes only into the request, which is on a socket that only root can open, and is not kept.
func Unlock(sock, token string, pin []byte) error {
	body, _ := json.Marshal(map[string]string{"token": token, "pin": string(pin)})
	resp, err := adminClient(sock).Post("http://admin/unlock", "application/json", bytes.NewReader(body))
	for i := range body {
		body[i] = 0
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", strings.TrimSpace(string(b)))
	}
	return nil
}

// ReloadService asks a running service to read its configuration again (SIGHUP). With systemd it is `systemctl reload`; otherwise the pid is found from the socket's owner is not
// possible, so the caller is told to send the signal itself.
func ReloadService(ctx context.Context, unit string) error {
	if !HasSystemd() {
		return fmt.Errorf("no systemd: send SIGHUP to the process (kill -HUP $(pidof hsmgate)) or restart it")
	}
	out, err := Systemctl(ctx, "reload", unit)
	if err != nil {
		return fmt.Errorf("%v\n%s", err, out)
	}
	return nil
}

// ErrNotRunning is what Status says when the socket is not there.
func ErrNotRunning(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "no such file") || strings.Contains(err.Error(), "connection refused") || os.IsNotExist(err) || isErrno(err, syscall.ECONNREFUSED))
}

func isErrno(err error, e syscall.Errno) bool {
	for err != nil {
		if en, ok := err.(syscall.Errno); ok {
			return en == e
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
