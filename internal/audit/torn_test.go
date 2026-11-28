package audit

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A file that ends in the middle of a line (a power loss, a full disk): the next line starts on a line of its own, also after a reopen.
func TestFileEndsAnUnfinishedLine(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(p, []byte("one\ntor"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFile(p, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("two\n"))
	f.Write([]byte("three\n"))
	if got := read(t, p); got != "one\ntor\ntwo\nthree\n" {
		t.Errorf("after a start: %q", got)
	}
	if err := os.WriteFile(p, []byte("cut"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("four\n"))
	if got := read(t, p); got != "cut\nfour\n" {
		t.Errorf("after a reopen: %q", got)
	}
}

// A write that is cut short while the service runs fails the call, and the next line is not glued to the piece it left.
func TestFileAfterAShortWrite(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := OpenFile(p, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("one\n"))
	full := errors.New("no space left on device")
	f.write = func(o *os.File, b []byte) (int, error) {
		n, _ := o.Write(b[:2])
		return n, full
	}
	if _, err := f.Write([]byte("lost\n")); !errors.Is(err, full) {
		t.Fatalf("the short write: %v", err)
	}
	f.write = func(*os.File, []byte) (int, error) { return 0, full } // still full: nothing is written, nothing is forgotten
	if _, err := f.Write([]byte("lost\n")); !errors.Is(err, full) {
		t.Fatalf("while full: %v", err)
	}
	f.write = nil
	if _, err := f.Write([]byte("two\n")); err != nil {
		t.Fatal(err)
	}
	if got := read(t, p); got != "one\nlo\ntwo\n" {
		t.Errorf("%q", got)
	}
}

// The files the service creates can be read by its group whatever the umask is (the systemd unit has 0077); a file that exists keeps the mode its owner gave it.
func TestFileModeUnderAStrictUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	f, err := OpenFile(p, 8, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	mode := func(path string) os.FileMode {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return st.Mode().Perm()
	}
	if m := mode(p); m != 0o640 {
		t.Errorf("a new file: %o", m)
	}
	f.Write([]byte("aaaaaa\n"))
	f.Write([]byte("bbbbbb\n")) // rotates
	if mode(p) != 0o640 || mode(p+".1") != 0o640 {
		t.Errorf("after a rotation: %o and %o", mode(p), mode(p+".1"))
	}
	own := filepath.Join(dir, "own.log")
	if err := os.WriteFile(own, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := OpenFile(own, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if m := mode(own); m != 0o600 {
		t.Errorf("a file that was there: %o", m)
	}
}
