package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// The file rotates by size: audit.log -> .1 -> .2, the oldest dropped beyond `keep`, and no line is lost or split.
func TestFileRotatesBySize(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := OpenFile(p, 20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, l := range []string{"aaaaaaaaaaaaaaa\n", "bbbbbbbbbbbbbbb\n", "ccccccccccccccc\n", "ddddddddddddddd\n"} {
		if _, err := f.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	if got := read(t, p); got != "ddddddddddddddd\n" {
		t.Errorf("current: %q", got)
	}
	if got := read(t, p+".1"); got != "ccccccccccccccc\n" {
		t.Errorf(".1: %q", got)
	}
	if got := read(t, p+".2"); got != "bbbbbbbbbbbbbbb\n" {
		t.Errorf(".2: %q", got)
	}
	if _, err := os.Stat(p + ".3"); err == nil {
		t.Error("a third old file was kept")
	}
}

// No limit: nothing is rotated. A file that exists is appended to.
func TestFileNoLimitAppends(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(p, []byte("old\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	f, err := OpenFile(p, 0, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte(strings.Repeat("x", 1000) + "\n"))
	if !strings.HasPrefix(read(t, p), "old\nxxx") {
		t.Error("not appended")
	}
	if _, err := os.Stat(p + ".1"); err == nil {
		t.Error("rotated without a limit")
	}
}

// After an outside rename (logrotate) a Reopen makes the service write to a new file at the path, not to the renamed one.
func TestFileReopenAfterRename(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := OpenFile(p, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.Write([]byte("one\n"))
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("two\n"))
	if read(t, p) != "two\n" || read(t, p+".1") != "one\n" {
		t.Errorf("new %q old %q", read(t, p), read(t, p+".1"))
	}
}

// A rotation that cannot rename leaves the file in use, writes still succeed, and the failure is reported (once in a minute, not for every line).
func TestFileRotationFailureIsReportedAndWritesGoOn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can rename in a read-only directory")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.log")
	f, err := OpenFile(p, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var warned []error
	f.Warn = func(err error) { warned = append(warned, err) }
	f.Write([]byte("aaaaaaaaaaaaaaa\n"))
	if err := os.Chmod(dir, 0o500); err != nil { // no rename possible
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	for i := 0; i < 3; i++ {
		if _, err := f.Write([]byte("bbbbbbbbbbbbbbb\n")); err != nil {
			t.Fatalf("a failed rotation stopped a write: %v", err)
		}
	}
	if len(warned) != 1 {
		t.Errorf("warned %d times, want once", len(warned))
	}
	if got := read(t, p); strings.Count(got, "\n") != 4 {
		t.Errorf("lines in the file: %q", got)
	}
}
