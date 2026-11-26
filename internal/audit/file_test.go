package audit

import (
	"errors"
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

// With sync on, every line is on the disk before Write returns; a failed fsync is a failed write, so that the call is not answered (the review of 2026-11-21).
func TestFileSyncsEveryLineWhenAsked(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := OpenFile(p, 20, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	files, dirs := 0, 0
	f.syncFile = func(*os.File) error { files++; return nil }
	f.syncDir = func(string) error { dirs++; return nil }
	f.Write([]byte("aaaaaaaaaaaaaaa\n"))
	if files != 0 {
		t.Fatalf("a line was synced with sync off: %d", files)
	}
	f.SetSync(true)
	if dirs != 1 {
		t.Errorf("the directory is synced once when sync is turned on: %d", dirs)
	}
	for _, l := range []string{"bbbbbbbbbbbbbbb\n", "ccccccccccccccc\n"} { // the second one rotates
		if _, err := f.Write([]byte(l)); err != nil {
			t.Fatal(err)
		}
	}
	if files != 2 {
		t.Errorf("two lines, %d fsyncs", files)
	}
	if dirs < 2 {
		t.Errorf("a rotation did not sync the directory: %d", dirs)
	}
	// the disk refuses: the write fails, and the line is in the file (the caller does not answer)
	f.syncFile = func(*os.File) error { return errors.New("input/output error") }
	if n, err := f.Write([]byte("ddddddddddddddd\n")); err == nil || n == 0 {
		t.Errorf("a failed fsync was not an error of the write: %d %v", n, err)
	}
	// and turned off again, nothing is synced
	f.SetSync(false)
	files = 0
	f.syncFile = func(*os.File) error { files++; return nil }
	f.Write([]byte("eeeeeeeeeeeeeee\n"))
	if files != 0 {
		t.Errorf("synced with sync off: %d", files)
	}
}

// The real fsync works on a real file (no hook).
func TestFileSyncOnARealFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	f, err := OpenFile(p, 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	f.SetSync(true)
	if _, err := f.Write([]byte("a line\n")); err != nil {
		t.Fatal(err)
	}
	if got := read(t, p); got != "a line\n" {
		t.Errorf("%q", got)
	}
}

func benchmarkWrite(b *testing.B, sync bool) {
	f, err := OpenFile(filepath.Join(b.TempDir(), "audit.log"), 0, 1)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	f.SetSync(sync)
	line := []byte(`{"time":"2026-11-22T00:00:00Z","request_id":"0123456789abcdef","client":"app","face":"transit","key":"k","op":"decrypt","result":"ok"}` + "\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := f.Write(line); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFileWrite(b *testing.B)     { benchmarkWrite(b, false) }
func BenchmarkFileWriteSync(b *testing.B) { benchmarkWrite(b, true) }

// The name of the file must reach the disk too (the review of 2026-11-22, finding 1): while the directory cannot be synced, after the file was created, rotated or reopened, nothing
// is written and every Write is an error, so that nothing is answered for; a later success restores the service.
func TestFileRefusesWhileTheDirectoryCannotBeSynced(t *testing.T) {
	broken := errors.New("input/output error")
	var fail bool
	dirs := 0
	open := func(t *testing.T, maxBytes int64) (*File, string) {
		p := filepath.Join(t.TempDir(), "audit.log")
		f, err := OpenFile(p, maxBytes, 3)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		f.syncDir = func(string) error {
			dirs++
			if fail {
				return broken
			}
			return nil
		}
		return f, p
	}
	refused := func(t *testing.T, f *File, p, line string) {
		t.Helper()
		for i := 0; i < 2; i++ { // and again: a failure is not forgotten
			if _, err := f.Write([]byte(line)); !errors.Is(err, broken) {
				t.Fatalf("write %d was not refused: %v", i, err)
			}
		}
		if strings.Contains(read(t, p), line) {
			t.Errorf("a refused line is in the file: %q", read(t, p))
		}
	}
	recovers := func(t *testing.T, f *File, p, line string) {
		t.Helper()
		fail = false
		if _, err := f.Write([]byte(line)); err != nil {
			t.Fatalf("after the directory can be synced again: %v", err)
		}
		before := dirs
		f.Write([]byte("z\n"))
		if !strings.Contains(read(t, p), "z\n") || (f.maxBytes == 0 && dirs != before) {
			t.Errorf("the directory is synced again for every line: %d, %d", before, dirs)
		}
	}
	t.Run("when sync is turned on", func(t *testing.T) {
		f, p := open(t, 0)
		fail = true
		if err := f.SetSync(true); !errors.Is(err, broken) {
			t.Fatalf("SetSync: %v", err)
		}
		refused(t, f, p, "first\n")
		recovers(t, f, p, "first\n")
	})
	t.Run("after a rotation", func(t *testing.T) {
		fail = false
		f, p := open(t, 10)
		if err := f.SetSync(true); err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("aaaaaaaa\n"))
		fail = true
		refused(t, f, p, "bbbbbbbb\n")
		recovers(t, f, p, "bbbbbbbb\n")
	})
	t.Run("after a reopen (logrotate)", func(t *testing.T) {
		fail = false
		f, p := open(t, 0)
		if err := f.SetSync(true); err != nil {
			t.Fatal(err)
		}
		f.Write([]byte("before\n"))
		if err := os.Rename(p, p+".moved"); err != nil {
			t.Fatal(err)
		}
		if err := f.Reopen(); err != nil {
			t.Fatal(err)
		}
		fail = true
		refused(t, f, p, "after\n")
		recovers(t, f, p, "after\n")
	})
	t.Run("sync off", func(t *testing.T) {
		fail = true
		f, _ := open(t, 10)
		for _, l := range []string{"aaaaaaaa\n", "bbbbbbbb\n"} {
			if _, err := f.Write([]byte(l)); err != nil {
				t.Fatalf("with sync off the directory is nothing to the write: %v", err)
			}
		}
		fail = false
	})
}
