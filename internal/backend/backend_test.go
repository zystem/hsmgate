package backend

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestSoftRefusesAKeyFileOthersCanRead(t *testing.T) {
	f := filepath.Join(t.TempDir(), "k")
	os.WriteFile(f, []byte(strings.Repeat("11", 32)), 0o644)
	if _, err := NewSoft(map[string]string{"m": f}); err == nil {
		t.Error("a world-readable key file was accepted")
	}
	os.Chmod(f, 0o600)
	if _, err := NewSoft(map[string]string{"m": f}); err != nil {
		t.Error(err)
	}
}

func TestSecretFileIsReadFromTheDescriptor(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte("abcd"), 0o600)
	if b, err := ReadSecretFile(good, 16); err != nil || string(b) != "abcd" {
		t.Fatalf("%q %v", b, err)
	}
	// a link is followed, as in a Kubernetes Secret volume (key -> ..data/key -> a directory named after the time) ...
	vol := filepath.Join(dir, "vol")
	os.MkdirAll(filepath.Join(vol, "..2026_10_20"), 0o755)
	os.WriteFile(filepath.Join(vol, "..2026_10_20", "k"), []byte("abcd"), 0o400)
	os.Symlink("..2026_10_20", filepath.Join(vol, "..data"))
	os.Symlink(filepath.Join("..data", "k"), filepath.Join(vol, "k"))
	if b, err := ReadSecretFile(filepath.Join(vol, "k"), 16); err != nil || string(b) != "abcd" {
		t.Errorf("a Secret volume: %q %v", b, err)
	}
	// ... but what it leads to is judged like any key file: mode, type, and a link that leads nowhere
	open := filepath.Join(dir, "open")
	os.WriteFile(open, []byte("abcd"), 0o644)
	os.Symlink(open, filepath.Join(dir, "link-to-open"))
	if _, err := ReadSecretFile(filepath.Join(dir, "link-to-open"), 16); err == nil {
		t.Error("a link to a world-readable file was read")
	}
	os.Symlink(filepath.Join(dir, "nowhere"), filepath.Join(dir, "dangling"))
	if _, err := ReadSecretFile(filepath.Join(dir, "dangling"), 16); err == nil {
		t.Error("a dangling link was read")
	}
	os.Symlink(dir, filepath.Join(dir, "link-to-dir"))
	if _, err := ReadSecretFile(filepath.Join(dir, "link-to-dir"), 16); err == nil {
		t.Error("a link to a directory was read")
	}
	if _, err := ReadSecretFile(dir, 16); err == nil {
		t.Error("a directory was read")
	}
	big := filepath.Join(dir, "big")
	os.WriteFile(big, []byte(strings.Repeat("a", 100)), 0o600)
	if _, err := ReadSecretFile(big, 16); err == nil {
		t.Error("a file over the limit was read")
	}
}

func TestSecretFileFIFODoesNotBlock(t *testing.T) {
	f := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(f, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() { _, err := ReadSecretFile(f, 16); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was read")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
}
