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
	link := filepath.Join(dir, "link")
	os.Symlink(good, link)
	if _, err := ReadSecretFile(link, 16); err == nil {
		t.Error("a symbolic link was followed")
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
