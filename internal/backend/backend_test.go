package backend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
