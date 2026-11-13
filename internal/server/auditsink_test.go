package server

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zystem/hsmgate/internal/config"
)

func sinkCfg(file string, stdout bool) *config.Config {
	c := &config.Config{}
	c.Audit.File, c.Audit.Stdout = file, stdout
	return c
}

// No file: the audit goes to standard output; with a file and no audit.stdout: to the file only; with audit.stdout: to both, the same line.
func TestOpenAuditSinks(t *testing.T) {
	dir := t.TempDir()
	var stdout bytes.Buffer

	f, w, err := openAudit(sinkCfg("", false), nil, &stdout)
	if err != nil || f != nil {
		t.Fatalf("no file: %v %v", f, err)
	}
	w.Write([]byte("only-stdout\n"))
	if stdout.String() != "only-stdout\n" {
		t.Errorf("stdout: %q", stdout.String())
	}

	stdout.Reset()
	p := filepath.Join(dir, "a.log")
	f, w, err = openAudit(sinkCfg(p, false), nil, &stdout)
	if err != nil || f == nil {
		t.Fatalf("file: %v", err)
	}
	w.Write([]byte("only-file\n"))
	f.Close()
	if got, _ := os.ReadFile(p); string(got) != "only-file\n" || stdout.Len() != 0 {
		t.Errorf("file %q, stdout %q", got, stdout.String())
	}

	q := filepath.Join(dir, "b.log")
	f, w, err = openAudit(sinkCfg(q, true), nil, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("both\n"))
	f.Close()
	if got, _ := os.ReadFile(q); string(got) != "both\n" || stdout.String() != "both\n" {
		t.Errorf("file %q, stdout %q", got, stdout.String())
	}

	var given bytes.Buffer // a writer given by a test wins and there is no file to reopen
	f, w, _ = openAudit(sinkCfg(p, true), &given, &stdout)
	w.Write([]byte("x"))
	if f != nil || given.String() != "x" {
		t.Errorf("given writer ignored: %v %q", f, given.String())
	}
}

func TestOpenAuditRefusesAnUnwritablePath(t *testing.T) {
	if _, _, err := openAudit(sinkCfg(filepath.Join(t.TempDir(), "no", "such", "dir", "a.log"), false), nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "no such") {
		t.Errorf("err = %v", err)
	}
}

// ReopenAudit is a no-op without a file of the service and reopens the path with one.
func TestReopenAudit(t *testing.T) {
	s := &Server{}
	if err := s.ReopenAudit(); err != nil {
		t.Errorf("no file: %v", err)
	}
}
