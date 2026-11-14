package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the flags block of docs/setup-tool.md from what -h prints")

// docs/setup-tool.md shows what `hsmgate-setup -h` prints, between two markers, so that it cannot say something else than the program does. After a flag changes:
// `cd tui && go test ./cmd/hsmgate-setup -run FlagsDoc -update`.
func TestFlagsDocIsCurrent(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "help")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if code := run([]string{"-h"}, f, f); code != 0 {
		t.Fatalf("-h exits with %d", code)
	}
	raw, _ := os.ReadFile(f.Name())
	block := "<!-- flags:start -->\n```text\n" + strings.TrimRight(string(raw), "\n") + "\n```\n<!-- flags:end -->"

	const path = "../../../docs/setup-tool.md"
	doc, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i, j := strings.Index(s, "<!-- flags:start -->"), strings.Index(s, "<!-- flags:end -->")
	if i < 0 || j < i {
		t.Fatal("docs/setup-tool.md has no flags block")
	}
	want := s[:i] + block + s[j+len("<!-- flags:end -->"):]
	if *update {
		if err := os.WriteFile(path, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if want != s {
		t.Error("the flags block of docs/setup-tool.md is not what -h prints: run `cd tui && go test ./cmd/hsmgate-setup -run FlagsDoc -update` and commit the file")
	}
}

// the flags of -auto that fill the answers are all in the page, and so is every flag
func TestEveryFlagIsInTheDocument(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "help")
	defer f.Close()
	run([]string{"-h"}, f, f)
	raw, _ := os.ReadFile(f.Name())
	doc, _ := os.ReadFile("../../../docs/setup-tool.md")
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, "  -") {
			name := strings.Fields(strings.TrimPrefix(l, "  "))[0]
			if !strings.Contains(string(doc), name) {
				t.Errorf("the flag %s is not in docs/setup-tool.md", name)
			}
		}
	}
}

// Every message of the setup tool and the packages that docs/troubleshooting.md explains is still in the code or the script that prints it, and the page has it: neither can drift away alone.
func TestTroubleshootingMessagesAreReal(t *testing.T) {
	page, err := os.ReadFile("../../../docs/troubleshooting.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []struct{ text, file string }{
		{"installed, not configured. Run 'sudo hsmgate-setup'", "../../../packaging/scripts/postinstall.sh"},
		{"the automatic setup did not finish", "../../../packaging/scripts/postinstall.sh"},
		{"needs a terminal; for an unattended setup use -auto", "main.go"},
		{"hsmgate-setup is not installed", "../../../cmd/hsmgate/setup.go"},
		{"does not write over one", "../../internal/setup/setup.go"},
		{"not saved, the service would refuse it", "../../internal/store/save.go"},
		{"the certificates were not made", "../../internal/setup/setup.go"},
		{"hsmgate check does not accept what was written", "../../internal/setup/setup.go"},
		{"The running service still has the old program", "../../../packaging/scripts/postinstall.sh"},
	} {
		src, err := os.ReadFile(m.file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), strings.TrimPrefix(m.text, "The ")) && !strings.Contains(string(src), m.text) && !strings.Contains(strings.ToLower(string(src)), strings.ToLower(m.text)) {
			t.Errorf("%q is not in %s any more: update docs/troubleshooting.md", m.text, m.file)
		}
		if !strings.Contains(strings.ToLower(string(page)), strings.ToLower(m.text)) {
			t.Errorf("%q is not in docs/troubleshooting.md", m.text)
		}
	}
}
