package card

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// run runs a program for real (the tests of this file use a card that is in a reader).
func run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- opensc-tool and arguments made by the test
	return string(out), err
}

// TestRealCard reads the card in the first reader that has one and prints its tree. It is skipped unless HSMGATE_REAL_CARD=1: it needs a SmartCard-HSM and sends only commands that
// read (no PIN is verified). Run: `HSMGATE_REAL_CARD=1 go test ./internal/card -run RealCard -v`.
func TestRealCard(t *testing.T) {
	if os.Getenv("HSMGATE_REAL_CARD") != "1" {
		t.Skip("set HSMGATE_REAL_CARD=1 to read a card in a reader")
	}
	ctx := context.Background()
	rs, err := Readers(ctx, run)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if !r.HasCard {
			continue
		}
		tree, err := Read(ctx, run, r)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("reader %d: %s", r.Nr, r.Name)
		t.Logf("%s (%s)  version %s platform %d, free memory %d", tree.Label, tree.DeviceID, tree.Version, tree.Platform, tree.FreeMemory)
		t.Log(tree.UserPIN.Text())
		t.Log(tree.SOPIN.Text())
		for _, d := range tree.Domains {
			if !d.Created {
				t.Logf("Key domain %d not created", d.Number)
				continue
			}
			t.Logf("DKEK with KCV %s (%s) shares %d, outstanding %d", d.KCV, d.Label, d.Shares, d.Outstanding)
			for _, k := range d.Keys {
				t.Logf("    %s (%d, %s) id %X algorithms %s uses %d", k.Label, k.ID, k.Algo, k.CKAID, strings.Join(k.Algorithms, ", "), k.Uses)
			}
		}
		for _, k := range tree.Loose {
			t.Logf("loose key %s (%d, %s) domain %d", k.Label, k.ID, k.Algo, k.Domain)
		}
		return
	}
	t.Skip("no card in a reader")
}
