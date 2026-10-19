package server

import (
	"sort"

	"github.com/zystem/hsmgate/internal/config"
	"github.com/zystem/hsmgate/internal/scheme/ecies"
)

func sortedKeys(m map[string]config.Key) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprintOf(point []byte) string { return ecies.Fingerprint(point) }
