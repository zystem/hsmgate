package kmsgrpc

import (
	"strconv"
	"strings"

	"github.com/zystem/hsmgate/internal/config"
)

// The names of resources are those of the service: projects/P/locations/L/keyRings/R/cryptoKeys/KEY[/cryptoKeyVersions/N]. P, L and R are fixed by the configuration; KEY is the
// name of a key of hsmgate that is on this face; N is the number of its version (1 is the first).
type names struct{ project, location, keyRing string }

func (n names) ring() string {
	return "projects/" + n.project + "/locations/" + n.location + "/keyRings/" + n.keyRing
}

func (n names) key(key string) string { return n.ring() + "/cryptoKeys/" + key }

func (n names) version(key string, ver int) string {
	return n.key(key) + "/cryptoKeyVersions/" + strconv.Itoa(ver)
}

// parseKey reads a cryptoKey or cryptoKeyVersion name. hasVer says whether it named a version.
func (n names) parseKey(name string) (key string, ver int, hasVer, ok bool) {
	rest, found := strings.CutPrefix(name, n.ring()+"/cryptoKeys/")
	if !found || rest == "" {
		return "", 0, false, false
	}
	key, vpart, hasSlash := strings.Cut(rest, "/")
	if key == "" {
		return "", 0, false, false
	}
	if !hasSlash {
		return key, 0, false, true
	}
	num, found := strings.CutPrefix(vpart, "cryptoKeyVersions/")
	if !found {
		return "", 0, false, false
	}
	v, err := strconv.Atoi(num)
	if err != nil || v < 1 || v > config.MaxVersions || strconv.Itoa(v) != num {
		return "", 0, false, false
	}
	return key, v, true, true
}

// isRing: is this the name of the key ring of the configuration (the parent of the keys)?
func (n names) isRing(name string) bool { return name == n.ring() }

// isLocation: is this the name of the location of the configuration (the parent of GenerateRandomBytes)?
func (n names) isLocation(name string) bool {
	return name == "projects/"+n.project+"/locations/"+n.location
}
