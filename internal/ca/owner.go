package ca

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
)

// chown makes the named user the owner of the files (the group stays).
func chown(name string, paths ...string) error {
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("owner: %w", err)
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, -1); err != nil {
			return fmt.Errorf("owner: %w", err)
		}
	}
	return nil
}
