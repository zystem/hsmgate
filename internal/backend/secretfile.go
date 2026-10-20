package backend

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ReadSecretFile reads a file that holds a key or a PIN. A symbolic link is followed (a Kubernetes Secret volume is made of them: key -> ..data/key), and the file it leads to
// is opened once, without following a further link, and judged by its open descriptor, not by the path: a regular file, owned by the user the service runs as (or root),
// not readable by group or others, and no larger than max bytes.
func ReadSecretFile(path string, max int64) ([]byte, error) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(real, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s must not be readable by group or others (mode %o)", path, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Geteuid() && sys.Uid != 0 {
		return nil, fmt.Errorf("%s is owned by another user", path)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(b)) > max {
		return nil, fmt.Errorf("%s grew beyond %d bytes while it was read", path, max)
	}
	return b, err
}
