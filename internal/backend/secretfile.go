package backend

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ReadSecretFile reads a file that holds a key or a PIN. A symbolic link is followed (a Kubernetes Secret volume is made of them: key -> ..data/key), and the file it leads to
// is opened once, without following a further link, and judged by its open descriptor, not by the path: a regular file, owned by the user the service runs as (or root),
// not readable by group or others, and no larger than max bytes. The content is read into one buffer, which is the only copy this function makes: the caller owns it and clears it
// when it is done; on an error it is cleared here.
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
	return readSecret(f, path, max)
}

// readSecret reads at most max bytes into a buffer made once: a buffer that grows (io.ReadAll) leaves copies of the secret behind.
func readSecret(r io.Reader, path string, max int64) ([]byte, error) {
	b := make([]byte, max+1)
	n, err := io.ReadFull(r, b)
	switch {
	case err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF):
		clear(b)
		return nil, err
	case int64(n) > max:
		clear(b)
		return nil, fmt.Errorf("%s grew beyond %d bytes while it was read", path, max)
	}
	return b[:n], nil
}
