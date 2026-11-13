package audit

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// File is the audit file: opened for append (mode 0640, so that a log shipper in the group can read it), reopened on request (after an outside tool such as logrotate
// renamed it) and, when maxBytes is set, rotated by the service itself: path -> path.1 -> path.2 ... up to `keep` older files, the oldest dropped.
type File struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	size     int64
	maxBytes int64
	keep     int
	// Warn, when set, is told (at most once a minute) that a rotation failed and the file is still in use: the file then grows past its limit until the cause is gone.
	Warn     func(error)
	lastWarn time.Time
}

// OpenFile opens (creating if needed) the file. maxBytes 0 means no rotation by the service; keep is how many older files are kept when it rotates (at least 1).
func OpenFile(path string, maxBytes int64, keep int) (*File, error) {
	if keep < 1 {
		keep = 1
	}
	a := &File{path: path, maxBytes: maxBytes, keep: keep}
	if err := a.open(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *File) open() error {
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640) // #nosec G302 G304 -- the group may read the log (a shipper); the path is the operator's
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	a.f, a.size = f, st.Size()
	return nil
}

// Reopen closes the file and opens the path again: what a rename by logrotate needs. On an error the old file stays open and in use.
func (a *File) Reopen() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	old := a.f
	if err := a.open(); err != nil {
		a.f = old
		return err
	}
	return old.Close()
}

// Write appends p, first rotating when it would pass the size limit. A failed rename leaves the file in use (and is tried again at the next write); a rotation that
// renamed the file and then could not open a new one returns the error, and the next write tries to open it again.
func (a *File) Write(p []byte) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		if err := a.open(); err != nil {
			return 0, err
		}
	}
	if a.maxBytes > 0 && a.size > 0 && a.size+int64(len(p)) > a.maxBytes {
		if err := a.rotate(); err != nil {
			if a.f == nil {
				return 0, err
			}
			if a.Warn != nil && time.Since(a.lastWarn) > time.Minute {
				a.lastWarn = time.Now()
				a.Warn(err)
			}
		}
	}
	n, err := a.f.Write(p)
	a.size += int64(n)
	return n, err
}

func (a *File) rotate() error {
	for i := a.keep; i >= 1; i-- {
		from := a.path
		if i > 1 {
			from = fmt.Sprintf("%s.%d", a.path, i-1)
		}
		to := fmt.Sprintf("%s.%d", a.path, i)
		if err := os.Rename(from, to); err != nil && !os.IsNotExist(err) {
			return err // the file is still in use
		}
	}
	old := a.f
	a.f, a.size = nil, 0
	_ = old.Close()
	return a.open()
}

// Close closes the file.
func (a *File) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}
