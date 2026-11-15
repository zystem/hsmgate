package store

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Diff is a unified-style difference between two texts, line by line, with three lines of context. It is for a person to read before a change is saved; "" means no difference.
func Diff(a, b []byte, nameA, nameB string) string {
	x, y := lines(a), lines(b)
	// longest common subsequence of lines: the files are small (hundreds of lines)
	n, m := len(x), len(y)
	l := make([][]int, n+1)
	for i := range l {
		l[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				l[i][j] = l[i+1][j+1] + 1
			} else if l[i+1][j] >= l[i][j+1] {
				l[i][j] = l[i+1][j]
			} else {
				l[i][j] = l[i][j+1]
			}
		}
	}
	type op struct {
		c byte
		s string
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			ops = append(ops, op{' ', x[i]})
			i++
			j++
		case l[i+1][j] >= l[i][j+1]:
			ops = append(ops, op{'-', x[i]})
			i++
		default:
			ops = append(ops, op{'+', y[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{'-', x[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{'+', y[j]})
	}
	changed := false
	for _, o := range ops {
		if o.c != ' ' {
			changed = true
		}
	}
	if !changed {
		return ""
	}
	const ctx = 3
	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.c != ' ' {
			for d := -ctx; d <= ctx; d++ {
				if k+d >= 0 && k+d < len(ops) {
					keep[k+d] = true
				}
			}
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", nameA, nameB)
	skipped := false
	for k, o := range ops {
		if !keep[k] {
			skipped = true
			continue
		}
		if skipped {
			sb.WriteString("@@\n")
			skipped = false
		}
		sb.WriteString(string(o.c) + " " + o.s + "\n")
	}
	return sb.String()
}

func lines(b []byte) []string {
	s := strings.TrimRight(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// DiffToOriginal is what Save would change.
func (d *Doc) DiffToOriginal() (string, error) {
	b, err := d.Bytes()
	if err != nil {
		return "", err
	}
	return Diff(d.orig, b, d.Path, d.Path+" (new)"), nil
}

// KeepBackups is how many copies of the old file are kept next to it.
const KeepBackups = 10

// Save checks the document with the loader of the service and, only if it is good, writes it: to a file next to the old one, flushed, then renamed over it, so that a power cut leaves
// the old file or the new one and never half of one. The old file is first copied to path.bak-DATE (the newest KeepBackups are kept). Mode and owner of the old file are kept; a new file
// is 0640. It returns the path of the backup ("" when there was no old file).
func (d *Doc) Save() (string, error) {
	if _, err := d.Config(); err != nil {
		return "", fmt.Errorf("not saved, the service would refuse it: %w", err)
	}
	b, err := d.Bytes()
	if err != nil {
		return "", err
	}
	mode, uid, gid := os.FileMode(0o640), -1, -1
	backup := ""
	if st, err := os.Stat(d.Path); err == nil {
		mode = st.Mode().Perm()
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			uid, gid = int(sys.Uid), int(sys.Gid)
		}
		backup = fmt.Sprintf("%s.bak-%s", d.Path, time.Now().Format("20060102-150405"))
		if err := copyFile(d.Path, backup, mode); err != nil {
			return "", fmt.Errorf("the backup failed, nothing written: %w", err)
		}
	}
	dir := filepath.Dir(d.Path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".hsmgate.yaml-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // a no-op after the rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return "", err
	}
	if uid >= 0 {
		_ = tmp.Chown(uid, gid) // only root can change the owner; the owner of the file is kept when it is root that edits
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), d.Path); err != nil {
		return "", err
	}
	if df, err := os.Open(dir); err == nil { // #nosec G304 -- the directory of the configuration; make the rename itself durable
		_ = df.Sync()
		df.Close()
	}
	d.orig, d.canon = b, b
	pruneBackups(d.Path)
	return backup, nil
}

func copyFile(from, to string, mode os.FileMode) error {
	in, err := os.Open(from) // #nosec G304 -- the operator's own file, named by its configuration
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) // #nosec G304
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func pruneBackups(path string) {
	all, _ := filepath.Glob(path + ".bak-*")
	if len(all) <= KeepBackups {
		return
	}
	sort.Strings(all) // the date is in the name: the oldest first
	for _, f := range all[:len(all)-KeepBackups] {
		os.Remove(f)
	}
}
