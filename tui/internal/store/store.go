// Package store edits hsmgate.yaml the way a person would: the file stays the one source of truth, comments and the order of the keys are kept, and every change is
// checked by the very loader the service uses (internal/config) before it is written. There is no second format and no database.
package store

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/zystem/hsmgate/internal/config"
)

// Doc is a configuration file open for editing.
type Doc struct {
	Path  string
	root  *yaml.Node // the mapping at the top of the document
	orig  []byte     // what was read (nil when the file did not exist)
	canon []byte     // what was read, written again by Bytes() with nothing changed: the same text without the spacing and blank lines a person kept
}

// Open reads the file. A file that does not exist is an empty document (Save then creates it).
func Open(path string) (*Doc, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own argument
	if err != nil {
		if os.IsNotExist(err) {
			return New(path), nil
		}
		return nil, err
	}
	d, err := parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	d.Path, d.orig = path, raw
	d.canon, _ = d.Bytes()
	return d, nil
}

// New is an empty document that would be written to path.
func New(path string) *Doc {
	return &Doc{Path: path, root: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}}
}

func parse(raw []byte) (*Doc, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(raw, &n); err != nil {
		return nil, err
	}
	if n.Kind == 0 { // an empty file
		return &Doc{root: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}}, nil
	}
	if n.Kind != yaml.DocumentNode || len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("the top of the file is not a mapping")
	}
	return &Doc{root: n.Content[0]}, nil
}

// Original is what the file held when it was opened (nil if it did not exist).
func (d *Doc) Original() []byte { return d.orig }

// Bytes is the document as it would be written.
func (d *Doc) Bytes() ([]byte, error) {
	var b bytes.Buffer
	e := yaml.NewEncoder(&b)
	e.SetIndent(2)
	if err := e.Encode(d.root); err != nil {
		return nil, err
	}
	if err := e.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Config parses the current text with the loader of the service and applies its rules. An error is what the service would say at its start.
func (d *Doc) Config() (*config.Config, error) {
	raw, err := d.Bytes()
	if err != nil {
		return nil, err
	}
	c, err := config.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Changed says whether the document differs from what was read. A file is compared with itself written again (canon), not with its own text: the writer does not keep the
// alignment of comments or the blank lines, and a file that nobody touched must not count as changed.
func (d *Doc) Changed() bool {
	if d.orig == nil && len(d.root.Content) == 0 {
		return false // a file that is not there and nothing written to it
	}
	b, err := d.Bytes()
	if err != nil {
		return true
	}
	if d.orig == nil {
		return true
	}
	return !bytes.Equal(b, d.canon)
}

// ---- nodes -------------------------------------------------------------------------------------------------------------------------------------------------

func scalar(v any) *yaml.Node {
	n := &yaml.Node{}
	if err := n.Encode(v); err != nil {
		panic(err) // only values made by this package are encoded
	}
	return n
}

// flow marks small collections to be written on one line, as people write them: {token: soft, label: m1}.
func flow(n *yaml.Node) *yaml.Node {
	n.Style |= yaml.FlowStyle
	return n
}

func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func set(m *yaml.Node, key string, v *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			// keep the comments the person wrote around the old value
			v.HeadComment, v.LineComment, v.FootComment = m.Content[i+1].HeadComment, m.Content[i+1].LineComment, m.Content[i+1].FootComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

func del(m *yaml.Node, key string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// mapping returns the mapping at key, making it (and an empty one in place of a null) when it is not there.
func mapping(m *yaml.Node, key string) *yaml.Node {
	n := get(m, key)
	if n == nil || n.Kind != yaml.MappingNode {
		n = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		set(m, key, n)
	}
	return n
}

func sequence(m *yaml.Node, key string) *yaml.Node {
	n := get(m, key)
	if n == nil || n.Kind != yaml.SequenceNode {
		n = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		set(m, key, n)
	}
	return n
}

// find returns the item of a sequence of mappings whose name is name, and its index.
func find(seq *yaml.Node, name string) (*yaml.Node, int) {
	if seq == nil {
		return nil, -1
	}
	for i, it := range seq.Content {
		if n := get(it, "name"); n != nil && n.Value == name {
			return it, i
		}
	}
	return nil, -1
}

func newMap(kv ...any) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := 0; i+1 < len(kv); i += 2 {
		set(m, kv[i].(string), scalar(kv[i+1]))
	}
	return m
}

// ---- generic settings --------------------------------------------------------------------------------------------------------------------------------

// Set writes a value (a string, number, bool or list of strings) at a path of keys, such as ("audit", "max_size_mb"). The mappings on the way are made.
func (d *Doc) Set(v any, path ...string) error {
	if len(path) == 0 {
		return fmt.Errorf("no path")
	}
	m := d.root
	for _, k := range path[:len(path)-1] {
		m = mapping(m, k)
	}
	n := scalar(v)
	if n.Kind == yaml.SequenceNode {
		n.Style |= yaml.FlowStyle
	}
	set(m, path[len(path)-1], n)
	return nil
}

// Unset removes the key at a path (and an emptied mapping above it, so that the file does not collect `audit: {}`).
func (d *Doc) Unset(path ...string) bool {
	if len(path) == 0 {
		return false
	}
	var chain []*yaml.Node
	m := d.root
	for _, k := range path[:len(path)-1] {
		chain = append(chain, m)
		if m = get(m, k); m == nil {
			return false
		}
	}
	ok := del(m, path[len(path)-1])
	for i := len(path) - 2; i >= 0 && ok; i-- {
		if cur := get(chain[i], path[i]); cur != nil && cur.Kind == yaml.MappingNode && len(cur.Content) == 0 {
			del(chain[i], path[i])
		}
	}
	return ok
}

// Value reads a scalar at a path ("" when it is not there).
func (d *Doc) Value(path ...string) string {
	m := d.root
	for _, k := range path {
		if m = get(m, k); m == nil {
			return ""
		}
	}
	return m.Value
}

// Has says whether a key is at a path.
func (d *Doc) Has(path ...string) bool {
	m := d.root
	for _, k := range path {
		if m = get(m, k); m == nil {
			return false
		}
	}
	return true
}

func plain(s string) string { return strings.TrimSpace(s) }
