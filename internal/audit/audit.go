// Package audit writes one JSON line per decision, refused ones included. Never a key, a plaintext, a PIN or a ciphertext.
package audit

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id,omitempty"`
	Client    string    `json:"client"`
	Face      string    `json:"face"`
	Key       string    `json:"key,omitempty"`
	Op        string    `json:"op"`
	Context   string    `json:"context,omitempty"` // public by rule; JSON escaping keeps a hostile value on its line
	Result    string    `json:"result"`
}

type Log struct {
	mu  sync.Mutex
	w   io.Writer
	now func() time.Time
}

func New(w io.Writer) *Log { return &Log{w: w, now: time.Now} }

func (l *Log) Write(e Event) {
	e.Time = l.now().UTC()
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.w.Write(append(b, '\n'))
}
