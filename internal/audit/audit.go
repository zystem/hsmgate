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
	mu     sync.Mutex
	w      io.Writer
	now    func() time.Time
	failed bool
	// Observer, when set, sees every event after it was written, with the error of the write (the metrics count them).
	Observer func(Event, error)
}

func New(w io.Writer) *Log { return &Log{w: w, now: time.Now} }

// Write returns an error when the line could not be written; the log is then unhealthy until a write succeeds.
func (l *Log) Write(e Event) error {
	e.Time = l.now().UTC()
	b, _ := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.w.Write(append(b, '\n'))
	l.failed = err != nil
	if l.Observer != nil {
		l.Observer(e, err)
	}
	return err
}

// Healthy: the last write succeeded. A service that cannot write down what it does stops doing it.
func (l *Log) Healthy() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return !l.failed
}
