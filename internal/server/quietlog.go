package server

import (
	"bytes"
	"io"
	"log"
	"os"
)

// quietWriter drops the one line that a health check makes: "http: TLS handshake error from <address>: EOF" is a peer that connected and closed without a single byte
// (a TCP probe of Kubernetes, a load balancer, a port check). A real failure has other words (no certificate, a certificate of another CA, TLS 1.2, a reset) and is written.
type quietWriter struct{ w io.Writer }

func (q quietWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("http: TLS handshake error from ")) && bytes.HasSuffix(bytes.TrimRight(p, "\n"), []byte(": EOF")) {
		return len(p), nil
	}
	return q.w.Write(p)
}

// newErrorLog is the log of the HTTP server: standard error as before, without the line of a bare TCP connect.
func newErrorLog(w io.Writer) *log.Logger {
	if w == nil {
		w = os.Stderr
	}
	return log.New(quietWriter{w}, "", log.LstdFlags)
}
