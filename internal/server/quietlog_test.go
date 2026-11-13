package server

import (
	"bytes"
	"strings"
	"testing"
)

func TestErrorLogDropsOnlyTheBareConnect(t *testing.T) {
	var out bytes.Buffer
	l := newErrorLog(&out)
	l.Printf("http: TLS handshake error from %s: %v", "10.244.12.53:42524", "EOF")
	if out.Len() != 0 {
		t.Fatalf("a connect that closed without a byte was written: %q", out.String())
	}
	for _, msg := range []string{
		"http: TLS handshake error from 10.0.0.1:1: tls: client didn't provide a certificate",
		"http: TLS handshake error from 10.0.0.1:1: read tcp 1.2.3.4:8443->10.0.0.1:1: read: connection reset by peer",
		"http: TLS handshake error from 10.0.0.1:1: tls: client offered only unsupported versions: [303 302 301]",
		"http: Accept error: too many open files; retrying",
	} {
		out.Reset()
		l.Print(msg)
		if !strings.Contains(out.String(), msg) {
			t.Errorf("a real failure was dropped: %q (got %q)", msg, out.String())
		}
	}
}
