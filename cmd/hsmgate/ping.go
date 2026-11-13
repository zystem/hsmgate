package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

const pingHelp = "Connects to the listener and exits 0 when it answers: a health check (a container, a Kubernetes probe) that never touches a token. Without -cert it is a TCP connect and needs no certificate. With -cert, -key and -ca it makes the whole TLS 1.3 handshake (the certificate of the service checked against the CA, a client certificate shown) and sends no request: use a certificate of the CA that no entry of clients: names, so that the probe has no rights and leaves no audit line."

// runPing is `hsmgate ping`. It returns the exit status.
func runPing(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: hsmgate ping [-addr host:port] [-cert file -key file -ca file [-name server-name]]\n\n%s\n\n", pingHelp)
		fs.PrintDefaults()
	}
	addr := fs.String("addr", "127.0.0.1:8443", "address to connect to")
	cert := fs.String("cert", "", "TLS mode: the certificate of the probe (a certificate of the CA that no client of the policy uses)")
	key := fs.String("key", "", "TLS mode: the key of that certificate")
	ca := fs.String("ca", "", "TLS mode: the CA that signed the certificate of the service")
	name := fs.String("name", "", "TLS mode: the name the certificate of the service must carry (default: the host of -addr)")
	timeout := fs.Duration("timeout", 3*time.Second, "give up after this long")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var err error
	if *cert == "" && *key == "" && *ca == "" {
		err = pingTCP(*addr, *timeout)
	} else if *cert == "" || *key == "" || *ca == "" {
		fmt.Fprintln(stderr, "hsmgate: ping: -cert, -key and -ca go together")
		return 2
	} else {
		err = pingTLS(*addr, *cert, *key, *ca, *name, *timeout)
	}
	if err != nil {
		fmt.Fprintln(stderr, "hsmgate:", err)
		return 1
	}
	return 0
}

// pingTCP: a connect and a close. The service logs nothing for it.
func pingTCP(addr string, timeout time.Duration) error {
	c, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return c.Close()
}

// pingTLS makes the handshake and stops. In TLS 1.3 the client is done before the service has judged its certificate, so it waits a moment for an alert: silence means
// the service accepted the handshake and waits for a request, which never comes (and the service writes nothing for a connection that closes at that point).
func pingTLS(addr, certFile, keyFile, caFile, name string, timeout time.Duration) error {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("-ca %s: no certificates read", caFile)
	}
	if name == "" {
		if name, _, err = net.SplitHostPort(addr); err != nil {
			return err
		}
	}
	c, err := (&net.Dialer{Timeout: timeout}).Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	t := tls.Client(c, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: name, Certificates: []tls.Certificate{pair}})
	if err := t.Handshake(); err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err = t.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return nil // no alert: accepted
	}
	if err == nil {
		err = errors.New("the service sent data before any request")
	}
	return err
}
