// Package client is the client of the Transit API of hsmgate: what `hsmgate encrypt` and `hsmgate decrypt` use. It follows the rules of
// docs/specs/transit.md: it trusts the header X-Hsmgate-Retryable, not the status number, to decide whether to try again, and it never puts a
// plaintext or a ciphertext in an error message.
package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config says where the service is and who the caller is.
type Config struct {
	Addr     string // https://host:8443 ; http only for a loopback address (development)
	Mount    string // default transit
	Key      string // the name of the key
	CAFile   string // PEM, the CA of the service; the system roots if empty
	CertFile string // the client certificate
	KeyFile  string // and its private key
	Timeout  time.Duration
}

type Client struct {
	cfg  Config
	base string
	http *http.Client
}

// APIError is an answer of the service that is not a success.
type APIError struct {
	Status     int
	Messages   []string
	Retryable  bool
	RetryAfter time.Duration
	Op         string
}

func (e *APIError) Error() string {
	msg := strings.Join(e.Messages, "; ")
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.Op, e.Status, msg)
}

// New checks the configuration and builds the HTTP client (TLS 1.3, the client certificate if given).
func New(c Config) (*Client, error) {
	if c.Addr == "" {
		return nil, errors.New("the address of the service is not set (-addr or HSMGATE_ADDR)")
	}
	if c.Key == "" {
		return nil, errors.New("the name of the key is not set (-transit-key or HSMGATE_TRANSIT_KEY)")
	}
	if c.Mount == "" {
		c.Mount = "transit"
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	u, err := url.Parse(c.Addr)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("the address %q is not an http(s) URL", c.Addr)
	}
	tr := &http.Transport{}
	if u.Scheme == "http" {
		if host := u.Hostname(); host != "localhost" && !isLoopback(host) {
			return nil, fmt.Errorf("plain http is for a loopback address only; %q needs https and a client certificate", u.Hostname())
		}
	} else {
		tc := &tls.Config{MinVersion: tls.VersionTLS13}
		if c.CAFile != "" {
			pem, err := os.ReadFile(c.CAFile)
			if err != nil {
				return nil, fmt.Errorf("the CA file: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("the CA file %s holds no certificate", c.CAFile)
			}
			tc.RootCAs = pool
		}
		if c.CertFile != "" || c.KeyFile != "" {
			cert, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
			if err != nil {
				return nil, fmt.Errorf("the client certificate: %w", err)
			}
			tc.Certificates = []tls.Certificate{cert}
		}
		tr.TLSClientConfig = tc
	}
	return &Client{cfg: c, base: strings.TrimRight(c.Addr, "/") + "/v1/" + c.Mount + "/", http: &http.Client{Transport: tr, Timeout: c.Timeout}}, nil
}

func isLoopback(h string) bool {
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) do(ctx context.Context, op, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.base+path+"/"+url.PathEscape(c.cfg.Key), bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		// a network failure may pass: the caller decides by Retryable
		return &APIError{Op: op, Messages: []string{"cannot reach the service: " + shortNetErr(err)}, Retryable: true}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusOK {
		return json.Unmarshal(raw, out)
	}
	e := &APIError{Op: op, Status: resp.StatusCode, Retryable: resp.Header.Get("X-Hsmgate-Retryable") == "true"}
	var er struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(raw, &er) == nil {
		e.Messages = er.Errors
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		e.RetryAfter = time.Duration(s) * time.Second
	}
	return e
}

// shortNetErr keeps the useful part of a network error (a certificate problem, a refused connection) without the URL, which can carry nothing secret but is long.
func shortNetErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}

// Encrypt seals plaintext under the latest version of the key, with the given context ("" for a key in fixed mode).
func (c *Client) Encrypt(ctx context.Context, plaintext []byte, aadContext string) (ciphertext string, version int, err error) {
	req := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	if aadContext != "" {
		req["context"] = base64.StdEncoding.EncodeToString([]byte(aadContext))
	}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}
	if err := c.do(ctx, "encrypt", "encrypt", req, &out); err != nil {
		return "", 0, err
	}
	if out.Data.Ciphertext == "" {
		return "", 0, errors.New("encrypt: the answer has no ciphertext")
	}
	return out.Data.Ciphertext, out.Data.KeyVersion, nil
}

// Decrypt opens a ciphertext. The context must be the one it was sealed with.
func (c *Client) Decrypt(ctx context.Context, ciphertext, aadContext string) ([]byte, error) {
	req := map[string]string{"ciphertext": ciphertext}
	if aadContext != "" {
		req["context"] = base64.StdEncoding.EncodeToString([]byte(aadContext))
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := c.do(ctx, "decrypt", "decrypt", req, &out); err != nil {
		return nil, err
	}
	p, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, errors.New("decrypt: the answer is not base64")
	}
	return p, nil
}

// Retry runs f again while it fails with a retryable error, until wait has passed. It sleeps for Retry-After when the service gave one, else backs off from 1 s to 8 s.
// A failure that is not retryable returns at once.
func Retry(ctx context.Context, wait time.Duration, f func() error, sleep func(time.Duration)) error {
	if sleep == nil {
		sleep = time.Sleep
	}
	deadline := time.Now().Add(wait)
	delay := time.Second
	for {
		err := f()
		var ae *APIError
		if err == nil || !errors.As(err, &ae) || !ae.Retryable || time.Now().Add(delay).After(deadline) || ctx.Err() != nil {
			return err
		}
		d := delay
		if ae.RetryAfter > 0 {
			d = ae.RetryAfter
		}
		sleep(d)
		if delay < 8*time.Second {
			delay *= 2
		}
	}
}

// Explain turns an API error into a sentence for a person who is setting up a pod. It names the key and the context, never a secret.
func Explain(err error, key, aadContext string) string {
	var ae *APIError
	if !errors.As(err, &ae) {
		return err.Error()
	}
	switch {
	case ae.Status == 0:
		return fmt.Sprintf("%s (the service may be down, the address wrong, or the certificate not accepted)", ae.Messages[0])
	case ae.Status == 403:
		return fmt.Sprintf("permission denied: this client has no right to %s with key %q and context %q (or the key does not exist, or the certificate is unknown to the service)", ae.Op, key, aadContext)
	case ae.Status == 400 && strings.Contains(strings.Join(ae.Messages, " "), "cannot be opened"):
		return fmt.Sprintf("the ciphertext cannot be opened with key %q and context %q: it was sealed with another key or another context, or it is damaged", key, aadContext)
	case ae.Status == 400:
		return fmt.Sprintf("the service refused the request: %s", strings.Join(ae.Messages, "; "))
	case ae.Status == 429:
		return "the rate limit of this client for this key is spent"
	case ae.Status == 503:
		return "the service cannot answer now (the token may be locked, or the line to it is full): " + strings.Join(ae.Messages, "; ")
	}
	return ae.Error()
}
