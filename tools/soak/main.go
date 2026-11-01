// Command soak runs hsmgate under load for a long time and says whether it leaks. It starts the real binary with a soft key, makes its certificates with the built-in authority,
// and drives all four faces (Transit, KMS-JSON, gRPC, REST) with encrypt-and-decrypt rounds from many workers while the configuration is reloaded (SIGHUP) every so often. Every
// sample interval it reads the runtime gauges of the metrics on the admin socket (goroutines, live heap after a collection, resident memory, open descriptors) and, at the end,
// compares the later part of the run with the earlier one: a number that keeps growing fails the run. It keeps the samples, a heap profile at the start of the measured part and
// one at the end (their difference says what grew), a CPU profile from the middle, the goroutines at the end and a report.
//
//	go run ./tools/soak -bin ./hsmgate -duration 30m -out soak-out
//
// It needs nothing but the binary: no card, no openssl, no network beyond loopback.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/zystem/hsmgate/internal/ca"
)

type sample struct {
	T          float64 `json:"t"`
	Goroutines float64 `json:"goroutines"`
	HeapAlloc  float64 `json:"heap_alloc"`
	Resident   float64 `json:"resident"`
	FDs        float64 `json:"fds"`
	Rounds     uint64  `json:"rounds"`
	Errors     uint64  `json:"errors"`
}

type options struct {
	bin         string
	duration    time.Duration
	workers     int
	reloadEvery time.Duration
	sampleEvery time.Duration
	out         string
	warmup      float64
	maxErrRate  float64
	// growth limits between the middle and the end of the measured part
	maxGoroutines float64
	maxFDs        float64
	maxHeapMiB    float64
	maxRSSMiB     float64
	maxGrowthPct  float64
	maxLatencyX   float64
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "soak: "+format+"\n", a...)
	os.Exit(2)
}

func main() {
	var o options
	flag.StringVar(&o.bin, "bin", "./hsmgate", "the hsmgate binary to run")
	flag.DurationVar(&o.duration, "duration", 30*time.Minute, "how long to run")
	flag.IntVar(&o.workers, "workers", 8, "concurrent clients")
	flag.DurationVar(&o.reloadEvery, "reload-every", 30*time.Second, "send SIGHUP (the configuration alternates between two valid ones) this often; 0: never")
	flag.DurationVar(&o.sampleEvery, "sample-every", 15*time.Second, "read the metrics this often")
	flag.StringVar(&o.out, "out", "soak-out", "directory for the samples, profiles and the report")
	flag.Float64Var(&o.warmup, "warmup", 0.25, "the part of the run that is not measured (the heap and the caches fill)")
	flag.Float64Var(&o.maxErrRate, "max-error-rate", 0.0005, "the share of rounds that may fail")
	flag.Float64Var(&o.maxGoroutines, "max-goroutine-growth", 25, "goroutines that may be added between the middle and the end")
	flag.Float64Var(&o.maxFDs, "max-fd-growth", 10, "open descriptors that may be added")
	flag.Float64Var(&o.maxHeapMiB, "max-heap-growth-mib", 8, "MiB of live heap that may be added (and see max-growth-pct)")
	flag.Float64Var(&o.maxRSSMiB, "max-rss-growth-mib", 16, "MiB of resident memory that may be added (and see max-growth-pct)")
	flag.Float64Var(&o.maxGrowthPct, "max-growth-pct", 20, "a memory number fails only if it grew by more than this many percent as well")
	flag.Float64Var(&o.maxLatencyX, "max-latency-factor", 3, "the median latency of the end may be this many times the middle's")
	flag.Parse()
	if o.duration < 20*time.Second || o.workers < 1 || o.sampleEvery < time.Second {
		die("duration at least 20s, workers at least 1, sample-every at least 1s")
	}
	os.Exit(run(o))
}

type harness struct {
	o      options
	dir    string
	addr   string
	admin  *http.Client
	cfgA   string
	cfgB   string
	cfg    string
	proc   *exec.Cmd
	faces  []face
	rounds atomic.Uint64
	errs   atomic.Uint64
	mu     sync.Mutex
	errMsg map[string]int
	lat    map[string][]latency
	start  time.Time
}

type latency struct {
	at time.Duration
	d  time.Duration
}

func run(o options) int {
	if err := os.MkdirAll(o.out, 0o755); err != nil { // #nosec G301 -- results
		die("%v", err)
	}
	dir, err := os.MkdirTemp("", "soak") // short: the admin socket's path has a limit
	if err != nil {
		die("%v", err)
	}
	defer os.RemoveAll(dir)
	h := &harness{o: o, dir: dir, errMsg: map[string]int{}, lat: map[string][]latency{}}
	if err := h.setup(); err != nil {
		die("setup: %v", err)
	}
	if err := h.startService(); err != nil {
		die("start: %v", err)
	}
	fails := h.drive()
	code := h.stopService()
	if code != 0 {
		fails = append(fails, fmt.Sprintf("the service exited with status %d on SIGTERM", code))
	}
	fails = append(fails, h.audit()...)
	if len(fails) > 0 {
		fmt.Println("\nSOAK FAILED:")
		for _, f := range fails {
			fmt.Println("  -", f)
		}
		h.writeReport(fails)
		return 1
	}
	h.writeReport(nil)
	fmt.Println("\nSOAK PASSED")
	return 0
}

// ---- setup ----

func (h *harness) file(name string, b []byte, mode os.FileMode) string {
	p := filepath.Join(h.dir, name)
	if err := os.WriteFile(p, b, mode); err != nil {
		die("%v", err)
	}
	return p
}

func (h *harness) setup() error {
	// soft keys: one private key for each face's key, never two the same
	keys := map[string]string{}
	for _, l := range []string{"m1", "m2", "m3", "m4"} {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		keys[l] = h.file(l+".hex", []byte(hex.EncodeToString(b)), 0o600)
	}
	// certificates from the built-in authority
	cadir := filepath.Join(h.dir, "ca")
	now := time.Now()
	if err := ca.Init(cadir, ca.Options{Name: "soak CA"}, now); err != nil {
		return err
	}
	c, err := ca.Load(cadir, nil)
	if err != nil {
		return err
	}
	srv, err := c.Issue(ca.Request{Kind: ca.Server, IPs: []net.IP{net.ParseIP("127.0.0.1")}}, now)
	if err != nil {
		return err
	}
	cl, err := c.Issue(ca.Request{Kind: ca.Client, CN: "soak"}, now)
	if err != nil {
		return err
	}
	caPEM := h.file("ca.pem", c.CertPEM, 0o644)
	certPEM := h.file("server.pem", srv.CertPEM, 0o644)
	keyPEM := h.file("server.key", srv.KeyPEM, 0o600)
	// the credentials of the clients
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	der, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	pubFile := h.file("sa.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o644)
	sigFile := h.file("sigv4.secret", []byte(sigSecret), 0o600)
	restFile := h.file("rest.secret", []byte(restSecret), 0o600)
	// a free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	h.addr = l.Addr().String()
	l.Close()
	adminSock := filepath.Join(h.dir, "a.sock")
	base := fmt.Sprintf(`listen: %s
tls: {cert: %s, key: %s, client_ca: %s}
admin_socket: %s
audit: {file: %s}
metrics: {enabled: true}
debug: {pprof: true}
kmsjson: {enabled: true}
kmsgrpc: {enabled: true}
kmsrest: {enabled: true}
tokens: [{name: soft, type: soft, keys: {m1: %s, m2: %s, m3: %s, m4: %s}}]
keys:
  t-seal: {versions: [{token: soft, label: m1}], aad: {mode: fixed}}
  j-seal: {kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m2}], aad: {mode: fixed}}
  g-seal: {kmsgrpc: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m3}], aad: {mode: fixed}}
  r-seal: {kmsrest: true, kmsjson_usage: encrypt_decrypt, versions: [{token: soft, label: m4}], aad: {mode: fixed}}
clients:
  - name: soak
    identity: {cn: soak}
    sigv4: {access_key_id: %s, secret_file: %s}
    jwt: {issuer: %s, public_key_file: %s}
    oauth: {client_id: %s, secret_file: %s}
    keys:
      t-seal: {ops: [encrypt, decrypt]}
      j-seal: {ops: [encrypt, decrypt]}
      g-seal: {ops: [encrypt, decrypt]}
      r-seal: {ops: [encrypt, decrypt]}
`, h.addr, certPEM, keyPEM, caPEM, adminSock, filepath.Join(h.dir, "audit.log"), keys["m1"], keys["m2"], keys["m3"], keys["m4"], akid, sigFile, jwtIssuer, pubFile, restID, restFile)
	// the second configuration has one more client: a reload that changes the policy
	extra := "  - {name: ghost, identity: {cn: ghost}, keys: {t-seal: {ops: [decrypt]}}}\n"
	h.cfgA = h.file("a.yaml", []byte(base), 0o600)
	h.cfgB = h.file("b.yaml", []byte(base+extra), 0o600)
	h.cfg = filepath.Join(h.dir, "hsmgate.yaml")
	if err := copyFile(h.cfgA, h.cfg); err != nil {
		return err
	}
	// the clients
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(c.CertPEM)
	pair, err := tls.X509KeyPair(cl.CertPEM, cl.KeyPEM)
	if err != nil {
		return err
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true,
		MaxIdleConnsPerHost: h.o.workers, IdleConnTimeout: 90 * time.Second}}
	base2 := "https://" + h.addr
	h.faces = []face{&transit{c: hc, base: base2}, &kmsjson{c: hc, base: base2}, &rest{c: hc, base: base2}, &grpc{c: hc, base: base2, key: rk}}
	h.admin = &http.Client{Timeout: 150 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", adminSock)
	}}}
	return nil
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from) // #nosec G304
	if err != nil {
		return err
	}
	tmp := to + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, to)
}

// ---- the service ----

func (h *harness) startService() error {
	logf, err := os.Create(filepath.Join(h.o.out, "service.log")) // #nosec G304
	if err != nil {
		return err
	}
	h.proc = exec.Command(h.o.bin, "serve", "-config", h.cfg) // #nosec G204 -- the operator's binary
	h.proc.Stdout, h.proc.Stderr = logf, logf
	if err := h.proc.Start(); err != nil {
		return err
	}
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", h.addr); err == nil {
			c.Close()
			if _, err := h.get("/metrics"); err == nil {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.proc.Process.Kill()
	return fmt.Errorf("the service did not come up (see %s)", filepath.Join(h.o.out, "service.log"))
}

func (h *harness) stopService() int {
	h.proc.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- h.proc.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				return ee.ExitCode()
			}
			return -1
		}
		return 0
	case <-time.After(30 * time.Second):
		h.proc.Process.Kill()
		return -2
	}
}

// get reads a path of the admin socket.
func (h *harness) get(path string) ([]byte, error) {
	resp, err := h.admin.Get("http://admin" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err == nil && resp.StatusCode != 200 {
		err = fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	return b, err
}

func (h *harness) save(name, path string) {
	b, err := h.get(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "soak:", err)
		return
	}
	os.WriteFile(filepath.Join(h.o.out, name), b, 0o644) // #nosec G306 -- results
}

// ---- load ----

func (h *harness) worker(ctx context.Context, id int) {
	rng := mrand.New(mrand.NewPCG(uint64(id)+1, uint64(time.Now().UnixNano())))
	for i := id; ctx.Err() == nil; i++ {
		f := h.faces[i%len(h.faces)]
		plain := make([]byte, 1+rng.IntN(512))
		for j := range plain {
			plain[j] = byte(rng.IntN(256))
		}
		t0 := time.Now()
		err := f.round(plain)
		d := time.Since(t0)
		if ctx.Err() != nil && err != nil { // the end of the run cut it
			return
		}
		h.rounds.Add(1)
		h.mu.Lock()
		h.lat[f.name()] = append(h.lat[f.name()], latency{at: time.Since(h.start), d: d})
		if err != nil {
			h.errs.Add(1)
			msg := err.Error()
			if len(msg) > 120 {
				msg = msg[:120]
			}
			h.errMsg[msg]++
		}
		h.mu.Unlock()
	}
}

func (h *harness) reader() (sample, error) {
	// a collection first, so that the live heap of two moments can be compared
	if _, err := h.get("/debug/pprof/heap?gc=1&debug=1"); err != nil {
		return sample{}, err
	}
	b, err := h.get("/metrics")
	if err != nil {
		return sample{}, err
	}
	s := sample{T: time.Since(h.start).Seconds(), Rounds: h.rounds.Load(), Errors: h.errs.Load()}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || strings.HasPrefix(line, "#") {
			continue
		}
		v, err := strconv.ParseFloat(f[1], 64)
		if err != nil {
			continue
		}
		switch f[0] {
		case "hsmgate_go_goroutines":
			s.Goroutines = v
		case "hsmgate_go_heap_alloc_bytes":
			s.HeapAlloc = v
		case "hsmgate_process_resident_bytes":
			s.Resident = v
		case "hsmgate_process_open_fds":
			s.FDs = v
		}
	}
	return s, nil
}

// drive runs the load for the duration, reloading and sampling, and returns the reasons the run failed (none: it passed).
func (h *harness) drive() []string {
	o := h.o
	ctx, cancel := context.WithTimeout(context.Background(), o.duration)
	defer cancel()
	h.start = time.Now()
	var wg sync.WaitGroup
	for i := 0; i < o.workers; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); h.worker(ctx, i) }(i)
	}
	var fails []string
	var samples []sample
	sf, _ := os.Create(filepath.Join(o.out, "samples.jsonl")) // #nosec G304
	defer sf.Close()
	warm := time.Duration(float64(o.duration) * o.warmup)
	savedStart, cpuStarted := false, false
	reloads, reloadFails := 0, 0
	nextReload := time.Now().Add(o.reloadEvery)
	tick := time.NewTicker(o.sampleEvery)
	defer tick.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-tick.C:
		}
		if o.reloadEvery > 0 && time.Now().After(nextReload) {
			src := h.cfgB
			if reloads%2 == 1 {
				src = h.cfgA
			}
			if err := copyFile(src, h.cfg); err == nil && h.proc.Process.Signal(syscall.SIGHUP) == nil {
				reloads++
			} else {
				reloadFails++
			}
			nextReload = time.Now().Add(o.reloadEvery)
		}
		s, err := h.reader()
		if err != nil {
			fails = append(fails, "reading the metrics: "+err.Error())
			break loop
		}
		samples = append(samples, s)
		b, _ := json.Marshal(s)
		fmt.Fprintf(sf, "%s\n", b)
		fmt.Printf("t=%4.0fs rounds=%-8d errors=%-4d goroutines=%-4.0f heap=%6.1fMiB rss=%6.1fMiB fds=%-3.0f reloads=%d\n", s.T, s.Rounds, s.Errors, s.Goroutines, s.HeapAlloc/(1<<20), s.Resident/(1<<20), s.FDs, reloads)
		since := time.Since(h.start)
		if !savedStart && since >= warm {
			h.save("heap-start.pb.gz", "/debug/pprof/heap?gc=1")
			savedStart = true
		}
		if !cpuStarted && since >= o.duration/2 && o.duration >= 2*time.Minute {
			cpuStarted = true
			secs := int(math.Min(30, o.duration.Seconds()/10))
			go h.save("cpu-middle.pb.gz", "/debug/pprof/profile?seconds="+strconv.Itoa(secs))
		}
	}
	cancel()
	wg.Wait()
	if s, err := h.reader(); err == nil {
		samples = append(samples, s)
		b, _ := json.Marshal(s)
		fmt.Fprintf(sf, "%s\n", b)
	}
	h.save("heap-end.pb.gz", "/debug/pprof/heap?gc=1")
	h.save("goroutines-end.txt", "/debug/pprof/goroutine?debug=2")
	h.heapDiff()
	if reloadFails > 0 {
		fails = append(fails, fmt.Sprintf("%d reloads could not be sent", reloadFails))
	}
	fmt.Printf("\n%d rounds, %d errors, %d reloads in %s\n", h.rounds.Load(), h.errs.Load(), reloads, time.Since(h.start).Round(time.Second))
	return append(fails, h.judge(samples)...)
}

// heapDiff writes what grew between the two heap profiles (best effort: it needs the go tool).
func (h *harness) heapDiff() {
	start, end := filepath.Join(h.o.out, "heap-start.pb.gz"), filepath.Join(h.o.out, "heap-end.pb.gz")
	if _, err := os.Stat(start); err != nil {
		return
	}
	out, err := exec.Command("go", "tool", "pprof", "-top", "-nodecount=20", "-sample_index=inuse_space", "-base", start, h.o.bin, end).CombinedOutput() // #nosec G204
	if err != nil {
		out = append(out, []byte("\n(go tool pprof failed: "+err.Error()+")")...)
	}
	os.WriteFile(filepath.Join(h.o.out, "heap-diff.txt"), out, 0o644) // #nosec G306
	fmt.Printf("\nwhat grew in the heap (end minus start of the measured part):\n%s\n", firstLines(string(out), 14))
}

func firstLines(s string, n int) string {
	l := strings.Split(s, "\n")
	if len(l) > n {
		l = l[:n]
	}
	return strings.Join(l, "\n")
}

// ---- judgement ----

func median(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	c := append([]float64(nil), v...)
	sort.Float64s(c)
	return c[len(c)/2]
}

func col(ss []sample, f func(sample) float64) []float64 {
	out := make([]float64, len(ss))
	for i, s := range ss {
		out[i] = f(s)
	}
	return out
}

// judge compares the middle third of the measured part (after the warm-up) with the last third: what keeps growing is a leak; what only moved is noise.
func (h *harness) judge(samples []sample) []string {
	o := h.o
	var fails []string
	rounds, errs := h.rounds.Load(), h.errs.Load()
	if rounds == 0 {
		return []string{"no round was made"}
	}
	if rate := float64(errs) / float64(rounds); rate > o.maxErrRate {
		fails = append(fails, fmt.Sprintf("%d of %d rounds failed (%.4f%%, the limit is %.4f%%)", errs, rounds, 100*rate, 100*o.maxErrRate))
		h.mu.Lock()
		for m, n := range h.errMsg {
			fails = append(fails, fmt.Sprintf("    %d x %s", n, m))
		}
		h.mu.Unlock()
	}
	var measured []sample
	for _, s := range samples {
		if s.T >= o.duration.Seconds()*o.warmup {
			measured = append(measured, s)
		}
	}
	if len(measured) < 6 {
		return append(fails, "too few samples in the measured part to judge a trend: run longer or sample more often")
	}
	third := len(measured) / 3
	mid, last := measured[third:2*third], measured[len(measured)-third:]
	check := func(name string, get func(sample) float64, limitAbs float64, pct bool, unit float64, unitName string) {
		a, b := median(col(mid, get)), median(col(last, get))
		growth := (b - a) / unit
		rel := 0.0
		if a > 0 {
			rel = 100 * (b - a) / a
		}
		fmt.Printf("  %-11s middle %10.1f  end %10.1f  growth %+8.1f %s (%+.1f%%)\n", name, a/unit, b/unit, growth, unitName, rel)
		if growth > limitAbs && (!pct || rel > o.maxGrowthPct) {
			fails = append(fails, fmt.Sprintf("%s grew by %.1f %s (%.1f%%) between the middle and the end of the measured part; the limit is %.1f %s", name, growth, unitName, rel, limitAbs, unitName))
		}
	}
	fmt.Println("\ntrends (median of the middle third, median of the last third of the measured part):")
	check("goroutines", func(s sample) float64 { return s.Goroutines }, o.maxGoroutines, false, 1, "")
	check("open fds", func(s sample) float64 { return s.FDs }, o.maxFDs, false, 1, "")
	check("live heap", func(s sample) float64 { return s.HeapAlloc }, o.maxHeapMiB, true, 1<<20, "MiB")
	check("resident", func(s sample) float64 { return s.Resident }, o.maxRSSMiB, true, 1<<20, "MiB")
	// latency: a slow creep shows in the median
	h.mu.Lock()
	defer h.mu.Unlock()
	t0 := o.duration.Seconds()
	for _, f := range h.faces {
		var a, b []float64
		for _, l := range h.lat[f.name()] {
			sec := l.at.Seconds()
			switch {
			case sec >= t0*o.warmup && sec < t0*(o.warmup+(1-o.warmup)*2/3):
				a = append(a, l.d.Seconds()*1000)
			case sec >= t0*(o.warmup+(1-o.warmup)*2/3):
				b = append(b, l.d.Seconds()*1000)
			}
		}
		all := col2(h.lat[f.name()])
		sort.Float64s(all)
		fmt.Printf("  %-8s %7d rounds  p50 %6.2f ms  p99 %7.2f ms  (median middle %.2f ms, end %.2f ms)\n", f.name(), len(all), pct(all, 50), pct(all, 99), median(a), median(b))
		if ma, mb := median(a), median(b); ma > 0 && mb > o.maxLatencyX*ma && mb-ma > 2 {
			fails = append(fails, fmt.Sprintf("the median latency of %s grew from %.2f ms to %.2f ms", f.name(), ma, mb))
		}
	}
	return fails
}

func col2(l []latency) []float64 {
	out := make([]float64, len(l))
	for i, x := range l {
		out[i] = x.d.Seconds() * 1000
	}
	return out
}

func pct(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1) * p / 100)
	return sorted[i]
}

// audit checks the log of the service against what the clients did: every successful round is two decisions, and a line is never half written.
func (h *harness) audit() []string {
	b, err := os.ReadFile(filepath.Join(h.dir, "audit.log")) // #nosec G304
	if err != nil {
		return []string{"the audit log: " + err.Error()}
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var fails []string
	for i, l := range lines {
		var e map[string]any
		if json.Unmarshal([]byte(l), &e) != nil {
			fails = append(fails, fmt.Sprintf("audit line %d is not JSON: %.80q", i+1, l))
			break
		}
	}
	ok := h.rounds.Load() - h.errs.Load()
	if uint64(len(lines)) < 2*ok {
		fails = append(fails, fmt.Sprintf("the audit log has %d lines for %d successful rounds (at least %d were due)", len(lines), ok, 2*ok))
	}
	fmt.Printf("audit log: %d lines\n", len(lines))
	return fails
}

func (h *harness) writeReport(fails []string) {
	r := map[string]any{"rounds": h.rounds.Load(), "errors": h.errs.Load(), "duration_seconds": time.Since(h.start).Seconds(), "passed": len(fails) == 0, "failures": fails}
	b, _ := json.MarshalIndent(r, "", "  ")
	os.WriteFile(filepath.Join(h.o.out, "report.json"), append(b, '\n'), 0o644) // #nosec G306
}
