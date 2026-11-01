# Long-running checks

What runs besides the tests of every push, when, what it finds, and how to run it by hand. All of it is in [`.github/workflows/`](../.github/workflows/) and runs on GitHub-hosted runners (free for a public repository); a failed scheduled soak opens an issue.

| Check | When | What it finds | By hand |
|---|---|---|---|
| **Soak** (`soak.yml`, `tools/soak`) | weekly (Saturday night), 40 minutes; or when asked, any length | a leak: goroutines, open descriptors, live heap, resident memory that keep growing; latency that creeps up; errors under load and during reloads; a damaged audit line | `go build -o hsmgate ./cmd/hsmgate && go run ./tools/soak -bin ./hsmgate -duration 30m -out soak-out` |
| **Nightly** (`nightly.yml`) | every night | rare races and order-dependent tests: `go test -race -count=12 -shuffle=on ./...`, and three runs on 1, 2 and 8 processors | `go test -race -count=12 -shuffle=on ./...` |
| **Fuzz** (`fuzz.yml`) | weekly, a minute per target; monthly, a quarter of an hour per target; or when asked | what the parsers that face the network do with bytes nobody expected (Transit, KMS-JSON, gRPC messages and names, REST routes, JWTs, the sealed format, the configuration, SigV4) | `go test -run '^$' -fuzz '^FuzzUnwrap$' -fuzztime 10m ./internal/scheme/ecies` |
| **Benchmarks** (`bench.yml`) | weekly | what the service itself costs (seal, open, sign, MAC, SigV4, JWT) on a soft token, kept for 90 days and compared with the last run by `benchstat`; read by people: shared runners are noisy and nothing fails on it | `go test -run '^$' -bench . -benchmem -count=6 ./internal/...` |
| **Scorecard, CodeQL, Trivy** | their own schedules | supply-chain and code-scanning findings | see Security on GitHub |

## The soak

`tools/soak` starts the real binary with four soft keys and certificates made by `hsmgate ca` (internal/ca), then drives all four faces from 8 workers: each round encrypts a random plaintext of 1 to 512 bytes and decrypts it, and compares. Every 30 seconds the configuration alternates between two valid ones and the service gets `SIGHUP` (a reload that also changes the policy). Every 15 seconds it reads the gauges on the admin socket after a forced collection. The first quarter of the run is the warm-up and is not judged; of the rest, the median of the middle third is compared with the median of the last third.

A run fails if, between them: goroutines grew by more than 25, open descriptors by more than 10, live heap by more than 8 MiB **and** 20 %, resident memory by more than 16 MiB **and** 20 %, or the median latency of a face by a factor of 3; if more than 0.05 % of the rounds fail; if the service does not stop cleanly on `SIGTERM`; or if the audit log has fewer lines than the successful rounds require or a line that is not JSON. The limits are flags (`-max-goroutine-growth` and the others); a healthy run moves by about 1 goroutine, 0 descriptors, 0.1 MiB of heap and 0.5 MiB of resident memory.

The artifact `soak` (30 days) holds `samples.jsonl` (every sample), `report.json`, `service.log`, `heap-start.pb.gz` and `heap-end.pb.gz` (the heap at the start of the measured part and at the end), `heap-diff.txt` (what grew between them), `cpu-middle.pb.gz` (30 seconds from the middle of runs of two minutes or more) and `goroutines-end.txt`. Open a profile with `go tool pprof -http=: ./hsmgate cpu-middle.pb.gz`, and the growth with `go tool pprof -base heap-start.pb.gz ./hsmgate heap-end.pb.gz`.

What the soak does not do: it has no card (the SmartCard-HSM's ECDH takes about 37 ms and the card serves one operation at a time; its behaviour under load, a card that is pulled out, a PIN that is refused are tried by hand with `tools/`), and it does not see a leak slower than its limits over its length (run it longer with `workflow_dispatch`: `duration` 3h finds what 40 minutes cannot).

## Profiling a running service

Off by default. In `hsmgate.yaml`, with `admin_socket` set:

```yaml
admin_socket: /run/hsmgate/admin.sock
metrics: {enabled: true}      # GET /metrics: the counters, and the gauges of the process (hsmgate_go_goroutines, hsmgate_go_heap_alloc_bytes, hsmgate_process_resident_bytes, hsmgate_process_open_fds, …)
debug: {pprof: true}          # GET /debug/pprof/…
```

Both are served on the admin socket (mode 0600) only, never on the network; `debug.pprof` needs a restart. A profile of the heap holds memory of the process, **secrets included**: take it on a machine you trust, and treat the file as a secret.

```bash
curl --unix-socket /run/hsmgate/admin.sock -o heap.pb.gz 'http://admin/debug/pprof/heap?gc=1'          # live heap after a collection
curl --unix-socket /run/hsmgate/admin.sock -o cpu.pb.gz  'http://admin/debug/pprof/profile?seconds=30' # CPU for 30 seconds (1 to 120)
curl --unix-socket /run/hsmgate/admin.sock 'http://admin/debug/pprof/goroutine?debug=2'                # every goroutine, with its stack
go tool pprof -http=: /usr/local/bin/hsmgate heap.pb.gz
```

Names: `heap`, `allocs`, `goroutine`, `threadcreate`, `block`, `mutex` (the last two are empty unless the rates are set, which the service does not do). Two heap profiles of two moments compare with `go tool pprof -base first.pb.gz hsmgate second.pb.gz`.
