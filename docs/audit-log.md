# The audit log

Every decision of the service is one line of JSON, **a refusal as well as a success**. A call is answered only after its line is written: if the log cannot be written the service answers 503 `audit log unavailable` and does nothing, and it writes a probe line until the log works again. There is never a key, a plaintext, a ciphertext or a PIN in it.

Where it goes: `audit.file` of the configuration (opened for append; a file the service creates has mode 0640 whatever its umask is, so that a log shipper in the group can read it, and a file that exists keeps its mode), or standard output when there is no file; `audit.stdout: true` writes to both (the journal, under systemd; `docker logs`; the log of the pod) ([configuration.md](configuration.md)).

## A line

```json
{"time":"2026-11-10T23:43:02.434Z","request_id":"adf8b199e374452c","client":"demo","face":"transit","key":"demo-ctx","op":"encrypt","context":"demo/a","result":"ok"}
{"time":"2026-11-10T23:43:02.458Z","request_id":"c9f71c4ea4629906","client":"demo","face":"transit","key":"demo-ctx","op":"encrypt","result":"bad_context"}
{"time":"2026-11-10T23:43:02.479Z","request_id":"ac7cb16c8f4866ac","client":"demo","face":"transit","key":"nokey","op":"encrypt","result":"forbidden"}
```

(These are lines from `hsmgate dev`: a context inside the key's `allow:`, one outside it, and a key that does not exist for this client.)

| Field | Meaning |
|---|---|
| `time` | UTC, when the line was written |
| `request_id` | the `X-Request-Id` header of the request if it has a safe one (up to 64 characters), otherwise random; the answer carries it back as `X-Request-Id`. It ties a line to a request in the log of the client |
| `client` | the `name` of the client in the configuration, as recognised by its certificate (empty when none was recognised: a handshake that failed never reaches this log, see below) |
| `face` | `transit`, `kmsjson`, `kmsgrpc`, `kmsrest`, or `admin` (unlock on the admin socket) |
| `key` | the key asked for (the token name for `admin`); absent for a call that names none |
| `op` | what was asked: `encrypt`, `decrypt`, `rewrap`, `keys` (key information), `sign`, `verify`, `derive`, ... on the other faces; `token-lookup` (a client library asking about its token); `unlock`; `audit-probe` |
| `context` | the context of the call, **public by rule** (never put a secret in a context). Written when the call was allowed or refused by the client's `contexts:` (`forbidden_context`); absent when the key's own rules refused it (`bad_context`), and for a `fixed` key |
| `result` | what was decided: the words below |

What is **not** here: a TLS handshake that failed (no certificate, an unknown CA, TLS 1.2): the service writes that to its own log (standard error), with the address, because there is no client to name ([troubleshooting.md](troubleshooting.md)).

## The result words

The class is what `hsmgate_requests_total{outcome=...}` counts at the `basic` level of the metrics ([operations.md](operations.md), "Metrics"); a word that the metrics do not know is counted as `invalid`, which is why a refused PIN and a probe are in that class too, and `other` is only a line with no result.

| `result` | Class | Meaning |
|---|---|---|
| `ok` | ok | done |
| `attempt` | ok | an unlock was tried (followed by `ok` or `refused`) |
| `forbidden` | denied | the client, key or operation is not in the policy |
| `forbidden_context` | denied | the context is outside the `contexts:` of this client |
| `unauthenticated` | denied | no valid credential for this call |
| `unknown_access_key`, `bad_signature`, `unsigned`, `malformed_signature`, `credential_mismatch` | denied | the signed faces: the credential does not check, or does not agree with the certificate |
| `bad_audience`, `bad_subject` | denied | a signed JWT that is for another audience than the ones listed (`kmsgrpc.token_audiences`, `kmsgrpc.bearer_audiences`, `kmsrest.audiences`), or whose subject is not the client ([configuration.md](configuration.md)) |
| `credential_changed` | denied | an access token that was given for a credential that has been replaced since: a new secret or public key, another client behind the same client id or issuer, or another list of the audiences the assertion had to name (`kmsgrpc.token_audiences`, `kmsrest.audiences`). The client asks for a new token |
| `address_refused` | denied | a credential used from an address it is not allowed from (`allow_from`) |
| `bad_usage`, `bad_algorithm` | denied | the key does not do that (its `kmsjson_usage`, or another algorithm than the key has) |
| `not_lockable` | denied | an unlock for a token that has no PIN (a software token, or an unknown name) |
| `refused` | invalid | the card refused the PIN (the service does not try again) |
| `throttled`, `throttled_auth` | throttled | over `per_minute` or `per_day`; or too many refused signatures from one address (the signed faces) |
| `busy` | throttled | more operations than `limits.max_concurrent` waited longer than `limits.queue_seconds` |
| `locked` | error | the card is waiting for its PIN |
| `unavailable`, `internal_error` | error | the token cannot answer now, or something else failed (nothing about it is said to the client) |
| `bad_request`, `bad_context`, `too_large`, `invalid_ciphertext`, `unsupported` | invalid | the request is wrong: a body, a context, a size, a ciphertext that does not open, a path |
| `probe` | invalid | `audit-probe`: the service checking that the log works again |

## Questions it answers

```bash
# who is being refused, and for what
jq -r 'select(.result|test("^(forbidden|forbidden_context|unauthenticated)$")) | [.time,.client,.key,.op,.result]|@tsv' audit.log
# how many of each result, per client
jq -r '[.client,.result]|@tsv' audit.log | sort | uniq -c | sort -rn
# every call of one request (the id the client logged)
jq -c 'select(.request_id=="my-trace-1")' audit.log
# who opened (decrypted) secrets of a context, and when
jq -c 'select(.op=="decrypt" and (.context//"")|startswith("k8s/shop/"))' audit.log
# unlock attempts on the card
jq -c 'select(.op=="unlock")' audit.log
```

Expect steady lines from some clients even when nobody does anything: OpenBao's `seal "transit"` asks hsmgate to `encrypt` (and now and then `decrypt`) every few seconds to check that its seal works. That is normal; a change in that rhythm, or an `encrypt` with a `result` other than `ok`, is the signal.

What to watch: a rise of `decrypt` for a client that normally only encrypts; `forbidden` or `forbidden_context` from a client that never used to get them (a probe, or a changed configuration); `locked` (the card is waiting for a person); `unavailable` (the reader, the card); any `refused` on an unlock (a wrong PIN: the card blocks after three); a gap in the lines of a busy service.

## What the log promises

- **Written before the answer.** A call is answered only after its line was handed to the file (`write`). If the line cannot be written, the call is refused with 503 and nothing is done.
- **A crash of the process loses nothing**: the line is in the cache of the kernel, which outlives the process.
- **A power loss, a kernel panic or a hard stop of the machine can lose the last lines** (the seconds the kernel keeps dirty pages: about 5 seconds for an ext4 journal commit and up to about 30 seconds for the data), although the client has had its answer. What was shipped off the host by then is not lost: a shipper that reads the file sees a line a moment after it is written, so the copy on the other side is usually more complete than the file after such a failure. **Shipping by UDP gives no acknowledgement**: a lost packet and a lost tail of the file together leave the line nowhere; use TCP or TLS for the audit. How a given shipper resumes after the file became shorter than the offset it remembers was not tried (not run for Fluent Bit of the chart).
- **`audit.sync: true`** closes that window on the host: every line is written to the disk (`fsync`) before the answer, and the directory too after a rotation, so a line that was answered for is there after a power loss. A failed `fsync` fails the call like a failed write. The name of the file must reach the disk too: after the file is created, rotated or reopened (logrotate and SIGHUP) the directory is synced before the next line is written, and while that fails every call is refused (503) and nothing is written; the first success restores the service. If the directory cannot be synced at start, the service does not start. Off by default. Cost, measured on 2026-11-22 on an NVMe disk with ext4 (LVM), one writer, `BenchmarkFileWrite` and `BenchmarkFileWriteSync` of `internal/audit`: 1.1 µs a line without it and 0.67 ms a line with it, so about 1500 lines a second at most, and all calls wait for each other at the file. A slower disk (a SATA SSD, a network disk, a hard disk) costs several milliseconds a line. Not measured: a volume of a cloud disk or a Kubernetes claim. **The lines are written one at a time, each with its own `fsync`, so the disk sets the most calls a second the service answers, however many clients there are** (the table below). A card does one operation at a time and an operation takes tens of milliseconds, so there the `fsync` matters less; with a software token it can be the limit.
- **A line that was cut short** (a power loss, a full disk) stays in the file as an unreadable piece, and without `sync` there can be a block of zero bytes. The service ends such a piece with a newline before it writes the next line, so every later line is whole. A reader of the file must skip a line that does not parse.

### What was run: hard stops, a full disk, latency

On 2026-11-28, release 0.10.0 from the deb in a virtual machine (Debian 13, Proxmox, 4 cores, ext4 on a ZFS volume, `cache=none`), a software token, the load from the host over a virtual network. A hard stop of the machine (`qm stop`) is a power loss for the guest; the disks and the caches of the host were not cut. Each acknowledged call was looked up in the files by its `X-Request-Id`.

| `audit.sync` | Stops | Acknowledged lines missing |
|---|---|---|
| `true` | 5, at a random moment under load | none of 8450 |
| `true` | 3, right after a rotation by the service | none of 389 |
| `false` | 5, at a random moment under load | between 35875 and 124894 each time (about the last 25 seconds or less) |

Latency of an `encrypt` over 20 seconds (an `fsync` of a 150-byte append took 10.7 ms in this machine, 60 ms with the disk held to 50 writes a second); the host was busy with other machines:

| Condition | `sync` | Clients at once | Calls a second | p50 | p99 |
|---|---|---|---|---|---|
| as is | off | 8 | 7253 | 1.0 ms | 2.6 ms |
| as is | on | 1 | 84 | 12 ms | 16 ms |
| as is | on | 8 | 91 | 86 ms | 104 ms |
| as is | on | 32 | 58, and 685 answers 503 | 400 ms | 454 ms |
| disk at 50 writes a second | on | 8 | 14 | 480 ms | 2.1 s |
| network delay 20 ms | on | 8 | 91 | 86 ms | 121 ms |

A full disk (an 8 MiB ext4 file system), with `sync` on and off: calls were refused with 503, the service went on when space was freed, and no acknowledged line was missing. Not run: a card, a cut of a physical machine, a network or cloud disk, a log shipper after a cut.

## Keeping it

- **Rotation:** with `audit.max_size_mb` the service rotates the file itself (`audit.log` -> `audit.log.1` -> ... up to `audit.max_files`, default 5; no line is split). Without it the file grows without limit. The file is also reopened on **SIGHUP** (before the configuration is read, so even a refused reload reopens it): a plain rename by `logrotate` then works, send `kill -HUP` in its `postrotate`; `copytruncate` works too. Do not combine `logrotate` with `audit.max_size_mb` on one file. Under systemd or in a container, standard output goes to the journal or the runtime, which rotate it themselves. Not run in a cluster.
- **Shipping:** read the file (group of the service user) or the journal; the lines are self-contained JSON. Ship it off the host: an audit log that lives only next to the service tells little when the host is the problem.
- **In Kubernetes** the chart writes to a file on an `emptyDir` (lost with the pod) unless `audit.persistence.enabled` gives it a claim, or ship it by reading the file in a sidecar of your own ([the chart](../deploy/helm/hsmgate/README.md)).
- **Integrity:** the log is a plain file: whoever can write it can change it. Keep the service user the only writer, and ship the lines away as they are written.
