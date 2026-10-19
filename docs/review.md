# Review notes (P8, 2026-10-19)

A self-review by the author of the code, plus fuzzing. **It is not the independent review that the plan asks for** (the card is the root of every secret): someone else should read at least `internal/backend/pkcs11.go`, `internal/face/transit/transit.go`,
`internal/scheme/ecies/ecies.go` and `internal/server/` before the real master key moves here.

## Fuzzing

Go native fuzzing, 25-30 s per target on 2026-10-19: `FuzzUnwrap` (8.4 M inputs; whatever text arrives, no panic, and a text that opens re-seals consistently), `FuzzRoundTrip` (wrap/unwrap; a different additional data never opens), `FuzzParse` (configuration), `FuzzDecryptRequest`
(any body to `decrypt`/`rewrap`: no panic, no 200, no 5xx but the retryable 503). No findings. One early failure of `FuzzDecryptRequest` was the test itself (a server per input exhausted the machine); the target now calls the handler directly. These are short runs: a longer run (hours) in CI is still to do.
Also run: `go vet`, `go test -race`, `govulncheck` (no vulnerable code reached; `golang.org/x/crypto` v0.58.0 has one open advisory, GO-2026-5932, without a fix, in a part this code does not call).

## Found and fixed in this pass

- `Unlock` on a token that was already logged in took any PIN (`C_Login` answers "already logged in") and remembered it for the next login after a lost session: a wrong PIN then cost a try. Now `ErrAlreadyUnlocked`, the remembered PIN is untouched. Test added.
- `admin_socket` removed whatever file was at that path. Now only a stale socket is replaced.
- A world- or group-readable soft key file or PIN file is refused.
- A context was unbounded and went into the audit line; capped at 1024 bytes. The request id is restricted to `[A-Za-z0-9._-]`.
- A failed audit write was ignored. Now the service **fails closed**: with the log unwritable, requests get 503 (retryable) until a probe line can be written.
- SIGINT/SIGTERM now log the tokens out and wipe the remembered PIN (`Server.Close`). Before, nothing was done at exit.
- An unknown certificate was let through `lookup-self` (earlier pass); it fails there now.

## Known and not done

- **PIN in memory**: kept as a byte slice and zeroed on close, but `Login` takes a Go `string` (a copy that cannot be zeroed) and the garbage collector may leave other copies. No `mlock`, no core-dump control beyond `LimitCORE=0` in the unit. A root user on the host can read it (threat model: not defended).
- **No global cap** on concurrent requests: each blocks on the card's single lock. The per-client, per-key limits bound it; one client with a high limit can still queue the others behind a slow card. A global limit and a queue timeout are to do.
- **No audit hash chain** (planned): a cut in the log is not visible. Ship the log off the host.
- **Timing**: `wrong_key` and `damaged` take different paths (no secret is involved: the fingerprint is public); no constant-time work was needed or done elsewhere. The unwrap path was not measured for timing leaks.
- **Relogin after a card swap**: after a lost session the service logs in again with the remembered PIN; a different card with the same label and another PIN would cost a try. The match is by label or serial; use `token_serial` for cards.
- **HTTP**: Go's `net/http` with the TLS 1.3 / mTLS settings in `internal/server`; no request body is read before the client is identified and authorised, except for the size-limited body of an authorised operation. HTTP/2 is on (the standard library's limits apply).
- **Not exercised**: SoftHSM2 in the pipeline (the script is written, not run), a second card as a replica, DKEK restore, unplugging the card under load, Kubernetes manifest, Docker build, the Woodpecker pipeline (linted only).
