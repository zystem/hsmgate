# Own audit of 2026-10-21

Done by the author's assistant on commit `ffe42e9` (and the commits after it up to `194b4b0`), after the external crypto audit of the same day ([response](audit-response-2026-10-21.md)). It is a review with scanners and by hand, not a substitute for an independent audit; it says what was run, what it found, what was changed and what it did not look at.

## What was run

| Tool | What for | Result |
|---|---|---|
| `go vet`, `go test -race -shuffle=on` (twice) | correctness, races | clean; no flaky test in two shuffled runs |
| `staticcheck` 0.8.2 | static analysis | clean (the three deprecations of the earlier scan were in a test and are gone) |
| `govulncheck` 1.9.0 | known vulnerabilities in what is called | 0 reachable; the one in `golang.org/x/crypto/openpgp` (GO-2026-5932) is a package the service does not import |
| `osv-scanner` | dependencies, all lock files | the same single, unreachable item; the Python `cryptography` of the test requirements was updated to 50.0.2 after the external scan |
| `gosec` 2.29.0 | security patterns | 31 notes before, 0 after: 24 are G104 (unchecked errors of closing files and of the best-effort audit line of a refusal; excluded in CI on purpose), 7 were annotated with their reason |
| `semgrep` (golang, security-audit, secrets) | patterns | 1 note: the base TLS config had no `MinVersion` (fixed) |
| `gitleaks` over the whole history | secrets | no real secret ever committed; the 138 hits were hashes in the raw output of the external audit (listed in `.gitleaks.toml`) and three made-up test credentials |
| `hadolint` | Dockerfile | one note (versions of apt packages are not pinned; the base image is pinned by digest) |
| `trivy` on the image | known vulnerabilities in the image | see "The image" below |
| `readelf` | binary hardening | the binary was not a PIE and had lazy binding: fixed (below) |
| OpenSSF Scorecard | practices of the repository | 4.0 of 10, see "Practices" |
| native fuzzing, 150 seconds per target | parsers that face the network | see "Fuzzing" |
| `go mod verify`, `go list -m -u` | supply chain | all modules verified; no direct dependency has a newer version |
| by hand | SigV4, authentication, limits, files, the admin socket, reload | see "Findings" |

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| S-01 | Medium | No cap on open connections, and no cap on HTTP/2 streams per connection. Once a client may call without a certificate (`no_cert`) the listener accepts anonymous TLS handshakes, which cost the server more than the peer; the only bound was the descriptors of the process | **fixed**: `limits.max_connections` (default 128) and 16 streams per connection; test `TestLimitListener` |
| S-02 | Low | The base `tls.Config` of the server had no `MinVersion` and no `ClientAuth`; the per-connection function always returns a config with TLS 1.3, so nothing was exploitable, but a future change that returned nothing would have fallen to the defaults | **fixed**: a floor of TLS 1.3 |
| S-03 | Low | The date of the SigV4 credential scope was accepted when it was any *prefix* of `X-Amz-Date` | **fixed**: exactly the eight digits; `TestScopeDateMustBeTheDay` |
| S-04 | Low (hardening) | The binary was a non-PIE executable with lazy binding | **fixed**: `-buildmode=pie` and `-z relro -z now` in the Dockerfile and in CI, which checks `DYN` and `BIND_NOW` |
| S-05 | Medium (supply chain) | The image `debian:bookworm-slim` carries 97 packages the service does not use; Trivy: 5 critical, 68 high. Three critical and four high have a fix in a newer base (the digest is old, Renovate will move it); the rest have none, and sit in `perl-base`, `util-linux`, `mount`, `bsdutils`, `gzip` | **fixed** (the Dockerfile is now distroless, 2026-10-21): a `distroless` image built from the same sources has 0 critical and 1 high (`libssl3`, no fix), is 41.6 MB instead of 99.3 MB, loads the OpenSC module and found the real card (`hsmgate check` in a container on the production machine: the key was seen, the token `locked` as expected). The image is checked in CI by a dry-run build (`image` step) |
| S-06 | Info | `authn`, `policy`, `gate` and `audit` had no tests of their own (they were covered through the faces) | **fixed**: direct tests (chain, usage, expiry, CN/URI/pin, empty identity; deny by default, budgets, contexts; the finite line; one line per event) |
| S-07 | Info | No security policy file; no static analysis in CI | **fixed**: `SECURITY.md`; a `static` step (staticcheck, gosec) in CI, versions tracked by Renovate |
| S-08 | Info | Operational: after the Docker daemon restarted on the production machine (00:53; the cause was not looked into) the container came back by itself and logged in again from the PIN file | noted: the unattended restart works because the PIN file is on the disk of the host (root, 0400); that is the trade-off of `pin_file` and is in the operations notes |

Nothing found that gives an attacker the key, a plaintext or a signature without a credential and a grant.

## Looked at by hand, found sound

- **SigV4** (`internal/sigv4`): scope (region, service), skew, required signed headers, sorted signed headers, header folding and multi-value headers, canonical query, payload hash (after CR-04 the real hash only), constant-time comparison; known-answer test of the published vector. Duplicate `X-Amz-Target` headers cannot select an operation other than the signed one because the signature covers all values.
- **Authentication** (`internal/authn`): the chain is judged again at every request with the client-auth usage; the CN is the last resort; an empty identity matches no certificate.
- **Files**: `ReadSecretFile` resolves symlinks, opens the target with `O_NOFOLLOW` and `O_NONBLOCK`, judges by `fstat` (regular file, no group/other access, owner, size). The admin socket is created under a `0177` umask, then `chmod 0600`; a path that is not a socket is never replaced.
- **Limits**: bodies are bounded before authentication (64 KiB on the KMS-JSON face; on Transit by `max_bytes` of the key), headers 16 KiB, read/write timeouts, the finite line to the token with a wait, a per-client budget; refused signatures of requests without a certificate are counted by address.
- **Audit**: one JSON line per event, hostile values stay on their line, fixed names for peers nobody knows, a failed write makes the service stop answering; metrics have no label a peer chooses.

## The image

| | `debian:bookworm-slim` (now) | `distroless/base-debian12` (tried) |
|---|---|---|
| size | 99.3 MB | 41.6 MB |
| critical / high (Trivy) | 5 / 68 | 0 / 1 |
| with a fix available | 7 | 0 |
| shell and package manager | yes | no |
| the OpenSC module and the real card | works | works (checked) |

`scratch` is not possible with the card (the module needs `glibc`, `libopensc` and a chain of GLib libraries) but is for a software-token-only image. The recipe that was tried is a multi-stage Dockerfile that installs `opensc-pkcs11` and `libpcsclite1` in a Debian stage, copies the module, `libpcsclite` and every library `ldd` lists (except the core of glibc) with `cp --parents -L` into `/rootfs`, and starts from the distroless base; the run user stays 10001 (the production compose file overrides it to root for the sake of `pcscd`'s polkit).

## Fuzzing

Native Go fuzzing, 150 seconds per target (on a laptop, with other work running), the parsers that face the network:

| Target | executions | result |
|---|---|---|
| `FuzzDecryptRequest` | 6 127 338 | PASS |
| `FuzzUnwrap` | 32 069 839 | PASS |
| `FuzzRoundTrip` | 2 550 324 | PASS |
| `FuzzParse` | 7 711 598 | PASS |
| `FuzzVerify` | 26 787 361 | PASS |
| `FuzzParseBlob` | 14 375 641 | PASS |
| `FuzzRequestBody` | 147 326 (second run) | PASS |

`FuzzRequestBody` (an HTTP request per execution, so the slowest) was reported as "hung" twice in the first runs, while the laptop was loaded by other programs (load average above 40): the Go fuzzer gives an execution 10 seconds, and the worker did not get the processor. The inputs it saved pass alone in milliseconds (they were removed), and the rerun with `-parallel 2` on a quieter machine passed. So: no crash, no hang caused by the service, no invariant broken. This is a smoke of a few minutes, not a campaign; a continuous run (a scheduled step in CI exists, and OSS-Fuzz or ClusterFuzzLite would be the next step) finds what minutes do not.

## Practices (OpenSSF Scorecard 4.0 of 10)

Done: licence, dependency-update tool, fuzzing, no binaries, vulnerabilities (1 unreachable). Added now: a security policy. What is left is for the owner of the repository: **branch protection** and **code review** (a single maintainer: a protected `main` with required checks, even with no reviewer, is a gain), the **OpenSSF Best Practices badge** (a questionnaire at bestpractices.dev), **signed releases** (sign the binary and the image, for example with `cosign`, and publish the signature next to them), **pinned CI images** (Renovate will propose the digests), and time (the repository is young).

## What this audit did not do

Hardware evidence (the random number generator of the card for ECDSA, the attributes and non-extractability of the real keys, a second card model), side channels, a formal proof of the constructions (the MAC point is the project's own, not RFC 9380), a penetration test of a live deployment, a review of the Go standard library and of the OpenSC module, revocation of client certificates (there is none: a client is removed by the configuration or by replacing the CA, as the threat model says). A review by people who did not write the code is still needed.

## Where to ask for a public audit

The honest picture first: the programs that give audits for nothing are meant for software with many users, and this project is a few weeks old with one deployment. What fits, in the order I would try:

1. **Free and at once.** Turn on GitHub's private vulnerability reporting for the repository (the `SECURITY.md` refers to it), earn the [OpenSSF Best Practices badge](https://www.bestpractices.dev/) (a questionnaire), protect `main`, sign releases. These cost nothing, and every funded program below asks for them.
2. **A design review by people, free.** The two places where a second pair of eyes matters most are the cryptographic constructions (`ecies1`, the derived MAC key, the blob binding) and the authentication of the KMS-JSON face. Ask on [Cryptography Stack Exchange](https://crypto.stackexchange.com/) (one question per construction, with the formulas of `docs/audit-*/CRYPTO.ru.md` and `docs/specs/ecies1.md`) and on the cryptography and security mailing lists and forums you read; send the external audit and its response with the request.
3. **[OSTIF](https://ostif.org/)** (Open Source Technology Improvement Fund) arranges and funds audits of open-source projects with partner firms; a project applies through the [Linux Foundation LFX Crowdfunding](https://docs.linuxfoundation.org/lfx/crowdfunding/apply-for-crowdfunding/add-a-project-for-security-audit) form or writes to OSTIF; OSTIF decides and sets a funding goal. Its [minimum standards for an audit](https://ostif.org/open-source-security-audit-minimum-standards-expectations/) list what the project must provide. A project with one user may not be chosen; the application costs an afternoon.
4. **[Sovereign Tech Resilience](https://sovereign.tech/programs/bug-resilience)** (Sovereign Tech Agency, Germany; security reviews with OSTIF) is for widely used infrastructure software: apply when hsmgate has users beyond the author.
5. **[NLnet NGI Zero](https://nlnet.nl/NGI0/)** pays for independent audits (by Radically Open Security) of projects it funds; it is a grant (5 000 to 50 000 euro) that comes first, and I could not confirm that its calls are open now: look at nlnet.nl.
6. **Paid, small, now.** A scoped review of the crypto and the two faces by a firm that publishes its reports (Radically Open Security is a non-profit; Cure53, Trail of Bits, Quarkslab and others do open-source work). I did not check prices or availability. A scoped review of this code (about 6 000 lines of Go outside the tests) is days, not weeks, and its report can be published.
7. **Continuous fuzzing.** [OSS-Fuzz](https://google.github.io/oss-fuzz/getting-started/) takes projects with a significant user base or critical to infrastructure (a pull request with a `project.yaml`; Go native fuzz targets are supported, seeds from `F.Add` are not used there); until hsmgate qualifies, ClusterFuzzLite or the scheduled `fuzz` step already in CI do the same on your own machines.

What to put in the request: the threat model, the two audit reports and their responses, `docs/specs/`, the commands to run the tests, the fuzz targets, the list of what was not checked (hardware randomness of the card, side channels), and a statement of what you want reviewed first.
