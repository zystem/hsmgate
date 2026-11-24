# Changelog

## Unreleased

### Added
- **`audit.sync`** (the review of 2026-11-21; off by default; needs `audit.file`; a restart): every audit line is written to the disk (`fsync`, and the directory after a rotation) before the call is answered, so that a line that was answered for survives a power loss. A failed `fsync` fails the call (503 `audit log unavailable`). Measured on an NVMe disk with ext4: 0.67 ms a line against 1.1 µs without it. [docs/audit-log.md](docs/audit-log.md) now says exactly what the log promises without it (a crash of the process loses nothing, a power loss can lose the last seconds) and what shipping by UDP does not. Not run: a real power cut; the shipper of the chart after such a cut.

### Fixed
- **A REST client that proves itself with a certificate works with the official Azure Go library.** The library signs the client assertion with PS256 and writes `nbf` and no `iat`; the REST face took RS256 and `iat` only, so such a client was refused (found on 2026-11-21 by a test against the library; the face had only been tried with a client secret). The REST face now takes PS256 (RFC 7518 section 3.5) and both faces take `nbf` as the time of issue when there is no `iat`; a token with neither is refused, one whose `nbf` is still ahead is not valid yet. The gRPC face still takes RS256 only. New test of the SDK module `test/kmsrest-sdk`. Other Azure libraries were not tried.
- **The gRPC face zeroes more of what held a plaintext** (the review of 2026-11-21, finding 3): the request buffer, the message of the reply and the frame that is handed to the writer are zeroed when the call is done. The threat model now says, per face, what is zeroed and what cannot be (a plaintext that goes through a JSON string; the buffers of the HTTP stack): [docs/threat-model.md](docs/threat-model.md).
- **The REST client secret is compared as a digest** (the review of 2026-11-21). `subtle.ConstantTimeCompare` answers at once when two values differ in length, so the time of a refusal told the length of the secret to someone who tried secrets of every length. The face now keeps only the SHA-256 of the secret (not the secret itself) and compares the digest of the secret that is presented with it, in constant time, with the same work for a client that has no secret (a client of a certificate). Tested with tries that are empty, shorter, longer, a prefix and the digest itself. A timing measurement was not made.
- **Secrets in memory: what the service wipes** (the review of 2026-11-21, finding 3, the second part). The PIN on the admin socket was decoded into a Go string, which cannot be wiped; it is now read as bytes (the body and the PIN cut out of it) and both are zeroed when the request is done. A PIN kept for the next login is zeroed when the card refuses it (it was only dropped). The ECDH shared secret and the key made from it in ECIES wrap and unwrap are zeroed. What is not in reach (the PKCS#11 binding takes the PIN as a Go string, the AEAD and curve code keep their own copies) is written in [docs/threat-model.md](docs/threat-model.md). The `unlock` request is the same JSON as before; a `pin` that is not a string (`null`, a number) is now a 400.
- **A reload no longer accepts a change of `debug.pprof`, `metrics.enabled` or `metrics.detail`** (the review of 2026-11-21, finding 5). They are set up when the process starts, so a reload that changed one was accepted and did nothing: an operator who turned the profiles off with SIGHUP still had them. The reload is now refused with "cannot change in a reload: restart", in both directions, and the running configuration stays as it was.

### Security
- **The table of access tokens no longer empties itself** (the review of 2026-11-21, finding 4). At 10 000 live tokens the table was replaced by an empty one, so that one client that asked for many tokens made every other client ask again at once. Now a client holds at most 100 live tokens (the next one ends its own oldest), and when the whole table is full the oldest token of the client that holds the most ends; the expired ones are dropped first. Tested: one busy client keeps the sessions of the others; a full table gives up one token for one new one.
- **An access token ends with the credential it was given for** (the review of 2026-11-21, finding 2). A token lived for its hour even after the secret or the key of its client was replaced; now every token carries a stamp of the client, the issuer and the secret or public key, and a call with a token whose stamp is not the one of the credential now is refused (`credential_changed`). A new secret, a new key, or another client behind the same client id or issuer ends the old tokens at the next call, without waiting for the hour and without a restart; a reload that changes nothing leaves them, and the tokens of other clients are not touched. Tested with rotation and rebinding on both faces. [upgrading.md](docs/upgrading.md).
- **The audience and the subject of a JWT** (the review of 2026-11-21, finding 1). A JWT that a client signs was checked for its signature and its dates only, so one made for one service was good for every service that trusts the same issuer. Now there are `kmsgrpc.token_audiences` and `kmsgrpc.bearer_audiences` (the assertion of the token exchange and a JWT used as the bearer have their own lists) and `kmsrest.audiences` (the client assertion). When a list is set, a token that names none of its values is refused (`bad_audience`). **The lists are empty by default and then nothing is checked, as before**: set them when more than one gateway or environment trusts the same issuer, and, better, give each its own service account. The **subject** is checked always: on the gRPC face it is the issuer or absent; on the REST face it must be the client id (RFC 7523 section 3: the documentation said so, the code did not check), and a REST client assertion without `sub`, or with another one, is refused (`bad_subject`). [upgrading.md](docs/upgrading.md).

## 0.9.4 — 2026-11-20

### Added
- **A SELinux module for the service** (the rpm; optional): the service runs as `hsmgate_t` instead of `unconfined_service_t`. The sources and `install.sh` are in `/usr/share/hsmgate/selinux/`; CI compiles the module on AlmaLinux 10. [docs/selinux.md](docs/selinux.md). Run on AlmaLinux 10.2 with a card in the enforcing mode, also after a reboot: no denial.
- **A polkit rule for the service account** in the deb and the rpm (`/usr/share/polkit-1/rules.d/50-hsmgate.rules`): without it `pcscd` refuses the account `hsmgate`, and a card is "no matching token in the reader" on a clean machine (found on AlmaLinux 10.2 with a card, 2026-11-20).
- `tools/retry-net.sh`: what CI downloads is run again when the network fails, and only then.
- A CI job `arm64` builds both programs and runs the tests on a native arm64 runner. The release still ships amd64 only.

### Fixed
- **The cache of derived MAC keys** (`kmsjson.mac_cache_seconds`; the review of 2026-11-21, finding 3). A key now leaves memory when its time is up (a timer of the cache wipes it; before, it stayed in the map until it was asked for again or replaced), and a request that began before a reload and finished after it can no longer put its key into the cache of the new generation (the cache has an epoch per generation, moved on after the new generation is published). The two copies of the cache (the KMS-JSON face had its own) are one. Tested with the timer, a clock of the caller's own, and a request held inside the token across a reload. Still true, as in the documentation: a cache puts a derived secret in the memory of the process for the TTL, and the default is off.
- **`hsmgate-setup -auto -mode card` as a person without root** did not look for the OpenSC module and said only "a card needs the PKCS#11 module, the label … and the CKA_ID …"; it now looks for the module as root does and names what is missing.
- **The quick setup on a machine that has the programs but no systemd unit** (an unpacked archive) said "Unit hsmgate.service does not exist (see: journalctl -u hsmgate)"; it now says that there is no unit and where to get it.
- **The deb's installation** no longer starts the wizard when `TERM` is unset or `dumb` (it printed a terminfo error from a session with no terminal).

## 0.9.3 — 2026-11-19

The **Card** page of `hsmgate-setup` grows from a reader into a card manager (PINs, key domains, DKEK shares in two formats, wrapped keys, key generation for EC, RSA and AES, the first steps of an XKEK group), and what was tried on a real card and on AlmaLinux with SELinux found five faults that are fixed here. XKEK with two cards (association, exchange keys, derivation) is not done, and arm64 packages are not built (the programs were built and run on emulated arm64 only): [setup-tool.md](docs/setup-tool.md) and [installing-packages.md](docs/installing-packages.md) say what was run and what was not.

### Fixed
- **`hsmgate-setup -auto` no longer gives `/etc/hsmgate` to the service account**: the directory stays `root:hsmgate 0750` as the package makes it (the service reads it through its group), so `rpm -V` is clean after a setup. The unit sets `LogsDirectoryMode=0750` (systemd made the audit directory 0755 at the first start, against the 0750 of the package); the same two lines are in `deploy/hsmgate.service`. Found by trying the rpm on a machine with SELinux.
- **The SO PIN** is taken as 8 characters or as 16 hexadecimal digits (how the vendor's tools write it); a 16-digit SO PIN was refused with `6A80`. Found on a real card; the change of the SO PIN and the unblocking were run there.
- **Generating an RSA key on the Card page** failed with `6700` on a real card: the answer is longer than a short Le can hold, so the command now uses extended lengths (RSA-2048 was made, wrapped, unwrapped and deleted on the real card). Found by the new real-card tests.
- **Changing the User PIN**: the card refuses a new PIN of another length than the current one (`6A80`); the page and the library now say so before any try is spent.
- The quick setup in card mode no longer says that the card "is locked until it gets its PIN" when a PIN file was given: it says that the service reads the PIN from that file. Found by running the wizard on a real card.

### Added
- **AES keys on the Card page**: generate an AES key of 128, 192 or 256 bits (encrypt/decrypt, CMAC, derivation, wrap) in a key domain; it shows in the tree as AES-n and can be wrapped and unwrapped like the others. Made, wrapped, unwrapped and deleted on the real card.
- **The Card page of `hsmgate-setup`**: the tree of a SmartCard-HSM as a card manager shows it (the User PIN and SO PIN with the tries left, the key domains with the key check value of their DKEK, a DKEK still being set up, an XKEK, the keys in them, and whether the configuration names a key), with a line on the right that says what each line means; with more than one card in readers it asks which. **Enter on a line lists what can be done with it**: change the User PIN or the SO PIN, unblock the User PIN with the SO PIN, make a DKEK share file (the **strong** format by default: AES-256-GCM and PBKDF2-HMAC-SHA-256; or the **compatible** one that the vendor's card managers read: AES-256-CBC with an MD5 key derivation; the page opens both), create a key domain, import a share, delete the DKEK or a key domain, **export a key to a file (wrap, the backup) and import it (unwrap)**, delete a key. The commands are the card's own, sent through `opensc-explorer` fed by a pipe, so a PIN is never in a command line; the page asks for the PIN in a masked field, does not send it when one try is left, and asks for a word for what cannot be undone. Reading changes nothing. It needs `opensc-tool` and `opensc-explorer` (the package opensc) and `pcscd`. Tried on a real card ([docs/setup-tool.md](docs/setup-tool.md), [docs/tokens/smartcard-hsm.md](docs/tokens/smartcard-hsm.md)); **generate a key** (EC P-256 or RSA, with a label and its use) and the first steps of an **XKEK** group: export the device ID, sign a key domain membership with a key on the card, create an XKEK key domain from a membership file (tried on the real card with the card as its own member). Not done: the association of XKEK domains, exchange keys and the derivation of an XKEK (they need a second card), AES keys. The sections of the menu are now numbered 1 to 8 (Card is 3, the ones after it moved by one).

## 0.9.2 — 2026-11-15

Two fixes found by trying 0.9.1 on a real host: `hsmgate ca` reads an authority key made with OpenSSL, and the setup tool no longer calls an untouched configuration "unsaved". Documentation of what was run on 0.9.1 and of the signatures of the SBOM and the VEX document.

### Added
- **`hsmgate ca` reads an authority key in SEC1 form** (`BEGIN EC PRIVATE KEY`, as `openssl ecparam -genkey` writes it) as well as PKCS#8; before, `ca client` and `ca server` on such a `ca.key` failed with `x509: failed to parse private key (use ParseECPrivateKey instead ...)`. P-256 only, as before; a test signs with a SEC1 key and refuses a damaged one and a P-384 one. Run 2026-11-15: a client certificate made with an OpenSSL-made authority key verifies with `openssl verify`. Not run: the key on the host that showed it (it was not copied).

### Changed
- **`hsmgate-setup` no longer calls an untouched configuration "unsaved"**: a file written by hand (aligned comments, blank lines) was compared with its own text after being written again, so it counted as changed at once, showed "(unsaved)" in the title and asked about saving on exit. It is now compared with itself written again; an edit still counts, and so does nothing else. Found on 2026-11-15 by looking at the tool on a real configuration. Test: `TestAnUntouchedHandWrittenFileIsNotChanged`.
- Documentation: the SBOM and the VEX document carry the `cosign` signature only, no build provenance attestation ([verifying-releases.md](docs/verifying-releases.md), what was run on v0.9.1); the AppImage does not start inside a container on a machine that registers AppImages with a launcher ([installing-packages.md](docs/installing-packages.md), [troubleshooting.md](docs/troubleshooting.md)); what was run on the files of 0.9.1, and on a real card.

## 0.9.1 — 2026-11-15

The number 0.9.0 was tagged but never released: its release run stopped before anything was published (the packaging step lost the execute bit of the downloaded programs, fixed in the workflow), so there is no 0.9.0 release and no 0.9.0 image. What was made for it is in this release.

A terminal tool for operators (`hsmgate-setup`) with a quick setup, and packages for Debian, Fedora and AppImage. The configuration stays YAML ([why](docs/why-yaml-not-sqlite.md)). The image carries a fixed `libssl3`.

### Added
- **`hsmgate-setup`, a terminal tool** in the manner of the installers of Debian and YaST ([setup-tool.md](docs/setup-tool.md)): menus to look at and change the tokens, keys (create, rotate, delete), clients and their rights, the faces, the audit settings, to read the audit log and to unlock a card; every change is made in the document, shown as a diff, checked with the loader of the service and written atomically with a backup. It edits `hsmgate.yaml`, which stays the one source of truth ([why not SQLite](docs/why-yaml-not-sqlite.md)). It is a program of its own (a module, `tui/`), so that the service does not carry a terminal library. `hsmgate setup` starts it.
- **A quick setup** (a wizard of six pages, or `hsmgate-setup -auto` with no screen): a configuration, a key file or a card, the authority and the certificates of the service and of the first client, the check as the service account, the unit, and the commands that work now.
- **Packages**: a `.deb`, an `.rpm` and an AppImage ([installing-packages.md](docs/installing-packages.md)), built by `packaging/build.sh` (nfpm and appimagetool, pinned), signed and attested with the other assets of a release. The package makes the account and the directories, installs the unit (it starts only when a configuration exists), and offers the quick setup after a first installation: by itself at a terminal, with `HSMGATE_SETUP_AUTO=1` with no screen, otherwise it says what to do. It never starts or restarts the service, and removal keeps the configuration, the keys and the audit log. The Packages workflow builds them and installs them in clean containers on every change to `packaging/` or `tui/`.
- CI: a `tui` job (tests under the race detector, a coverage floor, govulncheck, staticcheck, gosec) for the new module; Dependabot watches it.

### Security
- The image carries `libssl3` 3.0.22 (CVE-2026-84782, a DTLS retransmission read in OpenSSL; the code is not used by hsmgate, [VEX](vex/hsmgate.openvex.json)): the distroless base still holds 3.0.20, so the Debian stage supplies the library and the package record, and the build fails if the record is older. Trivy on the image: none (run 2026-11-15).
- The setup tool parses the ids of an account with a 32-bit limit (CodeQL `go/incorrect-integer-conversion`).

## 0.8.0 — 2026-11-13

The audit can be rotated, reopened and sent to the container output; the chart gets a Fluent Bit sidecar, `extraContainers` and `extraVolumes`; every API has an OpenAPI file and a page on GitHub Pages. **The chart no longer writes the audit file by default** ([upgrading.md](docs/upgrading.md)). The number 0.7.4 was prepared but never tagged: what was prepared for it is in this release.

### Added
- **Audit file rotation and reopening**: `audit.max_size_mb` / `audit.max_files` rotate the file in the service (`audit.log.1` ...); the file is reopened on SIGHUP (so `logrotate` with a rename works). Helm chart: `audit.maxSizeMB` (default 25; 150 MB at most with `maxFiles` 5, and a pair that does not fit the 256 MiB `emptyDir` is refused), `audit.maxFiles` (5), `audit.file` (default **false**: the audit goes only to the output of the container, `kubectl logs`; a chart upgrade no longer writes the file unless `audit.file=true`). Tests: rotation, reopen after a rename, the rules of the settings. Not run in a cluster; the signal path of `serve` is not tested.
- **`audit.stdout: true`**: with `audit.file`, every audit line is also written to standard output (for a log collector of a container). Without a file the audit was already on standard output. Needs a restart. Not tested by a test of its own; not run.
- **Helm chart: optional Fluent Bit sidecar** (`fluentbit.enabled`, `fluentbit.outputs`, `fluentbit.filters`, off by default; needs `audit.file=true`) that ships the audit file to any Fluent Bit output. [examples/falco](deploy/helm/hsmgate/examples/falco/README.md): Falco configuration, three rules and a Vector configuration (the Falco collector takes one event per POST, which Fluent Bit cannot send). Run in Docker, not in a cluster.
- **Helm chart: `extraContainers` and `extraVolumes`** (a Pod-spec list each, empty by default) for sidecars of your own; [examples/vector-sidecar-values.yaml](deploy/helm/hsmgate/examples/vector-sidecar-values.yaml) runs Vector this way. `helm lint` and `kubectl apply --dry-run=client`; not run in a cluster.
- **API reference**: OpenAPI files for every API of the service in `api/` (`kms-json.yaml`, `kms-rest.yaml`, `kms-grpc.yaml`, `admin.yaml`, next to the Transit `openapi.yaml`), a page that shows them all ([api/index.html](api/index.html), Scalar, read-only), and a workflow that publishes `api/` to GitHub Pages when a file there changes on `main` (the owner sets Settings, Pages, Source to "GitHub Actions" once). `internal/apispec` checks the files against the code. The service itself still serves no UI. gRPC is described as OpenAPI for lack of a better page; the answer fields of the new files are written from the code and are not tested.
- **`hsmgate ping -cert -key -ca [-name]`**: a health check that makes the whole TLS 1.3 handshake (the certificate of the service checked against the CA) with a client certificate that no client of the policy names, so it has no rights, sends no request and leaves no audit line. The Helm chart makes such a certificate (`<release>-probe`, CN `hsmgate-probe`) and its probes use it (`probe.tls`, on by default with the generated certificates; otherwise a TCP connect as before).
- **[docs/writing-docs.md](docs/writing-docs.md)**: how the pages are written (one of four kinds: tutorial, how-to, reference, explanation; a command with what it prints; what was not run) and which test keeps which page equal to the program. [docs/README.md](docs/README.md) says which kind each page is.
- **[docs/cli.md](docs/cli.md)**: every command and flag, generated from what `hsmgate <command> -h` prints; a test fails when the page differs from the program (`go test ./cmd/hsmgate -run CLIReference -update` rewrites it). `hsmgate` with no arguments, `hsmgate help` and `-h` list the commands with one line each; `serve` and `check` no longer show the flags of `unlock`; `dev -h` shows its flags. `hsmgate dev` for a listener on every address (`-listen 0.0.0.0:8443`, as in a container) now tells the client `127.0.0.1`, not `[::]`; the README shows how to try it with `docker run` and no Go.

### Changed
- Helm chart: with `audit.file=true` the keys `stdout`, `max_size_mb` and `max_files` are written into the configuration only when they are on, so an image that does not know them (up to v0.7.3) still starts with `audit.stdout=false` and `audit.maxSizeMB=0`. Run in a Talos cluster on 2026-11-13 with `ghcr.io/zystem/hsmgate:v0.7.3`: the audit in `kubectl logs`, the Fluent Bit sidecar, `extraContainers`/`extraVolumes` (details in the chart README).
- Helm chart: `audit.file` defaults to **false**; the audit goes only to the output of the container (`kubectl logs`). Set `audit.file=true` to keep the file as before.
- The service no longer writes `http: TLS handshake error from <address>: EOF` (a TCP connect that closed without a byte: a Kubernetes TCP probe, a load balancer, a port check). Every other handshake error is still written.
- Helm chart, tried in a cluster (2026-11-12, chart 0.7.3 and the OpenBao chart): `helm test` passes, OpenBao initialises through hsmgate, restarts and unseals itself. The OpenBao values in `deploy/helm/hsmgate/examples/openbao-helm-values.yaml` were wrong for current OpenBao (no `file` storage) and now use the integrated raft storage; the chart README says what was run and what was not, and that a namespace enforcing the `restricted` Pod Security Standard refuses the pod (uid 0). Troubleshooting and the audit-log page explain the probe handshake noise and OpenBao's periodic seal check.

## 0.7.3 — 2026-11-11

### Security
- **GO-2026-6859** (net/http: an HTTP/1 server crash through a race on the headers of a request body that `http.MaxBytesReader` limits). The Go standard library of the 0.7.2 binaries (Go 1.26.10) and images (Go 1.27.3) has it, and the program reaches it (`govulncheck` says so, and the CI of `main` failed on it). Built with Go 1.26.11 (the binaries) and 1.27.4 (the images), `govulncheck` is clean on the sources and on the program inside both images. Update from 0.7.2.

### Added
- **[docs/production.md](docs/production.md)** (a checklist before it holds real keys: the token and its backup, the PIN, the policy, certificates, the network, the audit log, the software, drills), **[docs/faq.md](docs/faq.md)** and **[docs/supported-versions.md](docs/supported-versions.md)** (which release is supported until when).

### Changed
- README: "Try it in a minute" shows what each command prints and ends with next steps; a test (`TestTryItOutputsAreWhatTheReadmeShows`) runs those commands against `hsmgate dev` and fails when what they print is not what the README shows.

## 0.7.2 — 2026-11-10

### Added
- **[docs/audit-log.md](docs/audit-log.md)**: the audit line field by field, every result word with its class in the metrics, questions the log answers (`jq`), what to watch, rotation (`copytruncate`; the file is not reopened on SIGHUP) and shipping. Tests keep the fields, the result classes and the metric names equal to the code.
- **[docs/configuration.md](docs/configuration.md)**: every setting of `hsmgate.yaml` with its default, what is required, and what needs a restart or only a reload; a test fails when a setting is added without a line there, and another keeps the stated defaults equal to the code's. The smallest configuration, `deploy/hsmgate.minimal.yaml` (tested); [docs/guides/clients.md](docs/guides/clients.md) (recipes for the command line, `curl`, OpenBao and Kubernetes, tried against `hsmgate dev`); [docs/README.md](docs/README.md), the index of the documents by what the reader wants.
- **`hsmgate dev`**: a throw-away service to try hsmgate in a minute with no hardware and nothing to prepare (a software token with a fresh key, a CA of its own, the certificate of the service and of a client `demo`, the keys `demo` and `demo-ctx`). It prints the commands to type (`hsmgate encrypt`/`decrypt` with the files it made). Without `-dir` everything is deleted at the stop; `-dir DIR` keeps it. Not for real keys.
- **[docs/troubleshooting.md](docs/troubleshooting.md)**: what the client sees and what the service says at its start (message, meaning, what to do), for a container or a cluster, and for OpenBao.

### Changed
- README: starts with what hsmgate is for (and is not for), a picture, the try-it path, a table of ways to install, a glossary and the documents by what the reader wants; the status moved to the end.
- Helm chart: **the chart makes the TLS files itself** (a CA, the certificate of the service and a certificate per client in `tls.generate.clients`; made once, reused on upgrade, kept on uninstall) when `tls.existingSecret` is not set, so `helm install` needs no cert-manager and no prepared Secret; an optional Ingress that passes the TLS through (`ingress.enabled`, `ingress.host`); an example of connecting OpenBao (`examples/values-openbao.yaml`, `openbao-seal.hcl`); [`examples/cert-manager.yaml`](deploy/helm/hsmgate/examples/cert-manager.yaml) makes the TLS Secret (a CA of its own, the certificate of the service, a client certificate) and the README says how to use it, why the chart has no Ingress (a proxy that ends TLS hides the client certificate) and how to reach the service from outside (LoadBalancer, TLS passthrough).

## 0.7.1 — 2026-11-09

### Added
- **Helm chart** (`deploy/helm/hsmgate`, [README](deploy/helm/hsmgate/README.md)) for a software token (tests, development, pilots): the configuration as values, TLS from a Secret, generated soft keys that are kept on uninstall, an optional claim for the audit log, an optional NetworkPolicy, `helm test`. The release publishes it as an OCI artifact, `oci://ghcr.io/zystem/charts/hsmgate`, signed (cosign, keyless) with a build provenance attestation, and as an asset of the GitHub release. CI lints and renders it and validates the result with kubeconform.

### Changed
- Documentation: the PIN file must be owned by the service user with mode 0400; a systemd credential (`LoadCredential=`) is refused because systemd shows it as 0440 (an ACL), so it is no longer suggested in `deploy/hsmgate.service` and `deploy/hsmgate.example.yaml`. The Docker case is described with the owner of the file that the container user needs.
- The test modules (`test/*-sdk`) use `golang.org/x/net` 0.62.0 and the fixed `golang.org/x/crypto` (the older ones have known findings; they are not shipped); the Python requirements of the boto3 test are pinned by hash; the size of a data key of the KMS-JSON face is checked once, on the variable that is allocated (a CodeQL finding; no change of behaviour).

## 0.7.0 — 2026-11-03

### Added
- **Algorithm agility** ([docs/key-management.md](docs/key-management.md)): the hash and the cipher of the sealed format can be replaced by configuration, and the hash of the HMAC per key. `seal_suite`: `ecies2` (HKDF-SHA-256, AES-256-GCM: the default), `ecies3` (HKDF-SHA-512, AES-256-GCM), `ecies4` (HKDF-SHA-256, XChaCha20-Poly1305, not FIPS-approved); every suite is always read, so a switch leaves what exists openable. `mac_hash` on a key with `generate_verify_mac`: `sha256` (the default), `sha384`, `sha512`, named by each face (`HMAC_SHA_384`, `HS384`, `HMAC_SHA384`). `golang.org/x/crypto` is a dependency again (for `ecies4` only).
- **Long-running checks** ([docs/long-running-checks.md](docs/long-running-checks.md)): a **soak** test (`tools/soak`, weekly in CI) that runs the real binary under load on all four faces with reloads and fails when goroutines, descriptors, heap, resident memory or latency keep growing; a nightly run of the tests with the race detector repeated and shuffled; fuzzing for a quarter of an hour per target monthly (and four new fuzz targets: gRPC messages and names, REST routes, JWTs); benchmarks kept and compared by `benchstat`.
- **Profiling** (off by default): `debug.pprof` serves the profiles of the process (CPU, heap, goroutines) on the admin socket, and the metrics (`metrics.enabled`) now carry the gauges of the process itself: goroutines, heap, resident memory, open descriptors, garbage collections.

### Changed
- The project has a **second maintainer** (`Juliesergienko`, write access). [GOVERNANCE.md](GOVERNANCE.md) says what each of the two can do and how the project goes on if one cannot (create and close issues, accept changes, release within a week); [docs/releasing.md](docs/releasing.md) is the procedure of a release; [SECURITY.md](SECURITY.md) says what happens to a private report when the owner is away.
- `golang.org/x/crypto` (a dependency again, for the `ecies4` suite only) is pinned to the commit that fixes GO-2026-5932 (the unmaintained `openpgp` package, which the program does not import); `govulncheck` is clean on the sources and on the binary.
- CI: the coverage gate counts the program, not `tools/`; the `image` job checks the program inside the image with `govulncheck`; Dependency Review blocks high severity and takes an allow-list of licenses.

## 0.6.0 — 2026-10-23

### Added
- **`hsmgate ca`**: a small certificate authority built into the program (`init`, `server`, `client`, `list`), made of the Go standard library only, so that the certificates for mutual TLS need no openssl or other tool. The key of the authority is a file (`-mode file`), **sealed to the token** (`-mode sealed`: nothing secret is stored; the token opens the key for one command) or **a signing key of the token** (`-mode token`: the key never leaves the card). `hsmgate ca setup -config hsmgate.yaml -client NAME` does it all in one command: the authority, the server certificate at the paths of `tls:` with its names guessed from `listen:` and the interfaces, the owner of the key file guessed, and client certificates. See [docs/operations.md](docs/operations.md).

## 0.5.0 — 2026-10-23

### Security
- The image of **v0.4.1** was built with Go 1.27.2 (a base-image update by Dependabot), which has GO-2026-6809 (CVE-2026-111943): `crypto/x509` distrusted too little when it verified a certificate chain. The binary asset of v0.4.1 (built with Go 1.26.10) is not affected. The Dockerfile now builds with Go 1.27.3, and CI checks the program inside the image with `govulncheck` so that a base-image update cannot bring a vulnerable toolchain in unnoticed. Upgrade the image.

### Added
- A **FIPS variant** of every release: `hsmgate-linux-amd64-fips` and the image `ghcr.io/zystem/hsmgate:vX.Y.Z-fips`, built with the frozen Go cryptographic module (`GOFIPS140=v1.0.0`, `fips140=on` by default), signed and attested like the others. CI tests with `GODEBUG=fips140=on` and checks the `require_fips` behaviour of both binaries.
- A VEX document, [`vex/hsmgate.openvex.json`](vex/hsmgate.openvex.json) (OpenVEX): the vulnerabilities found in shipped components that do or do not affect the project, with the reasons.

## 0.4.1 — 2026-10-23

No change of behaviour; the project's documents, checks and tests.

### Added
- Documents for the OpenSSF Best Practices levels: [verifying a release](docs/verifying-releases.md) (including how to check the signed tag), [governance](GOVERNANCE.md), [security policies](docs/security-policies.md), [security requirements](docs/security-requirements.md), [assurance case](docs/assurance-case.md), [architecture](docs/architecture.md), [building and dependencies](docs/building.md), [roadmap](docs/roadmap.md), [upgrading](docs/upgrading.md), [code of conduct](CODE_OF_CONDUCT.md), and the support and disclosure terms in [SECURITY.md](SECURITY.md).
- Sign-off of commits (DCO): [DCO.md](DCO.md) and a `DCO` check of pull requests.
- CI: statement coverage must stay at 80% or more (81.8% now); `staticcheck` runs with all its checks; Dependency Review and Trivy workflows; Dependabot replaces Renovate.
- More tests for the OAuth helpers, the configuration of the gRPC and REST faces, `kmsops` and the two faces.
- The release tag is signed with an SSH key of the maintainer (first signed tag: this one).

### Changed
- The `main` branch is protected by a ruleset: changes come by pull request with the checks passing.
- Doc comments reworded in the form `staticcheck` expects; an unused helper of `internal/oauth` is removed.

## 0.4.0 — 2026-10-23

### Removed
- **`ecies1`** (XChaCha20-Poly1305) and the `seal_format` option: the service seals and opens `ecies2` only. Texts of the earlier format are no longer read; re-seal them with 0.3.x first. The dependency on `golang.org/x/crypto` is gone. `require_fips` now only checks that the Go cryptographic module is in FIPS 140-3 mode. The ciphertext of a 32-byte data key is 441 characters in Transit form (473 before); the largest plaintext that keeps a Kubernetes KMS v2 ciphertext under 1 kB is 250 bytes (238 before). The test vectors are `testdata/vectors/ecies2.json`.

## 0.3.0 — 2026-10-23

### Changed
- CI and releases moved from Woodpecker to **GitHub Actions** (`.github/workflows/`). A release now signs the binary, the archive, the SBOM and the image (cosign, keyless), issues build provenance attestations and publishes an SPDX SBOM. Actions are pinned by commit. The weekly fuzz run replaces the Woodpecker cron. Dependency updates: Dependabot (`.github/dependabot.yml`) in place of Renovate; the versions in `go run tool@version` lines of the workflows are updated by hand.

### Added
- **gRPC face** (optional, `kmsgrpc.enabled`): a subset of the gRPC API of a cloud key service, for its client libraries (`GetPublicKey`, `AsymmetricSign`, `Encrypt`, `Decrypt`, `MacSign`, `MacVerify`, metadata calls, `GenerateRandomBytes`), authenticated by a service account (`jwt` on a client: token endpoint and self-signed bearers). See [docs/specs/kms-grpc.md](docs/specs/kms-grpc.md). Tried with the official Go client library (`test/kmsgrpc-sdk`).
- **REST face** (optional, `kmsrest.enabled`): a subset of the REST API of a cloud key vault for its client libraries (get key, sign/verify with ECDSA P-256 or HMAC, encrypt/decrypt, wrap/unwrap, list, random), authenticated by an OAuth client credential (`oauth` on a client: a secret or an RS256 assertion). See [docs/specs/kms-rest.md](docs/specs/kms-rest.md). Tried with the official Go SDK (`test/kmsrest-sdk`).
- **`ecies2`** (AES-256-GCM, HKDF-SHA256) and **`require_fips`**: with it the service refuses to start unless the Go cryptographic module is in FIPS 140-3 mode (`GODEBUG=fips140=on`, or a binary built with `GOFIPS140=v1.0.0`; the Dockerfile has the build argument), seals ecies2 and refuses to open ecies1. `seal_format` chooses the format otherwise (default ecies2; ecies1 for data an older version must open). See [docs/compliance.md](docs/compliance.md).
- `internal/kmsops`, `internal/oauth`, `internal/generation`, `internal/peer`: the parts that the key-service faces share.

## 0.2.0 — 2026-10-21

### Added
- **KMS-JSON face** (optional, `kmsjson.enabled`): a subset of the JSON API of a widely implemented cloud key service, on the same listener as Transit, so that programs written for it can use hsmgate by changing their endpoint. Operations: `GetPublicKey`, `DescribeKey`, `ListKeys`, `ListAliases`, `DeriveSharedSecret` (ECDH on the token), `Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey`, `GenerateDataKeyWithoutPlaintext`, `GenerateRandom`, `Sign`, `Verify` (ECDSA P-256 on the token), `GenerateMac`, `VerifyMac` (HMAC-SHA-256 under a key derived on the token). A key has one usage (`kmsjson_usage`: `key_agreement`, `encrypt_decrypt`, `sign_verify`, `generate_verify_mac`). See [docs/specs/kms-json.md](docs/specs/kms-json.md) and [docs/guides/kms-json-clients.md](docs/guides/kms-json-clients.md).
- Authentication of that face: request signing (SigV4, `sigv4` on a client) inside mutual TLS; `sigv4.no_cert` for programs that cannot show a certificate (listed addresses, keys with the usages `encrypt_decrypt`, `sign_verify` and `generate_verify_mac` but never `key_agreement`, secret of 32 bytes or more); refused signatures are counted by address.
- Metrics in the Prometheus text format on the admin socket (`GET /metrics`), **off by default** (`metrics.enabled`), coarse by default (`metrics.detail: basic`).
- Tried with: the official Go SDK and boto3 (CI), Node.js SDK v3, Java SDK v2, OpenBao and HashiCorp Vault `seal "awskms"`, SOPS 3.13.3, cosign 3.1.4, Terraform 1.16.6 (data sources and `aws_kms_ciphertext`), MongoDB client-side field encryption, AWS Encryption SDK for Python, the aws CLI; Sign and MAC on a SmartCard-HSM; shapes and errors compared with the real service.
- Fuzz tests for the signature verifier, the ciphertext blob and the request bodies; a scheduled fuzz step in CI.

### Fixed before release (audit of 2026-10-21, see docs/audit-response-2026-10-21.md)
- Go 1.26.10 (GO-2026-6809: the standard library distrusted too little when it verified a certificate chain; reachable through the check of client certificates). `govulncheck` in the release pipeline found it on the day of the release.
- With the KMS-JSON face in use no two keys may rest on the same private key (CR-01); ciphertext blobs authenticate the key name and version (CR-02, format `HGK2`); the derived MAC key cache returns a copy under its lock (CR-03); `UNSIGNED-PAYLOAD` and similar payload modes are refused (CR-04); Decrypt honours `max_bytes` (CR-05); the audit no longer holds a prefix of the message hash unless `kmsjson.audit_message_prefix` is set; the test requirements use `cryptography` 50.0.2.

### Image
- The image is distroless (42 MB instead of 99 MB; Trivy: 0 critical and 1 high without a fix, instead of 5 and 68), the binary is a PIE with full RELRO, CI builds the image on every push (dry run). Tried against the real card.

### Changed
- The operation, key and client names of a request nobody is known for are logged as `unknown` in both faces.
- Docs: the OpenSC PKCS#11 module exposes no AES; the card itself is not said to lack it.

### Not done
- AES on the card: **decided against** (2026-10-21; see docs/tokens/smartcard-hsm.md for the reasons and what would reopen it), RSA and other algorithms in the KMS-JSON face, key management calls, a replay cache (decided against).
