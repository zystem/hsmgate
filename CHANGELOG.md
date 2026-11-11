# Changelog

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
