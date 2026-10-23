# Changelog

## Unreleased

### Added
- **`hsmgate ca`**: a small certificate authority built into the program (`init`, `server`, `client`, `list`), made of the Go standard library only, so that the certificates for mutual TLS need no openssl or other tool. The key of the authority is a file (`-mode file`), **sealed to the token** (`-mode sealed`: nothing secret is stored; the token opens the key for one command) or **a signing key of the token** (`-mode token`: the key never leaves the card). See [docs/operations.md](docs/operations.md).

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
