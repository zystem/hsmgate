# Standards: what hsmgate does, and what it cannot

Honest summary. hsmgate is a **software gateway** in front of a token. Standards that certify a **cryptographic module or a device** (FIPS 140-3, PCI HSM, Common Criteria) cannot be satisfied by this program; what it can do is not get in their way and meet their *logical* rules. Standards for **software and its development** (OWASP ASVS) can be met in part, and the part that is not met is listed.

## 1. FIPS 140-3

**What a certificate covers.** A certificate is issued to a *module* as validated by a lab, and says nothing about the programs around it. hsmgate cannot be "FIPS certified". It can run on a validated module and use only approved algorithms.

**What is done.**
- The cryptography of the process is the Go standard library; the Go Cryptographic Module (`crypto/internal/fips140`) is validated under CMVP. `require_fips: true` makes the service refuse to start unless that module is in FIPS 140-3 mode (`GODEBUG=fips140=on`, or a binary built with `GOFIPS140=v1.0.0`, which the Dockerfile does with `--build-arg GOFIPS140=v1.0.0`). The module's own self-tests run at start.
- Algorithms in use: ECDSA and ECDH on P-256, SHA-256, HMAC-SHA-256, HKDF-SHA-256, AES-256-GCM (format `ecies2`), RSA ≥ 2048 for the verification of tokens, TLS 1.3. All are approved; the one that was not, ChaCha20-Poly1305 of the earlier format `ecies1`, is gone from the code ([specs/ecies2.md](specs/ecies2.md)). The test suite passes under `GODEBUG=fips140=on` and `fips140=only`.
- The token does only ECDH and ECDSA; sealing runs on the host, so the lack of AES-GCM on the card does not matter.

**What is not done, and why.**
- The Go module's certificate is for the version and the operating environments in its Security Policy. A binary on another platform is "built with a validated module" but is not the tested configuration; whoever must prove compliance must compare with the certificate.
- The SmartCard-HSM has its own status (its vendor states it; we do not claim it). The private key never leaves it, but the module that holds it is not covered by the Go certificate.
- Keys that the host derives (the MAC key of `generate_verify_mac`, the data keys of `ecies`) live in the memory of the process for the time of the operation. Level 3 of FIPS 140 wants key entry and output protected; that is a property of a device, which a process on a server is not.

## 2. OWASP ASVS 4.0 (level 2), self-assessment

Not an audit; a map of the claims to the code and the open points. "N/A": the program has no such thing.

| Chapter | State | Where / what is open |
|---|---|---|
| V1 Architecture | Partial | threat model [threat-model.md](threat-model.md); one trust boundary (the listener); no formal data-flow diagrams per release |
| V2 Authentication | Met for machine clients | mutual TLS (client identity by CN/URI/hash), request signing, client secrets of 32+ bytes from files with strict modes, JWT RS256 with expiry; no passwords, no human login; refused credentials counted by address and blocked |
| V3 Session | N/A / Met | no cookies; access tokens are random, 256 bits, one hour, in memory, bound to the credential and re-judged on every call |
| V4 Access control | Met | deny by default; the policy per client, key and operation; one answer for "no such key" and "not allowed"; budgets per minute |
| V5 Validation, encoding | Met | strict parsers, size limits on every body, the names of keys restricted to a set, fuzz tests (signature, blob, bodies); no templates, no SQL, no shell |
| V6 Cryptography | Met, with the points of section 1 | approved algorithms, key on the token, AEAD binds the key name, version and context, constant-time compares, crypto/rand only |
| V7 Errors, logging | Met | audit line before the answer (fail closed), no secrets or PINs in logs (tested), the request id returned |
| V8 Data protection | Met | no persistent state but the audit log; secrets only in files read at start; memory wiped after use (best effort in Go) |
| V9 Communication | Met | TLS 1.3 only |
| V10 Malicious code | Partial | dependencies few and pinned, `govulncheck`, gosec, staticcheck in CI, reproducible-ish build; releases not yet signed |
| V11 Business logic | Met | finite gate to the token, budgets, no replay cache by decision (reasons in the audit response) |
| V12 Files | N/A | no uploads |
| V13 API | Met | each face has a spec; REST/gRPC/JSON methods are explicit lists, the rest refused |
| V14 Configuration | Partial | distroless image, PIE, full RELRO; hardening of the host is the operator's; GitHub settings (branch protection, code scanning) are the owner's |

## 3. PCI HSM

PCI HSM (v3) is a standard for **payment hardware security modules** and is satisfied by **a device with physical security**, assessed by a PCI-approved laboratory: tamper detection and response, environmental failure protection, a defined device lifecycle (manufacture, shipping, installation, decommissioning), dual control and split knowledge for key loading, approved payment functions (PIN translation, key blocks, MAC for card data).

**What cannot be done.**
- The physical and lifecycle requirements are properties of hardware that this project does not make. The SmartCard-HSM is a general smart card, not a PCI-approved payment HSM, and a server running a gateway is not a secure cryptographic device.
- The payment functions (PIN blocks, DUKPT, key blocks of TR-31) are not in the scope of this service.
- A claim "PCI HSM compliant" would therefore be false, and none is made.

**What is aligned in the logical part (and may be cited by whoever assesses a system that uses hsmgate).**
- Keys are not exported in the clear; private keys stay on the token; the service gives operations, not keys.
- Separation of roles: the operator who starts the service and unlocks the token (admin socket) is not the client who uses the keys; clients have rights per key and operation.
- Audit of every use, written before the answer; a failure of the audit stops the answers.
- Approved algorithms and key sizes (see section 1); keys have versions and a rotation path.
- Not provided: dual control and split knowledge for loading keys (the card's DKEK scheme, with its shares, can give it for backups; see [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)).

## 4. The others

| Standard | Can the project meet it? | Why, and what is done |
|---|---|---|
| ISO/IEC 19790 | No | the international twin of FIPS 140: it certifies a module, in a lab, under a national scheme; the same limits as section 1 |
| Common Criteria, EN 419 221-5 | No | certify a device or module against a protection profile; the SmartCard-HSM has its own certificates (not claimed here); a gateway is not a profiled product |
| PCI HSM | No | section 3 |
| NIST SP 800-57, SP 800-131A | Yes, as guidance | [key-management.md](key-management.md) |
| OWASP ASVS | In part | section 2 |
| OpenSSF Best Practices (passing) | Almost; the badge is the owner's to claim | see below |
| SLSA | Level 1 in effect; level 2 needs signed provenance | see below |

### OpenSSF Best Practices, level "passing": where the project stands

Met: a free license (MIT); documentation (README, `docs/`); a public repository over HTTPS; a way to report vulnerabilities privately ([SECURITY.md](../SECURITY.md)); a working build and an automatic test suite (`go test`, black-box tests, fuzz tests, CI on every push); tests for new functionality ([CONTRIBUTING.md](../CONTRIBUTING.md)); warnings and static analysis (`go vet`, staticcheck, gosec) with the findings fixed; no known unpatched vulnerabilities (`govulncheck` in CI and in the release); no cryptographic primitives of our own, only the standard library; no secrets in the repository (gitleaks configuration); a changelog.

Open: the badge itself (a project page on bestpractices.dev, created by the owner of the repository: the answers above are the material); the release carries a SHA-256 file but no signature (see below).

### SLSA

CI and releases run in GitHub Actions (`.github/workflows/`): `ci.yml` (tests, static analysis, SoftHSM, the SDK tests, build, image), `fuzz.yml` (weekly), `release.yml` (a tag `v*`), `scorecard.yml`. All actions are pinned by commit.

- **Build L1** (provenance exists) and **L2** (signed provenance made by the build service): a release is built by the workflow, never by hand. For the binary, the deploy archive and the image, `actions/attest-build-provenance` issues a signed attestation (verify with `gh attestation verify FILE -R zystem/hsmgate`), and every file and the image are signed with cosign (keyless, the identity of the workflow; `cosign verify-blob --bundle FILE.sigstore.json --certificate-identity-regexp 'https://github.com/zystem/hsmgate/.github/workflows/release.yml@.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com FILE`). An SBOM in SPDX format is published with the release. **Not yet exercised by a real release**: the first tag after this change is the test.
- **Build L3** is not claimed: the build job is not isolated from the workflow's other jobs by a separate reusable builder, and the tests that precede it run in the same workflow.
