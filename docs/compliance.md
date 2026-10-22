# Standards: what hsmgate does, and what it cannot

Honest summary. hsmgate is a **software gateway** in front of a token. Standards that certify a **cryptographic module or a device** (FIPS 140-3, PCI HSM, Common Criteria) cannot be satisfied by this program; what it can do is not get in their way and meet their *logical* rules. Standards for **software and its development** (OWASP ASVS) can be met in part, and the part that is not met is listed.

## 1. FIPS 140-3

**What a certificate covers.** A certificate is issued to a *module* as validated by a lab, and says nothing about the programs around it. hsmgate cannot be "FIPS certified". It can run on a validated module and use only approved algorithms.

**What is done.**
- The cryptography of the process is the Go standard library; the Go Cryptographic Module (`crypto/internal/fips140`) is validated under CMVP. `require_fips: true` makes the service refuse to start unless that module is in FIPS 140-3 mode (`GODEBUG=fips140=on`, or a binary built with `GOFIPS140=v1.0.0`, which the Dockerfile does with `--build-arg GOFIPS140=v1.0.0`). The module's own self-tests run at start.
- Algorithms in use: ECDSA and ECDH on P-256, SHA-256, HMAC-SHA-256, HKDF-SHA-256, AES-256-GCM (format `ecies2`), RSA ≥ 2048 for the verification of tokens, TLS 1.3. All are approved. The one that was not, ChaCha20-Poly1305 of `ecies1`, is not used for sealing under `require_fips`, and `ecies1` is not opened ([specs/ecies1.md](specs/ecies1.md)). The test suite passes under `GODEBUG=fips140=on` and `fips140=only`.
- The token does only ECDH and ECDSA; sealing runs on the host, so the lack of AES-GCM on the card does not matter.

**What is not done, and why.**
- The Go module's certificate is for the version and the operating environments in its Security Policy. A binary on another platform is "built with a validated module" but is not the tested configuration; whoever must prove compliance must compare with the certificate.
- The SmartCard-HSM has its own status (its vendor states it; we do not claim it). The private key never leaves it, but the module that holds it is not covered by the Go certificate.
- Keys that the host derives (the MAC key of `generate_verify_mac`, the data keys of `ecies`) live in the memory of the process for the time of the operation. Level 3 of FIPS 140 wants key entry and output protected; that is a property of a device, which a process on a server is not.
- `ecies1` data of CiNim must be re-sealed (`rewrap`) before `require_fips` is turned on.

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

## 4. Others that were considered

- **ISO/IEC 19790**: the international twin of FIPS 140, the same limits.
- **Common Criteria, EN 419 221-5**: certify devices and modules; the card has its own certificates, which we do not claim.
- **NIST SP 800-57, 800-131A**: followed as guidance (key sizes, algorithm transitions), not certified.
- **OpenSSF Best Practices badge, SLSA**: realistic for the project; the badge needs the owner's account. Open: signed releases (cosign), provenance.
