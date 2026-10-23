# Assurance case

Why the security requirements of [security-requirements.md](security-requirements.md) are met. It is an argument, with the evidence in the repository; it is reviewed at each release (last: 0.4.0).

## 1. Threat model

[threat-model.md](threat-model.md): assets (the private key on the token, the plaintext in transit through the service), attackers (a compromised client, a network attacker, an unauthenticated peer, a stolen token, a compromised host, an operator error, a malicious ciphertext), the mitigation of each and the residual risk. The attack surface per entry point is in its "Attack surface" section; the actors and actions in [architecture.md](architecture.md); external audits and the responses in `docs/security-audit-2026-10-21/` and [audit-response-2026-10-21.md](audit-response-2026-10-21.md).

## 2. Trust boundaries

1. **Network to listener**: untrusted peers meet TLS 1.3. Nothing is trusted before the handshake and the credential check. The identity of a client comes from the certificate and/or a signed credential, never from a header.
2. **Listener to policy**: every request is judged by the same policy (client, key, operation, context, budget) before the token is asked.
3. **Service to token**: the only path to the private key, through a finite gate; the service sees the shared secret of one ECDH or one signature, never the key.
4. **Service to audit log**: written before the answer; failure of the write fails the call.
5. **Operator to service**: files, signals and a unix socket (mode 0600) on the host; not on the network.
6. **Build to user**: one release workflow builds, signs and attests; users verify.

## 3. Secure design principles (Saltzer and Schroeder)

| Principle | How it is applied |
|---|---|
| Economy of mechanism | few dependencies; the standard library for TLS, HTTP/2 and cryptography; the faces share one core (`internal/kmsops`) and one policy |
| Fail-safe defaults | deny by default; a key is on no face unless it says so; one usage per key; a credential without a certificate must be marked and bound to addresses; a reload that fails changes nothing |
| Complete mediation | policy and rights are checked on every request, not at login; a removed credential ends access at once |
| Open design | the formats and faces are specified in `docs/specs/`; the security does not rest on secrecy of the design |
| Separation of privilege | a client needs its certificate and its credential (unless marked); the operator who unlocks is not the client who uses |
| Least privilege | per client, key and operation grants; budgets; the service has no keys; systemd sandbox; a distroless image |
| Least common mechanism | a key has one usage; two names on one private key are refused when a face is in use |
| Psychological acceptability | one YAML file, `hsmgate check` before serving |
| Fail closed and audit | the audit line is written before the answer |

## 4. Common weaknesses countered

| Weakness (OWASP Top 10, CWE) | Counter | Evidence |
|---|---|---|
| Injection, malformed input (CWE-20, CWE-74) | strict parsers with allowlists and size limits; no shell, SQL or templates | fuzz targets: Transit request, KMS-JSON request, ecies text, SigV4, configuration |
| Broken access control (A01) | deny by default, per-grant policy, one answer for missing and forbidden | `internal/policy` tests, `TestDenyByDefault` |
| Cryptographic failures (A02) | approved algorithms from the standard library; AEAD binds name, version and context; constant-time comparison; no key material in the service | [key-management.md](key-management.md), tests of `internal/scheme/ecies`, `internal/kmsops` |
| Authentication failures (A07) | mutual TLS, signed requests, RS256 JWTs with expiry, tokens in memory only, refused credentials counted by address | `internal/sigv4`, `internal/oauth` tests |
| Logging failures (A09) | audit before the answer; no secrets in the log (tested); the request id returned | `internal/audit` tests |
| Vulnerable components (A06) | `govulncheck`, Dependabot, Dependency Review, Trivy, bill of materials | [security-policies.md](security-policies.md) |
| Supply chain and integrity (A08) | pinned actions and images, signed releases with provenance | [verifying-releases.md](verifying-releases.md) |
| Memory safety | Go; the cgo binding is small and calls a vendor module | `gosec`, `go vet`, the race detector |
| Denial of service (CWE-400) | body limits, the finite gate with a wait limit, budgets, a limit of connections and HTTP/2 streams, timeouts | `TestAdmissionIsAFiniteLine`, `TestSizeLimits` |

## 5. Hardening

PIE and full RELRO binary, distroless image, non-root by default, TLS 1.3 only, HTTP/2 stream limit, no debug interface, optional metrics on the admin socket only, secrets from files with checked modes.

## 6. Gaps (known)

Single maintainer (no second reviewer); no certified module; the audit log is on the host unless shipped elsewhere; no VEX statement yet. See [roadmap.md](roadmap.md) and [compliance.md](compliance.md).
