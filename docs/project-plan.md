# The key service as a project of its own: plan

Status: a plan, nothing built from it yet. `kekd` (docs/hardware-key.md sections 9-13, `src/kekd`) is the starting point: it works on the SmartCard-HSM, in Nim, behind a TLS front that is not part of it.
This page says what to take from the neighbours, what to change in the API, how to authenticate, what the project is called and in which steps to build it. Items marked **Decision** are the owner's.

## Revision 2026-10-19 (supersedes parts of sections 5, 8, 9)

- Decided: Go, MIT, name `hsmgate`. CiNim's own protocol (v1) is **not carried over and no v2 native protocol is built for it**.
- CiNim uses the **Vault/OpenBao Transit face**, see [transit-face.md](transit-face.md) (decided 2026-10-19; it replaces the AWS KMS choice made earlier the same day, which stays as the optional later face [awskms-face.md](awskms-face.md)). The service does the ECIES itself; named keys, a required context checked against policy, versions and `rewrap` map onto Transit.
  The `hsm1` multi-recipient format and the native v2 API are dropped for the first release.
- Section 8: P1 now contains the AWS KMS face spec and the `ecies1` vectors (done: `testdata/vectors/ecies1.json`, `internal/scheme/ecies`); P2 builds mTLS, policy, audit, the soft backend and the Transit operations (encrypt, decrypt, rewrap, keys); P4 "compat v1" is deleted and the native Kubernetes KMS v2 gRPC face is postponed (the `vault-kubernetes-kms` plugin already works through Transit, see transit-face.md); P7 is the client change described in transit-face.md.

### Sizing and key model (2026-10-19)

- CiNim today: one KEK per shard wraps one DEK per organisation. New requirement: an organisation **may have its own KEK** (default: the shard's KEK). Up to about 30 organisations per KEK; several KEKs per server; several hsmgate instances per host;
  one hsmgate may serve more than one physical token.
- Consequences for hsmgate: keys are addressed by name (alias) and each maps to (token, key id); a client's policy lists keys; a tenant's own KEK is simply another key (on the same token, another token, or another hsmgate) with its own grant.
  Isolation between organisations with their own KEK is then by key, which makes the loss of server-side context checking (see awskms-face.md) matter less.
- Consequences for CiNim (its own task, not this project's): the DEK of an organisation records which KEK sealed it (`kek id` per tenant, not one for the shard); `kek_check` per KEK; `vaultKek()` becomes a lookup by tenant; moving a tenant to its own KEK is a rewrap of that DEK only.
- A card holds roughly 70 EC keys at best (memory-bound, not a slot limit; vendor figures, not measured on our card).

## 1. What the project is

A small network service that holds **no key material of its own** and lets clients seal and open short secrets (data keys, the root key of another vault) under a master key that lives on a PKCS#11 token (an HSM, a smart card, a TPM, a software token for tests).
It is a door in front of the token: who may ask, for which key, with which context, how often, and what is written down. CiNim is its first client (the master key of the secrets of a shard); OpenBao unsealed by a card is the second.

Not goals: a general KMS (no key lifecycle for clients' own keys, no signing service, no PKI), a replacement for the vendor's PKCS#11 module, a cluster of services (one process per token; availability comes from a spare token, not from a protocol).

## 2. The neighbours (checked 2026-10; the ready-made first)

| Project | What it is | What to take | Why it is not enough |
|---|---|---|---|
| Eclipse KeySealer `k8s-kms-plugin` (Go, MIT/Apache, incubating) | Kubernetes KMS v2 gRPC service on a local or remote PKCS#11 token, with a proxy mode and a rotation command | the repository layout, a page per HSM with a matrix of what was tried, the release chain (signed releases, SBOM, SLSA), `crypto11`/`pkcs11-go` of Eclipse KeyPont | Kubernetes API only; needs AES or RSA in the token (the SmartCard-HSM has no AES): no ECDH-ES scheme; a plaintext unix socket, no client policy |
| Kubernetes KMS v2 | `Encrypt`, `Decrypt`, `Status` over gRPC | `Status` with a `key_id` that changes at rotation, a request `uid` for the logs, opaque `annotations`; a face for it later | an API of one client, no authentication of its own |
| OpenBao / Vault Transit | `encrypt`, `decrypt`, `rewrap`, named keys, `vault:vN:` prefix | key names and versions in the ciphertext, `rewrap`; the Transit face already exists in `kekd` (section 13) | a whole vault to run; keys are in it, the token only unseals it |
| AWS KMS | `Encrypt`, `Decrypt`, `ReEncrypt`, **EncryptionContext** | the context as a map that is bound to the ciphertext (our additional data), key policies, aliases, grants | a cloud API; a SigV4 face would be possible but needs a plugin on the OpenBao side |
| SOPS key service | a gRPC service that holds the keys for `sops` | proof that a thin wrap/unwrap service is a useful seam | one client; no HSM |
| KMIP, Eviden (Cosmian) KMS | the standard protocol and a server with HSM support (names the SmartCard-HSM, with `sc-hsm-embedded`) | a KMIP face as a possible far-off step | a whole KMS (BSL licence, PIN in its configuration); not tried on our card |
| `p11-kit server`, `pkcs11-proxy` | PKCS#11 over a socket or the network | nothing | no policy, the PIN and the whole token are exposed to the client |
| OpenBao `kms-pkcs11` plugin (External Keys) | auto-unseal and Transit keys on a local token | a reference for the PKCS#11 calls | local only, one consumer |

Conclusion: nothing ready that does a policy-checked, authenticated, network wrap/unwrap over a card that has ECDH and RSA but no AES. Build, with KeySealer as the model for the project's shape.

## 3. Name

**Decision.** Recommended: **`hsmgate`**: the gateway to an HSM (and to a token that is not one). Free on GitHub, npm, PyPI and crates.io at the time of checking, no product of that name known.
Others checked: `strongroom` (good meaning, a taken package name on npm, small repositories on GitHub), `kekgate` (free, but the "kek" reads as a joke), `kekd` (free, but a daemon name, says nothing to a stranger). Names that are taken by known projects and were dropped: keywarden, keygate, keyholder, keyseal, cairn, wicket, gatekeeper, turnstile, custos.
Binary `hsmgate` (subcommands `serve`, `unlock`, `keys`, `check`), configuration `hsmgate.yaml`, service `hsmgate.service`.

## 4. Language and licence

**Decision.** Recommended: **Go**, licence **Apache-2.0** (or MIT; the neighbours use both). The reasons are the work that Nim does not have: TLS 1.3 with client certificates in the standard library (GuildenStern has no TLS: today a front, a tunnel and a header
that someone has to keep alive and trust), gRPC and the Kubernetes KMS v2 package, `crypto11`/`pkcs11-go`, the OpenBao `go-kms-wrapping` libraries (a Transit and a KMS-plugin face share types), `crypto/ecdh`, HKDF and XChaCha20-Poly1305 in `x/crypto`,
`govulncheck`, `go test -fuzz`, goreleaser with signing. What is lost: about 800 lines of tested Nim and a hand-written `dlopen` binding with its layout check; the algorithm is small, the **test vectors** (step P1) carry it over. CiNim's own client side (`core/kekclient.nim`) stays Nim.
The other path, to keep Nim: write TLS termination and the policy into the service, with an own HTTP server loop over `std/net` and OpenSSL; slower to a result and more of it to review.

## 5. The API: what changes

The current protocol (`/v1/info`, `/v1/wrap`, `/v1/unwrap`, hex strings, one global additional-data prefix) was made for one client. The new native protocol is **v2**; the old one stays as a **compatibility face** until CiNim's client moves.

1. **Named keys.** A request names a key (`"key": "cinim-dek"`); the configuration maps names to tokens and key ids. `GET /v2/keys` lists what the caller may use; `GET /v2/keys/{name}` gives `key_id` (the fingerprint of the public key), the state (`ready`, `locked`, `absent`, `disabled`) and the scheme.
2. **A context map instead of a prefix.** `"context": {"purpose": "cinim/dek/v1", "org": "..."}` is canonicalised (sorted, length-prefixed) into the additional data, as AWS does with EncryptionContext. A **policy** says which contexts a client may use with a key (fixed values, required names, a pattern); the old prefix rule becomes one such policy.
3. **Operations**: `wrap`, `unwrap`, **`rewrap`** (open and seal again to the current key or another one without the plaintext leaving the service: the rotation, the move to a spare token), `status`. `status` and `/healthz` touch no card; a probe must never cost a PIN try or an ECDH.
4. **Encoding**: base64 in JSON (hex was a debugging choice); sizes limited per key. Every request may carry `X-Request-Id`; it is returned and written to the audit. Time stamps in RFC 3339.
5. **Errors**: one shape, `{"error": {"code": "locked", "message": "...", "retryable": true}}`, with the HTTP status as a hint. The codes of today (`wrong_key`, `damaged`, `bad_context`, `locked`, `busy`, `unavailable`, `disabled`, `forbidden`, `unauthenticated`) stay; `retryable` is what the client reads, not the status number.
6. **The sealed format** gets a version and recipients: `hsm1` with one or **several recipients** (a random content key, sealed to each token's public key; any one token opens it). That is how a spare card is made without the DKEK dance: add its public key as a recipient, `rewrap` what exists. The format of today (`ecies1`) is read for ever; there are test vectors for it.
7. **Schemes by key type**: EC P-256 (ECDH-ES + HKDF + XChaCha20-Poly1305, what runs on the card now), RSA (OAEP SHA-256, the PKCS#11 `RSA-PKCS-OAEP` decryption; tried on the card with `tools/hsm/rsa-oaep-check.sh`), AES (GCM, for tokens that have it). The token's capabilities decide which a key may use; a key with a scheme the token cannot do is refused at the start, not at the first request.
8. **Faces** (protocol adapters over the same policy and audit): `native v2` (JSON over HTTPS), `compat v1` (the core of CiNim, unchanged), `transit` (exists), then `k8s-kms-v2` (gRPC on a unix socket; the card then encrypts etcd), later AWS-KMS JSON and KMIP if someone needs them. A face carries no authority of its own: it maps to a client, a key, an operation, a context.

## 6. Authentication and authorisation

Today: a TLS front outside the service and a header that the service believes. New: **the service terminates TLS itself** and never believes a header.

- **Transport**: TLS 1.3, client certificate required, the server certificate and the client CA from files, reloaded on `SIGHUP`. Plain HTTP only on a loopback address, for tests, behind a flag with a long name.
- **Identity** of a client: the URI SAN (a SPIFFE-style ID such as `spiffe://example/ns/cinim/sa/core`), or the SHA-256 of the certificate (a pin), or the CN as the last resort. The configuration maps an identity to a **client** with a name. Revocation: remove it from the configuration and reload; short-lived certificates from the operator's CA are the better answer than lists.
- **Authorisation**: per client, per key: the allowed operations, the context rules, a rate limit (per minute, per day, per client and per key), a size limit. Deny by default. One client may be allowed `wrap` only (a producer that cannot read), another `unwrap` only.
- **Other doors, each its own client type**: a unix socket with the peer's uid/gid (`SO_PEERCRED`) for a local consumer such as the Kubernetes API server (the KMS v2 face); static credentials (an access key pair) only for a face whose protocol cannot present a client certificate. A token that is a bearer secret (OpenBao's `token`) is **not** an authentication, it is ignored as it is today.
- **Admin** is a separate listener (a unix socket, or another port with another CA): `unlock`, `disable`/`enable` (the switch), `reload`, `clients`, `keys`. The switch file stays too, for the case where nothing but a shell is left.
- **Unlocking the token**: the PIN comes from a systemd credential or a file, **or** the service starts locked and an operator runs `hsmgate unlock` (the PIN from the terminal, handed over the admin socket, kept in memory only). The PIN is tried **once**; a refusal leaves the service `locked` until an operator acts (the card blocks at three).
- **Audit**: one JSON line per decision, including the refused ones: time, request id, client, face, key, operation, context (public by rule), result, the token's state. Never a key, a plaintext, a PIN, a ciphertext. To a file, journald or syslog; an optional hash chain over the lines so that a cut is visible.
- **Threat model** to be written in step P1 (attackers: a compromised client, a network attacker, a stolen token, a stolen PIN without the token, an operator error, a client that exhausts the token). The first rule: a compromised client can do exactly what its policy allows and no more, and every use of it is written down.

## 7. Layout of the repository

```
cmd/hsmgate/            the program: serve, unlock, keys, check
internal/backend/       pkcs11 (module loading, slots, login once, locked state), soft (file key, for tests and development), tpm (later)
internal/scheme/        ecies, rsaoaep, aesgcm; the sealed format and its test vectors
internal/policy/        clients, keys, context rules, limits, reload
internal/authn/         mTLS identities, peer credentials, static credentials
internal/audit/         the lines, the chain, the sinks
internal/face/          native, compat1, transit, kmsv2 (gRPC)
api/                    the OpenAPI of v2, the protos
docs/                   concepts, protocol, sealed format, threat model, one page per token (the matrix of what was tried), operations
test/                   SoftHSM2 integration, the real-card script, conformance vectors
deploy/                 systemd unit (LoadCredential, sandboxing, no network except the listener) (Docker example; no Kubernetes: a card ties the service to one machine)
```

Supply chain as KeySealer: signed releases and containers, an SBOM, SLSA provenance, `govulncheck` and a linter in CI, fuzz targets for every parser (the sealed format, the context, the requests).

## 8. Steps

- **P0. Decisions**: the name, the language, the licence, where the repository lives, public or not (section 10).
- **P1. Specification, in CiNim's repository first**: the protocol v2, the sealed formats `ecies1` and `hsm1` with **test vectors made by the working Nim code** (so that the Go code is checked against something that has run on a card), the policy and the configuration, the threat model. Tests first: the vectors are a file both implementations read.
- **P2. Skeleton**: the Go module, the `soft` backend, the scheme, the policy, mTLS authentication, the audit, the native face, `check`; every rule of sections 5 and 6 has a test that names it.
- **P3. The PKCS#11 backend**: the module loading and its checks, the slot by label or serial, the login once, the locked state, `unlock`; SoftHSM2 in CI (it has ECDH, no RSA-OAEP key wrap; the matrix says what each token can do); the scripts of `tools/hsm` ported and run on the real card by the owner.
- **P4. Faces**: `compat v1` (the core of CiNim works unchanged against it, the tests of `tkekclient` run against the new service), `transit` (the OpenBao run of section 13 repeated, through mTLS and over a network, which was not tried), then `k8s-kms-v2`.
- **P5. Recipients, `rewrap`, rotation**: the spare token as a recipient, the rotation of a key (a new `key_id`, `rewrap` of what exists), a written procedure for losing a card and for restoring from a DKEK backup on the second card (tried once, with the card in hand).
- **P6. Packaging and documentation**: releases, the unit and the Docker example, the page per token (SmartCard-HSM: OpenSC module and `sc-hsm-embedded`, what was tried), the operations guide (PIN, backup, the switch, monitoring).
- **P7. CiNim moves to it**: **not a task of this project.** It is CiNim's own work (its client, chart, `src/kekd` removal, `docs/hardware-key.md`), planned and tracked in CiNim's repository. This project supplies the contract (docs/transit-face.md) and the test vectors; the notes below on what CiNim would change are for whoever picks that up.
- **P8. Review**: a pass over the whole by someone other than the author (the card is the root of every secret), fuzzing for a stated time, the timing of the unwrap path, memory handling of the PIN and the secrets.

## 9. What stays in CiNim

The client (`core/kekclient.nim`, `core/kekprovider.nim`), the choice of provider (`CINIM_KEKD_URL` becomes the URL of the service and the certificates), the emulator's role in the tests (replaced by the project's `soft` backend), the decision record (a `D-` entry when the project starts), the sections of `docs/hardware-key.md` about the card's setup and backup.

## 10. Questions for the owner

1. The name (`hsmgate`?), the licence, the repository's owner and visibility.
2. Go, or stay in Nim with TLS built into the service.
3. Which faces are worth the work: the Kubernetes KMS v2 (the card for etcd encryption) is the most useful one besides the two that exist.
4. The recipients format (several tokens at once): in the first release or after it.
5. Other tokens than the SmartCard-HSM in the first release (YubiHSM 2, TPM, SoftHSM only for tests).
6. Who reviews it (step P8), and the point at which the real master key moves to it.
