# The AWS KMS face (not chosen for CiNim; kept as a later option)

Status: superseded on 2026-10-19 by [transit-face.md](transit-face.md). Kept because it is the one standard API that exposes ECDH itself and keeps data keys out of the service.


Decision (2026-10-19): CiNim stops using its own protocol (`/v1/wrap`, `/v1/unwrap`). The service speaks a subset of the **AWS KMS JSON API**, whose `DeriveSharedSecret` is the one standard, SDK-supported ECDH call
(checked against the [API reference](https://docs.aws.amazon.com/kms/latest/APIReference/API_DeriveSharedSecret.html)). It is the only surveyed standard API that exposes ECDH itself. Kubernetes KMS v2 and Vault/OpenBao Transit only encrypt and decrypt; they *can* sit on an ECDH-only token if the service does the ECIES itself
(as `kekd` does today), but then the service sees plaintext and the AEAD's additional data. KMIP's ECDH derivation is not confirmed in any client we could use.
(Correction of an earlier wording: "needs AES in the token" was wrong; the real difference is who runs the AEAD, see the comparison in the chat of 2026-10-19 / README.)

## Shape

The service becomes an **ECDH oracle with policy**. The sealed format stays `ecies1`, but it is made and read by the *client*:

- wrap: the client has the master public key (`GetPublicKey`, DER SPKI, fetched once and pinned by `key_id`), makes an ephemeral P-256 key, does ECDH locally, HKDF, XChaCha20-Poly1305. No call to the service.
- unwrap: the client sends the ephemeral public key (DER SPKI) to `DeriveSharedSecret`; the token does ECDH; the client runs HKDF and opens the AEAD locally.

Consequences: `wrap`, `rewrap`, the multi-recipient format and rotation are client business (the service only needs the token's public keys and ECDH); the service never sees a plaintext data key or the additional data.
Price: **the context cannot be checked by the service** (AWS's `DeriveSharedSecret` has no EncryptionContext). Binding to a place stays in the AEAD's additional data, checked by the client. The policy per client and key
(allowed operations, rate, size) stays; a per-context policy does not exist in this face. A compromised client with `DeriveSharedSecret` rights can open anything sealed to that key: scope keys per client/tenant.

## Subset

JSON 1.1 over HTTPS, `POST /`, `X-Amz-Target: TrentService.<Op>`, errors `{"__type": "...", "message": "..."}`.

| Operation | Behaviour |
|---|---|
| `GetPublicKey` | `KeyId` (id, alias `alias/name`, or ARN-shaped) -> `PublicKey` (DER SPKI), `KeySpec: ECC_NIST_P256`, `KeyUsage: KEY_AGREEMENT`, `KeyAgreementAlgorithms: ["ECDH"]`. No token access. |
| `DescribeKey` | `KeyMetadata`: `KeyId`, `Arn`, `KeyState` (`Enabled`, `Disabled`; locked/absent token reports `Enabled` plus `hsmgate` extension field `TokenState`), `KeySpec`, `KeyUsage`, `Origin: EXTERNAL_KEY_STORE`-like value TBD. No token access (a probe never costs a PIN try). |
| `ListKeys`, `ListAliases` | what the caller may use |
| `DeriveSharedSecret` | `KeyAgreementAlgorithm` must be `ECDH`; `PublicKey` DER SPKI P-256, validated on the curve before the token is asked; returns `SharedSecret` (raw 32-byte x coordinate, base64), `KeyId`, `KeyAgreementAlgorithm`. `Recipient`/`DryRun`: `DryRun` supported, `Recipient` refused. |

Everything else: `UnsupportedOperationException`. (Later, optional: the `Encrypt`/`Decrypt`/`GenerateDataKey` family for tokens that have AES or for RSA-OAEP keys.)

Error mapping: locked token -> `KeyUnavailableException` (HTTP 500, retryable; the SDK retries, the service must not hammer a card: rate-limited, and after a PIN refusal stays locked), disabled key -> `DisabledException`, unknown key -> `NotFoundException`,
policy refusal -> `AccessDeniedException` (HTTP 400), rate -> `ThrottlingException` (HTTP 400, retryable), off-curve or malformed key -> `ValidationException`/`InvalidKeyUsageException`.

## Authentication

SigV4 (`AWS4-HMAC-SHA256`, service `kms`, a region string from configuration) is the credential that SDKs and CiNim's client can present: an access key id maps to a **client** in the policy, the secret is stored hashed-comparably (HMAC key kept in the config; not a password).
It is carried **inside TLS 1.3 with a required client certificate**; the client identity is the pair (certificate identity, access key id) and both must map to the same client. Clock skew <= 5 minutes, replay window by request signature. No header from a front is trusted.

## Changes in CiNim (CiNim's task, not this project's)

`core/kekclient.nim`: replace the v1 calls by `GetPublicKey` once (pinned), local wrap, `DeriveSharedSecret` per unwrap, SigV4 signing (the S3 signing chain exists), and the read of `ecies1` unchanged.
`src/kekd` (Nim) and its v1 protocol and Transit face are removed when the client has moved; stored `ecies1` texts keep opening (the vectors prove it).
