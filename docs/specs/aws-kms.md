# AWS KMS face

**Status: designed only. Nothing of this page is in the code, and nothing was tried against it.** It records the decision, the contract that would be served, and what it costs. The Transit API ([transit.md](transit.md)) is the API that is built and used.

## 1. Why this face is described at all

The AWS KMS `DeriveSharedSecret` call (ECDH with a key that stays in the service) is the one standard, SDK-supported API that exposes **ECDH itself**. Kubernetes KMS v2 and Transit only encrypt and decrypt; they can sit on an ECDH-only token (a SmartCard-HSM has no AES) only if the service does the sealing, and then the service sees every data key in plaintext. With `DeriveSharedSecret` the **client** seals and opens; the service is an ECDH oracle with a policy and never sees a data key or the additional data.

It was not chosen for CiNim because it gives up the server-side check of the context (§4) and needs request signing in the client. It stays as a possible second face.

## 2. The model

- **Seal** (client side, no call): the client has the public key (`GetPublicKey`, DER SubjectPublicKeyInfo, pinned by its fingerprint), makes an ephemeral key, does ECDH, derives the key and seals as in [ecies1.md](ecies1.md).
- **Open**: the client sends the ephemeral public key (DER SPKI, base64) to `DeriveSharedSecret`; the token does the ECDH; the client derives the key and opens locally.
- `rewrap`, several recipients and rotation then belong to the client; the service only needs the token's public keys and ECDH.

## 3. The operations that would be served

JSON 1.1 over HTTPS: `POST /` with `X-Amz-Target: TrentService.<Operation>` and `Content-Type: application/x-amz-json-1.1`. Errors are `{"__type": "<ExceptionName>", "message": "..."}` with the AWS HTTP status.

| Operation | Request | Response | Notes |
|---|---|---|---|
| `DeriveSharedSecret` | `KeyId` (key id, `alias/name` or ARN-shaped), `KeyAgreementAlgorithm` = `ECDH`, `PublicKey` (base64 DER SPKI, P-256, at most 8192 bytes), optional `DryRun`, `GrantTokens` (ignored) | `KeyId`, `KeyAgreementAlgorithm`, `SharedSecret` (base64) | From the AWS API reference. The point must be on the curve **before** the token is asked. `Recipient` (Nitro attestation) is refused. The shared secret is the raw ECDH result; for P-256 it is expected to be the 32-byte X coordinate, **to be checked against a real AWS endpoint** |
| `GetPublicKey` | `KeyId` | `KeyId`, `PublicKey` (DER SPKI), `KeySpec` `ECC_NIST_P256`, `KeyUsage` `KEY_AGREEMENT`, `KeyAgreementAlgorithms` `["ECDH"]` | Needs no token. The field set is from AWS documentation as remembered, not re-read for this page |
| `DescribeKey` | `KeyId` | `KeyMetadata` with the same facts and `KeyState` (`Enabled`/`Disabled`) | No token access; an extension field would carry `TokenState` |
| `ListKeys`, `ListAliases` | | what the client may use | |

Everything else: `UnsupportedOperationException`. Error mapping would be: a locked token → `KeyUnavailableException` (HTTP 500, retryable); a disabled key → `DisabledException`; an unknown key → `NotFoundException`; a policy refusal → `AccessDeniedException` (HTTP 400); a rate → `ThrottlingException` (HTTP 400, retryable); a malformed or off-curve key → `ValidationException`.

## 4. What it costs

- **No server-side context.** `DeriveSharedSecret` has no EncryptionContext. The binding of a sealed key to its place stays in the additional data that the client puts in the AEAD and checks itself. The service can limit a client to a key and a rate, not to an organisation: a client with the right to derive on a key can open anything sealed to it. Tenants who must be kept apart need their own keys.
- **Signing.** AWS clients sign requests with SigV4 (`AWS4-HMAC-SHA256`, service `kms`). The design carries it **inside** the same mutual TLS as Transit: the access key id maps to a client of the policy and must agree with the certificate's client; clock skew at most five minutes; no header from a front is believed.
- **A grant to derive is a grant to open.** `encrypt` cannot be restricted: anyone with the public key can seal.
- **Everything else is the same as Transit**: the policy, the rate limits, the finite line to the token, audit before answer, reload by generation, a locked token as a state.

## 5. If it is built

It must pass: the same policy and audit tests as the Transit face; a check that an off-curve point is refused before the token; the AWS SDK for Go v2 and boto3 calling `GetPublicKey` and `DeriveSharedSecret` against it; and a comparison of the shared secret with a local ECDH. A client change in CiNim would be: fetch and pin the public key once, seal locally, open through `DeriveSharedSecret`, sign requests.
