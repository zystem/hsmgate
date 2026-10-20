# KMS-JSON face

**Status: built and tested** (`internal/face/kmsjson`, `internal/sigv4`; a black-box test with the official Go SDK in `test/kmsjson-sdk`). Not used by any production client yet.

A second face, on the same listener as [Transit](transit.md), that serves a **subset of the JSON API of a widely implemented cloud key-management service** (the `TrentService` JSON 1.1 protocol that the SDKs of that service speak). Its point is one call, `DeriveSharedSecret`: ECDH with a key that stays on the token, so the **client** seals and opens and the service never sees a data key or the additional data.

## 0. Names, and what this is not

The face is **not** that service, is **not affiliated with, endorsed by or sponsored by** its vendor, and does not use its code. The vendor's name appears in this repository only to say which public wire protocol is imitated, and in the constants the SDKs require on the wire (`X-Amz-Target`, `X-Amz-Date`, `AWS4-HMAC-SHA256`, `application/x-amz-json-1.1`, the service name `kms`, the target prefix `TrentService`). Our own identifiers are neutral: the config key is `kmsjson`, the package is `kmsjson`, and key identifiers look like `arn:hsmgate:kms:<region>:000000000000:key/<name>` (deliberately **not** `arn:aws:…`). The error names (`AccessDeniedException`, …) are what the SDKs map to their error types.

## 1. Why this face exists

Kubernetes KMS v2 and Transit only encrypt and decrypt; on an ECDH-only token (a SmartCard-HSM has no AES) the service has to do the sealing and sees every data key. With `DeriveSharedSecret` the service is an ECDH oracle with a policy.

- **Seal** (client side, no call): fetch the public key (`GetPublicKey`, DER SubjectPublicKeyInfo, pin its fingerprint), make an ephemeral key, ECDH, derive, seal as in [ecies1.md](ecies1.md).
- **Open**: send the ephemeral public key to `DeriveSharedSecret`; the token does ECDH; the client derives the key and opens locally.

## 2. Operations

`POST /` with `X-Amz-Target: TrentService.<Operation>`, `Content-Type: application/x-amz-json-1.1`. Errors: `{"__type": "<Name>", "message": "…"}`.

| Operation | Answer |
|---|---|
| `GetPublicKey` | `KeyId`, `PublicKey` (DER SPKI), `KeySpec` `ECC_NIST_P256`, `KeyUsage` `KEY_AGREEMENT`, `KeyAgreementAlgorithms` `["ECDH"]` |
| `DescribeKey` | `KeyMetadata` (state, usage, numeric `CreationDate`; extras `HsmgateVersion`, `HsmgateLatestVersion`) |
| `ListKeys`, `ListAliases` | the keys the client may use (`alias/<name>`) |
| `DeriveSharedSecret` | `KeyId`, `KeyAgreementAlgorithm` `ECDH`, `SharedSecret` (the raw ECDH result, 32 bytes) |

`DeriveSharedSecret` checks the algorithm is `ECDH`, that the peer key is a P-256 DER SPKI and **on the curve before the token is asked**; `Recipient` is refused; `DryRun` answers `DryRunOperationException` after the policy check. Everything else: `UnsupportedOperationException`.

**Key ids**: `name`, `alias/name`, our ARN form, and the extension `name@N` for version N (the plain forms mean the latest version).

**Errors**: unknown key and ungranted key give the *same* `AccessDeniedException` (no probing); bad input `ValidationException`; rate or a full line to the token `ThrottlingException`; locked or unreachable token `KeyUnavailableException` (HTTP 500, retryable); audit not writable `KMSInternalException`. Signature problems: `MissingAuthenticationTokenException`, `UnrecognizedClientException`, `IncompleteSignatureException`, `InvalidSignatureException`.

## 3. Authentication

Mutual TLS **and** a request signature (SigV4, `AWS4-HMAC-SHA256`, service `kms`, the region from `kmsjson.region`). The access key id maps to a client in the policy; the certificate's client and the signature's client **must be the same**, else `AccessDeniedException`. Signed headers must include `host`, `x-amz-date`, `x-amz-target`; clock skew at most five minutes. The secret is read from `secret_file` (mode 0600, at least 20 bytes) and is replaced by SIGHUP reload. In development mode (loopback, no certificate) the client is taken from the credential.

**No replay cache**: the transport is mutual TLS, so a captured request cannot be seen; a cache would falsely refuse a legitimate retry within the same second (the signature has one-second resolution).

## 4. Configuration

```yaml
kmsjson: {enabled: true, region: local}      # enabling or disabling needs a restart, not a reload
keys:
  etcd: {kmsjson: true, aad: {mode: fixed}, versions: [...]}
clients:
  - name: sdk
    identity: {cn: sdk-client}
    sigv4: {access_key_id: AKIDEXAMPLEEXAMPLE1, secret_file: /run/secrets/sigv4}
    keys: {etcd: {ops: [derive]}}
```

Rules checked at load: a `kmsjson` key must be `aad.mode: fixed`; `derive` needs a `kmsjson` key and a `sigv4` credential; access key ids are 16–128 alphanumerics and unique; a credential with the face off, or the face on with no `kmsjson` key, is an error.

## 5. What it costs

- **No server-side context.** The API has no encryption context, so the service cannot check one; that is why only `fixed`-mode keys can be exposed (a `context`-mode key would let the face bypass context isolation). Keep tenants who must be separate on separate keys.
- **A grant to derive is a grant to open.** `encrypt` cannot be restricted: anyone with the public key can seal.
- **Everything else is as in Transit**: policy, rate limits, the finite line to the token, audit before the answer (peer key recorded as a 6-byte hash), reload by generation, replicas and pinned fingerprints.

## 6. Tests

Unit tests per package; a server test with both faces on one mTLS listener; `test/kmsjson-sdk` builds the real binary and calls it with the official Go SDK (shared secret equals local ECDH, versions, listings, error codes, wrong secret, unknown access key, unsupported operation). It runs in CI.
