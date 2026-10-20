# KMS-JSON face

**Status: built and tested** (`internal/face/kmsjson`, `internal/sigv4`; a black-box test with the official Go SDK in `test/kmsjson-sdk`). Not used by any production client yet.

A second face, on the same listener as [Transit](transit.md), that serves a **subset of the JSON API of a widely implemented cloud key-management service** (the `TrentService` JSON 1.1 protocol that the SDKs of that service speak), so that a program written for that service can use hsmgate by changing its endpoint. A key has one of two usages (`kmsjson_usage`): `key_agreement` (default), where `DeriveSharedSecret` does ECDH on the token and the **client** seals and opens, so the service never sees a data key or the additional data; and `encrypt_decrypt`, where the **service** seals and opens (`Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey`, `GenerateDataKeyWithoutPlaintext`), as in Transit, and sees the plaintext while it works.

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
| `DeriveSharedSecret` | `KeyId`, `KeyAgreementAlgorithm` `ECDH`, `SharedSecret` (the raw ECDH result, 32 bytes: the X coordinate) |

`DeriveSharedSecret` checks the algorithm is `ECDH`, that the peer key is a P-256 DER SPKI and **on the curve before the token is asked**; `Recipient` is refused; `DryRun` answers `DryRunOperationException` after the policy check. Everything else: `UnsupportedOperationException`.

### 2a. Sealing by the service (`kmsjson_usage: encrypt_decrypt`)

- `Encrypt` (plaintext 1 to 4096 bytes), `Decrypt` (the `KeyId` is optional: the ciphertext blob names the key and its version, as clients expect), `ReEncrypt` (needs `decrypt` on the source and `encrypt` on the destination), `GenerateDataKey` and `GenerateDataKeyWithoutPlaintext` (`KeySpec` `AES_128`/`AES_256` or `NumberOfBytes` 1 to 1024; the right is `encrypt`). The only algorithm is `SYMMETRIC_DEFAULT`; here it is `ecies1` ([ecies1.md](ecies1.md)), not AES-GCM, and the blob is ours and opaque. A blob sealed by this face is not readable by the cloud service or the reverse.
- `EncryptionContext` is the additional data. A key in `aad.mode: fixed` takes **none** (a request with one is refused). A key in `aad.mode: context` needs one: the pairs are made canonical (sorted `name=value` lines, at most 1024 bytes, no `\n` in a name or value, no `=` in a name), and the context is allowed when **one of its lines** begins with a prefix of the key's `aad.allow` (and of the client's `contexts`), such as `purpose=dek`. A context that does not match the one used for sealing gives `InvalidCiphertextException`.
- A key for key agreement is refused by these calls and a sealing key by `DeriveSharedSecret`: `InvalidKeyUsageException`. `GetPublicKey` of a sealing key is `UnsupportedOperationException`, as for a symmetric key in the cloud service.
- `GenerateRandom` uses the operating system's generator, not the token's.
- Not done: signing (`Sign`, `Verify`), MAC calls, `CreateKey` and the other management calls (keys are made in the configuration and on the token), grants, tags.

**Key ids**: `name`, `alias/name`, our ARN form, and the extension `name@N` for version N (the plain forms mean the latest version).

**Errors**: unknown key and ungranted key give the *same* `AccessDeniedException` (no probing); bad input `ValidationException`; rate or a full line to the token `ThrottlingException`; locked or unreachable token `KeyUnavailableException` (HTTP 500, retryable); audit not writable `KMSInternalException`. Signature problems: `MissingAuthenticationTokenException`, `UnrecognizedClientException`, `IncompleteSignatureException`, `InvalidSignatureException`.

**Checked against the real service (2026-10-20):** for an `ECC_NIST_P256` / `KEY_AGREEMENT` key in the vendor's cloud, `DeriveSharedSecret` returned a 32-byte `SharedSecret` equal to a local ECDH of the same peer key with the key's `GetPublicKey` output, which is what this face returns. The real answer also carries `KeyOrigin` (not sent by this face; the SDKs treat it as optional) and a full ARN in `KeyId`.

## 3. Authentication

Mutual TLS **and** a request signature (except for a client with `no_cert`, §5) (SigV4, `AWS4-HMAC-SHA256`, service `kms`, the region from `kmsjson.region`). The access key id maps to a client in the policy; the certificate's client and the signature's client **must be the same**, else `AccessDeniedException`. Signed headers must include `host`, `x-amz-date`, `x-amz-target`; clock skew at most five minutes. The secret is read from `secret_file` (mode 0600, at least 20 bytes) and is replaced by SIGHUP reload. In development mode (loopback, no certificate) the client is taken from the credential.

**No replay cache**: the transport is mutual TLS, so a captured request cannot be seen; a cache would falsely refuse a legitimate retry within the same second (the signature has one-second resolution).

## 4. Configuration

```yaml
kmsjson: {enabled: true, region: local}      # enabling or disabling needs a restart, not a reload
keys:
  etcd: {kmsjson: true, aad: {mode: fixed}, versions: [...]}                       # key agreement (the default usage)
  app:  {kmsjson: true, kmsjson_usage: encrypt_decrypt, aad: {mode: fixed}, versions: [...]}   # sealing by the service
clients:
  - name: sdk
    identity: {cn: sdk-client}
    sigv4: {access_key_id: AKIDEXAMPLEEXAMPLE1, secret_file: /run/secrets/sigv4}
    keys: {etcd: {ops: [derive]}, app: {ops: [encrypt, decrypt]}}
```

Rules checked at load: a `kmsjson` key of usage `key_agreement` must be `aad.mode: fixed`; `kmsjson_usage` needs `kmsjson: true`; `derive` needs a `kmsjson` key and a `sigv4` credential; access key ids are 16–128 alphanumerics and unique; a credential with the face off, or the face on with no `kmsjson` key, is an error.

## 5. What it costs

- **No server-side context for key agreement.** `DeriveSharedSecret` has no encryption context, so the service cannot check one; that is why only `fixed`-mode keys can have that usage (a `context`-mode key would let the face bypass context isolation). Keep tenants who must be separate on separate keys, or use the sealing usage, where the context is checked.
- **Clients that cannot present a certificate** (most programs written for the cloud service: the SDKs take only a CA bundle) are served by `sigv4.no_cert: true` on the client. That is **one proof instead of two**: the secret is then the only thing that says who calls. It is therefore narrow: off by default; `allow_from` (addresses or CIDR blocks, the address of the TCP peer, never a header) is required; the secret must be 32 bytes or more; only keys with `kmsjson_usage: encrypt_decrypt` and the rights `encrypt` and `decrypt`; no `derive`, no `rewrap`. The listener then accepts connections without a certificate, and the Transit face and every other client still need one. Refused signatures are counted by address (20 in a minute block that address for the next minute). Weaker than mutual TLS; for the rest, a TLS-terminating front is the alternative.
- **A grant to derive is a grant to open.** `encrypt` cannot be restricted: anyone with the public key can seal.
- **Everything else is as in Transit**: policy, rate limits, the finite line to the token, audit before the answer (peer key recorded as a 6-byte hash), reload by generation, replicas and pinned fingerprints.

## 6. Tests

Unit tests per package; a server test with both faces on one mTLS listener; `test/kmsjson-sdk` builds the real binary and calls it with the official Go SDK (shared secret equals local ECDH, versions, listings, error codes, wrong secret, unknown access key, unsupported operation). `test/kmsjson-boto3` does the same with the vendor's Python SDK (a second, independent client). Both run in CI.
