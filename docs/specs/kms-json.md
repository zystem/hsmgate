# KMS-JSON face

**Status: built and tested** (`internal/face/kmsjson`, `internal/sigv4`; a black-box test with the official Go SDK in `test/kmsjson-sdk`). Not used by any production client yet.

A second face, on the same listener as [Transit](transit.md), that serves a **subset of the JSON API of a widely implemented cloud key-management service** (the `TrentService` JSON 1.1 protocol that the SDKs of that service speak), so that a program written for that service can use hsmgate by changing its endpoint. A key has one of two usages (`kmsjson_usage`): `key_agreement` (default), where `DeriveSharedSecret` does ECDH on the token and the **client** seals and opens, so the service never sees a data key or the additional data; and `encrypt_decrypt`, where the **service** seals and opens (`Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey`, `GenerateDataKeyWithoutPlaintext`), as in Transit, and sees the plaintext while it works.

## 0. Names, and what this is not

The face is **not** that service, is **not affiliated with, endorsed by or sponsored by** its vendor, and does not use its code. The vendor's name appears in this repository only to say which public wire protocol is imitated, and in the constants the SDKs require on the wire (`X-Amz-Target`, `X-Amz-Date`, `AWS4-HMAC-SHA256`, `application/x-amz-json-1.1`, the service name `kms`, the target prefix `TrentService`). Our own identifiers are neutral: the config key is `kmsjson`, the package is `kmsjson`, and key identifiers look like `arn:hsmgate:kms:<region>:000000000000:key/<name>` (deliberately **not** `arn:aws:…`). The error names (`AccessDeniedException`, …) are what the SDKs map to their error types.

## 1. Why this face exists

Kubernetes KMS v2 and Transit only encrypt and decrypt; on a token that is used for ECDH only (a SmartCard-HSM through the OpenSC module, which exposes no AES) the service has to do the sealing and sees every data key. With `DeriveSharedSecret` the service is an ECDH oracle with a policy.

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

### 2b. Signing (`kmsjson_usage: sign_verify`)

`Sign` and `Verify` with `ECDSA_SHA_256` (P-256): the signature is made **on the token** (`CKM_ECDSA` over the SHA-256 digest) and returned as ASN.1 DER, as the SDKs expect. `MessageType` `RAW` (1 to 4096 bytes, hashed by the service) or `DIGEST` (32 bytes). `Verify` uses the public key and no private operation; an invalid signature is `KMSInvalidSignatureException`. The rights are `sign` and `verify`; `GetPublicKey` and `DescribeKey` show `SIGN_VERIFY` and `SigningAlgorithms`. A private key signs **or** does ECDH, never both: configuration is refused if a signing key shares a token key with another key. The audit holds the first 6 bytes of the digest, not the message. Tried on a card (§7).

### 2c. MAC (`kmsjson_usage: generate_verify_mac`)

`GenerateMac` and `VerifyMac` with `HMAC_SHA_256` (message 1 to 4096 bytes). The token has ECDH but no HMAC key, so the MAC key is **derived on the token**: `K = HKDF-SHA256(ECDH(private key, P), salt "hsmgate/mac/v1", info "mac|" + fingerprint of the public key)`, where `P` is a fixed point from a hash by try-and-increment (its value is pinned in `internal/keyops/mac_test.go`; nobody knows its discrete logarithm, so the shared secret cannot be computed without the private key). Nothing is stored: the same key gives the same MAC key at every start and on every replica of it; the service computes the HMAC itself and the key is in its memory while it works. `kmsjson.mac_cache_seconds` (0 to 3600, default 0) keeps the derived key in memory for that time, so that a MAC is not an ECDH on the card each time; a longer cache is faster and leaves a key derived from the token's key in memory for longer. A MAC carries no version: `GenerateMac` uses the latest version, `VerifyMac` tries the latest and then the earlier ones (a version can be asked for as `name@N`, then only it is tried). `VerifyMac` of a wrong MAC is `KMSInvalidMacException`. The rights are `generate_mac` and `verify_mac`; the key shares no token key with any other key. The MACs of this face are not the MACs of the cloud service (different keys), only the calls are the same.

### 2a. Sealing by the service (`kmsjson_usage: encrypt_decrypt`)

- `Encrypt` (plaintext 1 to 4096 bytes), `Decrypt` (the `KeyId` is optional: the ciphertext blob names the key and its version, as clients expect), `ReEncrypt` (needs `decrypt` on the source and `encrypt` on the destination), `GenerateDataKey` and `GenerateDataKeyWithoutPlaintext` (`KeySpec` `AES_128`/`AES_256` or `NumberOfBytes` 1 to 1024; the right is `encrypt`). The only algorithm is `SYMMETRIC_DEFAULT`; here it is `ecies1` ([ecies1.md](ecies1.md)), not AES-GCM, and the blob is ours and opaque. A blob sealed by this face is not readable by the cloud service or the reverse.
- `EncryptionContext` is the additional data. A key in `aad.mode: fixed` takes **none** (a request with one is refused). A key in `aad.mode: context` needs one: the pairs are made canonical (sorted `name=value` lines, at most 1024 bytes, no `\n` in a name or value, no `=` in a name), and the context is allowed when **one of its lines** begins with a prefix of the key's `aad.allow` (and of the client's `contexts`), such as `purpose=dek`. A context that does not match the one used for sealing gives `InvalidCiphertextException`.
- A key for key agreement is refused by these calls and a sealing key by `DeriveSharedSecret`: `InvalidKeyUsageException`. `GetPublicKey` of a sealing key is `UnsupportedOperationException`, as for a symmetric key in the cloud service.
- `GenerateRandom` uses the operating system's generator, not the token's.
- Not done: RSA and other curves, other MAC or signing algorithms, `CreateKey` and the other management calls (keys are made in the configuration and on the token), grants, tags.

**Identifiers in answers**: when the request names the key with a full identifier (`arn:PARTITION:kms:REGION:ACCOUNT:key/NAME`, the parts of safe characters, NAME the key), the answer carries that identifier; else `arn:hsmgate:kms:<region>:000000000000:key/<name>`. Programs that keep the identifier in what they make need this.

**Key ids**: `name`, `alias/name`, our ARN form, and the extension `name@N` for version N (the plain forms mean the latest version).

**Errors**: unknown key and ungranted key give the *same* `AccessDeniedException` (no probing); bad input `ValidationException`; rate or a full line to the token `ThrottlingException`; locked or unreachable token `KeyUnavailableException` (HTTP 500, retryable); audit not writable `KMSInternalException`. Signature problems: `MissingAuthenticationTokenException`, `UnrecognizedClientException`, `IncompleteSignatureException`, `InvalidSignatureException`.

**Checked against the real service (2026-10-20):** for an `ECC_NIST_P256` / `KEY_AGREEMENT` key in the vendor's cloud, `DeriveSharedSecret` returned a 32-byte `SharedSecret` equal to a local ECDH of the same peer key with the key's `GetPublicKey` output, which is what this face returns. The real answer also carries `KeyOrigin` (not sent by this face; the SDKs treat it as optional) and a full ARN in `KeyId`.

## 3. Authentication

Mutual TLS **and** a request signature (except for a client with `no_cert`, §5) (SigV4, `AWS4-HMAC-SHA256`, service `kms`, the region from `kmsjson.region`). The access key id maps to a client in the policy; the certificate's client and the signature's client **must be the same**, else `AccessDeniedException`. Signed headers must include `host`, `x-amz-date`, `x-amz-target`; clock skew at most five minutes. The secret is read from `secret_file` (mode 0600, at least 20 bytes) and is replaced by SIGHUP reload. In development mode (loopback, no certificate) the client is taken from the credential.

**No replay cache** (decided 2026-10-21): a captured request cannot be read off the transport (TLS 1.3), the window of the signature is five minutes, and a cache would falsely refuse a legitimate retry within the same second (the signature has one-second resolution). The residual risk is a front or a proxy that logs whole requests; for a client that must be protected against that, keep it on mutual TLS and do not log the `Authorization` header.

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

Rules checked at load: a `kmsjson` key of usage `key_agreement` must be `aad.mode: fixed`; `kmsjson_usage` needs `kmsjson: true` and is `key_agreement`, `encrypt_decrypt`, `sign_verify` or `generate_verify_mac`; a signing key and a MAC key have their own rights only (`sign`, `verify`; `generate_mac`, `verify_mac`) and share no token key with another key; `derive` needs a `kmsjson` key and a `sigv4` credential; access key ids are 16–128 alphanumerics and unique; a credential with the face off, or the face on with no `kmsjson` key, is an error.

## 5. What it costs

- **No server-side context for key agreement.** `DeriveSharedSecret` has no encryption context, so the service cannot check one; that is why only `fixed`-mode keys can have that usage (a `context`-mode key would let the face bypass context isolation). Keep tenants who must be separate on separate keys, or use the sealing usage, where the context is checked.
- **Clients that cannot present a certificate** (most programs written for the cloud service: the SDKs take only a CA bundle) are served by `sigv4.no_cert: true` on the client. That is **one proof instead of two**: the secret is then the only thing that says who calls. It is therefore narrow: off by default; `allow_from` (addresses or CIDR blocks, the address of the TCP peer, never a header) is required; the secret must be 32 bytes or more; only keys with `kmsjson_usage: encrypt_decrypt` and the rights `encrypt` and `decrypt`; no `derive`, no `rewrap`. The listener then accepts connections without a certificate, and the Transit face and every other client still need one. Refused signatures of requests **without a certificate** are counted by the address of the peer (20 in a minute block that address for the next minute, for requests without a certificate only, so that a peer cannot lock out the clients that show one and share its address). Weaker than mutual TLS; for the rest, a TLS-terminating front is the alternative.
- **A grant to derive is a grant to open.** `encrypt` cannot be restricted: anyone with the public key can seal.
- **Everything else is as in Transit**: policy, rate limits, the finite line to the token, audit before the answer (peer key recorded as a 6-byte hash), reload by generation, replicas and pinned fingerprints.

## 6. Tests

Unit tests per package; a server test with both faces on one mTLS listener; `test/kmsjson-sdk` builds the real binary and calls it with the official Go SDK (shared secret equals local ECDH, versions, listings, error codes, wrong secret, unknown access key, unsupported operation). `test/kmsjson-boto3` does the same with the vendor's Python SDK (a second, independent client). Both run in CI.

## 7. Verified with a real program (2026-10-20)

OpenBao v2.6.1 with `seal "awskms"` (`endpoint` = hsmgate, `kms_key_id = seal`, `AWS_CA_BUNDLE` = the CA of the service, a credential of a client with `no_cert: true` and `allow_from: [127.0.0.1]`, a soft key with `kmsjson_usage: encrypt_decrypt`): `operator init`, a secret written, OpenBao stopped and started again; it unsealed by itself through hsmgate (`describekey`, `decrypt`, `encrypt` as client `openbao` in the audit) and returned the secret. OpenBao 2.6 warns that this seal moves into an external plugin in the next minor release. SOPS 3.13.3 also sealed and opened its data key through the face (endpoint from `AWS_ENDPOINT_URL_KMS`, a `no_cert` client); it accepts only key identifiers that begin with `arn:aws`, which the face reads by their `:key/<name>` tail ([the guide](../guides/kms-json-clients.md)). Not tried: Terraform and other programs that manage keys.

On a SmartCard-HSM (firmware 4.1, OpenSC module), 2026-10-20: a new P-256 key pair made on the card with `pkcs11-tool --keypairgen` (usage sign), a second hsmgate instance on loopback with `kmsjson_usage: sign_verify` over that key and the PIN file read by hsmgate itself. `GetPublicKey` returned the card's public point, `Sign` returned a 70 to 72 byte DER signature that verified locally with that key (boto3 and `cryptography`), `Verify` was valid for the message and `KMSInvalidSignatureException` for another message; the audit holds the digest prefix only. The production instance and its key were not touched. Not tried: the signing key under load.

Checked against the real cloud service with two RSA_4096 keys (one ENCRYPT_DECRYPT, one SIGN_VERIFY), 2026-10-20: the fields of the answers of `Encrypt`, `Decrypt`, `Sign`, `Verify` and `GetPublicKey` and the error types for a damaged ciphertext (`InvalidCiphertextException`), a signature of another message (`KMSInvalidSignatureException`), an empty plaintext (`ValidationException`) and an algorithm that does not fit the key (`InvalidKeyUsageException`, which this face now also gives) are the same as here. The service requires the `KeyId` in `Decrypt` for an asymmetric key; here it is optional for the symmetric usage. This face has no RSA: the keys of that check were only a reference for the shapes.

The same check with an `ECC_NIST_P256` / `SIGN_VERIFY` key (the only algorithm this face has), 2026-10-20: `Sign` gave a 70 byte ASN.1 DER ECDSA signature that verifies locally with the key of `GetPublicKey` (as ours does); `RAW` and `DIGEST` both work; `Verify` is `SignatureValid: true`, and `KMSInvalidSignatureException` for another message and for 20 random bytes; a digest of the wrong length, an empty message and `DryRun` give `ValidationException`, `ValidationException` and `DryRunOperationException`; `RSASSA_PSS_SHA_256` and `ECDSA_SHA_384` give `InvalidKeyUsageException`. All as here.

And with a `SYMMETRIC_DEFAULT` key, 2026-10-20: `Encrypt`, `Decrypt` without a `KeyId`, `ReEncrypt`, `GenerateDataKey` (`AES_256`; `NumberOfBytes`), `GenerateDataKeyWithoutPlaintext`, a context that is the same, another or missing (`InvalidCiphertextException` for the last two), garbage (`InvalidCiphertextException`), a plaintext over 4096 bytes, `NumberOfBytes` over 1024, both or neither of `KeySpec` and `NumberOfBytes` (`ValidationException`), `DryRun`: the same fields and error types as here. The real answers carry one more optional field, `KeyMaterialId` (and `CurrentKeyMaterialId`, `Origin`, `AWSAccountId` in `DescribeKey`), which this face does not send; the SDKs do not need them. `GenerateRandom` could not be compared (no right for the test user). The service also has `GenerateMac` and `VerifyMac` (`HMAC_SHA_256`, key usage `GENERATE_VERIFY_MAC`); this face does not.

MAC: the fields and the error types of `GenerateMac` and `VerifyMac` (`Mac`, `MacAlgorithm`, `KeyId`; `MacValid`; `KMSInvalidMacException` for another message and for random bytes; `InvalidKeyUsageException` for `HMAC_SHA_512`; `ValidationException` for an empty message; `DryRunOperationException`) were read from the real service with an `HMAC_256` key before this was written, and the Go SDK and boto3 tests here call the same shapes. Values cannot be compared (the keys differ).

MAC on a SmartCard-HSM (firmware 4.1, OpenSC), 2026-10-20: a new P-256 key pair with the usage derive, a second hsmgate instance on loopback with `kmsjson_usage: generate_verify_mac` over it (no cache). `GenerateMac` took about 50 ms (one ECDH on the card), gave 32 bytes and the same MAC again for the same message, `VerifyMac` was valid, and `KMSInvalidMacException` for another message; after the instance was stopped and started again, the MAC made before still verified (the key is the same at every start, nothing is stored). The key was deleted from the card afterwards; the production key and instance were not touched.
