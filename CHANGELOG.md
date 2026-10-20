# Changelog

## Unreleased (planned as 0.2.0)

### Added
- **KMS-JSON face** (optional, `kmsjson.enabled`): a subset of the JSON API of a widely implemented cloud key service, on the same listener as Transit, so that programs written for it can use hsmgate by changing their endpoint. Operations: `GetPublicKey`, `DescribeKey`, `ListKeys`, `ListAliases`, `DeriveSharedSecret` (ECDH on the token), `Encrypt`, `Decrypt`, `ReEncrypt`, `GenerateDataKey`, `GenerateDataKeyWithoutPlaintext`, `GenerateRandom`, `Sign`, `Verify` (ECDSA P-256 on the token), `GenerateMac`, `VerifyMac` (HMAC-SHA-256 under a key derived on the token). A key has one usage (`kmsjson_usage`: `key_agreement`, `encrypt_decrypt`, `sign_verify`, `generate_verify_mac`). See [docs/specs/kms-json.md](docs/specs/kms-json.md) and [docs/guides/kms-json-clients.md](docs/guides/kms-json-clients.md).
- Authentication of that face: request signing (SigV4, `sigv4` on a client) inside mutual TLS; `sigv4.no_cert` for programs that cannot show a certificate (listed addresses, keys with the usages `encrypt_decrypt`, `sign_verify` and `generate_verify_mac` but never `key_agreement`, secret of 32 bytes or more); refused signatures are counted by address.
- Metrics in the Prometheus text format on the admin socket (`GET /metrics`), **off by default** (`metrics.enabled`), coarse by default (`metrics.detail: basic`).
- Tried with: the official Go SDK and boto3 (CI), Node.js SDK v3, Java SDK v2, OpenBao and HashiCorp Vault `seal "awskms"`, SOPS 3.13.3, cosign 3.1.4, Terraform 1.16.6 (data sources and `aws_kms_ciphertext`), MongoDB client-side field encryption, AWS Encryption SDK for Python, the aws CLI; Sign and MAC on a SmartCard-HSM; shapes and errors compared with the real service.
- Fuzz tests for the signature verifier, the ciphertext blob and the request bodies; a scheduled fuzz step in CI.

### Changed
- The operation, key and client names of a request nobody is known for are logged as `unknown` in both faces.
- Docs: the OpenSC PKCS#11 module exposes no AES; the card itself is not said to lack it.

### Not done
- AES on the card: **decided against** (2026-10-21; see docs/tokens/smartcard-hsm.md for the reasons and what would reopen it), RSA and other algorithms in the KMS-JSON face, key management calls, a replay cache (decided against).
