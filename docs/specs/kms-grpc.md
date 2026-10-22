# gRPC face

**Status: built and tested** (`internal/face/kmsgrpc`; a black-box test with the official Go client library in `test/kmsgrpc-sdk`). Not used by any production client yet.

A third face, on the same listener as [Transit](transit.md) and the [KMS-JSON face](kms-json.md), that serves a **subset of the gRPC API of a cloud key service** the way its client libraries speak it: unary calls over HTTP/2 in the gRPC framing, messages in protobuf. The face is **not** that service and not affiliated with its vendor. Our identifiers are neutral (`kmsgrpc`, package `kmsgrpc`); the vendor's names appear only where the wire needs them (the service path, the resource names `projects/…/keyRings/…/cryptoKeys/…`, the token grant type). There is no generated code and no gRPC library in the service: framing and the few messages are written by hand on top of `protowire` (`pb.go`), and the field numbers are checked by the black-box test.

## 1. Configuration

```yaml
kmsgrpc: {enabled: true, project: hsmgate, location: global, key_ring: main, token_path: /oauth2/token}
keys:
  seal: {kmsgrpc: true, kmsjson_usage: encrypt_decrypt, versions: [...], aad: {mode: fixed}}
clients:
  - name: app
    jwt: {issuer: app@example.test, public_key_file: /etc/hsmgate/app.pub, no_cert: true, allow_from: ["10.0.0.0/24"]}
```

A key is on the face with `kmsgrpc: true` and has one usage (`encrypt_decrypt`, `sign_verify`, `generate_verify_mac`; no key agreement here). Resource names are `projects/P/locations/L/keyRings/R/cryptoKeys/KEY[/cryptoKeyVersions/N]`; P, L, R come from the configuration, KEY is the name of the key, N its version (1 is the first). A name of another project, location or ring is answered like a key that does not exist.

## 2. Authentication

The client holds a **service account**: an RSA private key; the service knows its public half (`jwt.public_key_file`, RSA ≥ 2048 bits) and the `issuer` (`iss`). Two ways in, both accepted on every call:

1. the client trades a JWT assertion (RS256) at the token endpoint (`POST token_path`, `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) for an opaque access token (random, one hour, in memory only); it is what the client libraries do with the `token_uri` of a service account file;
2. the client sends a JWT that it signed itself as the bearer.

A JWT is refused when it is not RS256, is expired (5 minutes of clock skew), is issued in the future, or lives longer than 24 hours. The audience is not checked (there is one service). On every call, not only at login: the credential must still exist, a client certificate if shown must be the client's, a call without a certificate needs `jwt.no_cert` and a listed address (`allow_from`), and refused tokens without a certificate are counted by address (as in the KMS-JSON face). Audit before answer: if the audit line cannot be written, the call fails with `UNAVAILABLE`.

## 3. Methods, and the client function each one serves

The client functions are those of `go.step.sm/crypto/kms/cloudkms` (Apache-2.0) and of the official client library.

| Server method | Serves | Notes |
|---|---|---|
| `GetPublicKey` | `CloudKMS.GetPublicKey`, `CloudKMS.CreateSigner` (reads the key once) | sign_verify keys; PEM, `EC_SIGN_P256_SHA256`, `pem_crc32c` |
| `AsymmetricSign` | `Signer.Sign` | SHA-256 digest only; ECDSA on the token, DER signature; `digest_crc32c` checked |
| `Encrypt`, `Decrypt` | the library's symmetric calls | encrypt_decrypt keys; sealing under the key's token key (ecies2 blob that authenticates name and version); additional authenticated data passed as it is; 64 KiB; `*_crc32c` checked and answered |
| `MacSign`, `MacVerify` | the library's MAC calls | HMAC-SHA-256 under a key derived on the token |
| `GetCryptoKey`, `GetCryptoKeyVersion`, `ListCryptoKeys`, `ListCryptoKeyVersions` | tools that look a key up | only keys on the face the client may see; state ENABLED, protection level HSM |
| `GenerateRandomBytes` | the library's call | 1–1024 bytes of the operating system's generator |

Everything else answers `UNIMPLEMENTED`. Status codes: `UNAUTHENTICATED` (token), `PERMISSION_DENIED` (key not there, not on the face, or no right: one answer), `INVALID_ARGUMENT` (usage, size, checksum, damaged ciphertext), `RESOURCE_EXHAUSTED` (budget, busy), `UNAVAILABLE` (token locked or absent, audit), `INTERNAL`.

## 4. What does not work

- `go.step.sm/crypto/kms/cloudkms` has no option for an endpoint: it always dials the public address of the service. To use it with hsmgate the name `cloudkms.googleapis.com` has to resolve to hsmgate and the certificate has to be one that the client trusts for that name. The official client library takes `option.WithEndpoint` and works as it is (CI: `test/kmsgrpc-sdk`).
- REST transport of the same API: not yet.
- Key creation, rotation, import, destroy: not supported (keys are in the configuration).
