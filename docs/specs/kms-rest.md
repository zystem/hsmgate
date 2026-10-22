# REST face

**Status: built and tested** (`internal/face/kmsrest`; a black-box test with the official Go SDK in `test/kmsrest-sdk`). Not used by any production client yet.

A fourth face, on the same listener as the others, that serves a **subset of the REST API of a cloud key vault** the way its client libraries speak it: JSON over HTTPS, a bearer token from an OAuth 2.0 authority. The face is **not** that service and not affiliated with its vendor. Our identifiers are neutral (`kmsrest`, package `kmsrest`, credential block `oauth`); the vendor's names appear only where the wire needs them (the paths `/keys`, the field and algorithm names, the challenge resource).

## 1. Configuration

```yaml
kmsrest: {enabled: true, tenant: hsmgate}
keys:
  seal: {kmsrest: true, kmsjson_usage: encrypt_decrypt, versions: [...], aad: {mode: fixed}}
clients:
  - name: app
    oauth: {client_id: app-client, secret_file: /etc/hsmgate/app.secret}   # or public_key_file: of a certificate
```

A key is on the face with `kmsrest: true`, with one usage (`encrypt_decrypt`, `sign_verify`, `generate_verify_mac`; no key agreement). `tenant` is the directory identifier in the token path. A credential is a client secret (32 bytes or more, from a file) or the public key of a certificate whose private key the client holds (an RS256 assertion). `no_cert` and `allow_from` mean what they mean on the other faces.

## 2. Authentication

- `GET /{tenant}/v2.0/.well-known/openid-configuration` (public): where the token endpoint is.
- `POST /{tenant}/oauth2/v2.0/token`, grant `client_credentials`, with `client_id` and `client_secret`, or `client_assertion_type=…jwt-bearer` and `client_assertion` (RS256, `iss`/`sub` the client id, at most 24 hours long). The answer is an opaque access token (random, one hour, in memory only).
- A call without a valid bearer gets `401` and `WWW-Authenticate: Bearer authorization="https://HOST/TENANT", resource="https://vault.azure.net"`, the challenge the client libraries answer by asking their credential for a token.

On every call the credential must still exist, a client certificate if shown must be the client's, a call without a certificate needs `oauth.no_cert` and a listed address, and refused credentials without a certificate are counted by address. Audit before answer: if the audit line cannot be written, the call fails with `503`.

## 3. Operations, and the client function each one serves

The client functions are those of `go.step.sm/crypto/kms/azurekms` (Apache-2.0) and of the official SDK. `api-version` is required and not interpreted. A version is 32 hexadecimal digits (the number of the version of the key); a missing version is the latest.

| Server operation | Serves | Notes |
|---|---|---|
| `GET /keys/{name}[/{version}]` | `KeyVault.GetPublicKey`, the preload of `CreateSigner` | a signing key: a JWK `EC-HSM`, `P-256`; other usages: `oct-HSM`, no material |
| `POST …/sign` | `Signer.Sign` | `ES256` over a SHA-256 digest, ECDSA on the token, signature `r‖s` (64 bytes); `HS256` on a MAC key (the MAC of `value`) |
| `POST …/verify` | the SDK's verify | `ES256` or `HS256`; `digest`, `value` |
| `POST …/encrypt`, `…/decrypt` | the SDK's calls with a symmetric key | `A256GCM` as the clients name it; `aad` is passed as it is; 64 KiB |
| `POST …/wrapkey`, `…/unwrapkey` | the same calls | `A256KW` |
| `GET /keys`, `GET /keys/{name}/versions` | tools that look a key up | only keys the client may see |
| `POST /rng` | the SDK's call | 1–128 bytes of the operating system's generator |

Everything else answers `404`. Errors: `{"error": {"code", "message"}}`: `401 Unauthorized`, `403 Forbidden` (key not there, not on the face, or no right: one answer), `400 BadParameter` (usage, algorithm, size, damaged ciphertext), `429 Throttled`, `503 ServiceUnavailable`.

## 4. What does not work

- The algorithm names `A256GCM` and `A256KW` are what the clients send; the cipher is the one of the blob of the service (an ecies1 blob that authenticates the key name and the version). The blob goes in `value`; `iv` and `tag` are not used, and a client that wants to read them out of the answer gets none.
- Signing is ECDSA P-256 only (`ES256`); RSA, P-384 and P-521 keys are not offered.
- `go.step.sm/crypto/kms/azurekms` takes the vault from the name of the key (`vault.vault.azure.net`) and does not let the endpoint be set: to use it the name must resolve to hsmgate with a certificate the client trusts. The official SDK takes the vault URL and the authority host (CI: `test/kmsrest-sdk`).
- Key creation, rotation, import, backup and deletion: not supported (keys are in the configuration).
