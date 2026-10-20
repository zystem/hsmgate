# Transit API (the contract of the service)

**Status: implemented.** Code: `internal/face/transit`. Machine-readable form: [api/openapi.yaml](../../api/openapi.yaml) (a test keeps it equal to the handler). The ciphertext inside is described in [ecies1.md](ecies1.md).

hsmgate serves the part of the HashiCorp Vault / OpenBao **Transit** API that three programs use: OpenBao (`seal "transit"`), the etcd plug-in `vault-kubernetes-kms`, and CiNim. It is **not** a Vault: there are no tokens, no policies of Vault, no key creation through the API. Keys are named in the configuration of the service and live on the token; a client only uses them.

## 1. Who may call: identity and authorisation

**Transport.** HTTPS, TLS 1.3 only, a client certificate is **required** and must chain to the client CA of the service. A request without one does not get past the handshake. (A development mode serves plain HTTP on a loopback address only, as one fixed client; it is refused on any other address.)

**Identity.** The certificate is mapped to a *client* of the policy by one of: the SHA-256 of the certificate (`sha256`), a URI SAN (`uri`), or the Common Name (`cn`). Each client has exactly one of these; two clients may not share one. The chain is verified again at **every request** against the *current* CA, so replacing the CA or an expired certificate ends access on connections that are already open. A header is never an identity: `X-Vault-Token` (and anything like it) is ignored.

**Authorisation.** Deny by default. A client has, per key, a grant: the operations it may do (`encrypt`, `decrypt`, `rewrap`), a rate (`per_minute`, `per_day`; 0 is no limit), and for a key in `context` mode optionally `contexts`: prefixes of the contexts it may use (the context of a request must begin with one of them, as well as with one of the key's own `aad.allow`). That is how the certificate of one namespace is kept to the contexts of that namespace; a context outside the grant is `403`, judged before the rules of the key, so the client learns nothing about them. A client that has no grant for a key, a key that does not exist, and a certificate the policy does not know all get the **same** `403 permission denied`: the answer does not tell which keys exist.

## 2. What a key is

A **key** has a name, one or more **versions**, and a rule for the **additional data** (`aad`) of the sealed text. The service holds none of the private key material: a version is a public key whose private half is on a token (or on several tokens that hold the same key, the *holders*: a spare card). Version `N` is the `N`-th in the configuration; the last is the latest.

| `aad.mode` | The additional data is | A request with `context` | Used by |
|---|---|---|---|
| `fixed` | a constant of the key (`aad.fixed`; if unset, `openbao/seal/v1\|<key name>`) | refused (400) | OpenBao's seal and `vault-kubernetes-kms`, which send no context |
| `context` | the `context` of the request, byte for byte | **required**; must begin with one of the key's `aad.allow` prefixes, at most 1024 bytes | CiNim: `cinim/dek/v1\|<organisation>` |

The context is how one key serves many tenants without letting one open another's keys: a text sealed with the context of organisation A does not open with the context of B. It is public (it is written to the audit log); never put a secret in it.

A version may be **pinned** (`fingerprint:`): only holders whose public key has that fingerprint are used, at load and at every use. Holders of a version are tried in order; the next one only when the previous *could not answer* (locked, removed, busy, wrong card), never when it said the text is bad.

## 3. Operations

In every path below `transit` is the mount (`transit.mount`, default `transit`). Bodies are JSON; binary values are standard base64 with padding. `PUT` and `POST` are the same for the three operations.

### `GET /v1/transit/keys/{name}` — public keys and state

Needs any grant on the key. Does not touch the token (the public keys are cached; they are read again after a session was lost). Has its own budget of 120 a minute per client and key, apart from the operation budget.

```json
{"data": {"name": "cinim-shard", "type": "ecdh-es-p256", "latest_version": 1, "min_decryption_version": 1,
  "supports_encryption": true, "supports_decryption": true, "supports_derivation": true, "supports_signing": false,
  "token_state": "ready",
  "keys": {"1": {"public_key": "<base64 of the 65-byte point>", "fingerprint": "<64 hex>"}}}}
```

`token_state` is `ready`, `locked` or `absent` for the best holder of the latest version. `supports_derivation` is true for a key in `context` mode. `latest_version` is a number (Vault clients read it as one).

### `PUT /v1/transit/encrypt/{name}` — seal a data key

Request: `{"plaintext": "<base64>", "context": "<base64>"}`. `plaintext` is 1 byte up to the key's `max_bytes` (default 8192, at most 1 MiB). `context` as in §2.
Response `200`: `{"data": {"ciphertext": "vault:v1:<base64>", "key_version": 1}}`. The service seals under the **latest** version. It needs the public key only, so it works while the token is locked; after a session was lost it needs the card to be sure of the key.

### `PUT /v1/transit/decrypt/{name}` — open a sealed data key

Request: `{"ciphertext": "vault:v<N>:<base64>", "context": "<base64>"}`. The ciphertext may be any version from the first to the latest.
Response `200`: `{"data": {"plaintext": "<base64>"}}`. Needs the token logged in (one ECDH on the card). The opened data must not be larger than `max_bytes`; the ciphertext must not be larger than `3 × max_bytes + 1024` characters.

### `PUT /v1/transit/rewrap/{name}` — move a ciphertext to the latest version

Request as for decrypt. Response `200`: `{"data": {"ciphertext": "vault:v<latest>:...", "key_version": <latest>}}`. The data key is opened and sealed again **inside the service**; the plaintext never leaves it. This is the operation of a key rotation (see [../operations.md](../operations.md)). Needs the `rewrap` grant.

### Calls that other clients make around Transit

| Call | Answer |
|---|---|
| `GET /v1/sys/health` | `200 {"initialized": true, "sealed": false, "standby": false, "version": "hsmgate"}`; needs no client in the policy, does not touch the token |
| `GET /v1/auth/token/lookup-self` | `200` with `data.ttl = 0`, `data.creation_ttl = 0` for a client the policy knows (a token that never expires, so clients do not try to renew); `403` for a certificate the policy does not know, so such a client fails at its start |
| `POST /v1/auth/token/renew-self` | the same, with an `auth` block |

Everything else under the mount (`datakey`, `sign`, `hmac`, key creation, export, …) is `404 unsupported path`.

## 4. The ciphertext

`vault:v<N>:<base64 of an ecies1 text>`. `N` is the key version it was sealed under. OpenBao splits it at the colons into three; the third part has no colon. For a 32-byte data key the ciphertext is 473 characters. Clients must treat it as opaque.

## 5. Errors

Errors are `{"errors": ["<message>"]}`. The header `X-Hsmgate-Retryable: true|false` tells a client whether trying the **same request** later can succeed; a client should read that, not guess from the status. `Retry-After` (seconds) accompanies 429 and most 503.

| Status | Retryable | Message (examples) | When |
|---|---|---|---|
| 400 | false | `invalid request body`, `missing plaintext`, `failed to base64-decode plaintext`, `invalid plaintext` | the body is not what the operation takes |
| 400 | false | `missing context`, `context not allowed for this key`, `context is too long`, `this key takes no context`, `failed to base64-decode context` | the context breaks the rule of the key |
| 400 | false | `invalid ciphertext: cannot be opened with this key` | the text is damaged, for another key, of a version that does not exist, or sealed with another context. All these look the same to the client on purpose |
| 400 | false | `ciphertext too large for this key`, `…larger than max_bytes of this key` | size limits |
| 403 | false | `permission denied` | no certificate the policy knows, no grant for the key or the operation, a context outside the client's `contexts`, or no such key |
| 404 | false | `unsupported path` | a path or method the service does not have |
| 413 | false | `request body too large` | the body is over `4 × max_bytes + 4096` bytes |
| 429 | **true** | `rate limit exceeded` | the client's rate for this key is spent (fixed one-minute and one-day windows) |
| 503 | **true** | `token locked`, `token unavailable` | the token is locked (PIN not entered or refused), removed, or the wrong card is in |
| 503 | **true** | `busy` | the line to the token is full (§6) |
| 503 | **true** | `audit log unavailable` | the decision cannot be written down, so nothing is done |

A trailing garbage after the JSON value is a 400. Unknown JSON fields are ignored.

## 6. Guarantees about behaviour

- **Audit before answer.** Every decision, refused ones included, is one JSON line: time, request id, client, face, key, operation, the context (if the key takes one), result. An answer with data (`200`) is sent only **after** its line is written; if the log cannot be written, the client gets `503` and no data. Plaintext, ciphertext, PIN and keys are never written.
- **Request ids.** `X-Request-Id` of the request is returned (and logged) if it is made of letters, digits, `-`, `_`, `.` and at most 64 characters; otherwise a random one.
- **A finite line to the token.** At most `limits.max_concurrent` (default 8) operations run on the token and as many wait; the next is refused at once with 503 `busy`; one that waits longer than `limits.queue_seconds` (default 2) gets 503 too. A card does one operation at a time.
- **A locked token is a state, not a failure.** `encrypt` and `keys/{name}` work; `decrypt` and `rewrap` answer 503 retryable until an operator unlocks. The service never tries a PIN again by itself after a refusal (the card blocks after three).
- **Reloads are whole.** A configuration is applied as one generation (policy, keys, tokens, identities, certificates) or not at all. A request sees one generation from start to end. New versions are added without breaking old ciphertexts: `vault:v1:` texts open after `v2` exists.
- **Rotation.** `encrypt` always uses the latest version; `decrypt` accepts every version; `rewrap` moves a text to the latest.
- **No secrets in responses or errors.** Messages are fixed texts; a failure of the token is reported as `token unavailable`, not with the driver's words.

## 7. Examples

Against a development instance (software key, plain loopback; real use is the same with `--cacert --cert --key https://…`). `plaintext` is `0123456789abcdef0123456789abcdef`, `context` is `cinim/dek/v1|org-42`.

```
$ curl -s -X PUT $B/encrypt/cinim-shard -d '{"plaintext":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=","context":"Y2luaW0vZGVrL3YxfG9yZy00Mg=="}'
{"data":{"ciphertext":"vault:v1:ZWNpZXMxLjZjOGE4ZjU1Yj…","key_version":1}}

$ curl -s -X PUT $B/decrypt/cinim-shard -d '{"ciphertext":"vault:v1:ZWNpZXMx…","context":"Y2luaW0vZGVrL3YxfG9yZy00Mg=="}'
{"data":{"plaintext":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}}

# the context of organisation org-43
HTTP/1.1 400 Bad Request
X-Hsmgate-Retryable: false
{"errors":["invalid ciphertext: cannot be opened with this key"]}

# no context on a key in context mode
{"errors":["missing context"]}

# a key the client has no grant for (or that does not exist)
HTTP/1.1 403 Forbidden
{"errors":["permission denied"]}

# a client over its rate
HTTP/1.1 429 Too Many Requests
Retry-After: 5
X-Hsmgate-Retryable: true
{"errors":["rate limit exceeded"]}
```

## 8. How the three clients use it

| Client | Key mode | Calls | Notes |
|---|---|---|---|
| OpenBao `seal "transit"` | `fixed` | `encrypt/{key}`, `decrypt/{key}` (and `lookup-self`, unless renewal is off) | With `tls_ca_cert`, `tls_client_cert`, `tls_client_key` for mTLS. Verified: init, restart, auto-unseal |
| `vault-kubernetes-kms` (etcd encryption) | `fixed`, own constant | `lookup-self` at start and every minute; for each `Status` poll `keys/{key}` plus an `encrypt` and a `decrypt` of a probe; for each DEK `encrypt/{key}` then `keys/{key}` (reads `latest_version`), `decrypt/{key}` | Needs `ttl` and `creation_ttl` numbers in `lookup-self`. See [kubernetes-kms-v2.md](kubernetes-kms-v2.md) |
| CiNim (the core of the CI system) | `context` | `encrypt`, `decrypt`, `rewrap` | One key per shard or per organisation; the context carries the organisation |

## 9. Conformance

`TestOpenBaoSealRoundTrip`, `TestNimMadeOpenBaoCiphertextOpens`, `TestNimMadeCinimCiphertextOpensWithContext`, `TestDenyByDefault`, `TestRateLimit`, `TestLockedTokenIsRetryable`, `TestRotationWithReload`, `TestFirstFailedAuditWriteWithholdsThePlaintext`, `TestSizeLimits`, `TestAdmissionIsAFiniteLine`, `TestHandlerAnswersAreDocumented` (the OpenAPI file), `FuzzDecryptRequest`. A second implementation of this contract must open the vectors of [ecies1.md](ecies1.md) and answer the same way to these.
