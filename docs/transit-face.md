# The Transit face: the API for CiNim

Decision (2026-10-19): CiNim talks to hsmgate through the **Vault/OpenBao Transit API** (`encrypt`, `decrypt`, `rewrap`, `keys/<name>`). No own protocol. The AWS KMS option (`DeriveSharedSecret`) is kept only as a
possible later face: [awskms-face.md](awskms-face.md).

Why Transit: plain JSON over HTTPS, no request signing, a **context** that the service can check, named keys with versions and `rewrap`, and the same face serves OpenBao (seal `transit`), SOPS and `vault-kubernetes-kms` for etcd.
The service does the ECIES itself (the token does only ECDH, so a card without AES works); it sees data keys in plaintext while it wraps or unwraps, and says so in the threat model.

## Mapping

| Transit | hsmgate |
|---|---|
| mount (`transit` by default, configurable) | one face instance; a host may run several hsmgate processes, each with its own mount/port |
| key name | a configured key: `name -> (token, key id, scheme)`; a tenant's own KEK is just another name |
| `context` (base64) | per key, `aad.mode`: **`fixed`** (the default for OpenBao's seal, which sends no context): AAD is a constant for the key, `openbao/seal/v1\|<key name>` unless `aad.fixed` says otherwise (the value `kekd` used, so existing ciphertexts open), and a request with a context is refused; **`context`** (CiNim): AAD is the context bytes exactly as sent, required, and must begin with one of `aad.allow` (e.g. `cinim/dek/v1\|`), so texts made by CiNim's `kekd` open unchanged |
| `plaintext` / `ciphertext` | `vault:v<N>:` + base64 of the sealed text (`ecies1.<fingerprint>...`); N is the key version |
| key versions | one version per physical key/public key; new key = new version; `min_decryption_version`, `latest_version` as Transit reports them |
| `rewrap` | open under the version in the text, seal to the latest version, without the plaintext leaving the process |
| `GET keys/<name>` | `type: "ecdh-es-p256"` (extension), `latest_version`, `keys` (public keys by version, base64 DER), `supports_*` flags; no token access |
| `GET sys/health`, `auth/token/lookup-self`, `renew-self` | answered with fixed values so existing clients start; the token is never an authentication |

Not implemented (return Transit-style 4xx): `datakey`, `sign`, `verify`, `hmac`, `hash`, `random`, key creation and export through the API. Keys are created by the operator in the configuration and on the token.

Multiple physical tokens: a name lists tokens in order; a version belongs to one token, or one version may list several tokens that hold the same key (restored from a DKEK backup) for failover. A sealed text names the fingerprint,
so the service finds the right token without trying.

## Errors

Transit-style `{"errors": ["..."]}`, plus a header `X-Hsmgate-Retryable: true|false` (and `Retry-After` for rate limiting). HTTP: 400 bad request/context/ciphertext, 403 policy, 404 unknown key, 429 rate, 503 locked/unavailable (retryable),
final failures (wrong key, damaged, wrong context) are 400 with a distinct message so the client can tell final from passing, as `core/kekclient.nim` does today with 409/422/423/429/503.

## Authentication

TLS 1.3, **client certificate required**, identity from URI SAN / pin / CN mapped to a client in the policy; `X-Vault-Token` is ignored. Per client and per key: allowed operations (`encrypt`, `decrypt`, `rewrap`), allowed context patterns, rate (minute, day), size.
Deny by default; every decision, including refusals, is audited (never a key, plaintext, PIN or ciphertext body). Admin (unlock, disable, reload) on a separate socket.

## What CiNim changes (P7)

`core/kekclient.nim`: the calls become `PUT /v1/transit/encrypt/<key>` and `decrypt/<key>` with `context`; the key name comes from the tenant's KEK setting (shard default, or the tenant's own); `retryable` from the header.
Stored `ecies1` texts remain readable: the Transit text wraps them, and a migration can wrap old `kekd` outputs without opening them (the service accepts a bare `ecies1.` text on `decrypt` for this, behind a flag).
Old `kekd` (Nim) and its v1 API are removed after the move. The face's behaviour is specified by test vectors and by runs of the real clients (OpenBao seal, `vault-kubernetes-kms`), already done against the Nim `kekd` for OpenBao.

## Verified against OpenBao (2026-10-19)

OpenBao v2.6.1 with `seal "transit"` (address of hsmgate over plain loopback HTTP, `insecure_loopback_client`, soft key): `bao operator init -recovery-shares=1`, a KV secret written, OpenBao stopped and started again:
it unsealed by itself through hsmgate and returned the secret; the audit shows `encrypt`/`decrypt` as client `openbao`. Not yet run: the same over mTLS and a network, a card behind it (P3), `vault-kubernetes-kms`, SOPS.

## The PKCS#11 backend (P3)

`type: pkcs11` token (`module`, `token_label` or `token_serial`, `keys: label -> CKA_ID`). The public key is read without a PIN; `encrypt` works while the token is locked (it needs the public key only). `decrypt`/`rewrap` need the login:
the PIN comes from `pin_file` (one try at start) or from `hsmgate unlock -token NAME` over the admin socket (`admin_socket`, mode 0600; the PIN from the terminal or `-pin-stdin`, kept in memory). A refused PIN is never retried by the service
(the card blocks at 3): it answers 503 `locked`, retryable, until an operator unlocks again. A lost session or a removed token is reopened at the next call (state `absent` meanwhile); the PIN is remembered in memory only to log in again after that.
Unix socket paths are limited to ~108 bytes (use a short path).

Checked (2026-10-19): unit tests with a software token module (PIN tried once, relogin, token out, wrong label); the real SmartCard-HSM through OpenSC read-only (`HSMGATE_P11_MODULE=... HSMGATE_P11_KEY_ID=... go test -run RealModule ./internal/backend`)
and a running hsmgate on the card **with no PIN**: `keys/k` gives the card's key and `token_state: locked`, `encrypt` works, `decrypt` answers 503 retryable. **Run by the owner (2026-10-19)**: `tools/card-decrypt-test.sh` on the SmartCard-HSM: PIN file read by hsmgate once, `encrypt` then `decrypt` through the login and ECDH on the card gave the plaintext back (about 0.05 s for the decrypt call), a wrong context answered 400, the audit shows the three calls and no secrets. **Not run**: SoftHSM2 (not installed here), an unplugged card, a refused PIN on the card.

## Verified against vault-kubernetes-kms (2026-10-19)

`vault-kubernetes-kms` v1.4.0 (FalcoSuessgott; release tarball `vault-kubernetes-kms_Linux_x86_64.tar.gz`, SHA-256 checked against the release's `checksums.txt`) with `-auth-method token -token unused -transit-key kms`, pointed at hsmgate (plain loopback HTTP,
soft token). A small gRPC client for Kubernetes KMS v2 (`k8s.io/kms/apis/v2`) called `Status`, `Encrypt`, `Decrypt` on the plugin's unix socket: the plaintext came back, the plugin logged no errors, the audit shows `keys`, `encrypt`, `decrypt` as the client `kms`.
So **etcd encryption by the card needs no gRPC code in hsmgate**: kube-apiserver -> the plugin -> hsmgate Transit. Notes from the plugin's source: it sends no context, so its key must be `aad.mode: fixed` (give it its own `fixed` value, e.g. `k8s-kms/v1|kms`);
it reads `data.ttl` and `data.creation_ttl` from `auth/token/lookup-self` as numbers (the face answers 0 and 0, so it never tries to renew) and `data.latest_version` from `keys/<name>`; the token it presents is ignored.
Not run: a real kube-apiserver, mTLS between the plugin and hsmgate (the plugin has `-cert-*` options and the Vault API client reads `VAULT_CLIENT_CERT`/`VAULT_CLIENT_KEY`; to be tried), the card behind it.
