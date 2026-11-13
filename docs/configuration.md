# Configuration reference

The configuration is one YAML file (`hsmgate.yaml`, `-config` on every command). It is checked as a whole when it loads: **an unknown field is an error** (a misspelt policy line is never silently ignored), as is anything ambiguous (a duplicate name, two clients with one identity, a limit that would read as "none" by accident). `hsmgate check -config hsmgate.yaml` runs the same check and starts nothing.

The smallest working file is the one `hsmgate dev -dir DIR` writes (`DIR/hsmgate.yaml`); a larger one for a card is [deploy/hsmgate.example.yaml](../deploy/hsmgate.example.yaml). This page lists every setting, what happens when it is left out, and whether a change needs a restart or a reload (`kill -HUP`, [operations.md](operations.md)).

**Reload or restart.** A reload (SIGHUP) takes a new file as a whole or not at all (a refused file leaves the old one running). It changes the tokens' keys, the keys, the clients, the policy and the certificates. These need a **restart**: `listen`, `admin_socket`, `audit.file`, `audit.stdout`, `audit.max_size_mb`, `audit.max_files`, `limits`, `transit.mount`, `kmsjson.enabled`, `kmsgrpc.enabled` and `kmsgrpc.token_path`, `kmsrest.enabled` and `kmsrest.tenant`, and the module or slot of a `pkcs11` token.

## The service

| Setting | Default | Meaning |
|---|---|---|
| `listen` | **none: set it** (empty means a random port on every interface) | `host:port` to listen on, for example `0.0.0.0:8443`, or `127.0.0.1:8443` for the same machine only |
| `tls.cert`, `tls.key` | **required** | the certificate of the service and its key (TLS 1.3 is the only version offered). The names a client connects to must be in the certificate |
| `tls.client_ca` | **required** | the CA that signed the certificates of the clients: only those get past the handshake. `hsmgate ca setup` makes all three |
| `admin_socket` | none: no admin door | a unix socket (mode 0600, a short path: unix sockets allow about 108 bytes) for `hsmgate unlock` and `/status`. Needed for `metrics` and `debug.pprof` |
| `audit.file` | none: **the audit goes to standard output** (the journal, under systemd) | the audit log, one JSON line per call (a file is opened for append, mode 0640). A call is answered only after its line is written: if the log cannot be written the service answers 503 ([troubleshooting.md](troubleshooting.md), "audit log unavailable") |
| `transit.mount` | `transit` | the mount in the paths of the Transit API: `/v1/<mount>/encrypt/<key>` |
| `seal_suite` | `ecies2` (HKDF-SHA-256, AES-256-GCM) | what new ciphertexts are written with: `ecies2`, `ecies3` (SHA-512), `ecies4` (XChaCha20-Poly1305; not FIPS-approved). Every suite is always read, so a change leaves what exists openable ([key-management.md](key-management.md)) |
| `require_fips` | `false` | refuse to start unless the Go crypto module runs in FIPS 140-3 mode ([compliance.md](compliance.md)); it says nothing about the token |
| `insecure_loopback_client` | none | plain HTTP on a loopback address as this client: **tests only** (then `tls` is not needed) |

### Limits (restart)

| Setting | Default | Meaning |
|---|---|---|
| `limits.max_concurrent` | 8 (0 to 1024) | operations that may run or wait for the token at once (a card serves one at a time) |
| `limits.queue_seconds` | 2 (0 to 60; 0 means the default) | how long one waits for its turn before it gets 503 `busy` |
| `limits.max_connections` | 128 (0 to 65535) | connections open at once; the next waits in the backlog |

### Observability (off unless turned on; both need `admin_socket`)

| Setting | Default | Meaning |
|---|---|---|
| `metrics.enabled` | `false` | `GET /metrics` on the admin socket, Prometheus text format. What is counted tells when secrets are used: treat it as sensitive |
| `audit.stdout` | `false` | with `audit.file`, also write every audit line to standard output (for a log collector that reads the container's output). Without a file the audit is on standard output anyway. If either write fails the call is answered 503 as for any audit failure. Needs a restart |
| `audit.max_size_mb` | `0`: no limit, the file grows and is never rotated by the service | rotate the audit file when a line would pass this size (MiB): `audit.log` becomes `audit.log.1`, `.1` becomes `.2`, and so on; the oldest beyond `audit.max_files` is deleted. Needs `audit.file`. **Without it a full disk stops the service** (503). Needs a restart |
| `audit.max_files` | `5` when `max_size_mb` is set | how many older files are kept (`audit.log.1` is the newest). Needs `audit.file`. Needs a restart |
| `metrics.detail` | `basic` | `basic`: decisions by face and outcome class; `full`: also the operation and the result word of the audit line |
| `debug.pprof` | `false` | the profiles of the process (CPU, heap, goroutines) on the admin socket. A heap profile may hold secrets: for the operator who holds the socket |

## Tokens

`tokens` is a list. A **token** is where private keys live.

| Setting | Default | Meaning |
|---|---|---|
| `name` | required | the name the keys refer to |
| `type` | required: `soft` or `pkcs11` | `soft`: private keys in files (tests, development, pilots: whoever reads the file has the key). `pkcs11`: a card or an HSM through a PKCS#11 module |
| `keys` | required | `label: value`. `soft`: the **file** with the private key, 64 hexadecimal digits (a P-256 key; owned by the user of the service, no permission for group or others: 0400). `pkcs11`: the **CKA_ID** of the key pair, in hex |
| `module` | `pkcs11`: required | the PKCS#11 library, for example `/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` |
| `token_label` or `token_serial` | `pkcs11`: one of them | which token of the module |
| `pin_file` | none: the token starts **locked** until `hsmgate unlock` | a file with the PIN, tried **once** at start (the card blocks after 3 wrong tries). Owned by the user of the service, mode 0400 ([operations.md](operations.md)) |

## Keys

`keys` is a map: the name a client asks for. A key has versions; a rotation adds one, and old ciphertexts still open.

| Setting | Default | Meaning |
|---|---|---|
| `versions` | required | a list; the last is the latest. Each: `token`, `label` (a key of that token), optional `replicas` (other tokens that hold the same key, tried in order when the first cannot answer; the public keys must be equal) and optional `fingerprint` (pins the public key, as `hsmgate check` prints it) |
| `aad.mode` | required: `fixed` or `context` | `fixed`: no context is accepted, the key has a constant one (what OpenBao's seal and etcd encryption need: they send none). `context`: the client sends a context, bound into the ciphertext, required to open it |
| `aad.fixed` | `openbao/seal/v1\|<key name>` | the constant of a `fixed` key |
| `aad.allow` | `context` mode: required, not empty | the prefixes a context must begin with (`["k8s/"]`). An empty prefix is refused |
| `max_bytes` | 8192 (up to 1 MiB) | the largest value; this service seals short secrets |
| `mac_hash` | `sha256` | the hash of the HMAC of a MAC key: `sha256`, `sha384`, `sha512` |
| `kmsjson`, `kmsgrpc`, `kmsrest` | `false` | expose the key on the KMS-JSON, gRPC or REST face (they need those faces enabled) |
| `kmsjson_usage` | `key_agreement` | what the key does on those faces: `key_agreement`, `encrypt_decrypt`, `sign_verify` or `generate_verify_mac`. One key has one usage |

## Clients

`clients` is a list. A **client** is whoever connects with a certificate of the CA of the service.

| Setting | Default | Meaning |
|---|---|---|
| `name` | required | shown in the audit log |
| `identity` | required | how the certificate is recognised; any one that is set must match: `uri` (a URI name in the certificate, for example a SPIFFE id: preferred), `sha256` (the hash of the certificate, 64 hex digits), `cn` (the common name: the last resort, as the CN is whatever the CA put there) |
| `keys.<name>.ops` | required | what the client may do with the key: `encrypt`, `decrypt`, `rewrap` (Transit); `derive`, `sign`, `verify`, `generate_mac`, `verify_mac` (the other faces) |
| `keys.<name>.per_minute`, `per_day` | **0: no limit** | calls allowed per minute and per day for this client and key |
| `keys.<name>.contexts` | none: the key's own `allow` only | narrows a `context` key for this client: a context must begin with one of these (this is how one namespace's certificate is kept to its own contexts) |
| `sigv4`, `jwt`, `oauth` | none | the credentials of the KMS-JSON, gRPC and REST faces ([specs](specs/README.md)); each may also let a client call without a certificate (`no_cert`) from listed addresses (`allow_from`) |

### Credentials of the other faces (inside a client)

Clients of the KMS-JSON, gRPC and REST faces also prove who they are with a credential, on top of the certificate (or instead of it, with `no_cert`).

| Setting | Meaning |
|---|---|
| `sigv4.access_key_id`, `sigv4.secret_file` | the access key and the file with its secret (32 bytes or more, no permission for group or others) that the client signs requests with (KMS-JSON) |
| `jwt.issuer`, `jwt.public_key_file` | the service account (`client_email`) and its public key or certificate, RSA 2048 bits or more (gRPC) |
| `oauth.client_id`, `oauth.secret_file` or `oauth.public_key_file` | the application id and exactly one of: a secret file (32 bytes or more) or the public key of its certificate, RSA 2048 bits or more (REST) |
| `allow_from`, `no_cert` (each of the three) | the addresses or CIDR blocks the credential may be used from (the TCP peer, never a header); `no_cert: true` lets the client call without a certificate, only from listed addresses and only for keys on its own face. Then the secret is the only proof: give such a client keys of its own and `per_minute` limits |

A client that is not in the list gets 403, whatever its certificate says. A client gets nothing it is not given: no key, no operation, no context beyond what is written here.

## The other faces (restart to turn on)

| Setting | Default | Meaning |
|---|---|---|
| `kmsjson.enabled` | `false` | the KMS-JSON face on the same listener ([kms-json.md](specs/kms-json.md)) |
| `kmsjson.region` | `local` | the region string of the credential scope that clients sign with |
| `kmsjson.mac_cache_seconds` | 0 (0 to 3600) | how long a MAC key derived on the token stays in memory; 0 means one ECDH on the token per MAC |
| `kmsjson.audit_message_prefix` | `false` | write the first 6 bytes of the hash of the message into the audit line |
| `kmsgrpc.enabled` | `false` | the gRPC face ([kms-grpc.md](specs/kms-grpc.md)) |
| `kmsgrpc.project`, `location`, `key_ring` | `hsmgate`, `global`, `main` | make the resource names `projects/P/locations/L/keyRings/R/cryptoKeys/KEY` |
| `kmsgrpc.token_path` | `/oauth2/token` | where clients ask for a bearer token |
| `kmsrest.enabled` | `false` | the REST face ([kms-rest.md](specs/kms-rest.md)) |
| `kmsrest.tenant` | `hsmgate` | the directory identifier in the token path |

## Common mistakes

- **No `per_minute`** means no limit, not a default one. Give a client a limit that fits what it does.
- **A `context` key with no `allow`** is refused; a client with `contexts:` on a `fixed` key is refused too (there is nothing to narrow).
- **A key on the other faces has one usage**, and a `sign_verify` or `generate_verify_mac` key needs a token label that no other key uses: the right to derive would open anything sealed to the key.
- **`identity: {cn: ...}`** trusts the CA to give each name to one holder only; with a CA of your own that is easy to keep, with a shared one use `uri` or `sha256`.
