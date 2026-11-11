# Questions people ask

**What is it, in one line?** A network door in front of a key on a smart card or HSM: clients send a short secret and get it back sealed (or the reverse); the key never leaves the token; a policy says who, which key, which context, how often; every call is in the audit log. ([README](../README.md))

**How is it different from Vault or OpenBao?** It stores nothing and has no user interface, no secret engines and no tokens: only the key on the token and the Transit calls (`encrypt`, `decrypt`, `rewrap`, key information). Clients that speak Vault's Transit API (OpenBao's `seal "transit"`, `vault-kubernetes-kms`, any Transit client library) work with it ([transit.md](specs/transit.md)). Use hsmgate when you want the *key* in hardware and the policy small enough to read; use a vault when you want a secret store.

**Do I need hardware?** To try it, no: `hsmgate dev` or the Helm chart use a software key. For real keys, yes: a software token is a key in a file. It was tried on the SmartCard-HSM; any token with a PKCS#11 module is meant to work, others were not tried ([tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)).

**What is `vault:v1:...`?** The text form of a ciphertext, shaped like Vault's so that Transit clients accept it: `v1` is the version of the key, the rest is the sealed text (`ecies2`: ECDH on P-256, HKDF, AES-256-GCM, [ecies2.md](specs/ecies2.md)).

**Can I seal a file?** No: it seals short secrets (data keys, the root key of another vault); a value is at most 8 KiB by default (`max_bytes`, up to 1 MiB). Seal a data key and encrypt the file with it.

**Does it keep my secrets?** No. The key is on the token, the ciphertexts are with the clients. The service holds the PIN in memory while a card is unlocked, the rate counters in memory, and writes the audit log. That is all.

**What happens if the service restarts?** A card token comes up **locked** (unless `pin_file` is set): `encrypt` still works, `decrypt` and `rewrap` answer 503 `locked` until someone runs `hsmgate unlock`. A software token needs no PIN. ([production.md](production.md), "The PIN")

**What happens if the card is lost?** Without a backup, what was sealed under its key is lost for good. With the DKEK backup and its shares, you restore the key onto a second card and add it as a token (or as a replica); nothing already sealed has to change ([operations.md](operations.md)).

**Can I run two copies for availability?** Not on one card: a card serves one session at a time and the PIN is tried per login, so one token belongs to one process. A key can have **replicas** (a spare card made from the backup) that the same process tries in order when the first cannot answer. In Kubernetes the chart runs one pod with a software token.

**How do I rotate a key?** Add a version (a new key pair on the token) and reload; new `encrypt` calls use it, old ciphertexts still open, `rewrap` moves them. Retire the old key only when nothing sealed under it is left, backups included ([operations.md](operations.md), "Rotating a key").

**How do I revoke a client?** Remove it from `clients:` and reload (`kill -HUP`): effective at the next request. There is no revocation list for certificates ([operations.md](operations.md)).

**There is no limit on my client. Why?** A client key has no `per_minute` or `per_day` until you write one; 0 or missing means no limit. Set one for every client ([configuration.md](configuration.md), [production.md](production.md)).

**Can a client connect without a certificate?** On the Transit face, no. On the KMS-JSON, gRPC and REST faces a client may be allowed to call with its signature alone (`no_cert`), only from listed addresses and only for its own keys; then the secret is the only proof ([threat-model.md](threat-model.md)).

**Is the audit log tamper-proof?** No: it is a plain file, and a call is answered only after its line is written. Ship it off the host as it is written ([audit-log.md](audit-log.md)).

**Which Kubernetes uses?** Encryption of etcd through `vault-kubernetes-kms` ([kubernetes-kms-v2.md](specs/kubernetes-kms-v2.md)), secrets in pods without Vault ([guide](guides/kubernetes-pod-secrets.md)), and auto-unseal of OpenBao ([the chart](../deploy/helm/hsmgate/README.md)). The chart uses a software token: for tests, development and pilots.

**Is it FIPS or certified?** The service can run the Go cryptographic module in FIPS 140-3 mode (`require_fips`, the `-fips` image); that covers the module, not the product or the token. [compliance.md](compliance.md) says what is and is not claimed.

**Which systems does it run on?** The releases are Linux amd64 binaries and images; other platforms can build from source, which is not tested here ([building.md](building.md)).

**It does not work.** [troubleshooting.md](troubleshooting.md): the message, what it means, what to do.

**Which version should I use, and for how long is it supported?** The latest ([supported-versions.md](supported-versions.md)).
