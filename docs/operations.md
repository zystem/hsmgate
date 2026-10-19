# Operations: unlock, rotation, a spare card, a lost card

The card side (initialising the card, DKEK shares, making and backing up the key) is in CiNim's `docs/hardware-key.md` sections 2-5; this page is about the service.

## Start, unlock, reload

- `hsmgate check -config hsmgate.yaml` loads the configuration, opens the tokens and prints every key version with its holders, their state and the fingerprint of the public key (no PIN needed). Compare the fingerprints with the ones you wrote down when the key was made.
- A token starts `locked` unless `pin_file` is set (one try). `hsmgate unlock -config hsmgate.yaml -token card` asks for the PIN on the terminal (`-pin-stdin` reads it from standard input) and hands it over the admin socket; it stays in memory only.
  While locked, `encrypt` works (public key only) and `decrypt`/`rewrap` answer 503 `locked` (retryable). A refused PIN is never tried again by the service: the card blocks after 3 wrong tries.
- `kill -HUP <pid>` reloads the configuration, the policy (rate counters are kept), the server certificate and the client CA, and adds or removes keys and versions, without a restart and without a new PIN. A configuration that does not load, names an unknown token or key,
  or has holders with different public keys is refused and nothing changes (the reason is on standard error). The listen address, the admin socket, the audit file and a token's module or slot need a restart.

## Rotating a key

A version is a public key; a rotation adds one.

1. Make the new key pair on the card (same token, another `CKA_ID`) or on a new card; back it up like the first one.
2. Add its label to the token's `keys` and a version to the key in `hsmgate.yaml`: `versions: [{token: card, label: m}, {token: card, label: m2}]`. `hsmgate check` shows both fingerprints.
3. `kill -HUP`. New `encrypt` calls make `vault:v2:` texts; every `vault:v1:` text still opens (the old private key stays on the card).
4. Clients move what they hold with `rewrap` (CiNim: once per organisation's DEK; OpenBao: `bao operator rekey` is not needed, its seal key does not change, rewrap is for texts clients store). Count: the audit shows `rewrap` per client.
5. When no `v1` text is left anywhere (backups of databases count), the old key can be retired. Until then do not delete it.

## A spare card (no DKEK dance on the clients)

The service treats a second card as a **replica** of a key version: the same key restored from the DKEK backup onto the second card (CiNim `hardware-key.md` section 5), configured as another token:

```yaml
tokens:
  - {name: card,  type: pkcs11, module: ..., token_label: cinim, keys: {m: <CKA_ID>}}
  - {name: spare, type: pkcs11, module: ..., token_serial: <serial>, keys: {m: <CKA_ID>}}
keys:
  master: {versions: [{token: card, label: m, replicas: [{token: spare, label: m}]}], aad: ...}
```

`hsmgate check` refuses holders whose public keys differ (a wrong card restored). The first holder is used; the next is tried only when the first cannot answer (locked, removed, busy). A text that is bad is final on the first holder, not retried.
The spare card needs its own PIN entry (`hsmgate unlock -token spare`) and sits where the first one does, or elsewhere in another hsmgate process with the same configuration for that key.

## A lost or broken card

1. `hsmgate` keeps answering from replicas if there are any. Otherwise `decrypt` answers 503 (retryable) and `encrypt` still works, since the public key is cached; nothing new is lost, but nothing old opens.
2. Restore the key onto a new card from the DKEK backup and the shares (they are kept apart from the card and from the PIN). Add it as a token and as a replica (or replace the first holder), `kill -HUP`, `hsmgate unlock`.
3. If there is no backup, texts sealed under that key are lost for good. That is what the backup, and a periodic restore drill on the second card, are for.

## Several processes, several tokens

One hsmgate process serves one configuration: several keys, several clients, several tokens (cards in one or more readers), each key version pointing at its holders. Several processes on a host take separate `listen` ports and admin sockets, and one card must not be opened
by two processes at once (the card serves one session at a time and the PIN is tried per login): give a token to one process.

## Running in Docker (one machine or VM with the reader; no Kubernetes)

A card is a physical device: hsmgate runs on a machine (or a VM with the reader passed through) that has it, not on a scheduler that moves pods. `deploy/docker/compose.yaml` is the example; the image is built from the `Dockerfile` in the root.

- **pcscd stays on the host**; its socket `/run/pcscd` is mounted into the container. The image holds the OpenSC module and `libpcsclite1` (OpenSC loads it with `dlopen` and the package only *recommends* it: without it `C_Initialize` fails with `CKR_GENERAL_ERROR`).
- **User**: Debian's pcscd asks polkit (`org.debian.pcsc-lite.access_pcsc`, `access_card`: allowed for a local *active session* only). A container process has no session, so a non-root user gets `SCardEstablishContext failed: 0x8010006a`
  and the token shows `absent`. Verified on a card (2026-10-19): as root in the container (with `--cap-drop ALL`, `--read-only`, `no-new-privileges`) the service reads the key and is healthy; as uid 10001 or 1000 it does not.
  To run as a non-root user, give that user a polkit rule on the host (a user of that uid must exist on the host, so that polkit can name it) and set `user:` in the compose file. **That rule was not tried here.**
  Example for `/etc/polkit-1/rules.d/50-hsmgate.rules`: `polkit.addRule(function(a, s) { if ((a.id == "org.debian.pcsc-lite.access_pcsc" || a.id == "org.debian.pcsc-lite.access_card") && s.user == "hsmgate") return polkit.Result.YES; });`
- **Unlock and reload**: `docker compose exec hsmgate hsmgate unlock -config /etc/hsmgate/hsmgate.yaml -token card` (the PIN is typed on the terminal), `docker compose kill -s HUP hsmgate`.
- **Health check**: `hsmgate ping` is a TCP connect to the listener. It never touches the token, so a locked token is not a failing container; use `hsmgate check` or the key information (`GET /v1/transit/keys/<name>`, `token_state`) to monitor the token.
- **Limits**: the example sets memory and process limits; `limits.max_concurrent` and `limits.queue_seconds` in the configuration bound how many operations wait for the card.
- **USB passthrough** (`--device /dev/bus/usb` with pcscd inside the container) is possible and was not tried.
