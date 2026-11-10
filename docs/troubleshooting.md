# When it does not work

Two places tell you most: the **audit log** (one JSON line per call: `client`, `face`, `key`, `op`, `result`; a refusal is written down too) and the **log of the service** (standard error: what is wrong with a file, a token, a TLS handshake). Two commands show the state:

```bash
hsmgate check -config /etc/hsmgate/hsmgate.yaml          # loads the configuration, opens the tokens, lists every key version and its holders; needs no PIN
curl --unix-socket /run/hsmgate/admin.sock http://x/status    # {"card":"ready","soft":"ready"}: "locked" means a PIN is needed (hsmgate unlock)
```

Run `check` as the user the service runs as (`runuser -u hsmgate -- hsmgate check ...`): as root it refuses a key file that belongs to another user, and that is the point.

## What the client sees

| What you see | Meaning | What to do |
|---|---|---|
| The handshake fails: `tls: client didn't provide a certificate` (in the log of the service), `certificate required`, `bad certificate`, a connection reset | The service answers only clients with a certificate of its CA | Give the client its certificate and key (`curl --cert ... --key ...`, `HSMGATE_CERT`/`HSMGATE_KEYFILE`) |
| `tls: client offered only unsupported versions` (log) | TLS 1.3 is the only version offered | Use a client that speaks TLS 1.3 |
| `x509: certificate signed by unknown authority` (client) | The client does not trust the CA of the service | Give it `ca.crt`/`ca.pem` of the service (`--cacert`, `HSMGATE_CA`, `tls_ca_cert`) |
| `x509: certificate is valid for A, not B` (client) | The address the client uses is not one of the names in the certificate of the service | Connect by a name that is in it, or make the certificate again with that name (`hsmgate ca server -dns/-ip ...`; chart: `tls.generate.extraNames`, `ingress.host`) |
| **403** `permission denied`; `result` is `forbidden` | The certificate is valid, but the policy has no such client, key or operation for it | Check `identity` of the client (`cn`, `uri` or `sha256` of its certificate), its `keys:` and `ops:` in the configuration; the audit line names the client it saw |
| **403** `permission denied`; `result` is `forbidden_context` | The context is not in the `contexts:` of this client for this key | Use a context that begins with one of them |
| **400** `bad_context`: `missing context`, `this key takes no context`, `context not allowed for this key`, `context is too long`, `failed to base64-decode context` | The key needs a context (`aad.mode: context`) and none was sent; or it has a fixed one (`aad.mode: fixed`) and one was sent; or the context is outside `allow:` of the key; or it is not base64 (the Transit API sends it in base64; `hsmgate encrypt -context` does that for you) | Send a context for such a key, none for a fixed one, one that begins with a prefix of `allow:` |
| **400** `invalid ciphertext: cannot be opened with this key` | Wrong key, wrong context, or a damaged text | Open it with the key and the context it was sealed with; for a text from another hsmgate, its key is not this one |
| **400** `invalid request body` / `missing plaintext` | The JSON is wrong, or `plaintext` is not base64 | The Transit API wants the plaintext in base64 |
| **413** `request body too large` | A value is larger than `max_bytes` of the key (default 8192) | This service seals short secrets (data keys, root keys), not files |
| **429** `rate limit exceeded` (`throttled`) | The client passed `per_minute` or `per_day` of its key (0, or none, is no limit) | Retry later (`X-Hsmgate-Retryable: true`) or raise the limit |
| **503** `token locked` (`locked`) | A smart card is waiting for its PIN. `encrypt` still works, `decrypt` and `rewrap` do not | `hsmgate unlock -token NAME` (or `pin_file`); retryable |
| **503** `token unavailable` | The card is out, or its session was lost; it is reopened at the next call | Check the reader and `pcscd`; retryable |
| **503** `busy` | More operations than `limits.max_concurrent` (default 8) waited longer than `queue_seconds` (default 2) | Retry (`Retry-After`); raise the limits if it is the normal load |
| **503** `audit log unavailable` | The audit file cannot be written (disk full, no permission). With no log, nothing leaves: this is by design | Free the disk or fix the permissions of the audit file |
| **404** `unsupported path` | A path or a method the face does not have | Compare with the [Transit](specs/transit.md) API: `/v1/transit/{encrypt,decrypt,rewrap}/<key>`, `/v1/transit/keys/<key>` |

`X-Hsmgate-Retryable` says whether it makes sense to try again; the `hsmgate encrypt`/`decrypt` commands and `internal/client` follow it.

## What the service says when it starts

| Message | Meaning | What to do |
|---|---|---|
| `... must not be readable by group or others (mode 440)` | A secret file (PIN file, soft key, SigV4 or REST secret) has permission bits for group or others. A systemd credential (`LoadCredential=`) shows as 0440 and is refused too | `chmod 0400`; the file belongs to the user the service runs as ([operations.md](operations.md), "Start, unlock, reload") |
| `... is owned by another user` | The file is owned by neither the user of the service nor root | `chown` it to the user of the service |
| `... is not a regular file` | A directory, a link to somewhere else, a socket | Point the setting at a regular file |
| `token card stays locked: ...` | The PIN file was refused (see above) or the card does not take the PIN. It is tried **once**: the card blocks after 3 wrong tries | Fix the file or unlock by hand; look at the retry counter of the card before trying again |
| `key X: aad mode context needs allow patterns` and the other `key ...`/`client ...` messages | The configuration is wrong: the message names the key or client and the rule | Fix it; `hsmgate check` repeats the same check without starting anything |
| `tls.client_ca: no certificates read` | The file of the CA of the clients has no PEM certificate in it | Point it at the `ca.pem` that signed the client certificates |
| `hsmgate: reload refused, nothing changed: ...` (after SIGHUP) | The new configuration does not load; the old one is still in use | Fix the file and send SIGHUP again |
| `ConfigurationDirectory 'hsmgate' already exists but the mode is different` (systemd) | A warning about the mode of `/etc/hsmgate` (750 against 755 in the unit) | Harmless; set `ConfigurationDirectoryMode=0750` in the unit to silence it |

## In a container or a cluster

- **The pod does not start, `owned by another user` or `must not be readable`**: the files of a Secret volume must be mode 0400 and owned by the user that runs the service. The chart runs it as root (every capability dropped, read-only root file system) with `defaultMode: 256`; do not add `fsGroup` (it adds a group bit and the service refuses the file). With Docker the owner of the file must be the user of the container.
- **`helm install` fails on the TLS Secret**: the chart makes the files itself by default; with `tls.existingSecret` the Secret must exist in the namespace of the release with `tls.crt`, `tls.key` and `ca.crt` ([chart README](../deploy/helm/hsmgate/README.md)).
- **A client in another cluster gets a handshake error**: the Ingress must pass the TLS through (ingress-nginx: `--enable-ssl-passthrough`), and its host must be in the certificate of the service.
- **After renewing a certificate the clients still see the old one**: the service reads its certificate at start and on SIGHUP (`kill -HUP`, or restart the pod); nothing tells the pod that a Secret changed.

## OpenBao

OpenBao that cannot unseal and says it cannot connect or check the seal: look at the audit log of hsmgate first. No line at all means the call did not get past the handshake (the certificate, the CA, the name in `address`); a line with `forbidden` means the client's CN is not in `config.clients`; `bad_context` means the key has `aad.mode: context` and the OpenBao seal sends no context (give the key `aad: {mode: fixed}`).

## Still stuck

Open an issue with the lines of the service log and of the audit log around the failure, `hsmgate version`, and the configuration with the secrets and addresses removed (never a PIN, a key file or a private key).
