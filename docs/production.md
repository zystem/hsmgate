# Before it holds real keys

A checklist, in the order that costs least to fix. Each line says what to do and where the detail is. What is *not* checked by hsmgate itself is marked as yours. The threat model says what each item defends against: [threat-model.md](threat-model.md).

## 1. The token

- [ ] **A card or an HSM, not a software token.** A `soft` token is a key in a file (a Secret, in Kubernetes): whoever reads the file has the key. It is for tests, development and pilots ([configuration.md](configuration.md), "Tokens"). The Helm chart uses one and says so.
- [ ] **The key is backed up, and the backup is tried.** A key on a card leaves it only wrapped under the DKEK; keep the DKEK shares apart from the card and from the PIN, and restore onto a second card at least once, before you need it ([operations.md](operations.md), "A lost or broken card"; [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)). With one card and no backup, a lost card is lost data. A soft key's Secret or file needs the same care.
- [ ] **One process per card.** A card serves one session at a time, so give a token to exactly one hsmgate process; this is also why it is not a replicated deployment ([operations.md](operations.md), "Several processes, several tokens").

## 2. The PIN

- [ ] **Decide who unlocks after a restart.** Without `pin_file` the service starts **locked**: `encrypt` works, `decrypt` and `rewrap` answer 503 until someone runs `hsmgate unlock`. That is the safest and the most work; plan who does it and how they are told.
- [ ] **If you use `pin_file`**, the PIN then rests on the machine. The file is owned by the service user, mode 0400, tried once at start; a systemd credential does not qualify ([operations.md](operations.md), "Start, unlock, reload"). Never put a PIN in the configuration, the environment or an argument.

## 3. Who may do what (the policy)

- [ ] **One client per application**, named for it. A shared client makes the audit say nothing.
- [ ] **The identity is `uri` (a SPIFFE-like name) or `sha256`**, not `cn`, unless your CA gives each name to one holder only.
- [ ] **The least operations**: a client that only opens secrets gets `decrypt` only; one that only stores them, `encrypt`.
- [ ] **Contexts**: keys in `aad.mode: context` with `allow:` prefixes, and `contexts:` per client, so one application cannot open another's data. A `fixed` key has no such separation: give it one client, or few.
- [ ] **Every client key has `per_minute` (and `per_day`).** Without them there is **no limit**, and a stolen client key then decrypts as fast as the card goes ([configuration.md](configuration.md), "Clients").
- [ ] **`max_bytes`** stays small (default 8192): this service seals short secrets.
- [ ] Settings marked "tests only" are off: `insecure_loopback_client`, and `no_cert` unless a client truly cannot present a certificate (then `allow_from` is mandatory and the secret is the only proof).

## 4. Certificates

- [ ] **Your own CA for the clients** (`hsmgate ca`, cert-manager with a CA issuer, step-ca, your PKI). Not a CA that signs for strangers: the CA decides who may connect.
- [ ] **Keep the key of the CA off the service host** (make certificates elsewhere, copy the files), or keep it on the token or sealed to it (`hsmgate ca init -mode token|sealed`): who holds it can make a client the service accepts ([operations.md](operations.md), "Where the key of the authority lives").
- [ ] **Renewal is yours.** Certificates last 365 days by default (the CA ten years) and nothing renews them. Put the dates in a calendar or a monitor, and restart or `kill -HUP` after a renewal.
- [ ] **There is no revocation list.** To refuse a client, remove it from `clients:` and reload (effective at the next request). Short lifetimes are the other half of that.

## 5. The network and the host

- [ ] **`listen` is the address you mean**, and a firewall or a NetworkPolicy lets only the clients reach the port. The service answers only a valid client certificate anyway, but a smaller surface is cheaper than a clever one.
- [ ] **A dedicated user, the systemd unit as shipped** (`NoNewPrivileges`, `ProtectSystem=strict`, a private `/tmp`: [deploy/hsmgate.service](../deploy/hsmgate.service)), secret files 0400. In Docker the owner of a secret file must be the user of the container.
- [ ] **The admin socket** (unlock, status, metrics) is mode 0600 and not on a network. Whoever holds it can unlock the token.
- [ ] **Root on the host is out of scope**: with the token unlocked, root can use it. The defence is the spare token, the audit shipped off the host, and rotation ([threat-model.md](threat-model.md)).

## 6. The audit log

- [ ] **Shipped off the host** as it is written, and kept as long as your rules say. The log is a plain file: whoever can write it can change it ([audit-log.md](audit-log.md)).
- [ ] **Rotation is set up** (`copytruncate`: the file is not reopened on SIGHUP) or the output goes to the journal.
- [ ] **Someone watches it**: a rise of `decrypt`, new `forbidden`, `locked`, `unavailable`, any `refused` PIN. A call is answered only after its line is written, so a full disk stops the service: monitor free space.
- [ ] Metrics (`metrics.enabled`) and `debug.pprof` are **off unless you need them**; both are sensitive and live on the admin socket only.

## 7. The software

- [ ] **A release, verified** ([verifying-releases.md](verifying-releases.md)): signature, provenance, and the image by digest. Not `main`.
- [ ] **You follow releases.** Only the latest release gets security fixes (and the previous minor for 30 days for High and Critical): [supported-versions.md](supported-versions.md). Read [upgrading.md](upgrading.md) and run `hsmgate check` with the new binary before replacing the old.
- [ ] **FIPS**: if you need the Go crypto module in FIPS 140-3 mode, use the `-fips` image or binary with `require_fips: true`. That covers the module, not the product or the token ([compliance.md](compliance.md)).

## 8. Drills (yours, once, before real data)

- [ ] Restart the service and unlock it, from a clean state, by the procedure you wrote.
- [ ] Take the card out (or stop `pcscd`): clients see 503 `unavailable`, retryable; put it back and they recover with no restart.
- [ ] Restore the key onto the second card and open something sealed by the first.
- [ ] Rotate a key (add a version), `rewrap` something, and read the audit lines for it ([operations.md](operations.md), "Rotating a key").
- [ ] Refuse a client (remove it, reload) and see its calls become `forbidden` in the audit.
