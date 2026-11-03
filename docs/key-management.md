# Key management: NIST SP 800-57 and SP 800-131A

hsmgate follows these two as guidance; nothing here is a certification. Part 1 of SP 800-57 is general advice, Part 2 is for the organisation that runs a key-management system. The table says what the service does, and what is the operator's.

## Algorithms and sizes (SP 800-131A, SP 800-57 Part 1 table 2)

| Use | Algorithm | Security strength | State |
|---|---|---|---|
| Key establishment (sealing, `ecies`) | ECDH P-256 (SP 800-56A), HKDF-SHA-256 (SP 800-56C) | 128 bits | approved |
| Data protection | AES-256-GCM (`ecies2`) | 256 bits | approved |
| Signatures | ECDSA P-256 with SHA-256 (FIPS 186-5) | 128 bits | approved |
| MAC | HMAC-SHA-256, key derived on the token | 128 bits or more | approved |
| Authentication of clients | TLS 1.3, RSA ≥ 2048 for JWT assertions, secrets ≥ 32 bytes | 112 bits or more | approved; RSA 2048 is acceptable through 2030 |
| Random numbers | the operating system's generator through `crypto/rand` (in FIPS mode, the module's DRBG) | | approved in FIPS mode |

Not used: SHA-1, 3DES, RSA below 2048, P-192, MD5. The service refuses a JWT with any algorithm other than RS256.

## Key life cycle (SP 800-57 Part 1, section 7)

| Stage | What hsmgate does | Who |
|---|---|---|
| Generation | on the token (`tools/`, the card's own generator); the service never generates a master key | operator, with the token's PIN |
| Distribution | the public key is published (`hsmgate check` prints its fingerprint); a `fingerprint:` pin in the configuration refuses a holder with another key | operator |
| Storage | the private key stays on the token; the PIN is read from a file with strict modes and kept in memory | operator (the card's PIN policy: three tries) |
| Use | every use is policy-checked and audited before the answer; a key has one usage; budgets per minute | the service |
| Cryptoperiod | versions: a new version is added to the configuration and becomes the latest; the older ones stay for decryption and verification. A rule for the length of a period is the operator's: SP 800-57 suggests up to 2 years for an asymmetric key used for key establishment, and a shorter one for a key that signs | operator |
| Backup | the card's DKEK scheme (shares, a spare card with the same keys: `replicas`); see [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md) | operator |
| Re-sealing | `rewrap` re-seals a text under the latest version; needed to move data from an older version to the latest | client with the right |
| Destruction | removing a key from the card; texts sealed to it can no longer be opened (crypto-shredding) | operator |
| Compromise | remove the client or the key from the configuration and reload (SIGHUP): effective for the next request; the audit log says what the client used | operator |

## Open points

- No automatic rotation or expiry of a version: the operator decides (a cron job that adds a version is possible; not provided).
- Keys that are derived on the host for an operation (MAC keys, data keys) exist in memory for its duration; `kmsjson.mac_cache_seconds` lengthens it on purpose.
- Split knowledge and dual control for the initialisation of a token are the card's (DKEK shares), not the service's.

## Algorithm agility: what can be switched, and how fast

If an algorithm is broken, the project can move to another one with a change of configuration, no new release. What exists, and what does not:

| What | Choices | How to switch | Existing data |
|---|---|---|---|
| **Sealing: the hash** of the key derivation | SHA-256 (`ecies2`), SHA-512 (`ecies3`) | `seal_suite: ecies3`, reload | every suite is read; `rewrap` moves texts to the new one |
| **Sealing: the cipher** | AES-256-GCM (`ecies2`, `ecies3`), XChaCha20-Poly1305 (`ecies4`, another family, not FIPS-approved) | `seal_suite: ecies4`, reload | the same |
| **MAC: the hash of the HMAC** (keys with `kmsjson_usage: generate_verify_mac`) | SHA-256, SHA-384, SHA-512 | `mac_hash: sha384` on the key; the faces name it (`HMAC_SHA_384`, `HS384`, `HMAC_SHA384`) | a MAC made with another hash does not verify under the new one: make a new key (or version) with the new hash, and verify old MACs with the old key until they are gone |
| **Authentication of clients** | RS256 JWT; TLS 1.3 only (its own negotiation); SigV4 (HMAC-SHA-256, the scheme of the clients) | the JWT algorithm is checked, one is accepted; the other two are what the clients speak | none stored |
| **Signatures** | ECDSA P-256 with SHA-256 | **not switchable**: another curve (P-384) needs the card's keys and a new face contract | none stored (signatures are verified by the client's copy of the public key) |
| **The key agreement** | ECDH P-256 | **not switchable** for the same reason | sealed texts name the key by its fingerprint |

The sequence for a broken cipher or hash of sealing: (1) set `seal_suite` to the other suite and reload (new texts are in it from the next request); (2) re-seal what exists with `rewrap` (or by the client that holds the texts); (3) when nothing is left in the old suite, nothing else needs to be done: reading the old suite remains for old backups. For a broken MAC hash: make the new MAC key and move the clients to it.

What does not exist, and is said here so that nobody assumes it: other curves, RSA keys on the token, post-quantum algorithms. They would need new formats; the tags of the formats (`ecies2`, `HGK2`) and the versioned keys are what make such a change possible without breaking what is stored.
