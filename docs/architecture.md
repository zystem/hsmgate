# Architecture: actors and actions

What is in the system, who acts, and what each action does. Details: [threat-model.md](threat-model.md), [specs/README.md](specs/README.md).

```
 client programs ──TLS 1.3──▶ ┌───────────────────────────── hsmgate ──────────────────────────────┐
 (OpenBao, apiserver,         │ faces: Transit │ KMS-JSON │ gRPC │ REST   (one listener)             │
  SDKs, tools)                │   authenticate (certificate and/or credential) → policy → audit     │
                              │   → gate (finite line to the token) → token operation → answer      │
 operator ──unix socket────▶  │ admin: unlock, status, metrics            ┌──────────┐               │
 operator ──files/SIGHUP───▶  │ configuration and secret files, reload    │  token   │ ECDH, ECDSA   │
                              └───────────────────────────────────────────┴──────────┘ (card, soft) ─┘
                                           │ audit log (written before the answer)
```

## Actors

| Actor | Is | May |
|---|---|---|
| Client | a program with a certificate and/or a credential (SigV4 secret, service-account key, client secret) | the operations of its grants on the keys named in them, within its budgets |
| Operator | a person with access to the host | write the configuration and secret files, start and reload the service, unlock the token over the admin socket, read the audit log |
| Token | a PKCS#11 device or a software key | do ECDH and ECDSA with a private key that never leaves it |
| Maintainer | the owner of the repository | merge, tag and release; the release workflow builds and signs |
| Attacker | anyone on the network, a compromised client, a stolen card | see [threat-model.md](threat-model.md) |

## Actions

| Action | By | What happens |
|---|---|---|
| Seal / encrypt | client | the service seals the plaintext to the public key of the key (no token operation) in the `ecies2` format, bound to key name, version and context |
| Open / decrypt | client | policy and budget are checked; the token does one ECDH; the service opens the text and returns the plaintext |
| Derive | client with the right | the token does ECDH with a public key of the client's choice (key-agreement keys only) |
| Sign, verify, MAC | client | the token signs a digest (ECDSA P-256), or the service computes HMAC-SHA-256 under a key derived on the token; verify checks |
| Get public key, describe, list | client | public information from a small budget of its own |
| Obtain a token | client | exchange a signed assertion or a secret for a short-lived access token (gRPC and REST faces) |
| Unlock | operator | the PIN enters the memory of the service; nothing else leaves the card |
| Reload | operator | a new configuration is checked as a whole and replaces the old one for the next request |
| Release | maintainer | a tag runs the tests, builds the binary and the image, signs them and publishes them with provenance and a bill of materials |
