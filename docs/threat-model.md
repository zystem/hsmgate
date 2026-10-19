# Threat model (draft, P1)

Asset: the master private key on the token (it never leaves it) and the plaintext of what is unwrapped. The service holds neither the key nor, at rest, any plaintext; it holds the PIN in memory while unlocked.
Rule one: **a compromised client can do exactly what its policy allows and no more, and every use is written down.**

| Attacker | Can | Mitigation | Residual |
|---|---|---|---|
| Compromised client (stolen client key) | `wrap`/`unwrap` what its policy allows, at its rate limit | deny by default; per client+key ops, context rules, rate and size limits; audit of allowed and refused; revoke by config reload; short-lived certs | until revoked it can unwrap what policy lets it; limit bounds the speed of bulk decryption |
| Network attacker | observe, replay, impersonate the server | TLS 1.3 with mandatory client cert; service terminates TLS itself, believes no header; server cert pinned by clients | TLS stack bugs |
| Unauthenticated peer | connect, probe | handshake fails before any handler; `/healthz` and `status` touch no card; no oracle for unauthenticated | handshake-level DoS |
| Stolen token, no PIN | try PINs | card blocks after 3 tries; service tries the PIN once and stays `locked` after a refusal | physical attacks on the card |
| Stolen PIN, no token | nothing | token is required for any private operation | — |
| Host compromise (root on the service host) | read PIN from memory, drive the token while it is unlocked, forge audit | PIN only in memory, `unlock` over admin socket; systemd sandboxing; audit hash chain, shipped off-host; spare token and rotation limit the window | root on an unlocked host is full use of the token for the time it is unlocked; not defended |
| Operator error | wrong key, wrong context, lost card | named keys with state; `rewrap`; multi-recipient format (spare card); written recovery procedure | lost sole card = lost data |
| Client exhausting the token | many ECDH operations | per-client and per-key rate limits, global budget, `busy` with `retryable` | shared global budget lets one client starve others unless per-client limits are set |
| Malicious ciphertext | off-curve ephemeral point, oversize body | point validated before the token is asked; size limits; fuzz targets for parsers | token-side bugs |
| Wrapped text moved to another context | open a DEK sealed for tenant A in tenant B | context map canonicalised into AEAD additional data; policy restricts contexts | policy must be written correctly |

Out of scope: availability of the token fleet, side channels inside the token, a malicious vendor PKCS#11 module.
To do in P1: attacker "operator with admin socket", log-injection via context values, timing of the unwrap path (P8).
