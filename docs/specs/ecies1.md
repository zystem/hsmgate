# The sealed format `ecies1`

**Status: implemented** (`internal/scheme/ecies`). Vectors: `testdata/vectors/ecies1.json`, made by the Nim program `kekd` of CiNim and opened by the Go code (`TestNimVectorsOpen`, `TestNimInvalidVectors`).

A data key (up to a few kilobytes) is sealed to the **public** key of a master key that lives on a token. Sealing needs no token and no PIN. Opening needs the token to do one ECDH operation; nothing but the 32-byte shared secret leaves it.

## The text

```
ecies1.<fingerprint>.<ephemeral point>.<body>
```

All parts are lowercase hexadecimal, separated by `.`; there are exactly four.

| Part | Content |
|---|---|
| `ecies1` | the format tag; another tag means another format and is refused |
| fingerprint | 64 hex digits: SHA-256 of the DER `SubjectPublicKeyInfo` of the master public key, that is of the 26 bytes `3059301306072a8648ce3d020106082a8648ce3d030107034200` followed by the 65-byte point. It names the key; it is what `hsmgate check` prints and what a `fingerprint:` pin in the configuration is compared with |
| ephemeral point | 130 hex digits: the uncompressed P-256 point (`04` ‖ X ‖ Y) of a key pair made for this one text |
| body | hex of `nonce ‖ ciphertext ‖ tag`: a 24-byte nonce, the encrypted data key, a 16-byte Poly1305 tag. At least 40 bytes |

## Sealing (anyone who has the master public key)

1. Make an ephemeral P-256 key pair `E`. `Z = ECDH(E.private, master.public)`: the 32-byte X coordinate.
2. `fp` = the fingerprint above (as hex text). `eph` = the ephemeral point (65 bytes).
3. Key derivation, HKDF-SHA256 with one output block:
   - `PRK = HMAC-SHA256(key = "cinim/kek/v1", message = Z)`
   - `K = HMAC-SHA256(key = PRK, message = "cinim/kek/v1" ‖ "|" ‖ fp ‖ "|" ‖ hex(eph) ‖ 0x01)`  (32 bytes)

   The label `cinim/kek/v1` is part of the format and stays, whatever the product is called.
4. A random 24-byte `nonce`. `body = nonce ‖ XChaCha20-Poly1305(K, nonce, plaintext, aad)`.
5. The text is `ecies1.<fp>.<hex(eph)>.<hex(body)>`.

`aad` is the **additional data**: bytes that the opener must supply again, byte for byte. It binds the sealed key to its place. In hsmgate it is a constant of the key (mode `fixed`) or the `context` of the request (mode `context`); see [transit.md](transit.md).

## Opening (needs the token)

1. Split on `.`; not four parts or a tag other than `ecies1` → **damaged**.
2. The fingerprint is not the one of the key being asked → **wrong key** (final; the token is not asked).
3. The ephemeral point is not 65 bytes, or not on the curve → **damaged**, **before** the token sees it (an invalid point must never reach the ECDH of a token).
4. The body is shorter than 40 bytes or not hex → **damaged**.
5. The token computes `Z = ECDH(master.private, eph)`; the same `K`; XChaCha20-Poly1305 opens `body` with `aad`. A failed tag → **damaged** (also when only the `aad` differs: a text opened in another place).
6. A token that cannot answer (locked, removed, busy) is **not** "damaged": the caller may try again later.

## What it promises, and what it does not

- Two sealings of the same data key give different texts (fresh ephemeral key and nonce).
- A text sealed for one master key does not open under another (step 2), and a changed byte does not open (step 5).
- The text hides the data key; its **length** shows the length of the data key.
- It does not authenticate who sealed it: anyone with the public key can seal. Who may *open* is decided by the token and by the policy of the service.
- Growth: a data key of `n` bytes gives a text of `283 + 2n` characters (347 for 32 bytes).

## `ecies2`: the same with approved algorithms

For a deployment that must use only algorithms approved in a FIPS 140-3 module (`require_fips`, [../compliance.md](../compliance.md)). The text is `ecies2.<fingerprint>.<ephemeral point>.<body>`, with the same fingerprint and point; what differs:

- `K = HKDF-SHA256(ikm = Z, salt = "hsmgate/ecies2", info = fp ‖ "|" ‖ hex(eph), length 32)`;
- `body = nonce ‖ AES-256-GCM(K, nonce, plaintext, aad)` with a random 12-byte nonce and a 16-byte tag; at least 28 bytes. A key is made for this one text (a fresh ephemeral key), so a random nonce cannot repeat under it.

Choice: `seal_format` (`ecies1`, the default, or `ecies2`; `require_fips` makes it `ecies2`). Both formats are always read, except that `require_fips` refuses `ecies1`. The card plays the same part in both: one ECDH; the AEAD runs on the host.
