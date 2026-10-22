# The sealed format `ecies2`

**Status: implemented** (`internal/scheme/ecies`). Vectors: `testdata/vectors/ecies2.json` (a test key, never use it), opened by the Go code (`TestVectorsOpen`, `TestInvalidVectors`). The earlier format `ecies1` (XChaCha20-Poly1305) is neither written nor read since 0.4.0: its last user moved to this one, and the ChaCha code is gone. All algorithms here are approved in a FIPS 140-3 module ([../compliance.md](../compliance.md)).

A data key (up to a few kilobytes) is sealed to the **public** key of a master key that lives on a token. Sealing needs no token and no PIN. Opening needs the token to do one ECDH operation; nothing but the 32-byte shared secret leaves it. The token never does the AEAD: that runs on the host, so a token without AES-GCM (the SmartCard-HSM) is enough.

## The text

```
ecies2.<fingerprint>.<ephemeral point>.<body>
```

All parts are lowercase hexadecimal, separated by `.`; there are exactly four.

| Part | Content |
|---|---|
| `ecies2` | the format tag; another tag means another format and is refused |
| fingerprint | 64 hex digits: SHA-256 of the DER `SubjectPublicKeyInfo` of the master public key, that is of the 26 bytes `3059301306072a8648ce3d020106082a8648ce3d030107034200` followed by the 65-byte point. It names the key; it is what `hsmgate check` prints and what a `fingerprint:` pin in the configuration is compared with |
| ephemeral point | 130 hex digits: the uncompressed P-256 point (`04` ‖ X ‖ Y) of a key pair made for this one text |
| body | hex of `nonce ‖ ciphertext ‖ tag`: a 12-byte nonce, the encrypted data key, a 16-byte GCM tag. At least 28 bytes |

## Sealing (anyone who has the master public key)

1. Make an ephemeral P-256 key pair `E`. `Z = ECDH(E.private, master.public)`: the 32-byte X coordinate.
2. `fp` = the fingerprint above (as hex text). `eph` = the ephemeral point (65 bytes).
3. `K = HKDF-SHA256(ikm = Z, salt = "hsmgate/ecies2", info = fp ‖ "|" ‖ hex(eph), length 32)`.
4. A random 12-byte `nonce`. `body = nonce ‖ AES-256-GCM(K, nonce, plaintext, aad)`. A key is made for this one text (a fresh ephemeral key), so a random nonce cannot repeat under it.
5. The text is `ecies2.<fp>.<hex(eph)>.<hex(body)>`.

`aad` is the **additional data**: bytes that the opener must supply again, byte for byte. It binds the sealed key to its place. In hsmgate it is a constant of the key (mode `fixed`) or the `context` of the request (mode `context`); see [transit.md](transit.md).

## Opening (needs the token)

1. Split on `.`; not four parts or a tag other than `ecies2` (also `ecies1`) → **damaged**.
2. The fingerprint is not the one of the key being asked → **wrong key** (final; the token is not asked).
3. The ephemeral point is not 65 bytes, or not on the curve → **damaged**, **before** the token sees it (an invalid point must never reach the ECDH of a token).
4. The body is shorter than 28 bytes or not hex → **damaged**.
5. The token computes `Z = ECDH(master.private, eph)`; the same `K`; AES-256-GCM opens `body` with `aad`. A failed tag → **damaged** (also when only the `aad` differs: a text opened in another place).
6. A token that cannot answer (locked, removed, busy) is **not** "damaged": the caller may try again later.

## What it promises, and what it does not

- Two sealings of the same data key give different texts (fresh ephemeral key and nonce).
- A text sealed for one master key does not open under another (step 2), and a changed byte does not open (step 5).
- The text hides the data key; its **length** shows the length of the data key.
- It does not authenticate who sealed it: anyone with the public key can seal. Who may *open* is decided by the token and by the policy of the service.
- Growth: a data key of `n` bytes gives a text of `259 + 2n` characters (323 for 32 bytes).
