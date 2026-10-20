# SmartCard-HSM (CardContact; sold by Nitrokey as HSM 2)

What was tried, on one card (SmartCard-HSM 4K, firmware 4.1, a PC/SC USB reader, PKCS#15-emulated token with the label chosen at initialisation), 2026-10-19. Setup of the card (initialisation, DKEK shares, making and backing up the key) is in CiNim's `docs/hardware-key.md` sections 2-5.

| Question | Answer |
|---|---|
| Module | OpenSC `opensc-pkcs11.so` over `pcscd` (`/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so` on Debian/Ubuntu) |
| Key type used | EC P-256, usage `derive`; the public key object has the same `CKA_ID` as the private one |
| Mechanism | `CKM_ECDH1_DERIVE`, KDF `CKD_NULL`, peer point as 65 raw bytes; gives the 32-byte x coordinate. Nothing else is asked of the card (no AES is asked: the PKCS#11 module of OpenSC exposes no AES mechanism, only ECDH, ECDSA and RSA, checked on 2026-10-21 with `pkcs11-tool --list-mechanisms`; the card is reported to have AES through the vendor's own module, which has not been tried here) |
| Public key | readable without a PIN (`CKA_EC_POINT`, DER OCTET STRING around the point: `04 41 04 ...`); hsmgate reads it once and keeps it, so `encrypt` works with the card locked |
| Login | user PIN, once per session; hsmgate tries it once and never again by itself. The card blocks after 3 wrong tries (`--pin-retry` at initialisation); `pin min/max` is 6/15 |
| Speed | a `decrypt` through hsmgate (login already done): about 0.05 s per call, one operation at a time (the card serves a single session at a time; hsmgate serialises) |
| Capacity | ~179 KB for the 4.x family, about 2.5 KB per EC key and 4 KB per RSA key by the vendor's figures: roughly 70 EC keys at best. Not measured on this card. The unit that matters is the key: up to ~30 organisations per key is a design choice, not a card limit |
| Two keys on a card | yes (the card here also holds an RSA-4096 key for another use); each is a `keys:` label with its own `CKA_ID` |
| Two cards | a token is found by `token_label` or `token_serial`; two readers work as two tokens. Do not open one card from two processes |
| Backup | the private key leaves the card only wrapped under the DKEK; a second card with the same DKEK takes it. Then it is a **replica** of the key version (`docs/operations.md`) |
| Not tried | the PIN refused on the card (costs a try), unplugging the card under load, a second card restored from a DKEK backup, `sc-hsm-embedded` instead of OpenSC |

Checks that exist: `tools/card-decrypt-test.sh` (hsmgate on the card: encrypt, decrypt with the login, wrong context), the `RealModule` Go tests (`HSMGATE_P11_*` variables), `tools/softhsm-test.sh` (SoftHSM2, for CI).

## Other tokens

SoftHSM2 (tests only, no hardware protection), YubiHSM 2 (its PKCS#11 module supports ECDH; not tried), a TPM (through `tpm2-pkcs11`; not tried). A token that has AES-GCM would allow another scheme; the sealed format names its scheme, so it can be added.

## AES on the card (looked at 2026-10-21)

The vendor's module (`sc-hsm-embedded`, built from its repository at the head of the main branch, 2026-10-02, BSD-3-Clause) shows on the same card (firmware 4.1): `AES-CBC` (keys of 16 or 32 bytes, encrypt and decrypt), `AES-CMAC` (sign), `AES-KEY-GEN`, ECDSA, RSA (PKCS, PSS, OAEP). It shows **no AES-GCM, no key wrap, no HMAC and no ECDH** (the OpenSC module shows ECDH and no AES). So the two modules each give half of what a service would want, and a service that wants both would run two tokens on the one card (two modules, the same PIN file). Nothing is built on it yet. Facts to weigh: with ECDH (`ecies1`) a seal needs no card at all (the public key is enough), with an AES key on the card a seal needs the card too; the card does CBC without authentication, so a construction needs CMAC with a second key or a CMAC-derived per-message key.

Checked again on 2026-10-21 whether the vendor's stack has ECDH after all ([features page](https://www.smartcard-hsm.com/features.html), the source of `sc-hsm-embedded` and the source of OpenSC 0.27.1, latest release of 2026-03-31):

- The **card** does ECDH (the page: "an ECDH operation is used to derive a set of common encryption keys", and the APDU is there). The vendor's **PKCS#11 module** does not offer it: `ALGO_EC_DH` is a macro that nothing uses, and its `C_DeriveKey` is the card's EC *sub-key derivation* (a scheme "similar to BIP32": it makes a new key on the card, it gives no shared secret). The vendor's ECDH is in its Windows minidriver and CSP.
- **OpenSC** (Linux) is the one that offers `ECDH1-DERIVE`; its `card-sc-hsm.c` has no AES for user keys (AES appears only in the card's secure channel).
- The page calls the AES of the card an AES for *key management* and says the device's processing power is not enough for symmetric encryption schemes: it describes deriving sub-keys (CBC, CMAC, NIST SP800-56C) and doing the bulk work on the host. That is the shape of the option "CMAC as a PRF" (derive per-message keys with the card's CMAC, seal in software), not of "the card encrypts the data".
- So on Linux today ECDH and AES come from two different modules. Using both on one card means two tokens in `hsmgate.yaml` (one per module, the same card and PIN file), or an own driver over PC/SC (much work), or waiting for one of the two projects to add what the other has.

### A direct way: the card's own commands (looked at 2026-10-21, not tried)

The card does more than either PKCS#11 module shows. The vendor's public scripts ([scsh-scripts](https://github.com/CardContact/scsh-scripts), `sc-hsm/lib/smartcardhsm.js`) send the command `80 62 <key> <algorithm>` for "decipher" (RSA, and with the algorithm byte `0x80`, `ALGO_EC_DH` in the module's header, ECDH), and the module source lists the algorithms of an AES key as `0x10`, `0x11`, `0x18`, `0x99`. A forum quote of the vendor's manual (section "Derive Symmetric Key", `80 78`; to be checked against the vendor's own document before use) gives them as AES-CBC encrypt (`10`), AES-CBC decrypt (`11`), AES-CMAC with 16 bytes returned (`18`) and an **HMAC-SHA256** derivation (`99`). So a program that talks to the card over PC/SC itself could use ECDH, ECDSA, AES-CBC, AES-CMAC and HMAC-SHA256 on the one card, in one process, with no PKCS#11 module between: an HMAC with the key on the card would replace the MAC key that hsmgate now derives and holds in memory. Still no AES-GCM. Costs: the protocol code is ours to keep (and it is specific to the SmartCard-HSM and its relatives), the key references are the card's own one-byte references (not CKA_ID; they come from the PKCS#15 files), the PIN state of the card is shared with the other program that has the card open, and it needs `libpcsclite` at build time.
