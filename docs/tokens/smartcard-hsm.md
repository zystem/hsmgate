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
