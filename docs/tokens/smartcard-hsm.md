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
| Backup | the private key leaves the card only wrapped under the DKEK; a second card with the same DKEK takes it. Then it is a **replica** of the key version (`docs/operations.md`). A key can be wrapped only if it was made with wrapping allowed (the card lists the algorithms of a key; `wrap` is one). The **Card** page of `hsmgate-setup` does the wrap and the unwrap ([setup-tool.md](../setup-tool.md)) |
| Not tried | the PIN refused on the card (costs a try), unplugging the card under load, a second card restored from a DKEK backup (the wrap and the unwrap were tried on the one card, see below), `sc-hsm-embedded` instead of OpenSC |

## What the card does with the commands of the Card page (tried 2026-11-18, the same card, firmware 4.1, OpenSC 0.26.1 and pcsc-lite 2.3.3)

The commands are sent by `opensc-explorer` fed through a pipe (so a PIN is never in a command line); they are the card's own, learned from the vendor's card manager and checked here:

- **PIN state without a try**: `00 20 00 81` (User PIN) and `00 20 00 88` (SO PIN) answer `63Cx` (x tries left), `9000` (verified) or `6983` (blocked). The PIN itself is the body of the same command.
- **A key domain**: `80 52 00 n` is its status (shares, shares still to import, the key check value of 8 bytes, and for an XKEK the identifier of a key domain); `80 52 01 n` with the number of shares makes a DKEK domain (needs the User PIN); a share (32 bytes) is the body of `80 52 00 n`; `80 52 04 n` deletes the key encryption key and `80 52 03 n` the domain. **Deleting the key encryption key is one way** (tried on 2026-11-20, in a domain with a key and in an empty one): afterwards the status is `shares 1, outstanding 0, check value 0000000000000000`, and a share (`80 52 00 n`) or a new creation (`80 52 01 n`, any number of shares) answers `6985`, also for the share that was in before. What works: **delete the keys of the domain, delete the domain (`80 52 03 n`, the card refuses while a key is in it), make it again, import the shares, import the keys from their wrapped files**. The domain 0 is no exception. A key domain made again awaiting one share is what `sc-hsm-tool --import-dkek-share` needs (it takes a share only into the domain 0). The label of a domain is the file `C7nn`. **The key check value of the card is the first 8 bytes of the SHA-256 of the DKEK, and the DKEK is the XOR of the shares**: checked for one share (the card showed `6DDCAE2031D428DB` for the share whose SHA-256 begins so).
- **Changing the User PIN**: `00 24 00 81` with the current and the new PIN one after the other. **The card cuts the data in the middle, so the new PIN must have as many characters as the current one**: a PIN of 15 characters was changed to another of 15 and back, and a new PIN of 6, 10 and 14 characters was refused with `6A80` (2026-11-19). The program checks this before it sends anything, so no try is spent. The unblocking (`00 2C 00 81`, the SO PIN and the new User PIN) has no such rule: a new User PIN of 10 characters was taken for a PIN of 15 and put back. **The SO PIN is 8 bytes**: the program takes it as 8 characters or as 16 hexadecimal digits (as `sc-hsm-tool --so-pin` writes it; the default `3537363231383830` is the hexadecimal form of `57621880`). The SO PIN of this card was changed to another of the same length and back, and the 16 hexadecimal digits worked (2026-11-19).
- **A wrapped key**: `80 72 key 92` gives the blob (365 bytes for an EC P-256 key). **It needs an extended length for the answer** (a short Le gives `6700`). `80 74 key 93` with the blob puts it onto the card as the key with that number, in the key domain whose DKEK has the check value that the blob begins with. **A body of more than 255 bytes needs an extended length too: a chained command (class `10`) is refused with `6884`.** The description of the key (label, id) and its certificates are separate files (`C4nn`, `CEnn`) that the Card page copies.
- **A second connection**: selecting the application (`00 A4 04 04 …`) ends a login that another connection made. After the page had read the tree (which selects it) a delete in a session that was logged in earlier answered `6982`. The service on the same card went on sealing and opening texts after the page's reads and writes (one try).
- **Generating a key**: `00 46 key 00` with the specification of a certificate request (profile `5F29`, authority `42`, the key `7F49` with the algorithm and, for EC, the domain parameters of P-256, holder `5F20`, then the algorithms `91` and the key domain `92`) makes the key; the card answers with the **authenticated request** (489 bytes for an EC key) **once**: it is not kept, so the page writes it to the file `CEnn`. The description of the key is the file `C4nn` (label, identifier, usage, size). **The length of the data of a write (`00 D7`, the object `53`) is in BER: a length byte of 200 was refused with `6A80`, because 200 is the first byte of a long form.** **An RSA key needs the command with extended lengths** (the answer is about 900 bytes for RSA-2048; a short Le gave `6700`): RSA-2048 was made in 11 seconds on the card here (2026-11-19) and wrapped (a blob of 980 bytes with one certificate) and unwrapped.
- **XKEK**: the certificates of the device are the file `2F02` (the device certificate and the one that signed it, more than one block to read). A group signer key signs, with ECDSA-SHA-256 (`80 68 key 73`), `54` and the X of the public key of a device: the membership. The card verifies a certificate with `00 22 81 B6 83 reference` and `00 2A 00 BE` (it answers `6A88` to the first selection of a holder it does not know, then wants the authority), selects the signer with the outer authority of the request, and `80 52 02 n` with the request and the membership makes the key domain. The status then has the identifier of the key domain after the check value (the key check value is zero until an exchange key is made), and **deleting the key encryption key of such a domain answers `6985`**; deleting the domain works. Tried with the card as its own member (a group of one).
- **Generating an AES key**: `00 48 key B0|B1|B2` (128, 192 or 256 bits) with the algorithms `91` (`10` and `11` CBC encrypt and decrypt, `18` CMAC, `99` derivation, `92` wrap) and the key domain `92`; the card keeps the key and answers `9000` with nothing (a wrapping key is not named). The description is the file `C4nn` with the tag `A8` (label, identifier, usage `07C010`, size in the attributes `A0`). A key that may do CMAC or derivation is named by the first 8 bytes of `80 78 key 18 "KeyCheckValue"` (CMAC; `99` for a key that only derives), any other by its number. Made on the card here on 2026-11-19: AES-256 (CBC and wrap) and AES-128 (CMAC), both shown in the tree, the first wrapped (a blob of 92 bytes) and unwrapped as another key, all deleted. The program only makes them and keeps them for the card manager and the card's own functions: no module on Linux uses them (see below).
- **Share files**, in two formats that the Card page opens both. **Compatible**: `Salted__`, 8 bytes of salt, and AES-256-CBC of the share and sixteen bytes of `10`, the key and the vector made as OpenSSL's `EVP_BytesToKey` (MD5, count 10 000 000) makes them: the file that the vendor's card managers write and read (the derivation with the count 1 is checked against `openssl enc -md md5 -P`). MD5 is weak for a password; the count is what protects the file. **Strong** (the default of the page): `HGDKEKS1`, the number of iterations, a salt of 16 bytes, a nonce of 12 bytes and the share under AES-256-GCM, the key made by PBKDF2-HMAC-SHA-256 with 1 000 000 iterations, the header authenticated (a changed byte anywhere is refused); only this program reads it. Both were made by the page, imported into a key domain of the real card and the card took the share (the check value of the card was that of the share). **Compatible files and the vendor's tools, tried 2026-11-19**: (1) the share file that the vendor's own code makes (`DKEK.encryptKeyShare` of Smart Card Shell, run headless from a local copy with only its `print` calls removed) for a known share and password was opened by this program and gave exactly that share; (2) the compatible file that this program makes for the same share and password was opened by `DKEK.decryptKeyShare` of Smart Card Shell and gave exactly that share (a wrong password was refused); (3) a file made by `sc-hsm-tool --create-dkek-share` (OpenSC 0.26.1, on the host of the card) was opened by this program with its password and gave a share (the check of the padding passes only with the right key and vector). **Not tried:** this program's file opened by `sc-hsm-tool --import-dkek-share`: that command sends the share to the card, and the only key domain it reaches (the first) is complete, so an import there could change a DKEK. The tests are `TestInteropOpenVendorFile` and `TestInteropWriteOurFile` (`tui/internal/card/interop_test.go`, skipped unless their variables are set).

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

**Tried on 2026-10-21** with [tools/scard-spike](../../tools/scard-spike/README.md) on the card of the production machine (firmware 4.1; test keys made and removed, the production key and container not touched; the program read the PIN file itself):

| Command | Result |
|---|---|
| `SELECT` the applet, `VERIFY` the PIN over PC/SC (`00 20 00 81`) | works from a second program while another one has the card; the key references are the files `CCxx` listed by `80 58` |
| ECDH: `80 62 <ref> 80`, data = the peer point `04 \|\| X \|\| Y` | returns `04 \|\| X \|\| Y` of the result point (65 bytes); **X equals the local ECDH secret** |
| AES-CMAC: `80 78 <ref> 18` | 16 bytes, repeatable, depends on the message |
| HMAC-SHA256 function: `80 78 <ref> 99` | 32 bytes, repeatable, depends on the message; **whether it is the standard HMAC with the key as its key was not checked** (the key cannot be read, and none was imported) |
| AES-CBC: `80 78 <ref> 10` / `11` | round trip works; the card's CBC has a **zero IV** (a host that wants another IV XORs it into the first block, as the vendor's module does) |

An EC key refuses the AES commands (`6A81`) and an AES key refuses ECDH (`6A86`): the key types stay apart on the card. An AES-256 key made with the vendor's module's `CKM_AES_KEY_GEN` carries all four AES algorithms (10, 11, 18, 99). Still no AES-GCM.

### Speed (measured 2026-10-21, the same card, the reader OMNIKEY 3x21, one caller, 40 calls in a row)

| Operation | mean ms | per second |
|---|---|---|
| ECDH through the OpenSC module (what hsmgate does for every decrypt) | 37.0 | 27 |
| ECDH over PC/SC with the card's own command | 35.9 | 28 |
| AES-CMAC, 32 bytes (vendor's module / PC/SC) | 18.6 / 18.6 | 54 |
| AES-CBC encrypt, 64 bytes (vendor's module / PC/SC) | 17.4 / 17.4 | 57 |
| HMAC-SHA256 function `99`, 32 bytes (PC/SC) | 43.0 | 23 |
| ECDH P-256 in software (Go), for comparison | 0.09 | 11 700 |

Every operation on the card costs 17 to 43 ms whatever it is: the time is the round trip through the reader and the card, and the card does one thing at a time. The PKCS#11 layer adds about a millisecond; the vendor's module and OpenSC are equal. What this means for the designs:

- `ecies2` (ECDH): a **seal needs no card at all** (the public key; 0.1 ms in software), an **open is one ECDH, 37 ms**: at most about 27 opens per second per card. Sealing scales; opening is the limit.
- AES on the card (CMAC as a PRF, or CBC with CMAC): **every seal and every open is a card operation** (one or two, 19 to 37 ms), so sealing becomes 200 to 400 times slower and depends on the card, and the card's 20 to 55 operations per second are shared by seals and opens.
- MAC: the key derived by ECDH is one 37 ms operation per MAC without the cache and none with it (`kmsjson.mac_cache_seconds`); a MAC on the card is 19 ms (CMAC) or 43 ms (HMAC-SHA256 function) every time.
- The line to the card (`limits`: 8 at once, 2 seconds of waiting by default) is sized for these numbers: a burst of more than about 50 simultaneous opens finds the queue full and gets `busy`/`throttled` with a retry.

## Decision: no AES on the card (2026-10-21)

hsmgate does not use AES on the SmartCard-HSM until there is a new, weighty reason. The key stays an EC key: seals are made in software with `ecies1` from the public key, opens are one ECDH on the card.

Why:

- **No AES-GCM on the card** (CBC and CMAC only), so any AES design is an assembly in our code of two primitives and two keys, with the classic mistakes of such assemblies available.
- **Speed and availability.** A seal would become a card operation (19 to 37 ms instead of 0.1 ms) and would need the card to be present; the card's 20 to 55 operations per second would be shared by seals and opens.
- **No gain in the main risk.** A host that is compromised while the card is unlocked can ask the card for anything its policy allows, wherever the AES runs; the defence is the policy, the limits, the audit before the answer, the lock, and sealing by the client (`DeriveSharedSecret`).
- **No client needs it.** Every program tried (Vault, OpenBao, SOPS, cosign, Terraform, the SDKs, MongoDB, the Encryption SDK) treats the ciphertext as opaque.
- **Two modules.** ECDH comes from OpenSC and AES from the vendor's module; both on one card means two tokens, or an own driver over PC/SC (weeks of work and a protocol to maintain).

What would reopen it (any of):

1. A requirement that data keys be sealed by an AES key on the token (an auditor, a rule), or secrets that must outlive the elliptic curves (long-lived data against a quantum computer): then the option "CMAC as a PRF" of the discussion, with a single AES-256 key.
2. A MAC that must not have its key in the memory of the host: then the card's HMAC-SHA256 function (to be checked for being the standard HMAC) or CMAC, through an own driver.
3. A token or a module that has AES-GCM and ECDH together (another HSM, a newer OpenSC or vendor module).
4. A client that cannot work with the blob of this service and needs AES-GCM ciphertext of the cloud service (none found).

Meanwhile the MAC key derived by ECDH stays, with the cache off by default (`kmsjson.mac_cache_seconds`).
