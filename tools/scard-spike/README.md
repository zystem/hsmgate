# scard-spike

A spike, not part of the service and of its module (it has its own `go.mod`; CI does not build it). It talks to a SmartCard-HSM over PC/SC with the card's own commands and shows what the card does that neither PKCS#11 module offers together: ECDH (`80 62 <ref> 80`), AES-CBC (`80 78 <ref> 10/11`), AES-CMAC (`18`) and the HMAC-SHA256 function (`99`). Results: [docs/tokens/smartcard-hsm.md](../../docs/tokens/smartcard-hsm.md).

```
spike PINFILE make    # test keys: an EC pair with OpenSC's module, an AES-256 key with the vendor's module (ids 5167c2, 5167c1)
spike PINFILE test    # SELECT, VERIFY over PC/SC, then ECDH / CMAC / HMAC / CBC on the new key references
spike PINFILE clean   # deletes the test keys and lists the key references on the card
```

The PIN is read from the file by the program and never printed. It needs `libpcsclite-dev` to build (cgo), the OpenSC module and the vendor's `libsc-hsm-pkcs11.so` (`/tmp/libsc-hsm-pkcs11.so`, built from `CardContact/sc-hsm-embedded`) to run. Run it on a card that no other program is using in a way that matters: the PIN state of the card is shared with other programs that have it open (hsmgate logs in again by itself when it finds the card logged out).
