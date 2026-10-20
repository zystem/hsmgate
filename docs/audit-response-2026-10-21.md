# Response to the audit of 2026-10-21

The audit ([docs/security-audit-2026-10-21](security-audit-2026-10-21/CRYPTO.ru.md), snapshot `e766cb7`) found four problems in the KMS-JSON face and one in the limits. All were reproduced from the probes in the audit folder, all were real, none was in a release (the face is not in a tag), and all are fixed in the tree with tests that fail without the fix.

| ID | Finding | Verdict | Fix | Test |
|---|---|---|---|---|
| CR-01 | A physical key under a second label/CKA_ID passes `Validate`; a client that may `derive` on the alias recovers the MAC key of the first name (and can open what is sealed under it) | confirmed | with the face in use no two keys may rest on one private key: same soft file, same module/token/CKA_ID (case-insensitive), a fingerprint pinned twice (`config.distinctKeys`); at start and reload the public keys of the answering tokens are compared (`server.VerifyDistinct`) | `TestOnePrivateKeyOneName`, `TestACopyOfAKeyIsRefusedWhenTheFaceIsInUse` |
| CR-02 | The name and the version in the blob are not authenticated: a blob can be relabelled to another key with the same material and context | confirmed | format `HGK2`: domain, name and version are part of the AEAD additional data. `HGK1` blobs never left a test (no release), so there is no legacy path | `TestBlobCannotBeRelabelled` |
| CR-03 | The MAC key cache hands out its own memory; `put`/`clear` wipe it while a reader copies it (data race) | confirmed under `-race` | `get` returns a copy made under the lock | `TestMacCacheIsRaceFree` |
| CR-04 | `X-Amz-Content-Sha256: UNSIGNED-PAYLOAD` is accepted, so a body can be exchanged under a valid Authorization | confirmed | any value but the real hash of the body is refused | `TestUnsignedPayloadIsRefused` |
| CR-05 | Decrypt ignores `max_bytes` (Encrypt keeps it) | confirmed | the limit holds on the way out | `TestDecryptHonoursMaxBytes` |
| — | The audit line holds 6 bytes of the hash of a signed message or MAC input | accepted | off unless `kmsjson.audit_message_prefix: true` | `TestSignAndVerify`, `TestGenerateAndVerifyMac` |

What the audit could not know: `tools/scard-spike` **was** run on the card (on 2026-10-21: ECDH, AES-CBC, AES-CMAC and the HMAC function over PC/SC and the timings in `docs/tokens/smartcard-hsm.md`); the report says it was not.

Left as the audit says: hardware evidence (the RNG of the card for ECDSA, the attributes and non-extractability of the real keys, a second card model) is not produced by this change; the MAC point is the service's own construction, not RFC 9380; the Go heap is not wiped everywhere.

## Scanners (raw output in the audit folder)

- `govulncheck`: no vulnerability is called (the one in `golang.org/x/crypto/openpgp` is a package the service does not import).
- Python `cryptography` 46.0.1 in `test/kmsjson-boto3/requirements.txt` had seven known problems (four high). It is a test-only dependency; it is now 50.0.2.
- `gitleaks`: three hits, all credentials made up for the tests; `.gitleaks.toml` lists those files.
- `staticcheck`: the three deprecations were in a test; fixed. `golangci-lint`: 163 unchecked errors (closing files, writing the audit line of a refusal on purpose) and nine staticcheck notes; none changes behaviour.
- Image (`debian:bookworm-slim`): 5 critical and 68 high findings, none with a fix, all in packages the service does not use (`bsdutils`, `libblkid`, `gzip`, …). They are the reason to look at a smaller base image (a `scratch` image for the software token, `distroless` for the card) (decision pending: a `scratch` image for the software token is easy, the card needs `glibc` and the OpenSC module).
