# Upgrading

The latest release is supported, and the previous minor release for 30 days ([SECURITY.md](../SECURITY.md)). Upgrade one minor release at a time and read the notes below and in [CHANGELOG.md](../CHANGELOG.md).

General steps: read the notes; run `hsmgate check -config …` with the new binary (it needs no PIN); replace the binary or the image (pin the digest); restart; `hsmgate unlock`; look at the audit log. A configuration that the new version refuses is refused at the start, not at the first request. SIGHUP reloads the configuration without a restart for what a reload may change (not the listener, the admin socket, the audit file, the limits, the enabled faces).

## 0.3 to 0.4

- **`ecies1` is gone.** The service seals and opens `ecies2` only. Texts sealed by 0.3 or earlier in the old format (`ecies1.…`) are **not** read any more: with 0.3.x, `rewrap` them (Transit `rewrap`) so that they become `ecies2`, and only then upgrade. 0.3.0 and later already write `ecies2`; only data written before that is affected.
- The option `seal_format` is removed: delete it from the configuration (an unknown option is refused at the start).
- `require_fips` only checks that the Go cryptographic module is in FIPS 140-3 mode.
- Ciphertexts are shorter: 441 characters for a 32-byte data key in Transit form (473 before); the largest plaintext that keeps a Kubernetes KMS v2 ciphertext under 1 kB is 250 bytes.

## 0.2 to 0.3

- New optional faces (`kmsgrpc`, `kmsrest`) and `seal_format` (default `ecies2`). A service that wrote `ecies2` cannot be rolled back to 0.2 and keep those texts readable.
- CI and releases moved to GitHub Actions: releases are signed ([verifying-releases.md](verifying-releases.md)); the image is at `ghcr.io/zystem/hsmgate`.

## 0.1 to 0.2

- The KMS-JSON face (optional) and its credentials; the image is distroless (no shell: use `docker cp`, not `exec sh`).
- Keys exposed on a face may not share a private key; ciphertext blobs of that face carry the key name and version (`HGK2`).
