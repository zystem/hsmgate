# Upgrading

The latest release is supported, and the previous minor release for 30 days ([SECURITY.md](../SECURITY.md)). Upgrade one minor release at a time and read the notes below and in [CHANGELOG.md](../CHANGELOG.md).

General steps: read the notes; run `hsmgate check -config …` with the new binary (it needs no PIN); replace the binary or the image (pin the digest); restart; `hsmgate unlock`; look at the audit log. A configuration that the new version refuses is refused at the start, not at the first request. SIGHUP reloads the configuration without a restart for what a reload may change (not the listener, the admin socket, the audit file, the limits, the enabled faces).

## 0.9.2 to 0.9.3

- Nothing to do in the configuration or the formats. A package replaces the files in `/usr/bin` and does not restart the service. 0.9.2 had two faults in the directories (`hsmgate-setup -auto` gave `/etc/hsmgate` to the service account, and the unit made `/var/log/hsmgate` 0755; `rpm -V hsmgate` showed both): **`dnf upgrade` to 0.9.3 puts both right by itself** (tried on AlmaLinux 10, 2026-11-19; the service is restarted by you, and the new unit keeps the mode). For a deb that was not tried: if `dpkg -V hsmgate` shows a difference, `sudo chown root:hsmgate /etc/hsmgate` and `sudo chmod 0750 /var/log/hsmgate` do it by hand.

## 0.9.1 to 0.9.2

- Nothing to do. `hsmgate ca` now also reads an authority key in the SEC1 form (`BEGIN EC PRIVATE KEY`), and `hsmgate-setup` no longer shows an untouched file as "unsaved". A package replaces the files in `/usr/bin` and does not restart the service.

## 0.8 to 0.9 (0.9.1, 0.9.2, 0.9.3)

- Nothing in the configuration or the formats changed: `hsmgate check -config …` with the new binary is enough to know.
- New and optional: the terminal tool `hsmgate-setup` and the packages (deb, rpm, AppImage), [installing-packages.md](installing-packages.md). A package puts the program in `/usr/bin` and its unit in `/usr/lib/systemd/system`, never restarts the service and never touches `/etc/hsmgate` or the keys. A binary you placed in `/usr/local/bin` and a unit of your own in `/etc/systemd/system` come first and keep working: check `command -v hsmgate` and `systemctl cat hsmgate` after installing one. Not run: an upgrade from 0.8.0 by a package (0.9.1 is the first release that has one; 0.9.0 was never released).
- The image has a fixed `libssl3` (CVE-2026-84782); no action.

## 0.7 to 0.8

- **Helm chart: the audit file is not written by default.** `audit.file` is `false`: the audit goes to the output of the container (`kubectl logs deploy/<release>-hsmgate`). A cluster that reads `/var/log/hsmgate/audit.log` (a collector, `audit.persistence`) sets `audit.file=true`. The service and its configuration are not changed by this.
- With `audit.file=true` the chart rotates the file itself (`audit.maxSizeMB` 25, `audit.maxFiles` 5) and refuses a pair that does not fit the 256 MiB `emptyDir`. `audit.maxSizeMB=0` is the old behaviour (no limit).
- New settings of the service, all optional, off by default: `audit.stdout`, `audit.max_size_mb`, `audit.max_files`. SIGHUP now also opens the audit file again, so `logrotate` with a rename works.
- The chart runs `hsmgate ping` with a TLS handshake as its probe (`probe.tls`): use the image of the same release (0.8.0); with an older image set `probe.tls=false`.
- New and optional in the chart: `fluentbit.enabled`, `extraContainers`, `extraVolumes`.
- The service no longer logs `http: TLS handshake error ... EOF` for a bare TCP connect.

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
