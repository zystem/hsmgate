# Installing from a package (deb, rpm, AppImage)

*A how-to page.* The release has three ways to install hsmgate without building it. All three carry the program, the terminal tool [hsmgate-setup](setup-tool.md) and the quick setup, and are signed like the other assets of a release ([verifying-releases.md](verifying-releases.md)).

| You have | Take | Notes |
|---|---|---|
| Debian, Ubuntu | `hsmgate_X.Y.Z_amd64.deb` | an account `hsmgate`, the directories, the systemd unit, the quick setup |
| Fedora, RHEL-like | `hsmgate-X.Y.Z-1.x86_64.rpm` | the same |
| Any Linux, nothing to install, or a quick look | `hsmgate-X.Y.Z-x86_64.AppImage` | a single file; as an ordinary user it keeps everything in the home directory |

The programs are linked against the glibc of Debian 12 (bookworm), so a machine needs glibc 2.36 or newer. A card needs the OpenSC module and `pcscd` (`apt install pcscd opensc`; the deb recommends them; the rpm too).

## deb and rpm

```bash
sudo apt install ./hsmgate_X.Y.Z_amd64.deb          # or: sudo dnf install ./hsmgate-X.Y.Z-1.x86_64.rpm
```

What the package does, in this order:

1. **before unpacking:** makes the system account and group `hsmgate` (no login, no home);
2. **unpacks** `/usr/bin/hsmgate`, `/usr/bin/hsmgate-setup`, the unit `hsmgate.service`, the example configurations and the documents in `/usr/share/doc/hsmgate/`, and the directories `/etc/hsmgate` (root, group `hsmgate`, mode 0750) and `/var/log/hsmgate` (`hsmgate`, 0750);
3. **after unpacking**, on a *first* installation with *no* configuration:
   - at a terminal (and `DEBIAN_FRONTEND` is not `noninteractive`): starts **the quick setup** by itself (`hsmgate-setup -first-run`). `Cancel` and `Esc` go back to the menus, `F10` ends the tool; the package stays installed and unconfigured;
   - with `HSMGATE_SETUP_AUTO=1`: runs the quick setup with its defaults and no screen;
   - otherwise: prints `hsmgate: installed, not configured. Run 'sudo hsmgate-setup' …` and does nothing.

   `HSMGATE_NO_WIZARD=1` stops the first case.

An installation never fails because the setup was cancelled or did not finish.

**The service is not started by the package.** The unit starts only when `/etc/hsmgate/hsmgate.yaml` exists (`ConditionPathExists`), so a package without a configuration does not start and fail in a loop. The quick setup enables and starts it (`systemctl enable --now hsmgate`) when it is run as root on a machine with systemd; otherwise: `sudo systemctl enable --now hsmgate`.

### Unattended (Ansible, Dockerfile, cloud-init)

```bash
sudo HSMGATE_SETUP_AUTO=1 apt install -y ./hsmgate_X.Y.Z_amd64.deb
# or, to choose: install first, then
sudo hsmgate-setup -auto -listen 0.0.0.0:8443 -names hsm.example.org -key orders -client shop -context-prefixes orders/
```

It prints what it made and the commands that work now. The flags are in [setup-tool.md](setup-tool.md#flags). With a card: `-mode card -module … -token-label … -card-key-id …` ([tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)); the key pair must already be on the card.

### Upgrading

`apt install ./hsmgate_X.Y.Z_amd64.deb` (or `dnf upgrade`) replaces the programs and leaves the configuration, the keys and the running service alone. **It does not restart the service**: a restart of a card without a `pin_file` leaves the card locked until `hsmgate unlock`, and nobody should be surprised by that. The package says so when the service is running; restart it when you are ready: `sudo systemctl restart hsmgate`. What a release changes: [upgrading.md](upgrading.md).

### Removing

`apt remove hsmgate` (or `rpm -e`) stops and disables the service and removes the programs. **The configuration, the certificates, the keys and the audit log are kept, also by `apt purge`**, and so is the account: the key of the authority and the key files cannot be made again, and what was sealed under them cannot be opened without them. The package prints what is left; delete `/etc/hsmgate` and `/var/log/hsmgate` yourself when the keys are no longer needed.

## AppImage

```bash
chmod +x hsmgate-X.Y.Z-x86_64.AppImage
./hsmgate-X.Y.Z-x86_64.AppImage                     # no arguments: the quick setup on a first run, the menus afterwards
./hsmgate-X.Y.Z-x86_64.AppImage serve -config ~/.config/hsmgate/hsmgate.yaml
./hsmgate-X.Y.Z-x86_64.AppImage encrypt             # any command of hsmgate; `setup` is hsmgate-setup
```

As an **ordinary user** it keeps everything in your home directory (`~/.config/hsmgate`, `~/.local/state/hsmgate`), listens on `127.0.0.1:8443` and does not touch systemd: a way to try it or to run a pilot without installing. As **root** it uses the system layout like the packages. Nothing is written inside the AppImage. Without FUSE: `APPIMAGE_EXTRACT_AND_RUN=1 ./hsmgate-….AppImage`.

## What was run, and what was not

Run on 2026-11-14 by the Packages workflow (`.github/workflows/packages.yml`) on the files that `packaging/build.sh` made with **nfpm v2.48.0** and **appimagetool 1.9.1**, each in a clean container (the tests are in `packaging/test/`):

- *deb*, on **Debian 12, Debian 13 and Ubuntu 24.04**: `plain` (the account is a system account with no login, `/etc/hsmgate` is `root:hsmgate 0750`, no configuration is made, the installation says what to do, the unit has the condition) and `auto` (the quick setup makes the configuration `root:hsmgate 0640`, the key file owned by the service with mode 0400, the authority private to root; `hsmgate check` passes **as the service user**; the service runs as `hsmgate`; a client seals and opens a text with the certificate the setup made; the audit file is the service's; removal and purge keep the data);
- *wizard*, Debian 13: `apt-get install` on a terminal (made with `script`) starts the quick setup by itself and its keys were pressed to the end;
- *card*, Debian 13, with **SoftHSM2** and `hsmgate-setup -auto -mode card`: the service opens the token with the PIN file and a client seals and opens a text, with no key file made;
- *rpm*, on **Fedora (latest)**: `plain` and `auto` as for the deb, and removal keeps the configuration and the authority;
- *AppImage*, on **Debian 13 and Ubuntu 24.04**, as an ordinary user, with no FUSE: the program and the tool run, the quick setup keeps everything in the home directory, the service listens on the loopback and a client seals and opens a text.

Found by these runs and fixed: a configuration written by root was not readable by the service; `hsmgate check` run by root refused a key file owned by the service; `nfpm` does not expand variables in the paths of files; `appimagetool` needs `file(1)`; the test of the rpm needed `runuser`, and rpm prefixes what a scriptlet prints with `>>> `.

**Not run:** a real card or HSM (SoftHSM2 only), `systemctl enable --now` on a machine with systemd (the containers have none), an upgrade from an older package, the rpm on Rocky, Alma or RHEL (their glibc may be older than the 2.36 the programs need), arm64, and the packaging step of the **release** workflow (it has not run on a tag; it is the same script, with signing and attestation added).
