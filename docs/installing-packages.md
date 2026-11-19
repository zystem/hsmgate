# Installing from a package (deb, rpm, AppImage)

*A how-to page.* The release has three ways to install hsmgate without building it. All three carry the program, the terminal tool [hsmgate-setup](setup-tool.md) and the quick setup, and are signed like the other assets of a release ([verifying-releases.md](verifying-releases.md)).

| You have | Take | Notes |
|---|---|---|
| Debian, Ubuntu | `hsmgate_X.Y.Z_amd64.deb` | an account `hsmgate`, the directories, the systemd unit, the quick setup |
| Fedora, RHEL-like | `hsmgate-X.Y.Z-1.x86_64.rpm` | the same |
| Any Linux, nothing to install, or a quick look | `hsmgate-X.Y.Z-x86_64.AppImage` | a single file; as an ordinary user it keeps everything in the home directory |

The programs are built on Debian 12 (bookworm), but the newest glibc symbol that `hsmgate` and `hsmgate-fips` ask for is `GLIBC_2.34` (`objdump -T`, checked on the release v0.9.2) and `hsmgate-setup` asks for none, so a machine needs **glibc 2.34 or newer** (Debian 12, Ubuntu 22.04, RHEL and Rocky 9 and newer). The packages do not name a version of glibc; a later release may need a newer one, so check it with `objdump -T` on the file you install. A card needs the OpenSC module and `pcscd` (`apt install pcscd opensc`; the deb recommends them; the rpm too).

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

**On a machine that has a launcher for AppImages** (AppImageLauncher and the like register the AppImage format with the kernel, `ls /proc/sys/fs/binfmt_misc/`: `appimage-type2`), the file is started through that launcher. Inside a container or a chroot of such a machine the launcher is not there, and the start fails with `not found` (the system call says `ENOENT`) although the file is there and executable. Run the AppImage outside the container, or in a container on a machine without that registration. To test the file in a container on such a machine, clear bytes 8 to 10 of a **copy** (`printf '\000\000\000' | dd of=COPY bs=1 seek=8 conv=notrunc`): the kernel then does not hand it to the launcher. That copy no longer matches its signature: verify the original first ([verifying-releases.md](verifying-releases.md)).

## What was run, and what was not

Run on 2026-11-14 and 2026-11-15 by the Packages workflow (`.github/workflows/packages.yml`) on the files that `packaging/build.sh` made with **nfpm v2.48.0** and **appimagetool 1.9.1**, each in a clean container (the tests are in `packaging/test/`):

- *deb*, on **Debian 12, Debian 13 and Ubuntu 24.04**: `plain` (the account is a system account with no login, `/etc/hsmgate` is `root:hsmgate 0750`, no configuration is made, the installation says what to do, the unit has the condition) and `auto` (the quick setup makes the configuration `root:hsmgate 0640`, the key file owned by the service with mode 0400, the authority private to root; `hsmgate check` passes **as the service user**; the service runs as `hsmgate`; a client seals and opens a text with the certificate the setup made; the audit file is the service's; removal and purge keep the data);
- *wizard*, Debian 13: `apt-get install` on a terminal (made with `script`) starts the quick setup by itself and its keys were pressed to the end;
- *card*, Debian 13, with **SoftHSM2** and `hsmgate-setup -auto -mode card`: the service opens the token with the PIN file and a client seals and opens a text, with no key file made;
- *rpm*, on **Fedora (latest)**: `plain` and `auto` as for the deb, and removal keeps the configuration and the authority;
- *AppImage*, on **Debian 13 and Ubuntu 24.04**, as an ordinary user, with no FUSE: the program and the tool run, the quick setup keeps everything in the home directory, the service listens on the loopback and a client seals and opens a text.

Found by these runs and fixed: a configuration written by root was not readable by the service; `hsmgate check` run by root refused a key file owned by the service; `nfpm` does not expand variables in the paths of files; `appimagetool` needs `file(1)`; the test of the rpm needed `runuser`, and rpm prefixes what a scriptlet prints with `>>> `.

**Run on the files of the release v0.9.1 (2026-11-15):** the tests of the deb (`plain`, `auto`, Debian 13) and the rpm (`plain`, `auto`, Fedora latest) passed on the downloaded files, and the AppImage test passed on Debian 13 and Ubuntu 24.04 with the copy described above (the machine that ran it has AppImageLauncher). The packaging step of the release workflow ran for the first time on the tag v0.9.1; the tag v0.9.0 stopped at it (the downloaded programs had lost their execute bit) and was never released.

**A real card:** the binary of 0.9.1 was run on 2026-11-15 on a development host with a SmartCard-HSM (`hsmgate check` on its configuration, then a second instance on a loopback port: a text sealed and opened with the key on the card, and a context outside the policy refused). Not through a package, and not by the setup tool.

**Run on the files of the release v0.9.2 (2026-11-16), on machines with systemd** (the files were downloaded from the release and verified first, [verifying-releases.md](verifying-releases.md)):

- *deb, a development host (Debian 13) with a SmartCard-HSM*: the package 0.9.2 was installed over 0.9.1 with `apt install`, the hand-made unit and the program in `/usr/local/bin` of the earlier installation were taken away first, and `systemctl enable --now hsmgate` started the unit of the package (`/usr/lib/systemd/system/hsmgate.service`, the program `/usr/bin/hsmgate`). The card and the key file were `ready` (the PIN file was used), `hsmgate check` run as the service user said `configuration ok`, `systemctl reload` and `restart` worked, and a text was sealed and opened with a key on the card and with a key in a file (a context outside the policy was refused and is in the audit file). `dpkg -V` reported no change. Not by the setup tool: the configuration was the one that machine already had;
- *rpm, AlmaLinux 10 (an LXC container with systemd, no SELinux)*: `dnf install`, the unit stays off without a configuration (the start condition), `hsmgate-setup -auto` made the configuration and started the service, a client sealed and opened a text with the commands the setup printed, `reload` and `restart` worked, `rpm -V` was clean, and `dnf remove` kept the configuration;
- *rpm, AlmaLinux 10.2 (a virtual machine) with SELinux in the **enforcing** mode*: the same steps passed and `/var/log/audit/audit.log` held no `avc: denied` line. **The process runs in the domain `unconfined_service_t`** (the program is `bin_t` and the package has no SELinux policy), so SELinux does not confine it: "no denial" says that, not that a policy was tested. `/etc/hsmgate` is `etc_t` and `/var/log/hsmgate` is `var_log_t`;
**Run on 2026-11-19 on the files of the releases v0.9.1 and v0.9.2 (downloaded from the releases):**

- *rpm, AlmaLinux 10 (an LXC container, no SELinux), an upgrade from an older rpm*: `dnf install` of 0.9.1, `hsmgate-setup -auto` and the service started, a text sealed; then `dnf upgrade` to 0.9.2. The upgrade said that the running service still has the old program, left `/etc/hsmgate` byte for byte as it was (`sha256sum` of every file), `rpm -V` was clean, the service kept running and opened the old text, and after `systemctl restart` it opened it again. After a **reboot of the container** the enabled unit started by itself and opened the text;
- *rpm, AlmaLinux 10.2 (a KVM machine) with SELinux **enforcing**, 0.9.2 installed from nothing*: the setup, the start, a seal and open, `reload` and `restart` worked and `ausearch -m avc,user_avc,selinux_err` had no match. The process was in `unconfined_service_t` again, so this is "no denial", not a tested policy. **Two things that `rpm -V` showed, and that are fixed in the source (not yet in a release):** `hsmgate-setup -auto` gave `/etc/hsmgate` to the service account (the package makes it `root:hsmgate`, and the service must not own the directory of its configuration), and the unit had no `LogsDirectoryMode`, so systemd made `/var/log/hsmgate` 0755 at the first start (the package says 0750). With both fixed, `rpm -V` was clean after the setup and after the restart on that machine.

**Run on the files of the release v0.9.3 (2026-11-19, downloaded from the release and verified first):**

- *rpm, AlmaLinux 10.2 (a KVM machine) with SELinux enforcing, from nothing*: the setup, the start, a seal and open, a restart; `rpm -V` was clean after the setup and after the restart (with no drop-in: the unit of the package alone), the directories were `root:hsmgate 0750` and `hsmgate:hsmgate 0750`, the process was in `unconfined_service_t`, and `ausearch` found no denial;
- *rpm, AlmaLinux 10 (an LXC container), from 0.9.2 to 0.9.3 after a setup made by 0.9.2*: `rpm -V` showed the two faults of 0.9.2 before the upgrade, and was clean right after `dnf upgrade` (the package put the owner and the mode right) and after the restart; the text sealed before the upgrade opened after it.

- *rpm, Rocky Linux 9 (a container, glibc 2.34)*: the package installs and `hsmgate version` and `hsmgate-setup --version` print `v0.9.2`. The service was not started there. The highest glibc symbol that `hsmgate-linux-amd64` asks for is `GLIBC_2.34` (`objdump -T`), the tool needs none.

**Not run:** a package with a real card through the setup tool (the card test above used a configuration made earlier), the reboot of a machine with SELinux, the rpm on Rocky, Alma or RHEL with a card, a SELinux policy for the service (there is none), and arm64.
