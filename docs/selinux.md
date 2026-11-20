# SELinux: the service in its own domain

**A how-to** for the rpm on AlmaLinux, Rocky and RHEL (SELinux in the enforcing mode). Without this page's module the service works: it runs as `unconfined_service_t`, which SELinux does not restrict (checked: no denial, a seal and open with a card, also after a reboot). With the module it runs as `hsmgate_t` and may only do what the module lists. The module is optional.

## Install

The rpm puts the sources of the module and a script in `/usr/share/hsmgate/selinux/`. Building needs `selinux-policy-devel`.

```bash
sudo dnf install selinux-policy-devel
sudo /usr/share/hsmgate/selinux/install.sh
sudo systemctl restart hsmgate      # a card without a pin_file is locked after a restart until: hsmgate unlock
ps -eZ | grep -w hsmgate
```

The script builds `hsmgate.pp`, loads it with `semodule -i` and labels the files (`restorecon`). The last command prints `system_u:system_r:hsmgate_t:s0 … hsmgate`. To take the module away: `sudo /usr/share/hsmgate/selinux/install.sh remove`, then restart the service (until the restart the process shows an `unlabeled_t` context: its domain is gone).

## What the module allows

| The service may | Types |
|---|---|
| read `/etc/hsmgate` (configuration, PIN file, key files, certificates); never write it | `hsmgate_conf_t` |
| write `/var/log/hsmgate` (the audit file and its rotation) | `hsmgate_log_t` |
| make its admin socket in `/run/hsmgate` | `hsmgate_var_run_t` |
| listen on a TCP port of the type `http_port_t` (**8443** is one) and connect to such ports (an OIDC provider) | `http_port_t` |
| talk to `pcscd` over its socket (a card) | `pcscd_var_run_t`, `pcscd_t` |
| load the PKCS#11 module, resolve names, read the system state that the Go runtime reads | the usual interfaces |

It may **not** read other users' files, write outside the two directories, or use ports of other types.

## What it does not cover

- **A port other than 8443** (the setting `listen`): label it, `sudo semanage port -a -t http_port_t -p tcp 9443`.
- **Key files or tokens outside `/etc/hsmgate`** (a SoftHSM token directory, keys in another place): the service gets a denial. Move them under `/etc/hsmgate`, or label the place `hsmgate_conf_t` (`semanage fcontext -a -t hsmgate_conf_t '/srv/keys(/.*)?'; restorecon -R /srv/keys`).
- **An audit file in another directory.** The default is `/var/log/hsmgate/audit.log`.
- **The setup tool and the command line** (`hsmgate-setup`, `hsmgate unlock`, `hsmgate encrypt`) are run by a person and are not confined.
- **Containers and Kubernetes**: they have their own labels; this module is for the rpm.

A denial shows as `type=AVC` in `/var/log/audit/audit.log` (`ausearch -m avc -ts recent`). Do not turn SELinux off for it: label the place, or tell us what the service needed.

## The card needs a polkit rule

`pcscd` asks polkit before it lets a program use the reader, and the default rule allows only a local active session. The service account `hsmgate` has none, so on a clean machine the token is "no matching token in the reader". The packages (since the release after 0.9.3) install `/usr/share/polkit-1/rules.d/50-hsmgate.rules`, which allows the account `hsmgate` and nobody else. With 0.9.3 or older, create that file by hand (the text is in `packaging/50-hsmgate.rules`).

## What was run

On 2026-11-20, AlmaLinux 10.2 (a KVM machine, SELinux **Enforcing**, 0.9.3 from the release rpm) with a SmartCard-HSM passed to the machine: `rpm -V` clean; `hsmgate-setup -auto -mode card` as root; **without the polkit rule the token was absent** (`pcscd: Process … (user: 995) is NOT authorized for action: access_pcsc`), with it a seal and open worked; after a reboot the service started with the card and sealed and opened with **no denial** as `unconfined_service_t`. Then the module: it was written by running the service in the permissive mode and reading the denials (the first one was the transition itself, which the hardening `NoNewPrivileges=yes` needs `init_nnp_daemon_domain` for; then the Go runtime's reads of `/proc/sys/net/core/somaxconn`, the sysfs size of a huge page and the root of the control groups), then in the **enforcing** mode: start, a seal and open with the card, `systemctl reload`, a restart, the audit file written, and again after a reboot: the process is `hsmgate_t`, `/run/hsmgate/admin.sock` is `hsmgate_var_run_t`, **no denial**. The script was run to remove and to load the module again.

**Not run:** a soft token (keys in files) under the module (the files are `hsmgate_conf_t` by the same rule, but it was not tried); an OIDC provider and the other faces' outbound connections; an upgrade of the rpm with the module loaded; Fedora, Rocky and RHEL (only AlmaLinux 10.2); `hsmgate unlock` from a confined administrator; `sepolicy` / `audit2why` review by someone who writes policy for a living. The module is `0.1.0`: treat it as a first version.
