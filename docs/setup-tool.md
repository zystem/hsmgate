# hsmgate-setup: the terminal tool

*A how-to and reference page.* `hsmgate-setup` is a menu-driven terminal program, in the manner of the installers of Debian and YaST, to look at and change the configuration of hsmgate (tokens, keys, clients, faces, audit) and to go from nothing to a running service with a **quick setup**. It works over SSH and on a console of 80×24, with the keyboard or the mouse. It is a program of its own, installed next to `hsmgate` by the packages and the AppImage; `hsmgate setup` starts it.

It edits `hsmgate.yaml`, the one source of truth, and writes it only after the loader of the service accepted the result ([why a file and not a database](why-yaml-not-sqlite.md)).

## Start it

| How | What happens |
|---|---|
| `sudo hsmgate-setup` (or `sudo hsmgate setup`) | the menus; with no configuration yet, the Overview page offers the quick setup |
| `sudo hsmgate-setup -first-run` | the quick setup if there is no configuration, the menus otherwise. A package runs this after a first installation when somebody is at a terminal |
| `sudo hsmgate-setup -auto` | the quick setup with the defaults and the flags below, **no screen**: for Ansible, a Dockerfile, cloud-init |
| `HSMGATE_SETUP_AUTO=1 apt install ./hsmgate.deb` | the same, run by the package ([installing-packages.md](installing-packages.md)) |
| `./hsmgate-X.Y.Z-x86_64.AppImage` | the quick setup on a first run, in the home of an ordinary user ([installing-packages.md](installing-packages.md)) |

As root it uses the system layout (`/etc/hsmgate`, `/var/log/hsmgate`, `/run/hsmgate`, the account `hsmgate`); as an ordinary user everything is in the home directory and the service listens on the loopback only. Without a terminal it refuses to draw a screen and says to use `-auto`.

## The sections

Number keys `1`–`7` or the arrows choose a section on the left; `Tab` moves into the page and between its buttons, `Esc` goes back, `F10` or `Ctrl-C` quits (it asks first when changes are not saved). Every change is made in the **document** and written only on **Review and save**; the header shows `(unsaved)` until then.

| Section | You can | Changes the file | Needs |
|---|---|---|---|
| Overview | see whether the configuration is good, the state of the service and of every token; start, stop, restart, reload (systemd, root); the quick setup | no | reload or restart for the service to see a saved change |
| Tokens | add a soft token (keys in files) or a card (PKCS#11 module, token label or serial, PIN file); remove one nothing uses; **unlock** a card (the PIN is typed masked, goes over the admin socket, is kept nowhere) | yes | a restart for a new token |
| Keys | **create** a key (a soft token: the key file is made, mode 0400, owned by the service; a card: the CKA_ID of a key pair that is there), **rotate** it (a new version; the old ones still open), **delete** it | yes | a reload |
| Clients | add a client and make its certificate (`hsmgate ca client`), give or take away rights on a key (operations, rate, contexts), remove a client | yes | a reload |
| Settings and faces | listen, admin socket, audit file, rotation, stdout, limits, metrics, the KMS-JSON, gRPC and REST faces | yes | a restart for the ones marked (restart) |
| Audit log | the last decisions from the audit file: all, problems, ok | no | an audit file |
| Review and save | the difference to the file on disk, whether the service would accept it, **Save**, **Save and reload**, discard | the write | |

**Deleting a key** asks you to type its name, says that everything sealed under it cannot be opened afterwards, and removes its grants from the clients. The key files that nothing else uses are then offered for removal in a second, separate question: overwritten with zeros and deleted, which on a flash or a journalling file system is the best the program can do and not a guarantee. A backup of the key file is the only way back.

**What it does not do:** it does not make keys on a card (that is `pkcs11-tool`; the tool uses a key pair that is there), it does not revoke a certificate (there is no revocation list: remove the client), and it does not seal the key of the authority to a token (use `hsmgate ca init -mode sealed|token` by hand).

## The quick setup

Six pages: where the keys are (files or a card), the place (directory, listen address, more names for the certificate, the service account, enable the unit), the card (module, token, key pair, PIN file; only for a card), the first key and client, the audit, a review that lists what will be done. Then:

1. writes `hsmgate.yaml` (mode 0640, root, group of the service);
2. makes the key file (a soft token; `soft-KEY-1.hex`, mode 0400, owned by the service account);
3. runs `hsmgate ca setup`: the authority in `ca/` (mode 0700), the certificate of the service (its names are guessed from the listen address and the interfaces) and the certificate of the first client in `clients/`;
4. runs `hsmgate check` as the service account (a card is not opened here);
5. enables and starts the unit, when there is systemd and it is root;
6. prints the commands that work now (`export HSMGATE_ADDR=… HSMGATE_CERT=…`, `hsmgate encrypt`, `hsmgate decrypt`) and the client's files.

It **does not write over a configuration**: with `hsmgate.yaml` there, it stops and says so. If it fails half way it says which files exist; remove them and start again.

Back up `ca/` and the key files: they cannot be made again, and what was sealed under them cannot be opened without them.

## Flags

<!-- flags:start -->
```text
Usage of hsmgate-setup:
  -audit-file string
    	-auto: the audit file (default: /var/log/hsmgate/audit.log as root, in ~/.local/state/hsmgate otherwise; "none": the output of the service)
  -audit-max-mb int
    	-auto: rotate the audit file at this size in MB (0: never) (default 25)
  -auto
    	the quick setup with no screen: the defaults and these flags (also HSMGATE_SETUP_AUTO=1)
  -bin string
    	the hsmgate program (default: next to this tool, or on the PATH)
  -card-key-id string
    	-auto, card: the CKA_ID of the key pair (hex)
  -client string
    	-auto: name of the first client (default "app")
  -config string
    	the configuration file (default: /etc/hsmgate/hsmgate.yaml as root, ~/.config/hsmgate/hsmgate.yaml otherwise)
  -context-prefixes string
    	-auto: make the key a context key with these prefixes (comma separated); empty: a fixed key
  -enable
    	-auto: enable and start the systemd unit (default: yes when this is root and there is systemd; -enable=false: no)
  -first-run
    	start with the quick setup when there is no configuration
  -key string
    	-auto: name of the first key (default "app")
  -listen string
    	-auto: address:port (default: 0.0.0.0:8443 as root, 127.0.0.1:8443 otherwise)
  -mode string
    	-auto: soft (keys in files) or card (default "soft")
  -module string
    	-auto, card: the PKCS#11 module (default: the OpenSC one, when it is found)
  -names string
    	-auto: more names or addresses for the certificate of the service, comma separated
  -pin-file string
    	-auto, card: the file with the PIN, mode 0400 (default: pin in the directory of the configuration)
  -socket string
    	the admin socket of the running service (default: the one in the configuration)
  -token-label string
    	-auto, card: the label of the token
  -unit string
    	the systemd unit of the service (default "hsmgate")
  -user string
    	-auto: the account the service runs as (default: hsmgate, when it exists and this is root)
  -version
    	print the version
```
<!-- flags:end -->

## What was run, and what was not

Run on 2026-11-14 (an Ubuntu 24.04 host, containers of Debian 13 and Ubuntu 24.04):

- the editing layer, the key actions and the quick setup have unit tests; the quick setup is also run for real: the service started on what it made seals and opens a text for the client it made;
- the screens: driven with a simulated screen of 80×24 (the sections, creating a key with the keyboard, the confirmation to delete one, the diff, the quit question), under the race detector;
- the wizard at a real terminal: the built program in a pseudo-terminal of 80×24, every page, then the service and a client;
- the card path of the quick setup on **SoftHSM2** (a software token that speaks PKCS#11) in a Debian 13 container: a key pair made with `pkcs11-tool`, `hsmgate-setup -auto -mode card`, the service as its own user with the PIN from a file, a client sealing and opening a text (no key file is made: the key stays on the "card");
- a package installed with `apt` at a terminal starts the wizard by itself and its keys were pressed to the end ([installing-packages.md](installing-packages.md)).

**Not run:** the card path on a **real** card or HSM (SoftHSM2 only), the Tokens and Keys screens with a card, the unlock from the screen against a real card, the start of the unit by the wizard on a machine with systemd, Save and reload against a running service from the screen, the settings page, the audit page on a large file, a screen reader or a terminal other than xterm-like ones.
