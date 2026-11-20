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

Number keys `1`–`8` or the arrows choose a section on the left; `Tab` moves into the page and between its buttons, `Esc` goes back, `F10` or `Ctrl-C` quits (it asks first when changes are not saved). Every change is made in the **document** and written only on **Review and save**; the header shows `(unsaved)` until then.

| Section | You can | Changes the file | Needs |
|---|---|---|---|
| Overview | see whether the configuration is good, the state of the service and of every token; start, stop, restart, reload (systemd, root); the quick setup | no | reload or restart for the service to see a saved change |
| Tokens | add a soft token (keys in files) or a card (PKCS#11 module, token label or serial, PIN file); remove one nothing uses; **unlock** a card (the PIN is typed masked, goes over the admin socket, is kept nowhere) | yes | a restart for a new token |
| Card | the tree of a **SmartCard-HSM** as a card manager shows it (the card and its device id, the User PIN and SO PIN with the **tries left**, the key domains: a **DKEK** with its key check value (KCV), a DKEK still being set up with the shares that are missing, or an **XKEK**, the keys in each: number, type, CKA_ID, what it may be used for, and whether the configuration names it), with a line on the right that says what the selected line means. With more than one card in readers the page asks which one (**Reader** shows the menu again). **Enter on a line (or Actions) lists what can be done with it**: change the User PIN or the SO PIN, unblock the User PIN with the SO PIN, make a DKEK share file (the **strong** format by default, or the **compatible** one that the vendor's card managers read), create a key domain, import a share, delete the DKEK or a key domain, export a key to a file (wrap, for a backup; only a key that allows `wrap`), import a key from a file (unwrap), delete a key, **generate a key** (EC P-256 or RSA, with a label and what it may be used for), and the steps of an **XKEK** group: export the device ID of the card, sign a key domain membership with a key on the card (the group signer), create an XKEK key domain from a membership file. Reading changes nothing and sends no PIN. **Every action that changes the card asks for the PIN in a masked field** (it goes down a pipe to `opensc-explorer`, never into a command line, and is overwritten after use), refuses to send a PIN when only one try is left, and asks for a word to type for what cannot be undone. A confirmation comes first when the running service holds a card open | the card (and the files it writes: share and key files, mode 0600, never over a file that is there) | `opensc-tool` and `opensc-explorer` (the package opensc), `pcscd` and a reader |
| Keys | **create** a key (a soft token: the key file is made, mode 0400, owned by the service; a card: the CKA_ID of a key pair that is there), **rotate** it (a new version; the old ones still open), **delete** it | yes | a reload |
| Clients | add a client and make its certificate (`hsmgate ca client`), give or take away rights on a key (operations, rate, contexts), remove a client | yes | a reload |
| Settings and faces | listen, admin socket, audit file, rotation, stdout, limits, metrics, the KMS-JSON, gRPC and REST faces | yes | a restart for the ones marked (restart) |
| Audit log | the last decisions from the audit file: all, problems, ok | no | an audit file |
| Review and save | the difference to the file on disk, whether the service would accept it, **Save**, **Save and reload**, discard | the write | |

**Deleting a key** asks you to type its name, says that everything sealed under it cannot be opened afterwards, and removes its grants from the clients. The key files that nothing else uses are then offered for removal in a second, separate question: overwritten with zeros and deleted, which on a flash or a journalling file system is the best the program can do and not a guarantee. A backup of the key file is the only way back.

**What it does not do:** it does not make keys on a card (the page can make a key on the card: Card page, EC, RSA and AES; for the association of XKEK domains, exchange keys and the derivation of an XKEK use the vendor's card manager), it does not revoke a certificate (there is no revocation list: remove the client), and it does not seal the key of the authority to a token (use `hsmgate ca init -mode sealed|token` by hand).

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
- the card path of the quick setup on the **real card** (SmartCard-HSM `cinim`, on the development host 192.168.100.77 with the service running, 2026-11-19): `hsmgate-setup -auto -mode card` and the wizard on the screen (pseudo-terminal, 100×30: every page, the review, Install) each wrote a configuration in a directory of their own; `hsmgate check` read the fingerprint of the key pair, `hsmgate serve` on the new configuration opened the card with the PIN from the file, and a client sealed and opened a text with it (audit: `encrypt` and `decrypt`, `ok`). The service of the host kept answering. Found: as an ordinary user over SSH pcscd shows no reader (`No smart card readers found`), so the card path needs root there; a PIN file owned by another user is refused (right: the card stays locked); the review of the wizard says `enable and start the service` by default, which is why the box has to be cleared on a host that already has the unit.
- the **Card** layer on the **real card** again (2026-11-19, a test card whose data is backed up): an RSA-2048 key made, wrapped, unwrapped as a second key, seen in the tree and deleted (this found the `6700` that an RSA key got from a short Le: fixed); a key domain of **two shares** (the key check value after both is that of their XOR); the User PIN changed to another and back (this found that the card refuses a new PIN of another length than the current one: the page says so before it asks the card); the SO PIN changed and back, and the User PIN set with the SO PIN (this found that the SO PIN is 8 bytes that a person may write as 16 hexadecimal digits, which the page now takes). The card was read again after each run: 3 tries of the User PIN, the same objects.
- the generation of **AES** keys on the **real card** (2026-11-19): AES-256 (CBC and wrap) and AES-128 (CMAC, named by the check value the card derives) through the layer, both in the tree, the first wrapped and unwrapped, then deleted; the form driven in the real program in a pseudo-terminal (AES 256, made, seen, deleted). Not run: AES-192, what a key is then used for (no module on Linux uses it: [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)).
- a package installed with `apt` at a terminal starts the wizard by itself and its keys were pressed to the end ([installing-packages.md](installing-packages.md)).

Run on 2026-11-18, the **Card** page, reading: the screens are driven with a card made of bytes (`tui/internal/card/cardtest`; the tree, the explanation of each line, the match of a key with the configuration, the menu of the readers, no reader, no `opensc-tool`, no card), under the race detector; the reading is also run for real on a **SmartCard-HSM 4.1 (JCOP 4)**: the tree it printed is the one that the vendor's card manager (Smart Card Shell) shows for the same card, line for line (`HSMGATE_REAL_CARD=1 go test ./tui/internal/card -run RealCard -v`).

Run on 2026-11-18, the **Card** page, **changing the card**: the commands are the card's own, sent through `opensc-explorer` (the layer `tui/internal/card`, tests on a simulated card that answers as the real one did: extended length, `6884` for a chained command, `6982` before the login, the end of a login at a new selection; the key derivation of the compatible share file is checked against `openssl enc -md md5 -P`, and the strong format refuses a change of any byte). On the **real card**, in the machine that has the reader (a virtual machine with the reader passed through, the User PIN read by the test from the file the service uses, never printed; the tests stop when only one try is left): a key domain on a free number made with a label, a share imported, the key check value of the card equal to the SHA-256 of the share, then the DKEK and the domain deleted (`TestRealDomainAndShare`); a key wrapped (a blob of 365 bytes), the file written and read back, the key brought back as another key number with another label and id in the same key domain and then deleted (`TestRealWrapAndUnwrap`); and the **whole page** driven in a pseudo-terminal against the real card: create a key domain with a label, make a share file with a password (once in the compatible and once in the strong format), import it, delete the DKEK, delete the domain, the card as it was (the User PIN with all its tries). Run on 2026-11-19, **keys and XKEK** on the real card (the layer, `TestRealGenerateKey`, `TestRealXKEKDomain`, `TestRealXKEKFiles`, and the page in a terminal): an EC P-256 key made in a key domain with the specification of the vendor's card manager (the card answered with a request of 489 bytes, the page wrote the description and kept the request in the file `CEnn`), read back in the tree with its label, type, domain, id and algorithms, and deleted; a group signer key made, the device certificates read from the card, a membership signed with the key and written as the file of the card manager (1044 bytes), read back, and an **XKEK key domain made from what the file held**: the card said it is an XKEK domain and gave its identifier; the domain and the key were deleted, the card as it was. The page drove the generation and the deletion of a key against the real card. A group of one card (the card is its own member) is what one card can show. Run on 2026-11-20 on the real card (domain 0 with the key `cinim`, whose wrapped file of 2026-10-19 and share file were at hand and were checked first: the file opened under the share on an empty domain 3 as another key number, with the same id, and was deleted): **our share file in the compatible format was imported by the vendor's `sc-hsm-tool --import-dkek-share` into the domain 0**, which showed the key check value that our code computed (`C16F3E44AE5734CC`), so the format is read by the vendor's tool. To do it the DKEK of the domain 0 was deleted, and the card then **refused every new share and every new creation (`6985`)**, so the way back was: delete the key, delete the domain, make it again, import the original share (check value `3795813EFB1753D6` again), import the key from its file (key number 1, same id `5ded83a1…`); the service was started again and listens. The card is as it was (3 User PIN tries, 15 SO PIN tries, the same keys, the same domains), the key `cinim` was out of the card for about two minutes. **The page's warning for "Delete the DKEK" said that the same shares could be loaded again; that was wrong and is changed.** Not run: the key `cosign` of domain 2 (its share's password was not at hand).

What the test of the layer does: `HSMGATE_REAL_CARD=1 HSMGATE_REAL_CARD_WRITE=1 HSMGATE_REAL_PIN_FILE=/path/to/pin go test -c ./tui/internal/card` and run the program where the reader is. The facts about the card that this showed are in [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md).

**Not run:** on the **Card** page XKEK with **two cards** (a membership made for another card, the exchange of keys between the cards, the association of two XKEK domains, the exchange key and the derivation of an XKEK: the page does not do these), a key of **RSA-4096** wrapped and unwrapped (longer blobs), the unwrap on a **second card** (the key came back into the same card), a compatible share file imported by `sc-hsm-tool` (it can only import into key domain 0, which is complete and holds the keys that matter; the files of Smart Card Shell and of `sc-hsm-tool` were opened here, and ours by Smart Card Shell: [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)), the generation of keys, XKEK domains (made, derived, associated: the page does not do them), initializing the card, the page on a card with more than 128 objects (one answer of the card is read, the rest is not), on a card other than that SmartCard-HSM 4.1, with two **real** readers (the menu is tested with readers made of bytes), and **while the running service holds the card** (the page asks first, because a second program that selects the application of the card may end the service's login; whether it does was not tested), an **XKEK** key domain on a real card (it is read and worded as the vendor's card manager words it, but the page was tried only on a card made of bytes, and the card used had none), and from an SSH session (on the development host `opensc-tool -l` over SSH as root showed no reader while the service there used the card: pcscd may refuse a program that is not on the console, which the page says when it finds no reader); the card path on a **real** card or HSM through the setup (SoftHSM2 only), the Tokens and Keys screens with a card, the unlock from the screen against a real card, the start of the unit by the wizard on a machine with systemd, Save and reload against a running service from the screen, the settings page, the audit page on a large file, a screen reader or a terminal other than xterm-like ones.
