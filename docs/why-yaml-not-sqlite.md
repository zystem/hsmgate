# Why the configuration stays a YAML file (and the setup tool edits it)

*An explanation page. Decided 2026-11-14, with the terminal tool [hsmgate-setup](setup-tool.md) in view.*

A menu-driven tool that creates and deletes keys, adds clients and changes settings raises the question whether the configuration should move from `hsmgate.yaml` to a database such as SQLite. A database is what most graphical and terminal administration tools sit on. For hsmgate the answer is **no**: the file stays the one source of truth, and the tool edits the file.

## What a database would give

- Changes in one transaction, so the tool cannot leave half a change.
- No text to parse and write back: the comments and the order of a hand-written file are not a problem.
- Queries ("which clients may use this key") without reading the whole file.

## Why it does not pay here

- **The file is the interface of everything around the service.** The Helm chart renders it into a ConfigMap, compose and Ansible copy it, `hsmgate check` runs against it in a pipeline before a deployment, a pull request shows a change to it, and a test (`internal/config`) keeps [configuration.md](configuration.md) equal to its fields. A database would need a second form for each of these, and the two would drift.
- **The policy must be readable and comparable.** Who may use which key is the security decision of the whole service. In a text file it is reviewed with a `diff`, signed in a commit and read by an auditor. In a binary database it needs a tool to read, and a way to show that nobody changed it behind the service's back.
- **Weight.** The service has five direct dependencies. SQLite is either a C library behind cgo (the FIPS image and the static builds then change) or a pure Go port with dozens of modules. The service keeps no state besides the files its configuration names (and the audit log); needing no database to run is a property worth keeping.
- **Reload is a whole-file swap.** SIGHUP reads a new file, checks all of it, and swaps the generation or changes nothing. With a live database and edits from several places the same guarantee needs snapshots and an "apply" step, which is the file again.
- **Secrets are not in the configuration anyway.** It holds paths and public names; the keys are in files of mode 0400 or on a card. A database would not make it safer, and it would add a file whose protection must be explained.

## What the tool does instead

`hsmgate-setup` reads `hsmgate.yaml` as a document tree, so **comments and the order are kept**, changes the tree, and before it writes:

1. parses the result with the loader of the service (`internal/config`, the same `Parse` and `Validate`), so a file the service would refuse is never written;
2. shows the difference, as a diff;
3. copies the old file to `hsmgate.yaml.bak-DATE` (the newest ten are kept);
4. writes a new file next to the old one, flushes it and renames it over the old one (a power cut leaves the old file or the new, never half), with the mode and the owner of the old file.

A reload (`systemctl reload hsmgate`) or a restart then applies it, as for a change made by hand; the tool says which of the two the change needs.

What does not belong in the configuration at all (notes about a key, the day it was made) can go in a small file of its own beside it if it is ever wanted; it would not be read by the service.

## What was run

The editing layer is tested with the example file of the repository (every comment survives), with the operations the screens use, with an invalid document (nothing is written), with the backup and the mode of the old file, and through a real service: the quick setup writes a configuration, the service started on it seals and opens a text. Run 2026-11-14.
