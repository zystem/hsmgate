# Governance

hsmgate is a small project run by two maintainers. This file says how it is run, so that a contributor knows what to expect, a user knows what the controls are, and the project can go on if one of the two cannot.

## Members and roles

| Member | Role | Access to sensitive resources |
|---|---|---|
| `zystem` (the owner of the repository) | maintainer: decides, reviews and merges, makes releases, answers security reports, holds the settings of the repository (rulesets, security settings, Dependabot), the container package and the badge entry | admin of the repository, the settings, the container package; write access to the CI (the CI has no long-lived secrets: [docs/security-policies.md](docs/security-policies.md)) |
| `Juliesergienko` (collaborator since 2026-11) | second maintainer: reviews and merges pull requests, triages and closes issues, makes releases (a tag starts the release workflow) | write access to the repository (the most that a collaborator of a personal repository can have); editor of the badge entry |
| contributors | anyone who sends a pull request or an issue | none |

This is the complete list of members with access to sensitive resources; it is changed in this file when a permission is granted or removed.

## How the project is run

- **Decisions** are made by the maintainers, in the open: in issues and pull requests, with the reasons in the commit message or in `docs/`. When the two disagree, the owner decides.
- **Contributions** come as pull requests and follow [CONTRIBUTING.md](CONTRIBUTING.md).
- **Escalated permissions** (write access to the repository, the right to publish releases or packages, access to the settings of the repository) are given only to a person who has contributed accepted changes over time, whose identity is known to the owner, who uses two-factor authentication (GitHub requires it of anyone who contributes code), and who has been reviewed by the owner before the permission is granted. The owner reviews the list of collaborators when a release is made and removes those who are no longer active.
- **Releases** are made by the release workflow from a signed tag created by a maintainer ([docs/releasing.md](docs/releasing.md)); no person holds a signing key of the project (the signature of the files is keyless, bound to the workflow); the tag is signed with the SSH key of the maintainer who makes it, and the keys are listed in [docs/verifying-releases.md](docs/verifying-releases.md).
- **Review of changes**: every change to `main` is a pull request that the automatic gates check (tests, static analysis, dependency review, CodeQL, DCO: [docs/security-policies.md](docs/security-policies.md)). The maintainers review each other's changes by convention. An approval by a person other than the author is **not** enforced by the ruleset: the settings of a personal repository can be changed by its owner only, and a rule that demands another person's approval would stop the project if that person were away, so either maintainer can merge a change whose checks pass. The enforcement comes with an organisation that has two owners ([docs/roadmap.md](docs/roadmap.md)).
- **Security reports** go as in [SECURITY.md](SECURITY.md).

## If one maintainer cannot go on

The project must be able to create and close issues, accept changes and release a version within a week of the loss of either maintainer. What each one needs, and where it is:

| Task | What it needs | Who can do it |
|---|---|---|
| create and close issues, label and answer | write access | either |
| review and merge a pull request | write access; the checks pass (the ruleset on `main`) | either |
| make a release | write access to push a tag; the steps in [docs/releasing.md](docs/releasing.md); the workflow `release.yml` signs the files with its own identity and publishes the image with the token of the run | either; the tag is signed with the key of whoever makes it |
| update the dependencies | Dependabot opens the pull requests; merge them | either |
| change the settings of the repository, the rulesets, the security settings, the package, give or take access | admin | the owner only (a personal repository has no role between write and owner) |
| read private vulnerability reports | admin or security manager | the owner only; see [SECURITY.md](SECURITY.md) for what is done when the owner is away |

Nothing else is needed: the CI keeps no secret that a person could lose (the PIN of a card and the keys of a deployment are the operator's, not the project's), the domain names of the project are none, and the licence (MIT) lets anyone who has the repository carry on.

If the **owner** is the one who cannot go on, the second maintainer carries on with write access as above. Taking over the settings, the package and the badge entry needs the owner's account to be handed over or the repository to be transferred (Settings → Transfer ownership, which GitHub's succession rules for an account allow); the owner keeps the arrangement for that in a place the second maintainer can reach. Moving the project to an organisation with two owners removes this single point; it is on the [roadmap](docs/roadmap.md).
