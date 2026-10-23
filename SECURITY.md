# Security policy

hsmgate stands in front of a key token, so a report of a weakness is welcome and is read first.

## Reporting

- Use GitHub's private vulnerability reporting for this repository (Security → Report a vulnerability), or write to the maintainer at the address on the commits (a noreply address is used there; ask for a private channel in a first message that holds no details).
- Do not put details of an unfixed problem into a public issue.
- Say what you saw, on which commit, and how to see it again; a failing test is the best report.

You will get an answer within a few days. A confirmed problem is fixed and tested first, then described in the changelog and in a note under `docs/`; the people who reported it are named there if they wish.

## What is supported

- **Scope**: the latest release (all fixes of security problems are made there) and the head of `main`. An earlier release does not get a fix: update to the latest.
- **Duration**: a release is supported until the next release is made; in practice the previous minor release (for example 0.3.x when 0.4.0 is out) is supported for 30 days after the new one, for fixes of High and Critical problems only. The project is young (first released in October 2026) and has no long-term-support line.
- **End of support**: when a release is no longer supported it is said in the release notes of the release that replaces it. A release that is more than one minor release behind, or older than 30 days after its successor, receives no security updates.
- How a release is verified: [docs/verifying-releases.md](docs/verifying-releases.md). The policies for dependencies, analysis and secrets: [docs/security-policies.md](docs/security-policies.md). How the project is run: [GOVERNANCE.md](GOVERNANCE.md).

The threat model is in [docs/threat-model.md](docs/threat-model.md) and the audits and responses are in `docs/security-audit-*` and `docs/audit-response-*`.

## What helps a reviewer

- `docs/threat-model.md`, `docs/specs/` (the formats and the faces), `docs/operations.md`.
- Tests are the specification: `go test -race ./...`; fuzz targets run with `go test -fuzz`; the black-box tests with the vendors' SDKs are in `test/`.
- Scanners that the project runs: `govulncheck`, `staticcheck`, `gosec`, `gitleaks`, Trivy on the image.
