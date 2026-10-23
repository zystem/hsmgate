# Security policy

hsmgate stands in front of a key token, so a report of a weakness is welcome and is read first.

## Reporting

- Use GitHub's private vulnerability reporting for this repository (Security → Report a vulnerability), or write to the maintainer at the address on the commits (a noreply address is used there; ask for a private channel in a first message that holds no details).
- Do not put details of an unfixed problem into a public issue.
- Say what you saw, on which commit, and how to see it again; a failing test is the best report.

## Coordinated disclosure, and the timeframe

- **Acknowledgement** within 7 days of a report; an assessment (confirmed, not reproducible, not a vulnerability) within 14 days.
- **Fix**: a confirmed problem is fixed and tested first; for High and Critical severity the target is a release within 30 days, for the rest the next release. The reporter is told when the fix is ready.
- **Disclosure**: after the fix is released, or after 90 days from the report if no fix is possible, whichever is first (earlier by agreement). The problem is then described in the changelog, in a GitHub security advisory and in a note under `docs/` (see `docs/audit-response-*`), with the people who reported it named if they wish. The data about found vulnerabilities is public there.
- **Contact**: the private vulnerability reporting of this repository (above) is the security contact; there is no other channel to a person, to keep reports out of public places.

## What is supported

- **Scope**: the latest release (all fixes of security problems are made there) and the head of `main`. An earlier release does not get a fix: update to the latest.
- **Duration**: a release is supported until the next release is made; in practice the previous minor release (for example 0.3.x when 0.4.0 is out) is supported for 30 days after the new one, for fixes of High and Critical problems only. The project is young (first released in October 2026) and has no long-term-support line.
- **End of support**: when a release is no longer supported it is said in the release notes of the release that replaces it. A release that is more than one minor release behind, or older than 30 days after its successor, receives no security updates.
- How a release is verified: [docs/verifying-releases.md](docs/verifying-releases.md). The policies for dependencies, analysis and secrets: [docs/security-policies.md](docs/security-policies.md). How the project is run: [GOVERNANCE.md](GOVERNANCE.md).

The threat model is in [docs/threat-model.md](docs/threat-model.md) and the audits and responses are in `docs/security-audit-*` and `docs/audit-response-*`.

## Vulnerabilities in components that do not affect the project

They are published as a VEX document (OpenVEX): [vex/hsmgate.openvex.json](vex/hsmgate.openvex.json), also attached to each release; see [docs/security-policies.md](docs/security-policies.md).

## What helps a reviewer

- `docs/threat-model.md`, `docs/specs/` (the formats and the faces), `docs/operations.md`.
- Tests are the specification: `go test -race ./...`; fuzz targets run with `go test -fuzz`; the black-box tests with the vendors' SDKs are in `test/`.
- Scanners that the project runs: `govulncheck`, `staticcheck`, `gosec`, `gitleaks`, Trivy on the image.
