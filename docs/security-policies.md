# Security policies of the project

The rules the project holds itself to; the automatic parts are in [`.github/workflows/`](../.github/workflows/).

## Findings in dependencies and licenses (software composition analysis)

Tools: `govulncheck` (CI, and in the release), Dependabot alerts and security updates, Dependency Review on every pull request, Trivy on the image (weekly and on every push), the software bill of materials of every release.

Threshold for remediation of a finding about a vulnerability:

| Severity (CVSS) | A fix exists | No fix exists |
|---|---|---|
| Critical, High | fixed before the next release, and at once if the vulnerable code is reachable | the finding is recorded with the reason it is not exploitable (reachability analysis: `govulncheck` says whether the code is called); a mitigation is applied if it is reachable |
| Medium | within 30 days | recorded |
| Low | at the next routine update | none |

Licenses: dependencies must be under permissive licenses (MIT, BSD, Apache-2.0, ISC, MPL-2.0); Dependency Review accepts only an allowed list of such licenses (MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0, 0BSD, Unlicense, CC0-1.0, Python-2.0, PSF-2.0, BlueOak-1.0.0) and refuses the rest, in particular copyleft (GPL, AGPL).

**Before a release**: the CI of the tagged commit must be green, which includes `govulncheck` of the sources and of the program inside the image; a release is not made while a Critical or High finding with a fix is open. A finding that is accepted instead of fixed is written into the changelog or the audit response with the reason.

**Automatic gate**: Dependency Review runs on every pull request and fails it on a known vulnerability of High or Critical severity or on a denied license; `govulncheck` fails the CI. The malicious-package alerts of Dependabot are on.

## Vulnerabilities that do not affect the project (VEX)

A finding of a scanner in a component the project ships (a Go module, the Go standard library, a package of the image) is either fixed or **accounted for** in the VEX document [`vex/hsmgate.openvex.json`](../vex/hsmgate.openvex.json) (OpenVEX): for each such vulnerability, the products (releases and images) and a status: `not_affected` with a justification and an impact statement saying why the vulnerable code cannot be reached (for example, the library file is present but nothing loads it), `affected` with the action to take, `fixed`, or `under_investigation`. The document is reviewed with every release and whenever the scanners (`govulncheck`, Trivy, Dependabot, OSV) report something new; it is attached to the release, signed like the other assets ([verifying-releases.md](verifying-releases.md)). Today the findings of the Go modules are none (`osv-scanner` over all manifests, `govulncheck`), and the VEX covers the image: the standard library of one released image and the OpenSSL library of its base.

## Findings of static analysis (SAST)

Tools: CodeQL, `staticcheck`, `gosec`, `go vet` on every push and pull request.

Threshold: a finding of any severity is fixed before the change is merged, or suppressed in the code with the reason next to it (`// #nosec Gxxx -- reason`; a `nolint`-style comment names the rule and says why it does not apply). The CI fails on a finding. A finding that appears in CodeQL after the merge is fixed within 14 days for High and Critical, and 30 days for the rest.

## Secrets and credentials

- No secret is in the repository (`.gitleaks.toml`, GitHub secret scanning and push protection).
- The service reads the PIN of a token, signing secrets and client secrets from files with strict owner and mode (checked at start), never from the configuration, the environment or the command line; they are not logged.
- The CI uses no long-lived secret: the release uses the short-lived `GITHUB_TOKEN` of the run and the identity of the workflow for signing. A new secret in the CI needs a reason in the pull request and is a repository secret limited to the job that needs it.
- Rotation: a signing secret or client secret is replaced when the person who knew it leaves, when it may have been seen, and at least once a year; the old one is removed from the configuration and the service reloaded (effective at the next request). The PIN of a token is changed when an operator leaves ([operations.md](operations.md)).
- A secret that leaked is treated as compromised: replaced first, then the audit log is read for its use.

## Support of releases

See "What is supported" in [../SECURITY.md](../SECURITY.md).
