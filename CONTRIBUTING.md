# Contributing

- **Bugs and ideas**: open an issue. **Security problems**: not in an issue; see [SECURITY.md](SECURITY.md).
- **Build and test**: `go build ./...`, `go vet ./...`, `go test -race ./...`. The black-box tests with the official client libraries are modules of their own: `cd test/kmsjson-sdk && go test ./...` (also `kmsgrpc-sdk`, `kmsrest-sdk`).
- **Style**: `gofmt`; `staticcheck` and `gosec` run in CI. Comments say why, not what. Names of cloud services appear only where a wire format needs them; our identifiers are neutral ([docs/specs/README.md](docs/specs/README.md)).
- **Tests**: a change of behaviour comes with a test that fails without it; parsers of input come with a fuzz test.
- **Cryptography**: no new primitive of our own; use the standard library, and say in the change which approved algorithm it is ([docs/compliance.md](docs/compliance.md)).
- **Commits**: a short subject saying what changed and why; the change log (`CHANGELOG.md`) is kept for user-visible changes.
- **License**: by contributing you agree that your work is under the MIT license of the project.

## When and how the tests run

- **By you, before a pull request**: `go vet ./...` and `go test -race ./...`; the black-box tests with `cd test/<module> && go test ./...`; the fuzz targets with `go test -run '^$' -fuzz '^FuzzName$' -fuzztime 60s ./package`.
- **Automatically**: on every push to `main` and every pull request, `.github/workflows/ci.yml` runs gofmt, `go vet`, `go test -race`, `govulncheck`, `staticcheck`, `gosec`, the PKCS#11 backend against SoftHSM2, the black-box tests with the official client libraries and with boto3, the build and the image build; `fuzz.yml` runs the fuzz targets weekly; CodeQL, Trivy and Scorecard run on their own schedules; Dependency Review runs on pull requests. A release (a tag `v*`) runs `ci.yml` again before it publishes anything.
- **A change of behaviour** (a fix, a feature, a change of a format) adds or updates a test in the automatic suite; a pull request without one is asked to add it.
