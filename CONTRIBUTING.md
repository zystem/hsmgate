# Contributing

- **Bugs and ideas**: open an issue. **Security problems**: not in an issue; see [SECURITY.md](SECURITY.md).
- **Build and test**: `go build ./...`, `go vet ./...`, `go test -race ./...`. The black-box tests with the official client libraries are modules of their own: `cd test/kmsjson-sdk && go test ./...` (also `kmsgrpc-sdk`, `kmsrest-sdk`).
- **Style**: `gofmt`; `staticcheck` and `gosec` run in CI. Comments say why, not what. Names of cloud services appear only where a wire format needs them; our identifiers are neutral ([docs/specs/README.md](docs/specs/README.md)).
- **Tests**: a change of behaviour comes with a test that fails without it; parsers of input come with a fuzz test.
- **Cryptography**: no new primitive of our own; use the standard library, and say in the change which approved algorithm it is ([docs/compliance.md](docs/compliance.md)).
- **Commits**: a short subject saying what changed and why; the change log (`CHANGELOG.md`) is kept for user-visible changes.
- **License**: by contributing you agree that your work is under the MIT license of the project.
