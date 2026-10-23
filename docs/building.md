# Building, testing and dependencies

## Build

Requirements: the Go toolchain of `go.mod` (1.26.10; the `go` command fetches it by itself), a C compiler (`gcc`) because the PKCS#11 binding (`github.com/miekg/pkcs11`) uses cgo, and for a real token a PKCS#11 module (OpenSC `opensc-pkcs11.so` for a SmartCard-HSM; SoftHSM2 for a software token).

```bash
git clone https://github.com/zystem/hsmgate && cd hsmgate
go build -o hsmgate ./cmd/hsmgate         # the program
go vet ./... && go test -race ./...        # the tests
```

The release binary is built as the release workflow builds it, a position-independent executable with full RELRO:

```bash
CGO_ENABLED=1 go build -buildmode=pie -trimpath -buildvcs=false \
  -ldflags "-s -w -linkmode=external -extldflags '-Wl,-z,relro,-z,now' -X main.version=dev" -o hsmgate ./cmd/hsmgate
```

The binary is dynamic (libc, and the PKCS#11 module loaded at run time), so it is built on the system it runs on, Debian 12 for the image. The image: `docker build -t hsmgate .` (the `Dockerfile` pins its base images by digest; `--build-arg GOFIPS140=v1.0.0` builds with the frozen Go cryptographic module, see [compliance.md](compliance.md)).

Further tests: the PKCS#11 backend against SoftHSM2 (`apt install softhsm2 opensc`, then `tools/softhsm-test.sh`); the black-box tests with the official client libraries, each a module of its own (`cd test/kmsjson-sdk && go test ./...`, also `kmsgrpc-sdk` and `kmsrest-sdk`), and with boto3 (`test/kmsjson-boto3`); the fuzz targets (`go test -run '^$' -fuzz '^FuzzUnwrap$' ./internal/scheme/ecies`). What runs when: [CONTRIBUTING.md](../CONTRIBUTING.md).

## How dependencies are chosen, obtained and tracked

- **Choice**: few, and from the standard library first: cryptography, TLS, HTTP/2 and JSON come from Go itself. A third-party module is added only when the standard library has nothing for the job, and it is named with the reason in the change. Today: `github.com/miekg/pkcs11` (the PKCS#11 binding), `google.golang.org/protobuf` (only its wire encoding, for the gRPC face), `gopkg.in/yaml.v3` (the configuration), `golang.org/x/term` (the PIN prompt), `golang.org/x/sys`.
- **Obtaining**: Go modules (`go.mod`, `go.sum` with checksums, verified through the Go checksum database); the build uses no network access beyond that and no vendored binaries. Tools of the CI are run by `go run module@version` with a fixed version; the actions of the workflows and the base images of the `Dockerfile` are pinned by commit and by digest.
- **Tracking**: Dependabot (`.github/dependabot.yml`) proposes updates each week for the Go modules, the actions, the images and the Python test requirements, and opens security updates at once; `govulncheck`, Dependency Review and Trivy check for vulnerabilities; every release carries a software bill of materials. The policy for findings is in [security-policies.md](security-policies.md). The test modules under `test/` hold the client libraries of the vendors whose APIs the faces imitate; they are not part of the program.
