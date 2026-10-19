# hsmgate

A small network service that holds no key material of its own and lets authenticated clients seal and open short secrets
(data keys, the root key of another vault) under a master key that lives on a PKCS#11 token (HSM, smart card, software token for tests).
A door in front of the token: who may ask, for which key, with which context, how often, and what is written down.

Status: **working service** (steps P0-P6 of the plan). Tried on: OpenBao (seal `transit`), `vault-kubernetes-kms`, the SmartCard-HSM, mTLS; see the "Verified" sections of [docs/transit-face.md](docs/transit-face.md). The plan is [docs/project-plan.md](docs/project-plan.md), the threat model is [docs/threat-model.md](docs/threat-model.md).
What exists: the `ecies1` sealed format in Go ([internal/scheme/ecies](internal/scheme/ecies)), checked against test vectors made by the Nim implementation
in CiNim's `kekd` ([testdata/vectors/ecies1.json](testdata/vectors/ecies1.json), a test key: never use it).

Decisions (P0): name `hsmgate`, language Go, licence MIT. First client: CiNim, through the Transit face ([docs/transit-face.md](docs/transit-face.md)); no own protocol. Later: Kubernetes KMS v2, AWS KMS JSON ([alternative](docs/awskms-face.md)).

```
go test ./...
```

## Quick start

```
go build -o hsmgate ./cmd/hsmgate
cp deploy/hsmgate.example.yaml hsmgate.yaml    # edit: certificates, token, clients
./hsmgate check -config hsmgate.yaml           # lists key versions, holders, fingerprints; needs no PIN
./hsmgate serve -config hsmgate.yaml &
./hsmgate unlock -config hsmgate.yaml -token card
```

Docs: [transit-face.md](docs/transit-face.md) (the API), [operations.md](docs/operations.md) (unlock, rotation, spare card, lost card), [threat-model.md](docs/threat-model.md),
[tokens/smartcard-hsm.md](docs/tokens/smartcard-hsm.md), [project-plan.md](docs/project-plan.md). Deployment: [deploy/](deploy/) (systemd unit; Docker: `Dockerfile` in the root and [deploy/docker/compose.yaml](deploy/docker/compose.yaml), see [Running in Docker](docs/operations.md)). One card means one machine or VM with the reader, not a scheduler.
