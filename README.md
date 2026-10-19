# hsmgate

A small network service that holds no key material of its own and lets authenticated clients seal and open short secrets
(data keys, the root key of another vault) under a master key that lives on a PKCS#11 token (HSM, smart card, software token for tests).
A door in front of the token: who may ask, for which key, with which context, how often, and what is written down.

Status: **P1 (specification)**. The plan is [docs/project-plan.md](docs/project-plan.md), the threat model is [docs/threat-model.md](docs/threat-model.md).
What exists: the `ecies1` sealed format in Go ([internal/scheme/ecies](internal/scheme/ecies)), checked against test vectors made by the Nim implementation
in CiNim's `kekd` ([testdata/vectors/ecies1.json](testdata/vectors/ecies1.json), a test key: never use it).

Decisions (P0): name `hsmgate`, language Go, licence MIT. First client: CiNim, through the Transit face ([docs/transit-face.md](docs/transit-face.md)); no own protocol. Later: Kubernetes KMS v2, AWS KMS JSON ([alternative](docs/awskms-face.md)).

```
go test ./...
```
