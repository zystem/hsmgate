[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15821/badge)](https://www.bestpractices.dev/projects/15821)

**hsmgate keeps the master key of your secrets on a smart card or HSM and lets your applications use it over the network, only as far as a policy allows.**

Your applications and vaults (OpenBao, Kubernetes, your own code) need a key to seal their secrets, and that key should not sit in a file next to the data it protects.
hsmgate is a small service in front of a PKCS#11 token (a SmartCard-HSM, any HSM with a PKCS#11 module, or a software token for tests). The key never leaves the token; clients send a short secret and get it back sealed, or sealed and get it opened.
It is a door, not a vault: **who** may ask (a client certificate), for **which key**, with **which context**, **how often**, and what is **written down** (an audit line for every call, a refusal too).

```
 your application / OpenBao /          mTLS: the certificate        ┌──────────────────────────────┐
 Kubernetes (etcd) / a script   ─────────────────────────────────▶ │ hsmgate: the policy, the rate, │ ───▶  token: card, HSM,
   "seal this" / "open this"     ◀─────────────────────────────────  │ the audit line                │      or a software key (tests)
                                  vault:v1:...  (the ciphertext)     └──────────────────────────────┘      (the private key stays there)
```

**Use it for**
- **Auto-unseal of OpenBao** (`seal "transit"`): the key of the vault stays behind hsmgate. [Step by step, also for another cluster](deploy/helm/hsmgate/README.md#openbao-auto-unseal).
- **Encryption of etcd in Kubernetes** through `vault-kubernetes-kms` ([the contract](docs/specs/kubernetes-kms-v2.md)) and **secrets in pods without Vault** ([guide](docs/guides/kubernetes-pod-secrets.md)).
- **The master key of an application**: seal its data keys with a key that only the card can open (CiNim does).
- Other clients of the AWS-KMS-, Google-Cloud-KMS- or Azure-style APIs that sign requests ([KMS-JSON, gRPC and REST faces](docs/specs/README.md)).

**Not for**: encrypting large data (it seals short secrets: a value is at most 8 KiB by default), a replacement for a key-management product with its own user interface, or a service with no machine to keep the token on (a card is one machine or VM with a reader; the Kubernetes chart uses a software token and is for tests and pilots).

## Try it in a minute (no hardware, nothing to prepare)

You need Go ([building.md](docs/building.md)). From a clone of this repository:

```bash
go run ./cmd/hsmgate dev
```

It starts a throw-away service with a software token, a CA of its own and a client certificate, and prints what to type in another terminal. First the three variables it names (`HSMGATE_ADDR`, `HSMGATE_CA`, `HSMGATE_CERT`, `HSMGATE_KEYFILE`, `HSMGATE_TRANSIT_KEY=demo`), then:

```console
$ echo 'my secret' | hsmgate encrypt > sealed.txt
sealed under version 1 of key "demo" with context ""
$ cat sealed.txt
vault:v1:ZWNpZXMy...
$ hsmgate decrypt < sealed.txt
my secret
$ echo x | hsmgate encrypt -transit-key demo-ctx -context demo/a > c.txt
sealed under version 1 of key "demo-ctx" with context "demo/a"
$ hsmgate decrypt -transit-key demo-ctx -context demo/b < c.txt
hsmgate decrypt: the ciphertext cannot be opened with key "demo-ctx" and context "demo/b": it was sealed with another key or another context, or it is damaged
```

(The ciphertext is longer than shown. A test runs these commands against `hsmgate dev` and fails when what they print is not what is shown here.)

What you just saw: the key never left the service; the ciphertext opens only with the key *and* the context it was sealed with; a client with no certificate cannot even connect, and the audit log (`audit.log` in the directory `dev` names) has a line for each call, the refused one too. Stop it with Ctrl-C: everything it made is deleted (`-dir DIR` keeps it). **Not for real keys**: the key is a file, and what you sealed cannot be opened again after the stop.

**Next:** [connect a client](docs/guides/clients.md) (`curl`, OpenBao, Kubernetes) · [install it for real](#install-for-real) · [what to do before it holds real keys](docs/production.md) · [questions people ask](docs/faq.md).

## Install for real

| You have | Use | Token | Start here |
|---|---|---|---|
| A machine (or VM) and a SmartCard-HSM or another PKCS#11 token | the binary from a [release](https://github.com/zystem/hsmgate/releases) (verify it: [verifying-releases.md](docs/verifying-releases.md)) and the systemd unit in [deploy/](deploy/) | the card | [operations.md](docs/operations.md), [smartcard-hsm.md](docs/tokens/smartcard-hsm.md) |
| Docker on that machine | the image `ghcr.io/zystem/hsmgate` ([compose.yaml](deploy/docker/compose.yaml)) | the card (a reader passed through) | [operations.md, "Running in Docker"](docs/operations.md) |
| Kubernetes, for tests, development or a pilot | the Helm chart `oci://ghcr.io/zystem/charts/hsmgate`: `helm install` makes its own certificates | software (a key in a Secret: whoever reads the Secret has the key) | [the chart](deploy/helm/hsmgate/README.md) |
| Only curiosity | `hsmgate dev` | software | above |

The steps of a manual install with a card: `hsmgate ca setup` (the certificates: no openssl needed), `hsmgate check` (what the configuration means, no PIN needed), `hsmgate serve`, `hsmgate unlock` (the PIN goes in once and stays in memory).

```bash
go build -o hsmgate ./cmd/hsmgate
cp deploy/hsmgate.example.yaml hsmgate.yaml     # edit: the token, the keys, the clients (smaller: deploy/hsmgate.minimal.yaml; every setting: docs/configuration.md)
./hsmgate ca setup -config hsmgate.yaml -client demo
./hsmgate check -config hsmgate.yaml
./hsmgate serve -config hsmgate.yaml &
./hsmgate unlock -config hsmgate.yaml -token card
```

## Words

| Word | Means |
|---|---|
| **token** | the PKCS#11 device (card, HSM) or a software key that holds the private keys. Not an access token: clients are known by their certificates |
| **key** | a named master key of the service (`demo`, `cinim-shard`); one or more **versions** (a rotation adds a version; old ciphertexts still open) |
| **client** | whoever connects with a certificate; known by its CN, a URI name or the hash of the certificate, and allowed some operations on some keys |
| **context** | a string bound into the ciphertext: it must be the same to open it (for example `k8s/shop/secret/field`); a key may require one, or have a fixed one |
| **face** | an API the service speaks: Transit (the Vault/OpenBao one), and optional KMS-JSON, gRPC and REST ones |
| **seal / open** | `encrypt` / `decrypt`; **rewrap** re-seals a ciphertext under the latest key version without showing the plaintext |
| **unlock** | giving the card its PIN (once, over a local socket; the service never tries a refused PIN again) |

## Documentation

The full list by what you want to do: [docs/README.md](docs/README.md).

- **I want to know what it is and whether it fits:** [questions people ask](docs/faq.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md), [compliance](docs/compliance.md), [roadmap](docs/roadmap.md).
- **I install and run it:** [before it holds real keys](docs/production.md), [operations](docs/operations.md) (unlock, rotation, spare card, lost card, Docker), [the SmartCard-HSM](docs/tokens/smartcard-hsm.md), [the Helm chart](deploy/helm/hsmgate/README.md), [upgrading](docs/upgrading.md), [supported versions](docs/supported-versions.md), [key management](docs/key-management.md), [verifying a release](docs/verifying-releases.md).
- **I set it up:** [every setting and its default](docs/configuration.md), the smallest file [deploy/hsmgate.minimal.yaml](deploy/hsmgate.minimal.yaml).
- **I watch it:** [the audit log](docs/audit-log.md) (every result word, what to watch), metrics in [operations.md](docs/operations.md).
- **It does not work:** [troubleshooting](docs/troubleshooting.md): the message, what it means, what to do.
- **I connect a client:** [recipes: the command line, `curl`, OpenBao, Kubernetes](docs/guides/clients.md), [the Transit API](docs/specs/transit.md) ([OpenAPI](api/openapi.yaml)), [OpenBao](deploy/helm/hsmgate/README.md#openbao-auto-unseal), [Kubernetes KMS v2](docs/specs/kubernetes-kms-v2.md), [secrets in pods](docs/guides/kubernetes-pod-secrets.md), [the KMS-JSON face](docs/guides/kms-json-clients.md), [all the specifications](docs/specs/README.md), [the sealed format](docs/specs/ecies2.md).
- **I check how it is made:** [security requirements](docs/security-requirements.md), [assurance case](docs/assurance-case.md), [security policies](docs/security-policies.md), [design notes and what was tried](docs/transit-face.md), [the plan](docs/project-plan.md).
- **I contribute:** [CONTRIBUTING](CONTRIBUTING.md), [building](docs/building.md), [releasing](docs/releasing.md), [governance](GOVERNANCE.md), [code of conduct](CODE_OF_CONDUCT.md), [security reports](SECURITY.md).

## Status

A working service. Tried on: OpenBao (`seal "transit"` and `awskms`), `vault-kubernetes-kms`, the SmartCard-HSM, mTLS; the "Verified" sections of [docs/transit-face.md](docs/transit-face.md) say exactly what was run and what was not. The Helm chart was checked by rendering and by running the image with its files; not yet in a long-lived cluster. The sealed format `ecies2` (and `ecies3`, `ecies4`) is specified with test vectors ([testdata/vectors/ecies2.json](testdata/vectors/ecies2.json): a test key, never use it). Releases are signed and come with a provenance attestation, an SBOM and a VEX document ([CHANGELOG](CHANGELOG.md)). Licence: MIT.
