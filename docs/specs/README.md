# Specifications

What hsmgate promises to the programs that talk to it, written for a person who has to write or review a client, and also checked by tests where it can be. Each page says at the top whether the contract is **implemented** or only **designed**; a page never describes a promise as kept that is not.

| Spec | What it is | Status |
|---|---|---|
| [transit.md](transit.md) | The Vault/OpenBao **Transit** API: encrypt, decrypt, rewrap, key information. The API of CiNim, OpenBao's `seal "transit"`, `vault-kubernetes-kms` | **Implemented.** Checked by `internal/face/transit` tests and [api/openapi.yaml](../../api/openapi.yaml); run against OpenBao v2.6.1 and `vault-kubernetes-kms` v1.4.0 (also over mTLS) and, with a PKCS#11 token, on a SmartCard-HSM |
| [ecies1.md](ecies1.md) | The **sealed format** behind every Transit ciphertext (ECDH-ES on P-256, HKDF-SHA256, XChaCha20-Poly1305) | **Implemented.** Test vectors from the original Nim implementation in `testdata/vectors/ecies1.json`, opened by the Go code |
| [kubernetes-kms-v2.md](kubernetes-kms-v2.md) | The **Kubernetes KMS v2** gRPC contract, and how a cluster's etcd encryption reaches the card | **Served through the `vault-kubernetes-kms` plugin over Transit**; verified with a real kube-apiserver (k3s, software key) and by an automated simulator test, not yet with a card. A native gRPC face or a bridge of our own is **deliberately not built** (reasons and when to revisit: §3) |
| [aws-kms.md](aws-kms.md) | The **AWS KMS** subset (`GetPublicKey`, `DescribeKey`, `DeriveSharedSecret`) as a second face | **Designed only.** Nothing of it is in the code |

Words: **must**, **must not**, **should**, **may** are used in the sense of RFC 2119. "The service" is a running `hsmgate`; "a client" is whatever the policy of the service calls a client; "the token" is the PKCS#11 device (or the software key in tests).

The design notes and the records of what was tried live next to these pages: [../transit-face.md](../transit-face.md), [../operations.md](../operations.md), [../threat-model.md](../threat-model.md), [../audit-2026-10.md](../audit-2026-10.md).
