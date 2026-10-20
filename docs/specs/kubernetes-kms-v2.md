# Kubernetes KMS v2 (etcd encryption by the card)

**Status: served through a plug-in; verified with a gRPC client and with a real kube-apiserver (k3s v1.36.5) using a software key; not yet with a card; a native gRPC face or a bridge of our own is deliberately not built (§3).**

Kubernetes can encrypt Secrets in etcd with a key it does not hold: `kube-apiserver` calls a *KMS plug-in* over a local gRPC socket, and the plug-in sends the apiserver's data keys to a key service. hsmgate is that key service; the key is on the card. There are two ways to connect them. Only the first exists.

```
kube-apiserver --gRPC (unix socket)--> vault-kubernetes-kms --HTTPS, mTLS, Transit--> hsmgate --PKCS#11--> card
```

## 1. The contract of KMS v2 (what the apiserver and a plug-in agree on)

Source: `k8s.io/kms/apis/v2/api.proto` (checked against `k8s.io/kms` v0.37.1). A plug-in serves three calls on a unix socket; the apiserver is the only caller.

```proto
service KeyManagementService {
  rpc Status(StatusRequest)   returns (StatusResponse);    // polled
  rpc Encrypt(EncryptRequest) returns (EncryptResponse);
  rpc Decrypt(DecryptRequest) returns (DecryptResponse);
}
message StatusResponse  { string version = 1; string healthz = 2; string key_id = 3; }
message EncryptRequest  { bytes plaintext = 1; string uid = 2; }
message EncryptResponse { bytes ciphertext = 1; string key_id = 2; map<string, bytes> annotations = 3; }
message DecryptRequest  { bytes ciphertext = 1; string uid = 2; string key_id = 3; map<string, bytes> annotations = 4; }
message DecryptResponse { bytes plaintext = 1; }
```

| Rule (from the proto's comments) | Meaning for a key service |
|---|---|
| `Status.version` must be `v2` (or `v2beta1`) | |
| `Status.healthz` other than `ok` is a failing health check; the value is shown in the apiserver's healthz | an unreachable or locked key service should make this not `ok` |
| `key_id`: not empty, under 1 kB | names the **current write key**; the apiserver uses it to decide that stored data is stale |
| `Encrypt.ciphertext`: not empty, under **1 kB** | the key service's ciphertext must fit |
| `annotations` are stored **in plaintext in etcd**; keys are DNS names; keys + values under 32 kB | nothing secret there |
| `uid` identifies the request | for logs |
| `Decrypt.key_id` is the `key_id` that `Encrypt` returned for this ciphertext | |

What the plaintext is: a data-encryption key (DEK) of the apiserver, 32 bytes. The apiserver caches DEKs, so calls are few: one `Encrypt` per new DEK, one `Decrypt` per DEK when it is first needed after a start.

## 2. The way that exists: `vault-kubernetes-kms` over Transit

`vault-kubernetes-kms` (v1.4.0 verified) is a ready KMS v1/v2 plug-in whose key service is a Vault/OpenBao **Transit** engine. hsmgate is a Transit engine ([transit.md](transit.md)), so the plug-in works with it unchanged.

**Mapping**

| KMS v2 | Transit calls (what the plug-in does; read from its source, v1.4.0) | Value |
|---|---|---|
| `Status` | `GET transit/keys/{key}`, **and a health probe: `encrypt` then `decrypt` of the six bytes `health`** | `version "v2"`, `key_id` = `latest_version` as a string (`"1"`), `healthz "ok"` if the probe round trip worked, else `"err"` |
| `Encrypt` | `PUT transit/encrypt/{key}` `{"plaintext"}`, then `GET transit/keys/{key}` | `ciphertext` = the Transit ciphertext as bytes (`vault:v1:…`, 473 bytes for a 32-byte DEK; up to 238 bytes of plaintext stay under 1 kB); `key_id` = `latest_version` |
| `Decrypt` | `PUT transit/decrypt/{key}` `{"ciphertext"}` | `plaintext` |
| (the plug-in's own token upkeep) | `GET auth/token/lookup-self` at start and every `-token-refresh-interval` (default 60 s) | a failure there is logged; at start it is fatal |

Every `Status` the apiserver polls therefore costs hsmgate **one `encrypt`, one `decrypt` (an ECDH on the card) and two `keys` reads** (seen in the audit as `keys, encrypt, keys, decrypt` within about 6 ms). That is how a locked or absent card shows up as a failing healthz in the apiserver, which is the point, but it also means the probe needs the card unlocked and counts against the rate of the client.

`annotations` are not used. The plug-in sends no `context`, so the hsmgate key must be in `fixed` mode, with a constant of its own (for example `k8s-kms/v1|k8s-etcd`).

**Configuration of hsmgate** (excerpt; a full example is `deploy/hsmgate.example.yaml`):

```yaml
keys:
  k8s-etcd:
    versions: [{token: card, label: m1}]
    aad: {mode: fixed, fixed: "k8s-kms/v1|k8s-etcd"}
clients:
  - name: kube-kms
    identity: {cn: kube-kms}               # the CN of the client certificate the plug-in presents
    keys: {k8s-etcd: {ops: [encrypt, decrypt], per_minute: 600}}
```

**The plug-in's side**: `-vault-address https://hsmgate:8443 -transit-key k8s-etcd -transit-mount transit -auth-method token -token unused -socket unix:///opt/kms/vaultkms.socket`, and the environment `VAULT_CACERT`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY` for mutual TLS. The token is ignored by hsmgate; it is there because the plug-in insists on one. In the apiserver's `EncryptionConfiguration` the provider is `kms` with `apiVersion: v2` and the plug-in's socket as `endpoint`.

**Behaviour to expect**

- **Start.** The plug-in calls `lookup-self` first. A client certificate the policy does not know gets `403` and the plug-in exits: fail at the start, not at the first Secret.
- **Locked card or hsmgate down.** `Encrypt` works while the card is only locked (public key only); `Decrypt` fails with 503 until an operator unlocks, and so does the health probe, so `Status` answers `healthz "err"` and the apiserver's `/healthz` fails (seen with hsmgate stopped: `[-]kms-providers failed`). A load balancer or probe that watches `/healthz` or `/readyz` will take such an apiserver out. New writes may keep working on a cached DEK for a while. A restarted apiserver cannot read its Secrets during that time. Keep the card unlocked (`pin_file`, or `hsmgate unlock` after each start) and see [../operations.md](../operations.md).
- **Rotation.** Add a version to the key, reload (`SIGHUP`). `latest_version` becomes `2`; the plug-in's next `Encrypt` returns `key_id "2"`, which tells the apiserver the data under `"1"` is stale; old ciphertexts (`vault:v1:`) still decrypt. Do not retire the old key while any stored data is on `v1`.
- **Rate.** The apiserver caches DEKs, so `Encrypt` and `Decrypt` calls are few, but `Status` is polled (about **once a minute** while healthy: measured in the audit of a real apiserver, one probe at the same second of every minute; the interval when unhealthy was not measured) and each poll is the three calls above. Set `per_minute` with room for that and for a restart (the example says 600).

**Checked.** The plug-in was started against hsmgate (plain HTTP and then mTLS) and a gRPC client for `k8s.io/kms/apis/v2` called `Status` (`version v2`, `healthz ok`, `key_id "1"`), `Encrypt` and `Decrypt`; the plaintext came back and the audit shows `keys`, `encrypt`, `decrypt` for the client. A client certificate unknown to the policy made the plug-in exit at the start. The mapping above was then read from the plug-in's source (`pkg/plugin/plugin_v2.go`, `pkg/vault/transit.go`), which corrected an earlier guess that `Status` only reads the token. **Checked on a real cluster** (2026-10-20, single-node k3s v1.36.5 with `tools/k3s-kms-test.sh`; hsmgate with a software key and the plug-in as systemd units, mutual TLS between them, `EncryptionConfiguration` with `kms` v2 first and `identity` second): the apiserver reported `[+]kms-providers ok`; a Secret was read back through the API; its plaintext was not in the datastore and a `k8s:enc:kms:v2:hsmgate` envelope was; the audit showed the apiserver's calls as the client `kube-kms`. **Rotation**: after a second key version and a reload, the next Secret was sealed under `vault:v2:` while the earlier one stayed under `vault:v1:` and both were read through the API. **Automated** (`internal/face/transit/kms_v2_test.go`, runs in the pipeline): a simulator of the plug-in's calls, written from its source and checked against the audit log of the real apiserver, asserts the start (`lookup-self` with numeric `ttl` and `creation_ttl`, so no renewal), the cost of one `Status` (`keys, encrypt, keys, decrypt`), `latest_version` as a number, the 473-byte ciphertext of a 32-byte DEK and the 238-byte bound under 1 kB, a rotation (`key_id` 1 to 2, `vault:v2:`, old ciphertexts open), a locked token (`Status` probe fails, `Encrypt` works) and the refusal of a context-mode key. Two deliberate breaks of the contract (no `creation_ttl`; `latest_version` as a string) made these tests fail. **Not yet checked**: the card behind the plug-in, a locked card (the test uses a fake locked token, not a card), a restart of the apiserver while hsmgate is down. **Outage of hsmgate for 30 s**: `/healthz` failed with `[-]kms-providers failed: reason withheld` (and so the whole `/healthz` answered an error), a Secret write during it **still succeeded** (consistent with the apiserver reusing a cached DEK: it asks the key service for a DEK, not for every Secret; not verified separately), and after hsmgate was back `kms-providers` was `ok` and writes continued. Reads after an apiserver restart have no such cache and need the key service.

**Removing the provider** (checked the same day): `identity` first and `kms` second, restart; rewrite every Secret (`kubectl get secrets -A -o json | kubectl replace -f -`, 20 Secrets here); then remove the provider and restart. After that all 20 Secrets were read without the plug-in, and the apiserver had no `kms-providers` check. Do not stop the plug-in before the rewrite: a Secret that stays under the provider is unreadable without it. On this host the last restart failed once with `listen tcp :6443: bind: address already in use`: `tailscaled` (a `tailscale serve` rule for 6443) had taken the port on the tailnet address while k3s was stopped; turning the rule off let k3s start. That is a property of that host, not of KMS; any restart of the apiserver is a window for it.

## 3. Deliberately not built: a native KMS v2 face, or a bridge of our own

**The decision (2026-10-20): the plug-in stays; nothing is built.** The reasons:

- `kube-apiserver` talks to a KMS plug-in only over a **local unix socket**. When hsmgate is on another machine (the usual case: one card, several control-plane nodes), something local on every control-plane node must translate "socket" into "network". That is what the plug-in is. A gRPC face inside hsmgate would remove it only where hsmgate and the apiserver share a host (like the single-node k3s of the test), which is not the general case.
- The plug-in works: it was run against a real apiserver (§2), and the calls it makes are held by an automated test (`kms_v2_test.go`) that fails when the contract of the Transit API changes.

**What the plug-in costs, so that the decision can be revisited:**

| Cost | Detail |
|---|---|
| a third-party program in the path of every DEK | it sees the DEK in plaintext, as hsmgate does: two parties to trust instead of one; its releases have to be followed |
| one more component on every control-plane node | it must be running before the apiserver, with a client certificate of hsmgate on the node |
| `Status` is expensive | every poll (about once a minute) is an `encrypt` and a `decrypt` (an ECDH on the card) and two `keys` reads; the probe is built into the plug-in and cannot be made light |
| no context | the plug-in never sends one, so its key is in `fixed` mode: whoever holds a certificate with a grant on that key can open the DEKs of every cluster that uses it. Give each cluster its own key |

**When to build something:** if the probe load on the card matters, or a third-party program in the DEK path is not acceptable, build a **small bridge of our own** (a separate binary in this repository, about 300 lines: `k8s.io/kms/apis/v2` on a unix socket on one side, `internal/client` on the other), not a gRPC face inside the service. It would answer `Status` from the state of the token (`token_state` of `keys/{name}`) without an ECDH, put one party of our own in the path, and be covered by the same simulator test. If the apiserver and hsmgate do share a host and the extra hop is the only objection, a gRPC face on a unix socket with `SO_PEERCRED` identity is the other way; it must then:

- serve `Status`, `Encrypt`, `Decrypt` as in §1 on a unix socket (mode 0600), identify the caller by `SO_PEERCRED` (uid/gid), map it to a client of the policy, and then use the same keys, grants, limits, audit and token as Transit;
- return `Status.healthz` not `ok` while the token is locked or absent, and `key_id` = the latest version of the key;
- seal under the key's `fixed` constant and keep the ciphertext under 1 kB (an `ecies1` text for a 32-byte DEK is 347 characters, without the `vault:v1:` wrapper);
- write one audit line per RPC before answering, as [transit.md](transit.md) §6 says.
