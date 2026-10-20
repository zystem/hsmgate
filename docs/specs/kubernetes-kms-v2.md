# Kubernetes KMS v2 (etcd encryption by the card)

**Status: served through a plug-in; verified with a gRPC client and with a real kube-apiserver (k3s v1.36.5) using a software key; not yet with a card; a native gRPC face is not built.**

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
- **Locked card.** `Encrypt` works (public key only); `Decrypt` fails with 503 until an operator unlocks, and so does the health probe, so `Status` answers `healthz "err"` and the apiserver's health check fails. A restarted apiserver cannot read its Secrets during that time. Keep the card unlocked (`pin_file`, or `hsmgate unlock` after each start) and see [../operations.md](../operations.md).
- **Rotation.** Add a version to the key, reload (`SIGHUP`). `latest_version` becomes `2`; the plug-in's next `Encrypt` returns `key_id "2"`, which tells the apiserver the data under `"1"` is stale; old ciphertexts (`vault:v1:`) still decrypt. Do not retire the old key while any stored data is on `v1`.
- **Rate.** The apiserver caches DEKs, so `Encrypt` and `Decrypt` calls are few, but `Status` is polled (about **once a minute** while healthy: measured in the audit of a real apiserver, one probe at the same second of every minute; the interval when unhealthy was not measured) and each poll is the three calls above. Set `per_minute` with room for that and for a restart (the example says 600).

**Checked.** The plug-in was started against hsmgate (plain HTTP and then mTLS) and a gRPC client for `k8s.io/kms/apis/v2` called `Status` (`version v2`, `healthz ok`, `key_id "1"`), `Encrypt` and `Decrypt`; the plaintext came back and the audit shows `keys`, `encrypt`, `decrypt` for the client. A client certificate unknown to the policy made the plug-in exit at the start. The mapping above was then read from the plug-in's source (`pkg/plugin/plugin_v2.go`, `pkg/vault/transit.go`), which corrected an earlier guess that `Status` only reads the token. **Checked on a real cluster** (2026-10-20, single-node k3s v1.36.5 with `tools/k3s-kms-test.sh`; hsmgate with a software key and the plug-in as systemd units, mutual TLS between them, `EncryptionConfiguration` with `kms` v2 first and `identity` second): the apiserver reported `[+]kms-providers ok`; a Secret was read back through the API; its plaintext was not in the datastore and a `k8s:enc:kms:v2:hsmgate` envelope was; the audit showed the apiserver's calls as the client `kube-kms`. **Rotation**: after a second key version and a reload, the next Secret was sealed under `vault:v2:` while the earlier one stayed under `vault:v1:` and both were read through the API. **Not yet checked**: the card behind the plug-in, a locked card, a restart of the apiserver under load, an outage of hsmgate (the script's `outage` step; result below when run).

## 3. The way that does not exist: a native KMS v2 face

hsmgate could serve the three RPCs itself on a unix socket and drop the plug-in. It was **postponed** because the plug-in does the job and a native face would add gRPC and a second authentication path for no new function. If it is built, it must:

- serve `Status`, `Encrypt`, `Decrypt` as in §1 on a unix socket (mode 0600), identify the caller by `SO_PEERCRED` (uid/gid), map it to a client of the policy, and then use the same keys, grants, limits, audit and token as Transit;
- return `Status.healthz` not `ok` while the token is locked or absent, and `key_id` = the latest version of the key;
- seal under the key's `fixed` constant and keep the ciphertext under 1 kB (an `ecies1` text for a 32-byte DEK is 347 characters, without the `vault:v1:` wrapper);
- write one audit line per RPC before answering, as [transit.md](transit.md) §6 says.
