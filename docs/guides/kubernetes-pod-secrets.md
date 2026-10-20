# Secrets in Kubernetes: ciphertext in the `Secret`, plaintext only in the pod

**Status:** the commands `hsmgate encrypt` and `hsmgate decrypt` and the per-client context rule are implemented and tested against the real service (`cmd/hsmgate/client_test.go`, `internal/client`), including mutual TLS. The whole scheme was **not yet run in a cluster**; the manifests below are the intended use and untried. They need a release of hsmgate that contains the two commands (v0.1.3 and earlier do not).

## What you get

A Spring Boot application reads `spring.config.import: "configtree:/vault/secrets/"`: every file in that directory is a property (`api-keys-secret` with the text `test-password`). Without Vault, the file is made like this:

```
Git / kubectl / etcd:   Secret app-secrets   api-keys-secret: "vault:v1:ZWNpZXMx…"      (a ciphertext, safe to store and to show)
                              │
pod start:   init container ──┘  hsmgate decrypt  ──mTLS──▶  hsmgate (the key is on the token)
                              │
                              ▼
pod memory:  /vault/secrets/api-keys-secret = test-password   (an emptyDir with medium: Memory, read by the application)
```

Whoever reads the `Secret` through the API, a backup of etcd or the Git repository gets only the ciphertext. To get the plaintext they need a client certificate of hsmgate with a grant for that key **and that context**; every use is written to the audit log of the service.

## 1. The service: one key, one certificate per namespace

```yaml
keys:
  apps:                                   # one key for the applications of the cluster
    versions: [{token: card, label: m1}]
    aad: {mode: context, allow: ["k8s/"]}
clients:
  - name: ns-shop
    identity: {cn: ns-shop}               # the CN of the certificate that cert-manager issues to the namespace shop
    keys:
      apps: {ops: [decrypt], contexts: ["k8s/shop/"], per_minute: 120}   # opens contexts of the namespace shop only
```

`contexts:` is the narrowing that makes this safe for many namespaces: a certificate of `shop` that asks for `k8s/bank/…` gets `403` and the refusal is audited (`forbidden_context`). Give the pods only `decrypt`; the administrator who prepares secrets has another client with `encrypt`.

## 2. The administrator: make a ciphertext

```bash
printf '%s' 'test-password' | hsmgate encrypt -addr https://hsmgate.example.org:8443 -transit-key apps \
    -ca ca.pem -cert admin.pem -keyfile admin.key -k8s shop/app-secrets/api-keys-secret > app-secrets.yaml
```

(`HSMGATE_ADDR`, `HSMGATE_TRANSIT_KEY`, `HSMGATE_CA`, `HSMGATE_CERT`, `HSMGATE_KEYFILE` set the common flags.) Without a pipe the command asks for the value without echo. A trailing newline of the input is removed (`-raw` keeps it). The output is a ready manifest:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
  namespace: shop
type: Opaque
stringData:
  api-keys-secret: "vault:v1:ZWNpZXMx…"
```

The **context is fixed by the name**: `k8s/<namespace>/<secret>/<field>`. A ciphertext made for `shop/app-secrets/api-keys-secret` does not open under any other namespace, Secret or field name, so copying it to another place gives nothing. Apply the manifest (or commit it).

## 3. The pod: an init container opens the ciphertexts into memory

```yaml
spec:
  securityContext: {fsGroup: 10001}                      # the group that may read the files in the memory volume
  initContainers:
    - name: decrypt
      image: ghcr.io/zystem/hsmgate:<a release with encrypt/decrypt>
      args: ["decrypt", "-addr", "https://hsmgate.example.org:8443", "-transit-key", "apps",
             "-ca", "/tls/ca.crt", "-cert", "/tls/tls.crt", "-keyfile", "/tls/tls.key",
             "-in-dir", "/enc", "-out-dir", "/vault/secrets",
             "-context-prefix", "k8s/$(POD_NAMESPACE)/app-secrets/"]
      env: [{name: POD_NAMESPACE, valueFrom: {fieldRef: {fieldPath: metadata.namespace}}}]
      securityContext: {runAsNonRoot: true, runAsUser: 10001, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
      volumeMounts:
        - {name: enc, mountPath: /enc, readOnly: true}
        - {name: tls, mountPath: /tls, readOnly: true}
        - {name: plain, mountPath: /vault/secrets}
  containers:
    - name: app
      volumeMounts: [{name: plain, mountPath: /vault/secrets, readOnly: true}]
  volumes:
    - {name: enc, secret: {secretName: app-secrets}}              # the ciphertexts
    - {name: tls, secret: {secretName: ns-shop-hsmgate-client}}   # the client certificate (cert-manager)
    - {name: plain, emptyDir: {medium: Memory}}
```

What the init container does: for every file in `/enc` (the Secret's fields; the kubelet's `..data` machinery is skipped) it asks hsmgate to decrypt it with the context `<prefix><file name>`, and **only if all of them open** it writes the files to `/vault/secrets` (mode 0440, by default, atomically). If any fails, nothing is written, the init container exits with an error that names the file, the key and the context (never a value), and the pod does not start. The application then reads `/vault/secrets/api-keys-secret` through `configtree`.

**Waiting.** When the service answers that the problem may pass (a locked token, a busy queue, a rate limit; header `X-Hsmgate-Retryable: true`), the command tries again with backoff for up to `-wait` (default 1 minute), then fails. A pod that starts while the card is locked waits and starts when an operator unlocks.

## 4. What this protects, and what it does not

| Who / what | Sees |
|---|---|
| `kubectl get secret`, a backup of etcd, Git, a reader of the namespace | the ciphertext only |
| etcd encryption (KMS v2 with hsmgate, see [../specs/kubernetes-kms-v2.md](../specs/kubernetes-kms-v2.md)) | a second layer on top: the ciphertext is also encrypted at rest |
| someone who steals the client certificate Secret `ns-shop-hsmgate-client` | everything of that namespace that has the right context, until the certificate is revoked (remove the client from the policy and reload; short-lived certificates make this window short) |
| someone who can `exec` into the pod, or root on the node | the plaintext, as for any scheme in which the application must read it |
| another namespace's certificate | nothing: `403 forbidden_context` |

The client certificate is itself a secret in the cluster, so the security of the scheme rests on three things: a certificate per namespace with a short life, a grant that names only `decrypt` and only that namespace's contexts, and the audit log that records every opening.

## 5. Rotation and change

- **A new value:** make a new ciphertext (step 2) and apply it. An init container runs once per pod start: restart the pods (a rollout).
- **A new key version:** add a version to the key in hsmgate and reload. Old ciphertexts still open. Move them to the new version with the `rewrap` operation of the Transit API (it never shows the plaintext); a command for it in the client is not written yet.
- **A different field or Secret name** changes the context: the ciphertext must be made again for the new name (this is what ties it to its place).

## 6. Commands

`hsmgate encrypt` and `hsmgate decrypt` take the same connection flags (also as environment variables): `-addr`, `-transit-key`, `-mount` (default `transit`), `-ca`, `-cert`, `-keyfile`, `-wait`. Plain HTTP is accepted for a loopback address only (development). Exit codes: 0 done, 1 failed (the reason is on standard error), 2 wrong usage.

The same two flags name the sources in both commands, and they can be given together:

| Flag | In `encrypt` | In `decrypt` |
|---|---|---|
| `-in-dir DIR` | every regular file of DIR (not those starting with a dot) is a value; the file name is the field name | every regular file of DIR is a ciphertext (a mounted Secret); the file name is the field name |
| `-in-file SRC[=TARGET]` (repeat) | SRC holds one value; TARGET is its **field name** (default: the base name of SRC) | SRC holds one ciphertext; TARGET is the **path** it is written to (default: `-out-dir`/base name of SRC) |
| `-in FILE` / standard input | one value (alone, not with the two above) | one ciphertext to standard output (alone) |

`-k8s NAMESPACE/SECRET` (with `-in-dir`/`-in-file`) or `-k8s NAMESPACE/SECRET/FIELD` (one value) sets the context `k8s/NAMESPACE/SECRET/<field>` and prints a `Secret` manifest; `-context` gives a bare context and prints a bare ciphertext. In `decrypt` the context is `-context-prefix` followed by the field name (the base name of the ciphertext file). Two sources for one field (`encrypt`) or one destination (`decrypt`) is an error, and nothing is done. A file is limited to 1 MiB, and by the `max_bytes` of the key (8192 by default).

Examples:

```bash
# a whole directory and one more file, as one Secret
hsmgate encrypt -k8s shop/app-files -in-dir ./plain -in-file ./certs/keystore.p12=keystore > app-files.yaml
# in the pod: all of them to /vault/secrets, and one of them also to a path the application wants
hsmgate decrypt -context-prefix 'k8s/$(POD_NAMESPACE)/app-files/' -in-dir /enc -out-dir /vault/secrets \
                -in-file /enc/keystore=/etc/ssl/app/keystore.p12
```

Binary files work (the value is bytes, not text). The files are written all together or not at all, atomically, with mode 0440 by default (`-mode`).
