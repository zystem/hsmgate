# hsmgate Helm chart

Runs hsmgate with a **software token** (the private keys are files in a Secret): for tests, development and pilots. It is not for keys that must outlive the cluster: whoever can read the Secret has the keys. A SmartCard-HSM needs a machine with a reader and is not covered by this chart ([operations.md](../../../docs/operations.md), "Docker" and "systemd").

## Install

The chart is an OCI artifact on ghcr.io, signed like the image ([verifying-releases.md](../../../docs/verifying-releases.md)). A package on ghcr.io is private until its owner makes it public.

```bash
helm install hsmgate oci://ghcr.io/zystem/charts/hsmgate --version 0.7.0 \
  --namespace hsmgate --create-namespace \
  --set tls.existingSecret=hsmgate-tls \
  -f my-values.yaml
```

`--version` is the number of the release without the `v`; the chart starts the image of the same release.

### The TLS Secret (required)

A Secret in the release's namespace with three entries: `tls.crt` and `tls.key` (the service's certificate; the names clients connect to, such as `hsmgate.hsmgate.svc`, must be in it) and `ca.crt` (the CA that signed the certificates of the clients: only those get past the handshake).

```bash
kubectl -n hsmgate create secret generic hsmgate-tls \
  --from-file=tls.crt=server.pem --from-file=tls.key=server.key --from-file=ca.crt=clients-ca.pem
```

A cert-manager `Certificate` with `secretName: hsmgate-tls` and a CA issuer makes a Secret of the same shape. The built-in CA of hsmgate (`hsmgate ca setup`, [operations.md](../../../docs/operations.md)) makes the files too.

### The keys and the clients

`config.keys` and `config.clients` are the `keys:` and `clients:` of `hsmgate.yaml` ([the example](../../hsmgate.example.yaml)); a key names the soft token (`softToken.name`, default `soft`) and one of its labels (`softToken.labels`, default `m1`). The defaults make one key `demo` and one client `demo`: replace them. Anything else of the configuration (the other faces, `seal_suite`, `limits`, `metrics`) goes into `config.extra`.

```yaml
config:
  extra:
    kmsjson: {enabled: true, region: local}
  keys:
    apps:
      versions: [{token: soft, label: m1}]
      aad: {mode: context, allow: ["k8s/"]}
  clients:
    - name: shop
      identity: {cn: shop}
      keys: {apps: {ops: [encrypt, decrypt]}}
```

### The soft keys

By default the chart makes a random key for each label at the first install, in a Secret `<release>-hsmgate-soft`, and **keeps it when the release is uninstalled** (`helm.sh/resource-policy: keep`): what was sealed under a key can never be opened without it. **Back that Secret up** before you rely on it. To bring your own, make a Secret with one entry per label (64 hexadecimal digits each) and set `softToken.existingSecret` and `softToken.generate=false`.

### The audit log

The service writes a file. On the default `emptyDir` it is lost with the pod; `audit.persistence.enabled=true` keeps it on a claim (kept when the release is uninstalled).

## How it runs

One replica, strategy `Recreate`, a read-only root file system, no capabilities, seccomp `RuntimeDefault`, no service-account token. The container runs as **uid 0**: the key files come from a Secret volume (owned by root, mode 0400) and the service refuses a secret that group or others can read, so `fsGroup` is not an option and only root can read them. With every capability dropped that root can do nothing else. The Pod Security level is therefore *baseline*, not *restricted* (`runAsNonRoot`).

The configuration is a ConfigMap; a change restarts the pod. `networkPolicy.enabled=true` limits ingress to port 8443 (set `networkPolicy.from` to the namespaces that may call) and allows no egress. `helm test <release>` connects to the port.

All values are in [values.yaml](values.yaml).
