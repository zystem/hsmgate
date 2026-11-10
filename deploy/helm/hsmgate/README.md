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

**From cert-manager:** [`examples/cert-manager.yaml`](examples/cert-manager.yaml) makes all of it: a CA of its own, the certificate of the service (the Secret `hsmgate-tls` with `tls.crt`, `tls.key` and `ca.crt`, the three that the chart wants) and the certificate of one client (`demo-client-tls`, for the application that calls hsmgate; its `commonName` is the `identity: {cn: ...}` of a client in `config.extra.clients`). The Secret must exist before the pod can start, so apply it first:

```bash
kubectl -n hsmgate apply -f examples/cert-manager.yaml
kubectl -n hsmgate wait certificate/hsmgate-tls certificate/demo-client --for=condition=Ready --timeout=2m
```

An `Issuer` that already exists in your cluster can take the place of the CA of the example, if it is a CA issuer: then `ca.crt` of the Secret is that CA, and it is the CA of the clients too. With an ACME issuer (Let's Encrypt) `ca.crt` is not what clients are signed by, and a client certificate from it would not do: the clients of hsmgate need a CA of your own. The built-in CA of hsmgate (`hsmgate ca setup`, [operations.md](../../../docs/operations.md)) makes the files too.

cert-manager renews the certificate in the Secret, but nothing tells the pod that the files changed: restart it after a renewal (`kubectl -n hsmgate rollout restart deploy/hsmgate`), or use a tool that does it for you (such as Reloader).

### Reaching it from outside the cluster

hsmgate knows a client by the certificate it presents in the handshake, so a proxy that ends TLS hides the client from it (and the policy has nothing to decide on). Everything here keeps the handshake end to end:

- **Ingress with TLS passthrough:** `--set ingress.enabled=true --set ingress.host=hsmgate.example.com`. For ingress-nginx the chart adds `ssl-passthrough: "true"`; the controller must be started with `--enable-ssl-passthrough` (it is off by default), and the host must be one of the names in the certificate of the service (add it to `dnsNames` in the cert-manager example). For another controller set `ingress.className` and `ingress.annotations` to what it needs. The Ingress is not an HTTP router here: it only picks the pod by the name in the handshake (SNI).
- **A Service of type `LoadBalancer` or `NodePort`:** `service.type`.
- A Gateway API `TLSRoute` with `mode: Passthrough` (not made by the chart).

For a client in the cluster the Service `hsmgate.<namespace>.svc:8443` is enough. With `networkPolicy.enabled` add the namespace of the ingress controller to `networkPolicy.from`.

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
