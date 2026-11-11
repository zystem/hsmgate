# hsmgate Helm chart

Runs hsmgate with a **software token** (the private keys are files in a Secret): for tests, development and pilots. It is not for keys that must outlive the cluster: whoever can read the Secret has the keys. A SmartCard-HSM needs a machine with a reader and is not covered by this chart ([operations.md](../../../docs/operations.md), "Docker" and "systemd").

## Install

The chart is an OCI artifact on ghcr.io, signed like the image ([verifying-releases.md](../../../docs/verifying-releases.md)). A package on ghcr.io is private until its owner makes it public.

```bash
helm install hsmgate oci://ghcr.io/zystem/charts/hsmgate --version 0.7.0 \
  --namespace hsmgate --create-namespace \
  -f my-values.yaml
```

`--version` is the number of the release without the `v`; the chart starts the image of the same release.

### TLS: made by the chart, or yours

The service answers only clients with a certificate of its CA; a client is known by the CN of its certificate (`identity: {cn: ...}` in `config.clients`).

**By default the chart makes everything, once:** a CA (`<release>-ca`, with its key: nothing mounts it), the certificate of the service (`<release>-tls`: `tls.crt`, `tls.key`, `ca.crt`; the names are the service's own, `localhost`, `ingress.host` and `tls.generate.extraNames`) and a certificate for each name in `tls.generate.clients` (default `[demo]`: the Secret `<release>-client-demo` with `tls.crt`, `tls.key`, `ca.crt`). An upgrade reuses what exists (the Secrets carry `helm.sh/resource-policy: keep`, so an uninstall leaves them, and a client that holds a certificate keeps working after a reinstall). To give a client its files:

```bash
kubectl -n hsmgate get secret hsmgate-client-demo -o jsonpath='{.data.tls\.crt}' | base64 -d > demo.pem     # likewise tls.key and ca.crt
```

or mount the Secret into the pod of the client. Add a client: put its name into `tls.generate.clients` **and** a client with the same `identity.cn` into `config.clients`, then `helm upgrade`.

*Renewal.* The certificates last 730 days (the CA 3650) and nothing renews them. To renew the service's certificate delete the Secret `<release>-tls` and `helm upgrade` (the CA is kept, so the clients stay valid; the pod then needs a restart: `kubectl rollout restart deploy/<release>`); for a client delete its Secret the same way and hand out the new files. A new CA: delete all of `<release>-ca`, `-tls` and the clients' Secrets, and give the clients their files again. The keys the chart makes are RSA 2048 (Helm makes no other); `hsmgate ca` ([operations.md](../../../docs/operations.md)) makes P-256 ones, and files made by it, or by your own PKI, go in through `tls.existingSecret`.

**Your own Secret:** `--set tls.existingSecret=hsmgate-tls`, in the release's namespace, with `tls.crt` and `tls.key` (the certificate of the service; the names clients connect to, such as `hsmgate.hsmgate.svc`, must be in it) and `ca.crt` (the CA that signed the certificates of the clients).

```bash
kubectl -n hsmgate create secret generic hsmgate-tls \
  --from-file=tls.crt=server.pem --from-file=tls.key=server.key --from-file=ca.crt=clients-ca.pem
```

**From cert-manager:** [`examples/cert-manager.yaml`](examples/cert-manager.yaml) makes the same Secrets (a CA of its own, the certificate of the service and the certificates of two clients), and cert-manager renews them. Apply it before the install and set `tls.existingSecret`:

```bash
kubectl -n hsmgate apply -f examples/cert-manager.yaml
kubectl -n hsmgate wait certificate/hsmgate-tls certificate/demo-client certificate/openbao-client --for=condition=Ready --timeout=2m
```

With an ACME issuer (Let's Encrypt) `ca.crt` is not what clients are signed by: the clients of hsmgate need a CA of your own. cert-manager renews the files in the Secret, but nothing tells the pod: restart it after a renewal (or use a tool such as Reloader).

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

### OpenBao (auto-unseal)

OpenBao unseals itself through hsmgate with `seal "transit"`: the key stays behind hsmgate, OpenBao holds only what hsmgate sealed. The files are in [`examples/`](examples/): [`values-openbao.yaml`](examples/values-openbao.yaml) (for this chart: the key `openbao-unseal`, with a fixed context because the seal sends none; the client `openbao`, `encrypt` and `decrypt` only; its certificate), [`openbao-seal.hcl`](examples/openbao-seal.hcl) (the stanza) and [`openbao-helm-values.yaml`](examples/openbao-helm-values.yaml) (the values of the OpenBao chart). Soft keys live in a Secret of the cluster of hsmgate: **back that Secret up** (`<release>-soft`), what OpenBao sealed cannot be opened without it.

**In the same cluster:** install this chart with `-f examples/values-openbao.yaml`, mount the Secret `<release>-client-openbao` into OpenBao and use `address = "https://hsmgate.<namespace>.svc:8443"` in the stanza.

**In another cluster** (hsmgate in A, OpenBao in B):

1. *In A.* A name that resolves to the ingress controller of A is needed (say `hsmgate.example.com`); the chart puts it into the certificate of the service. The controller must pass the TLS through (ingress-nginx: `--enable-ssl-passthrough`).

   ```bash
   helm install hsmgate oci://ghcr.io/zystem/charts/hsmgate --version 0.7.3 -n hsmgate --create-namespace \
     -f examples/values-openbao.yaml --set ingress.enabled=true --set ingress.host=hsmgate.example.com
   ```

2. *Copy the certificate of the client to B.* The Secret `hsmgate-client-openbao` holds `tls.crt`, `tls.key` and `ca.crt`:

   ```bash
   kubectl --context B create namespace openbao
   kubectl --context A -n hsmgate get secret hsmgate-client-openbao -o json \
     | jq 'del(.metadata.namespace,.metadata.resourceVersion,.metadata.uid,.metadata.creationTimestamp,.metadata.annotations,.metadata.labels,.metadata.managedFields)' \
     | kubectl --context B -n openbao apply -f -
   ```

3. *Install OpenBao in B* with [`openbao-helm-values.yaml`](examples/openbao-helm-values.yaml) (set `address` to your host): the chart mounts the Secret at `/openbao/userconfig/hsmgate-client-openbao/`, which is what the stanza names.

   ```bash
   helm repo add openbao https://openbao.github.io/openbao-helm
   helm --kube-context B install openbao openbao/openbao -n openbao -f examples/openbao-helm-values.yaml
   ```

4. *Initialise once:* `kubectl --context B -n openbao exec openbao-0 -- bao operator init -recovery-shares=1 -recovery-threshold=1` (keep the recovery key and the root token), then delete the pod: it starts unsealed. In A the audit of hsmgate shows `encrypt` and `decrypt` by the client `openbao`.

What was run is OpenBao v2.6.1 with this seal over mTLS ([transit-face.md](../../../docs/transit-face.md)); this procedure across two clusters was not run, only rendered (`helm template` of both charts). The OpenBao chart renders with these values and mounts the Secret at the path above.

### The soft keys

By default the chart makes a random key for each label at the first install, in a Secret `<release>-hsmgate-soft`, and **keeps it when the release is uninstalled** (`helm.sh/resource-policy: keep`): what was sealed under a key can never be opened without it. **Back that Secret up** before you rely on it. To bring your own, make a Secret with one entry per label (64 hexadecimal digits each) and set `softToken.existingSecret` and `softToken.generate=false`.

### The audit log

The service writes a file. On the default `emptyDir` it is lost with the pod; `audit.persistence.enabled=true` keeps it on a claim (kept when the release is uninstalled).

## How it runs

One replica, strategy `Recreate`, a read-only root file system, no capabilities, seccomp `RuntimeDefault`, no service-account token. The container runs as **uid 0**: the key files come from a Secret volume (owned by root, mode 0400) and the service refuses a secret that group or others can read, so `fsGroup` is not an option and only root can read them. With every capability dropped that root can do nothing else. The Pod Security level is therefore *baseline*, not *restricted* (`runAsNonRoot`).

The configuration is a ConfigMap; a change restarts the pod. `networkPolicy.enabled=true` limits ingress to port 8443 (set `networkPolicy.from` to the namespaces that may call) and allows no egress. `helm test <release>` connects to the port.

All values are in [values.yaml](values.yaml).
