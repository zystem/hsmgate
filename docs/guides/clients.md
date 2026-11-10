# Connecting a client: recipes

What every client needs is the same three files and an address: its **certificate** and **key** (made by `hsmgate ca client`, by the Helm chart, or by your own CA), the **CA certificate** of the service, and the address `https://host:8443`. The client is known by the identity of its certificate (`identity:` in `clients:`) and may do only what its `keys:` say ([configuration.md](../configuration.md)). Without a certificate the handshake fails.

The examples use the service that `hsmgate dev` starts ([README](../../README.md#try-it-in-a-minute-no-hardware-nothing-to-prepare)): the key `demo` (no context) and `demo-ctx` (a context beginning with `demo/`). Replace the address and the names with yours.

## The command line: `hsmgate encrypt` and `decrypt`

```bash
export HSMGATE_ADDR=https://127.0.0.1:8443 HSMGATE_CA=ca.pem HSMGATE_CERT=demo.pem HSMGATE_KEYFILE=demo.key HSMGATE_TRANSIT_KEY=demo
echo 'my secret' | hsmgate encrypt > sealed.txt        # vault:v1:...
hsmgate decrypt < sealed.txt                           # my secret
echo x | hsmgate encrypt -transit-key demo-ctx -context demo/a > c.txt
hsmgate decrypt -transit-key demo-ctx -context demo/a < c.txt
```

It follows the service's hint of whether to try again (a locked card, a busy service, a rate limit) for up to a minute (`-wait`). A whole directory at once, and Kubernetes Secrets: `-in-dir`, `-out-dir`, `-in-files`, `-context-prefix`, `-k8s` (`hsmgate encrypt -h`; [secrets in pods](kubernetes-pod-secrets.md)).

## `curl` (the Transit API)

Values are base64. This is the API of Vault and OpenBao's Transit engine, so any client library for it works with the mount `transit`.

```bash
C="curl -s --cacert ca.pem --cert demo.pem --key demo.key"; U=https://127.0.0.1:8443/v1/transit
$C -X POST $U/encrypt/demo -d "{\"plaintext\":\"$(printf 'my secret' | base64)\"}"
#  {"data":{"ciphertext":"vault:v1:..."}}
$C -X POST $U/decrypt/demo -d '{"ciphertext":"vault:v1:..."}'
#  {"data":{"plaintext":"bXkgc2VjcmV0"}}            (base64 of: my secret)
$C -X POST $U/rewrap/demo  -d '{"ciphertext":"vault:v1:..."}'     # under the latest key version, the plaintext never shown
$C $U/keys/demo                                                    # versions, fingerprints, public keys
# a key with a context: the context is base64 too
$C -X POST $U/encrypt/demo-ctx -d "{\"plaintext\":\"eA==\",\"context\":\"$(printf 'demo/a' | base64)\"}"
```

What the answers mean: `{"errors":["permission denied"]}` with 403 is a client, key, operation or context that the policy does not give; `context not allowed for this key` with 400 is a context outside the key's `allow:`. [troubleshooting.md](../troubleshooting.md) lists the rest; the whole API is in [transit.md](../specs/transit.md) and [openapi.yaml](../../api/openapi.yaml).

## OpenBao: auto-unseal

In OpenBao's configuration (the key needs `aad: {mode: fixed}`, because the seal sends no context, and the client needs `encrypt` and `decrypt` on it):

```hcl
seal "transit" {
  address         = "https://hsmgate.example.com:8443"
  mount_path      = "transit/"
  key_name        = "openbao-unseal"
  tls_ca_cert     = "/path/ca.pem"
  tls_client_cert = "/path/openbao.pem"
  tls_client_key  = "/path/openbao.key"
}
```

Then `bao operator init -recovery-shares=1`; OpenBao opens itself after a restart. In Kubernetes, with the Helm charts of both, and across two clusters: [the chart's README](../../deploy/helm/hsmgate/README.md#openbao-auto-unseal). Run against OpenBao v2.6.1 over mTLS ([transit-face.md](../transit-face.md)).

## Kubernetes

- **Encryption of etcd** (the API server's `EncryptionConfiguration` with a KMS v2 provider): through the `vault-kubernetes-kms` plugin, which speaks Transit: [kubernetes-kms-v2.md](../specs/kubernetes-kms-v2.md).
- **Secrets in pods without Vault**: ciphertexts in ordinary Secrets, opened by the pod at start with `hsmgate decrypt`; one namespace's certificate sees only its own contexts: [kubernetes-pod-secrets.md](kubernetes-pod-secrets.md).

## Clients of cloud key services

Programs written for the key services of the large clouds (their SDKs sign requests): the KMS-JSON, gRPC and REST faces, each with its own credential: [kms-json-clients.md](kms-json-clients.md), [specs](../specs/README.md).

## Making the files of a client

| How hsmgate was installed | Where the client files come from |
|---|---|
| `hsmgate dev` | `DIR/clients/demo.pem`, `demo.key`, `ca.pem` |
| By hand (systemd, Docker) | `hsmgate ca client -dir ca -config hsmgate.yaml -cn NAME` (then a client with `identity: {cn: NAME}` in `clients:`) |
| The Helm chart | the Secret `<release>-client-<name>` ([the chart](../../deploy/helm/hsmgate/README.md)) |
