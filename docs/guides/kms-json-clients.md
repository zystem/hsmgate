# Using the KMS-JSON face from other programs

hsmgate can speak a subset of the JSON API of a widely implemented cloud key service ([the specification](../specs/kms-json.md)), so a program written for that service can use hsmgate by pointing at another endpoint. The name of that service is used here only to say which public protocol is meant; hsmgate is not affiliated with its makers.

What a client needs:

| Setting | Value |
|---|---|
| Endpoint | `https://<hsmgate host>:8443` (the same port as the Transit face) |
| Region | the `kmsjson.region` of the service (`local` when not set); the credential scope is signed with it |
| Access key id and secret | those of the client in `hsmgate.yaml` (`sigv4.access_key_id`, the content of `sigv4.secret_file`) |
| Trust | the CA of the server certificate: for most SDKs the environment variable `AWS_CA_BUNDLE=/path/ca.pem` |
| Key id | the name of the key in `hsmgate.yaml` (`app`), `alias/app`, or `arn:hsmgate:kms:<region>:000000000000:key/app`; `app@2` asks for version 2 |
| Client certificate | **required** unless the client has `sigv4.no_cert: true` (see the specification, section 5: one proof instead of two, listed addresses, sealing keys only) |

Most programs cannot show a client certificate (the SDKs take only a CA bundle), so they need a client with `no_cert: true`, and for that the keys they use must have `kmsjson_usage: encrypt_decrypt` (`Encrypt`, `Decrypt`, `GenerateDataKey`). Signing, MAC and `DeriveSharedSecret` need the certificate: use an SDK that can pass one (below) or a TLS front that presents it.

A client in `hsmgate.yaml`:

```yaml
kmsjson: {enabled: true, region: local}
keys:
  app: {kmsjson: true, kmsjson_usage: encrypt_decrypt, aad: {mode: fixed}, versions: [{token: card, label: m1}]}
clients:
  - name: app
    sigv4: {access_key_id: AKIDAPPAPPAPPAPP0001, secret_file: /etc/hsmgate/app.sigv4, no_cert: true, allow_from: [10.20.0.0/16]}
    keys: {app: {ops: [encrypt, decrypt]}}
```

The secret file holds 32 bytes or more of random text (`openssl rand -hex 32`), mode 0600, owned by the user of the service.

## aws CLI

```bash
export AWS_ACCESS_KEY_ID=AKIDAPPAPPAPPAPP0001 AWS_SECRET_ACCESS_KEY="$(cat app.sigv4)" AWS_DEFAULT_REGION=local AWS_CA_BUNDLE=ca.pem
aws kms encrypt --endpoint-url https://hsmgate.example:8443 --key-id alias/app --plaintext fileb://secret.txt --query CiphertextBlob --output text
```

The CLI cannot present a client certificate, so this is the `no_cert` case. Tried (aws CLI 1.45): `encrypt`, `decrypt`, `generate-data-key` and `describe-key` against a local service with the client above.

## boto3 (can present a client certificate)

```python
import boto3
from botocore.config import Config
kms = boto3.client("kms", region_name="local", endpoint_url="https://hsmgate.example:8443",
                   aws_access_key_id="AKID...", aws_secret_access_key="...", verify="ca.pem",
                   config=Config(client_cert=("client.pem", "client.key")))
sig = kms.sign(KeyId="release", Message=b"...", SigningAlgorithm="ECDSA_SHA_256")
```

## Go SDK v2

```go
c := kms.New(kms.Options{Region: "local", BaseEndpoint: aws.String("https://hsmgate.example:8443"),
    Credentials: credentials.NewStaticCredentialsProvider(akid, secret, ""), HTTPClient: httpClientWithCAAndClientCert})
```

(`test/kmsjson-sdk` is a working example.)

## OpenBao: seal `awskms` (tried)

```hcl
seal "awskms" {
  region     = "local"
  kms_key_id = "app"
  endpoint   = "https://hsmgate.example:8443"
  access_key = "AKIDAPPAPPAPPAPP0001"
  secret_key = "..."
}
```

with `AWS_CA_BUNDLE` set in the environment of OpenBao and a client with `no_cert: true`. The seal uses `Encrypt`, `Decrypt` and `DescribeKey`. OpenBao 2.6 warns that this seal moves into an external plugin in the next minor release; Transit (`seal "transit"`, with a certificate) does not have that problem.

## SOPS, Terraform, others

Not tried. SOPS (`kms:` entries with an endpoint) and programs that call only `Encrypt`, `Decrypt`, `GenerateDataKey`, `Sign`, `Verify`, `GenerateMac`, `VerifyMac` and `GenerateRandom` are expected to work; programs that manage keys (`CreateKey`, rotation, tags, key policies; the Terraform provider reads some of them) will not, because keys here are made in the configuration and on the token.

## What differs from the cloud service

- The ciphertext blob, the signature algorithm set (ECDSA P-256 only), the MAC (HMAC-SHA-256 under a key derived on the token) and the key identifiers (`arn:hsmgate:…`) are hsmgate's own: nothing made here can be opened by the cloud service or the reverse.
- An encryption context is accepted only on keys in `aad.mode: context`; a key in `fixed` mode takes none.
- `GenerateRandom` uses the operating system's generator, not the token's.
- There are no grants, key policies, tags, rotation calls or multi-region keys; rights are the `ops` of the client in `hsmgate.yaml`.
