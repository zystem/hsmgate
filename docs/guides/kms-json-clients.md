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

## SOPS (tried)

SOPS 3.13.3 against a local service with a `no_cert` client and a key with `kmsjson_usage: encrypt_decrypt`:

```bash
export AWS_ACCESS_KEY_ID=AKIDAPPAPPAPPAPP0001 AWS_SECRET_ACCESS_KEY="$(cat app.sigv4)" AWS_REGION=local AWS_CA_BUNDLE=ca.pem
export AWS_ENDPOINT_URL_KMS=https://hsmgate.example:8443
```

```yaml
# .sops.yaml
creation_rules:
  - path_regex: .*
    kms: arn:aws:kms:local:000000000000:key/app
```

`sops encrypt -i file.yaml` and `sops decrypt file.yaml` worked, as did a wrong secret (refused with a signature error). **SOPS accepts only identifiers that begin with `arn:aws…`** (`arn:hsmgate:…` is refused by SOPS itself: "no valid ARN found"). hsmgate does not care about the partition and the account part of an identifier: it reads the key from the `:key/<name>` or `:alias/<name>` at the end, so write the key as `arn:aws:kms:<region>:000000000000:key/<name>` for SOPS; that text is then stored in the encrypted files. The data key of SOPS is sealed with `Encrypt` and opened with `Decrypt`.

## AWS Encryption SDK for Python (tried)

`aws-encryption-sdk` with a `StrictAwsKmsMasterKeyProvider` over `arn:aws:kms:<region>:000000000000:key/<name>`, `AWS_ENDPOINT_URL_KMS`, `AWS_CA_BUNDLE` and a `no_cert` client: encrypt and decrypt round-tripped with `GenerateDataKey` and `Decrypt`. It stores the key identifier in each message and compares it when it reads, so hsmgate **answers with the identifier the client named the key with** when that is a full identifier of this key (`arn:<partition>:kms:<region>:<account>:key/<name>`), and with its own `arn:hsmgate:…` when the key was named by name or alias. The default algorithm suite signs and puts `aws-crypto-public-key` into the encryption context, so such a key must be in `aad.mode: context` with `allow: ["aws-crypto-public-key=", ...]`; a key in `fixed` mode takes only a suite without signing (`AES_256_GCM_HKDF_SHA512_COMMIT_KEY`) and no context of the caller.

## HashiCorp Vault: seal `awskms` (tried, Vault 2.2.0)

Same `seal "awskms"` block as for OpenBao (above), but Vault's wrapper hands its own HTTP client to the SDK, which then refuses `AWS_CA_BUNDLE` ("unable to add custom RootCAs"): make Vault trust the CA of the service with `SSL_CERT_FILE=/path/ca.pem` (or the system store). `operator init`, a secret, stop, start: it unsealed by itself (`describekey`, `encrypt`, `decrypt` in the audit).

## cosign (tried, 3.1.4): `awskms://`

`cosign sign-blob` and `verify-blob` with `--key awskms://<host>:<port>/alias/<name>` work, signing through the face and verifying with the public key from `GetPublicKey`. Three things to know: cosign accepts a key **id** only as a UUID, so name the key by **alias** (`alias/<name>`), which hsmgate keys always have; it builds `https://<host>:<port>` itself, so the endpoint must be TLS; and it cannot show a client certificate, while signing needs one: put a **TLS front that presents the certificate** in front of hsmgate (a few lines of Go with `httputil.ReverseProxy`; keep the `Host` header, the signature covers it) and make cosign trust the front with `SSL_CERT_FILE`.

## Terraform (tried, 1.16.6, provider aws)

The data sources and resources that only use keys work against the face: `data "aws_kms_key"` (`DescribeKey`), `resource "aws_kms_ciphertext"` (`Encrypt`), `data "aws_kms_secrets"` (`Decrypt`), `data "aws_kms_public_key"` (`GetPublicKey`); a second `plan` shows no changes. Provider settings: `endpoints { kms = "https://…" }`, `custom_ca_bundle`, `skip_credentials_validation`, `skip_requesting_account_id`, `skip_metadata_api_check`, `skip_region_validation`. Resources that **make or manage** keys (`aws_kms_key`, `aws_kms_alias`, grants, policies, rotation) do not work: keys here are made in the configuration and on the token.

## SDKs and services tried

| What | Version | Result |
|---|---|---|
| Go SDK v2 (`test/kmsjson-sdk`, in CI) | kms 1.61 | all operations |
| boto3 (`test/kmsjson-boto3`, in CI) | 1.43 | all operations |
| Node.js SDK v3 (`@aws-sdk/client-kms`) | current | Encrypt, Decrypt, GenerateDataKey, Sign, Verify, GenerateMac, VerifyMac, GenerateRandom, DescribeKey |
| Java SDK v2 (`software.amazon.awssdk:kms`) | 2.31 | the same; `InvalidCiphertextException` arrives as the SDK's own type; trust the CA with `-Djavax.net.ssl.trustStore` |
| AWS Encryption SDK for Python | current | round trip (see above) |
| MongoDB client-side field encryption (`pymongo[encryption]`, libmongocrypt) | current | `create_data_key` and decrypt through the face; `master_key = {region, key: "arn:aws:kms:…:key/<name>", endpoint: "host:port"}`, `kms_tls_options` with the CA; a client without a certificate (`no_cert`) is enough |
| SOPS | 3.13.3 | see above |
| OpenBao, HashiCorp Vault | 2.6.1, 2.2.0 | auto-unseal |
| aws CLI | 1.45 | see above |

None of them depends on the ciphertext being AES: the blob is opaque to clients, they only carry it back.

Not tried: the Kubernetes `aws-encryption-provider` (for EKS only; etcd encryption here is done by `vault-kubernetes-kms` through Transit), MySQL `keyring_aws` (Enterprise), MinIO KES (its AWS back end is Secrets Manager, not this API).

## What differs from the cloud service

- The ciphertext blob, the signature algorithm set (ECDSA P-256 only), the MAC (HMAC-SHA-256 under a key derived on the token) and the key identifiers (`arn:hsmgate:…`) are hsmgate's own: nothing made here can be opened by the cloud service or the reverse.
- An encryption context is accepted only on keys in `aad.mode: context`; a key in `fixed` mode takes none.
- `GenerateRandom` uses the operating system's generator, not the token's.
- There are no grants, key policies, tags, rotation calls or multi-region keys; rights are the `ops` of the client in `hsmgate.yaml`.
