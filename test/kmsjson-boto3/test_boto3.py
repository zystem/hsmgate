"""A black-box test of the KMS-JSON face with boto3, the vendor's Python SDK: a second, independent implementation of the client side (the Go SDK test is in ../kmsjson-sdk).

Usage: python test_boto3.py /path/to/hsmgate
It makes certificates, a software key and a config in a temporary directory, starts the binary, calls it, and compares the shared secret with a local ECDH.
"""
import datetime, os, socket, subprocess, sys, tempfile, time, unittest

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

AKID = "AKIDBOTOTESTBOTOTEST"
SECRET = "a-signing-secret-of-the-test-0123456789"
BIN = sys.argv.pop(1) if len(sys.argv) > 1 else "build/hsmgate"
PROC = None
ENDPOINT = ""
DIR = ""


def cert(cn, issuer_key, issuer_name, key, ca=False, server=False):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(hours=1))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if server:
        import ipaddress
        b = b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    elif not ca:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256()), name


def write(path, data, mode=0o600):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, mode)


def pem_cert(c):
    return c.public_bytes(serialization.Encoding.PEM)


def pem_key(k):
    return k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())


def setUpModule():
    global PROC, ENDPOINT, DIR
    DIR = tempfile.mkdtemp(prefix="kmsjson-boto3")
    f = lambda n: os.path.join(DIR, n)
    cak = ec.generate_private_key(ec.SECP256R1())
    ca, caname = cert("ca", None, None, cak, ca=True)
    sk = ec.generate_private_key(ec.SECP256R1())
    srv, _ = cert("hsmgate", cak, caname, sk, server=True)
    ck = ec.generate_private_key(ec.SECP256R1())
    cli, _ = cert("boto-client", cak, caname, ck)
    write(f("ca.pem"), pem_cert(ca)); write(f("srv.pem"), pem_cert(srv)); write(f("srv.key"), pem_key(sk))
    write(f("cli.pem"), pem_cert(cli)); write(f("cli.key"), pem_key(ck))
    write(f("sigv4-secret"), (SECRET + "\n").encode())
    write(f("k1.hex"), b"07" * 32); write(f("k2.hex"), b"09" * 32); write(f("k3.hex"), b"0b" * 32)
    s = socket.socket(); s.bind(("127.0.0.1", 0)); addr = "127.0.0.1:%d" % s.getsockname()[1]; s.close()
    write(f("hsmgate.yaml"), f"""listen: {addr}
tls: {{cert: {f('srv.pem')}, key: {f('srv.key')}, client_ca: {f('ca.pem')}}}
audit: {{file: {f('audit.log')}}}
kmsjson: {{enabled: true, region: local}}
tokens: [{{name: soft, type: soft, keys: {{m1: {f('k1.hex')}, m2: {f('k2.hex')}, m3: {f('k3.hex')}}}}}]
keys:
  etcd: {{kmsjson: true, versions: [{{token: soft, label: m1}}, {{token: soft, label: m2}}], aad: {{mode: fixed}}}}
  sig: {{kmsjson: true, kmsjson_usage: sign_verify, versions: [{{token: soft, label: m3}}], aad: {{mode: fixed}}}}
  seal: {{kmsjson: true, kmsjson_usage: encrypt_decrypt, versions: [{{token: soft, label: m1}}], aad: {{mode: fixed}}}}
  hidden: {{versions: [{{token: soft, label: m1}}], aad: {{mode: fixed}}}}
clients:
  - name: boto
    identity: {{cn: boto-client}}
    sigv4: {{access_key_id: {AKID}, secret_file: {f('sigv4-secret')}}}
    keys: {{etcd: {{ops: [derive]}}, seal: {{ops: [encrypt, decrypt]}}, sig: {{ops: [sign, verify]}}}}
""".encode())
    PROC = subprocess.Popen([BIN, "serve", "-config", f("hsmgate.yaml")])
    host, port = addr.split(":")
    for _ in range(100):
        try:
            socket.create_connection((host, int(port)), 0.2).close(); break
        except OSError:
            time.sleep(0.1)
    ENDPOINT = "https://" + addr


def tearDownModule():
    PROC.kill(); PROC.wait()


def mtls_client(**kw):
    c = boto3.client("kms", region_name="local", endpoint_url=ENDPOINT, aws_access_key_id=kw.get("akid", AKID),
                     aws_secret_access_key=kw.get("secret", SECRET), verify=os.path.join(DIR, "ca.pem"),
                     config=Config(retries={"max_attempts": 1}, client_cert=(os.path.join(DIR, "cli.pem"), os.path.join(DIR, "cli.key"))))
    return c


def code(e):
    return e.exception.response["Error"]["Code"]


class KMSJSON(unittest.TestCase):
    def test_shared_secret_matches_local_ecdh(self):
        c = mtls_client()
        pk = c.get_public_key(KeyId="alias/etcd")
        self.assertEqual(pk["KeySpec"], "ECC_NIST_P256")
        self.assertEqual(pk["KeyUsage"], "KEY_AGREEMENT")
        self.assertEqual(pk["KeyAgreementAlgorithms"], ["ECDH"])
        master = serialization.load_der_public_key(pk["PublicKey"])
        mine = ec.generate_private_key(ec.SECP256R1())
        der = mine.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        out = c.derive_shared_secret(KeyId="etcd", KeyAgreementAlgorithm="ECDH", PublicKey=der)
        self.assertEqual(out["SharedSecret"], mine.exchange(ec.ECDH(), master))
        self.assertEqual(out["KeyAgreementAlgorithm"], "ECDH")
        # version 1 by the "@N" form gives a different secret
        v1 = serialization.load_der_public_key(c.get_public_key(KeyId="etcd@1")["PublicKey"])
        out1 = c.derive_shared_secret(KeyId="etcd@1", KeyAgreementAlgorithm="ECDH", PublicKey=der)
        self.assertEqual(out1["SharedSecret"], mine.exchange(ec.ECDH(), v1))
        self.assertNotEqual(out1["SharedSecret"], out["SharedSecret"])

    def test_describe_and_lists(self):
        c = mtls_client()
        md = c.describe_key(KeyId="etcd")["KeyMetadata"]
        self.assertEqual((md["KeyId"], md["Enabled"], md["KeyState"], md["KeyUsage"]), ("etcd", True, "Enabled", "KEY_AGREEMENT"))
        self.assertIn("CreationDate", md)
        self.assertEqual(sorted(k["KeyId"] for k in c.list_keys()["Keys"]), ["etcd", "seal", "sig"])
        self.assertEqual(sorted(a["AliasName"] for a in c.list_aliases()["Aliases"]), ["alias/etcd", "alias/seal", "alias/sig"])

    def test_encrypt_decrypt_and_data_keys(self):
        c = mtls_client()
        md = c.describe_key(KeyId="seal")["KeyMetadata"]
        self.assertEqual((md["KeyUsage"], md["KeySpec"]), ("ENCRYPT_DECRYPT", "SYMMETRIC_DEFAULT"))
        enc = c.encrypt(KeyId="alias/seal", Plaintext=b"hello")
        dec = c.decrypt(CiphertextBlob=enc["CiphertextBlob"])  # no KeyId, as services do
        self.assertEqual((dec["Plaintext"], dec["KeyId"]), (b"hello", enc["KeyId"]))
        dk = c.generate_data_key(KeyId="seal", KeySpec="AES_256")
        self.assertEqual(len(dk["Plaintext"]), 32)
        self.assertEqual(c.decrypt(CiphertextBlob=dk["CiphertextBlob"], KeyId="seal")["Plaintext"], dk["Plaintext"])
        re = c.re_encrypt(CiphertextBlob=enc["CiphertextBlob"], DestinationKeyId="seal")
        self.assertEqual(c.decrypt(CiphertextBlob=re["CiphertextBlob"])["Plaintext"], b"hello")
        self.assertEqual(len(c.generate_random(NumberOfBytes=40)["Plaintext"]), 40)
        bad = bytearray(enc["CiphertextBlob"]); bad[-2] ^= 1
        with self.assertRaises(ClientError) as e:
            c.decrypt(CiphertextBlob=bytes(bad))
        self.assertEqual(code(e), "InvalidCiphertextException")
        with self.assertRaises(ClientError) as e:
            c.encrypt(KeyId="etcd", Plaintext=b"x")
        self.assertEqual(code(e), "InvalidKeyUsageException")

    def test_sign_and_verify(self):
        c = mtls_client()
        pk = c.get_public_key(KeyId="sig")
        self.assertEqual((pk["KeyUsage"], pk["SigningAlgorithms"]), ("SIGN_VERIFY", ["ECDSA_SHA_256"]))
        pub = serialization.load_der_public_key(pk["PublicKey"])
        msg = b"release v1.0.0"
        sg = c.sign(KeyId="alias/sig", Message=msg, SigningAlgorithm="ECDSA_SHA_256")
        pub.verify(sg["Signature"], msg, ec.ECDSA(hashes.SHA256()))  # raises when it does not verify
        self.assertTrue(c.verify(KeyId="sig", Message=msg, Signature=sg["Signature"], SigningAlgorithm="ECDSA_SHA_256")["SignatureValid"])
        with self.assertRaises(ClientError) as e:
            c.verify(KeyId="sig", Message=b"other", Signature=sg["Signature"], SigningAlgorithm="ECDSA_SHA_256")
        self.assertEqual(code(e), "KMSInvalidSignatureException")

    def test_errors(self):
        c = mtls_client()
        der = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        for key in ("hidden", "nope"):
            with self.assertRaises(ClientError) as e:
                c.derive_shared_secret(KeyId=key, KeyAgreementAlgorithm="ECDH", PublicKey=der)
            self.assertEqual(code(e), "AccessDeniedException", key)
        with self.assertRaises(ClientError) as e:
            c.derive_shared_secret(KeyId="etcd", KeyAgreementAlgorithm="ECDH", PublicKey=der, DryRun=True)
        self.assertEqual(code(e), "DryRunOperationException")
        with self.assertRaises(ClientError) as e:
            c.derive_shared_secret(KeyId="etcd", KeyAgreementAlgorithm="ECDH", PublicKey=b"junk")
        self.assertEqual(code(e), "ValidationException")
        with self.assertRaises(ClientError) as e:
            mtls_client(secret="this-is-not-the-secret-0123456789").derive_shared_secret(KeyId="etcd", KeyAgreementAlgorithm="ECDH", PublicKey=der)
        self.assertEqual(code(e), "InvalidSignatureException")
        with self.assertRaises(ClientError) as e:
            mtls_client(akid="AKIDNOBODYNOBODYNOBODY").derive_shared_secret(KeyId="etcd", KeyAgreementAlgorithm="ECDH", PublicKey=der)
        self.assertEqual(code(e), "UnrecognizedClientException")
        with self.assertRaises(ClientError) as e:
            c.schedule_key_deletion(KeyId="etcd")
        self.assertEqual(code(e), "UnsupportedOperationException")


if __name__ == "__main__":
    unittest.main(verbosity=2)
