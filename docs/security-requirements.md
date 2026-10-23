# What a user can and cannot expect, in security

## Can expect

- **The private key does not leave the token.** The service asks the token for one ECDH or one signature; it holds no key material of its own. A stolen disk or process image of the service holds no private key (it may hold the PIN of an unlocked token in memory: see below).
- **A client does only what its policy allows**, on the keys named in it, within its rate limits; deny by default. A key that does not exist, is not on the face or is not granted gives one answer.
- **Everything is written down before it is answered.** If the audit line cannot be written, the call fails and nothing is returned.
- **A sealed text is bound to its place**: the key name, the version and the context are authenticated, so a text cannot be moved to another key, version or tenant.
- **Authenticated, encrypted transport**: TLS 1.3 only; client certificates and/or signed credentials; secrets only in files with strict owner and mode, never in the configuration, environment or logs.
- **Releases you can check**: signed, with build provenance and a bill of materials ([verifying-releases.md](verifying-releases.md)).
- **Approved algorithms**: ECDH and ECDSA on P-256, AES-256-GCM, HKDF and HMAC with SHA-256 ([compliance.md](compliance.md), [key-management.md](key-management.md)).

## Cannot expect

- **Protection from a compromised host.** Whoever is root on the service host can read the PIN from memory and drive the token while it is unlocked, and can forge the audit log. Put the audit log on another machine ([threat-model.md](threat-model.md)).
- **Protection from a compromised client beyond its grants**: it can do exactly what its policy allows. Give each client its own keys and rate limits.
- **Availability of the token**: one card is one machine; the service is not a cluster. A lost card without a backup (the DKEK scheme and a spare card) loses the data sealed to it.
- **Side-channel resistance inside the token, or protection from a malicious PKCS#11 module.**
- **A certified module or device.** The project is not FIPS 140-3, PCI HSM or Common Criteria certified and does not claim it.
- **Confidentiality of the plaintext from the service while it works**: on the faces where the service seals and opens, it sees the plaintext for the time of the operation (it is not logged and is wiped after use). Use key agreement (the client seals and opens) when the service must not see a data key.
- **Hiding the length of a sealed secret, or who sealed it**: anyone with a public key can seal.
- **Fixes for old releases** beyond what [SECURITY.md](../SECURITY.md) says.
