# Roadmap (October 2026 to October 2027)

What the project intends to do and not do in the next year. It is a plan of one maintainer, not a promise; items move when a user's need or a security problem asks for it. Done work is in [CHANGELOG.md](../CHANGELOG.md).

## Intends to do

1. **Use in production and fix what it shows**: the faces (Transit, KMS-JSON, gRPC, REST) have been tried with the official client libraries and some tools, and the Transit face with a cluster; real use by CiNim and others will show what the tests did not.
2. **Cover more client tools** that speak the key-service APIs: Vault/OpenBao seals, SOPS, Terraform and the like for the gRPC and REST faces, each with a test or a documented check.
3. **Supply chain**: keep the releases signed with provenance and a bill of materials; add a VEX statement for findings that do not affect the program; keep CI green and the dependencies current (Dependabot).
4. **Quality**: keep statement coverage at 80% or more and measured in CI; more fuzz targets for the new parsers; a regression test for every fixed bug.
5. **Documentation**: keep the specifications, the guides and the upgrade notes in step with the code; a short guide per face.
6. **A second maintainer and a second reviewer**, so that review by someone other than the author is possible (see [GOVERNANCE.md](../GOVERNANCE.md)).
7. **Badges**: the OpenSSF Best Practices badge at "passing", then "silver" as far as the project can honestly meet it.

## Considers (no date)

- A token backend for a TPM 2.0 chip (a machine-bound key; ECDH and ECDSA).
- A helper for rotation: a command that adds a version and re-seals data.
- Reproducible release builds checked by a second builder.

## Does not intend to do

- AES on the SmartCard-HSM (reasons in [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md)).
- A replay cache for the signed requests (decided against; reasons in the audit response).
- Creating, importing or destroying keys over the network: keys are in the configuration and on the token.
- Being a replacement for a certified payment HSM or a certified module ([compliance.md](compliance.md)).
- A web interface.
