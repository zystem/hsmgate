# Verifying a release

Every release (a tag `v*`) is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on a GitHub-hosted runner, never by hand. The files, the image, the SBOM and their signatures are produced in that one run. Verify before you run: a release that fails any of these checks must not be used; report it as in [SECURITY.md](../SECURITY.md).

The assets of release `vX.Y.Z` (https://github.com/zystem/hsmgate/releases): `hsmgate-linux-amd64` (the binary), `hsmgate-linux-amd64-fips` (the same program built with the frozen Go cryptographic module, see below) with a `.sha256` file for each, `hsmgate-deploy.tar.gz` (the deployment files and the docs), `hsmgate.spdx.json` (the software bill of materials, SPDX), `hsmgate.openvex.json` (the VEX document: which known vulnerabilities do or do not affect the release), and a `*.sigstore.json` bundle for the binaries, the archive and the SBOM. The images are `ghcr.io/zystem/hsmgate:vX.Y.Z` and `ghcr.io/zystem/hsmgate:vX.Y.Z-fips`.

## Integrity (the content is what was built)

```bash
echo "$(cut -d' ' -f1 hsmgate-linux-amd64.sha256)  hsmgate-linux-amd64" | sha256sum -c -
```

(The `.sha256` file names the path `dist/hsmgate-linux-amd64`, so `sha256sum -c` on it directly needs that path; the command above compares the hash only.)

## Authenticity and identity (who built it: this repository's release workflow)

The signature is keyless (sigstore): the certificate names the workflow that signed, and a public log records it. The expected identity is the release workflow of `zystem/hsmgate` on a tag `v*`; the expected issuer is GitHub Actions.

```bash
cosign verify-blob \
  --bundle hsmgate-linux-amd64.sigstore.json \
  --certificate-identity-regexp '^https://github.com/zystem/hsmgate/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  hsmgate-linux-amd64
```

The same for `hsmgate-linux-amd64-fips`, `hsmgate-deploy.tar.gz`, `hsmgate.spdx.json` and `hsmgate.openvex.json` with their own bundles. The build provenance attestation (SLSA) says from which commit and workflow run the file was built:

```bash
gh attestation verify hsmgate-linux-amd64 -R zystem/hsmgate
```

## The FIPS variant

`hsmgate-linux-amd64-fips` and the image tagged `-fips` are built with `GOFIPS140=v1.0.0`: the Go cryptographic module, frozen at the version validated under FIPS 140-3, runs with `fips140=on` by default and its self-tests run at start. Use it with `require_fips: true` ([compliance.md](compliance.md)). Take it only when you need that mode: the frozen module does not get the fixes of newer Go releases to the cryptographic code until a newer module version is validated, and the mode refuses algorithms that are not approved (for example client certificates with RSA keys under 2048 bits). Its signature, hash and provenance are checked as above.

## The tag

From v0.4.1 on, the tag `vX.Y.Z` is an annotated tag signed by the maintainer with an SSH key (earlier tags, up to v0.4.0, are not signed). The public key of the maintainer, `zystem`, is

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPp5WWSw0xFjlzPEtln90NY8dc7MUvkun/14yTINPM/
```

(fingerprint `SHA256:lW4afK66UsIcTD4xXiwz2vutEsLvEYqYk+pTx+MuPHo`). To check a tag:

```bash
echo "10708003+zystem@users.noreply.github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPp5WWSw0xFjlzPEtln90NY8dc7MUvkun/14yTINPM/" > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v vX.Y.Z
```

The key is also published on https://github.com/zystem.keys. The release assets are verified as above, independently of the tag.

## The image

Use `cosign` 3 or later for the images: since cosign 3 the signature is stored as an OCI referrer in the new bundle format, which cosign 2 does not find ("no signatures found"). The blob bundles above verify with cosign 2.5 and 3.

```bash
cosign verify ghcr.io/zystem/hsmgate@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/zystem/hsmgate/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/zystem/hsmgate:vX.Y.Z -R zystem/hsmgate
```

Run by the digest (`image: ghcr.io/zystem/hsmgate:vX.Y.Z@sha256:…`, as `deploy/docker/compose.yaml` does), not by a tag that can move. The digest of a release is in the log of its workflow run and in `docker buildx imagetools inspect`.

These commands were run against v0.4.0 and succeeded.
