# Verifying a release

Every release (a tag `v*`) is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on a GitHub-hosted runner, never by hand. The files, the image, the SBOM and their signatures are produced in that one run. Verify before you run: a release that fails any of these checks must not be used; report it as in [SECURITY.md](../SECURITY.md).

The assets of release `vX.Y.Z` (https://github.com/zystem/hsmgate/releases): `hsmgate-linux-amd64` (the binary), `hsmgate-linux-amd64.sha256`, `hsmgate-deploy.tar.gz` (the deployment files and the docs), `hsmgate.spdx.json` (the software bill of materials, SPDX), and a `*.sigstore.json` bundle for the binary, the archive and the SBOM. The image is `ghcr.io/zystem/hsmgate:vX.Y.Z`.

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

The same for `hsmgate-deploy.tar.gz` and `hsmgate.spdx.json` with their own bundles. The build provenance attestation (SLSA) says from which commit and workflow run the file was built:

```bash
gh attestation verify hsmgate-linux-amd64 -R zystem/hsmgate
```

## The image

```bash
cosign verify ghcr.io/zystem/hsmgate@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/zystem/hsmgate/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/zystem/hsmgate:vX.Y.Z -R zystem/hsmgate
```

Run by the digest (`image: ghcr.io/zystem/hsmgate:vX.Y.Z@sha256:…`, as `deploy/docker/compose.yaml` does), not by a tag that can move. The digest of a release is in the log of its workflow run and in `docker buildx imagetools inspect`.

These commands were run against v0.4.0 and succeeded.
