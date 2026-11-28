# Verifying a release

Every release (a tag `v*`) is built by [`.github/workflows/release.yml`](../.github/workflows/release.yml) on a GitHub-hosted runner, never by hand. The files, the image, the SBOM and their signatures are produced in that one run. Verify before you run: a release that fails any of these checks must not be used; report it as in [SECURITY.md](../SECURITY.md).

The assets of release `vX.Y.Z` (https://github.com/zystem/hsmgate/releases): `hsmgate-linux-amd64` (the binary), `hsmgate-linux-amd64-fips` (the same program built with the frozen Go cryptographic module, see below) with a `.sha256` file for each, `hsmgate-deploy.tar.gz` (the deployment files and the docs), `hsmgate.spdx.json` (the software bill of materials, SPDX), `hsmgate.openvex.json` (the VEX document: which known vulnerabilities do or do not affect the release), `hsmgate-setup-linux-amd64` (the terminal tool, with a `.sha256` file), the packages `hsmgate_X.Y.Z_amd64.deb`, `hsmgate-X.Y.Z-1.x86_64.rpm` and `hsmgate-X.Y.Z-x86_64.AppImage` ([installing-packages.md](installing-packages.md)), and a `*.sigstore.json` bundle for every file above except the `.sha256` files (verified with `cosign verify-blob`). **The build provenance attestation (`gh attestation verify`) covers the binaries, the three packages, the chart `hsmgate-X.Y.Z.tgz` and `hsmgate-deploy.tar.gz`; it does not cover the SBOM and the VEX document**, which carry the `cosign` signature only (their `gh attestation verify` says "Not Found", and that is expected). The images are `ghcr.io/zystem/hsmgate:vX.Y.Z` and `ghcr.io/zystem/hsmgate:vX.Y.Z-fips`.

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

The same for every other file with its own bundle: `hsmgate-linux-amd64-fips`, `hsmgate-setup-linux-amd64`, the deb, the rpm, the AppImage, `hsmgate-X.Y.Z.tgz`, `hsmgate-deploy.tar.gz`, `hsmgate.spdx.json` (the SBOM) and `hsmgate.openvex.json` (the VEX document). The SBOM and the VEX document are checked **only** this way: the signature says that this release workflow made them, and there is no provenance attestation for them. The build provenance attestation (SLSA) of the other files says from which commit and workflow run the file was built:

```bash
gh attestation verify hsmgate-linux-amd64 -R zystem/hsmgate
```

Run on 2026-11-15 on the release v0.9.1: `cosign verify-blob` passed for all 10 files that have a bundle (the three binaries are among them, the three packages, the chart, the archive, the SBOM and the VEX document), `gh attestation verify` passed for the 8 files that have an attestation and answered "Not Found" for the SBOM and the VEX document, `cosign verify` and `gh attestation verify oci://` passed for both images and the chart. Not run: the same for an older release.

Run on 2026-11-19 on the release v0.9.3 (cosign 3.0.2, `gh attestation verify`): `cosign verify-blob` passed for all 10 files that have a bundle, the `.sha256` of the three programs matched, `gh attestation verify` passed for the 8 files that have an attestation, `cosign verify` and `gh attestation verify oci://…` passed for both images (`v0.9.3`, `v0.9.3-fips`), `cosign verify` for the chart and `gh attestation verify` for it, and `govulncheck -mode=binary` found no vulnerability in `hsmgate-linux-amd64` and `hsmgate-setup-linux-amd64`. The tag was signed with the SSH key of the maintainer (`git tag -v`: good signature). The `hsmgate-linux-amd64-fips` binary was not run through `govulncheck`.

Run on 2026-11-20 on the release v0.9.4 (cosign 3.0.2, `gh attestation verify`, `govulncheck` from golang.org/x/vuln v1.10.0): `cosign verify-blob` passed for all 10 files that have a bundle, the `.sha256` of the three programs matched, `gh attestation verify` passed for the 8 files that have an attestation, `cosign verify` and `gh attestation verify oci://…` passed for both images (`v0.9.4`, `v0.9.4-fips`), `cosign verify` for the chart and `gh attestation verify` for its `.tgz`, and `govulncheck -mode=binary` found no vulnerability in `hsmgate-linux-amd64` and `hsmgate-setup-linux-amd64`. The tag was signed with the SSH key of the maintainer (`git tag -v`: good signature). `test-deb.sh auto` passed in `debian:13` with the files of the release; `test-appimage.sh` passed in `debian:13` on a copy of the AppImage whose bytes 8 to 10 (the AppImage magic) were zeroed, because the machine of the run has the AppImageLauncher handler registered in `binfmt_misc`, which takes the file and fails in a container ("not found"); the signature of the file was checked before, on the original. The same `test-appimage.sh` passed on the original, unchanged AppImage on AlmaLinux 10.2 with SELinux enforcing (a virtual machine, no AppImageLauncher), with no AVC denial; it runs in the user's domain, not in `hsmgate_t`. Not run: `gh attestation verify` for the chart by its OCI reference; `hsmgate-linux-amd64-fips` through `govulncheck`.

Run on 2026-11-27 on the release v0.10.0 (cosign 3.0.2, `gh attestation verify`, `govulncheck` from golang.org/x/vuln v1.10.0): `cosign verify-blob` passed for all 10 files that have a bundle, the `.sha256` of the three programs matched, `gh attestation verify` passed for the 8 files that have an attestation (not for the SBOM and the VEX document, as expected), `cosign verify` and `gh attestation verify oci://…` passed for both images (`v0.10.0`, `v0.10.0-fips`) and for the chart (the pulled `.tgz` is the same file as the asset), and `govulncheck -mode=binary` found no vulnerability in `hsmgate-linux-amd64`, `hsmgate-linux-amd64-fips` and `hsmgate-setup-linux-amd64`. The tag was signed with the SSH key of the maintainer (`git tag -v`: good signature). `test-deb.sh auto` passed in `debian:13` with the files of the release; `test-appimage.sh` passed in `debian:13` on a copy of the AppImage with bytes 8 to 10 zeroed (the reason is in the note on v0.9.4 above). Not run: the rpm, the original AppImage, an upgrade from 0.9.4.

Run on 2026-11-28 on the release v0.10.1 (cosign 3.0.2, `gh attestation verify`, `govulncheck` from golang.org/x/vuln v1.10.0): `cosign verify-blob` passed for all 10 files that have a bundle, the `.sha256` of the three programs matched (the files name them under `dist/`, so that prefix was removed for `sha256sum -c`), `gh attestation verify` passed for the 8 files that have an attestation (not for the SBOM and the VEX document, as expected), `cosign verify` and `gh attestation verify oci://…` passed for both images (`v0.10.1`, `v0.10.1-fips`) and for the chart (the pulled `.tgz` is the same file as the asset), and `govulncheck -mode=binary` found no vulnerability in `hsmgate-linux-amd64`, `hsmgate-linux-amd64-fips` and `hsmgate-setup-linux-amd64`. The tag was signed with the SSH key of the maintainer (`git tag -v`: good signature). `test-deb.sh auto` passed in `debian:13` with the files of the release; `test-appimage.sh` passed in `debian:13` on a copy of the AppImage with bytes 8 to 10 zeroed (the reason is in the note on v0.9.4 above). Not run: the rpm, the original AppImage, an upgrade from 0.10.0.

## The FIPS variant

`hsmgate-linux-amd64-fips` and the image tagged `-fips` are built with `GOFIPS140=v1.0.0`: the Go cryptographic module, frozen at the version validated under FIPS 140-3, runs with `fips140=on` by default and its self-tests run at start. Use it with `require_fips: true` ([compliance.md](compliance.md)). Take it only when you need that mode: the frozen module does not get the fixes of newer Go releases to the cryptographic code until a newer module version is validated, and the mode refuses algorithms that are not approved (for example client certificates with RSA keys under 2048 bits). Its signature, hash and provenance are checked as above.

## The tag

From v0.4.1 on, the tag `vX.Y.Z` is an annotated tag signed with an SSH key by the maintainer who made the release (earlier tags, up to v0.4.0, are not signed). The maintainers' public keys are listed here; a maintainer adds their own when they first make a release ([releasing.md](releasing.md)). The key of `zystem` is

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPp5WWSw0xFjlzPEtln90NY8dc7MUvkun/14yTINPM/
```

(fingerprint `SHA256:lW4afK66UsIcTD4xXiwz2vutEsLvEYqYk+pTx+MuPHo`). To check a tag:

```bash
echo "10708003+zystem@users.noreply.github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHPp5WWSw0xFjlzPEtln90NY8dc7MUvkun/14yTINPM/" > allowed_signers
git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v vX.Y.Z
```

The key is also published on https://github.com/zystem.keys. The release assets are verified as above, independently of the tag.

## The Helm chart

The chart is an OCI artifact, `oci://ghcr.io/zystem/charts/hsmgate`, with the number of the release (without the `v`); the same `.tgz` is among the assets of the release, with a `.sigstore.json` and a build provenance attestation. Signed as the images are (keyless, by the release workflow):

```bash
cosign verify ghcr.io/zystem/charts/hsmgate@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/zystem/hsmgate/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
helm pull oci://ghcr.io/zystem/charts/hsmgate --version X.Y.Z    # or: helm install … --version X.Y.Z
```

The digest is printed by `helm pull` (`Digest:`) and by `helm push` in the log of the release. Use cosign 3 or later, as for the images.

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
