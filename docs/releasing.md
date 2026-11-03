# Making a release

For a maintainer (either of the two, [GOVERNANCE.md](../GOVERNANCE.md)). A release is a signed tag `vX.Y.Z` on `main`; the workflow [`release.yml`](../.github/workflows/release.yml) does the rest: the tests again, the binary and its FIPS variant, the images on ghcr.io, the signatures (keyless), the build provenance, the SBOM and the VEX document, and the GitHub release. Nothing needs a secret that a person holds.

## Before

1. `main` is green (the checks of the last run on it) and there is nothing open that must go in. `git pull` on `main`.
2. Choose the number ([Semantic Versioning](https://semver.org/): a fix or a change of documents only is the third number; a new feature the second; a break of compatibility the first, while it is 0.x the second). Read what has gone in since the last tag (`git log vPREV..main --oneline`).

## The release pull request

3. A branch `release-X.Y.Z`. In `CHANGELOG.md` the heading `## Unreleased` becomes `## X.Y.Z — DATE`, and what is missing from it is added (user-visible changes, security fixes with their identifiers).
4. In `vex/hsmgate.openvex.json`: raise `version`, set `timestamp`, and add the images `vX.Y.Z` and `vX.Y.Z-fips` to the products of the statements that hold for them (for example the OpenSSL finding that is `not_affected`). Check it: `go run github.com/openvex/vexctl@v0.4.1 merge vex/hsmgate.openvex.json`. If a scanner has reported a new finding in a shipped component since the last release, account for it in the document (see [security-policies.md](security-policies.md)) or fix it first.
5. Commit with a sign-off (`git commit -s`), push, open the pull request, wait for the checks, merge.

## The tag

6. `git checkout main && git pull`, then a signed annotated tag: `git tag -m "vX.Y.Z" vX.Y.Z` (with `gpg.format ssh`, `user.signingkey` set to your public key and `tag.gpgSign true`; see below), check it with `git tag -v vX.Y.Z`, and push it: `git push origin vX.Y.Z`. The tag starts the workflow `Release`.
7. Wait for it (`gh run watch`). It runs `ci.yml` first and publishes only if that passes.

## After

8. Check what was made, as a user would ([verifying-releases.md](verifying-releases.md)): the assets of the release (binary, FIPS binary, archive, SBOM, VEX, each with a `.sigstore.json`, and the `.sha256` files), `cosign verify-blob` of each, `gh attestation verify`, `cosign verify` (cosign 3 or later) and `gh attestation verify oci://…` of both images, and `govulncheck -mode=binary` on the binary.
9. In `compose.yaml` the example image is a release and a digest; Dependabot proposes the bump, merge it.
10. If something is wrong with a release, do not move the tag: fix on `main` and make the next release; say what was wrong in its notes.

## Setting up the signature of a tag (once)

```bash
git config --local gpg.format ssh
git config --local user.signingkey ~/.ssh/KEY.pub          # your public key (the private one in ssh-agent)
git config --local tag.gpgSign true
```

Add the public key to your GitHub account as a **signing key** (Settings → SSH and GPG keys → New SSH key → Signing Key), so that the tag shows "Verified", and add it, with your GitHub login, to the list in [verifying-releases.md](verifying-releases.md) in a pull request.
