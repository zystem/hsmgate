# Supported versions

The rule is in [SECURITY.md](../SECURITY.md), "What is supported": the **latest release** gets every security fix; the **previous minor release** gets fixes for High and Critical problems for 30 days after the new minor release; anything older gets none. A new patch release (0.7.1 after 0.7.0) replaces the one before it: update.

| Release | Date | Status |
|---|---|---|
| **0.7.3** | 2026-11-11 | supported: the latest (a security fix, GO-2026-6859: update from 0.7.2) |
| 0.7.2, 0.7.1, 0.7.0 | 2026-11-10, 2026-11-09, 2026-11-03 | replaced by 0.7.3: update (patch releases) |
| 0.6.0 | 2026-10-23 | previous minor: High and Critical fixes only, **until 2026-12-03**; then not supported |
| 0.5.x and older | 2026-10-20 to 2026-10-23 | not supported |

How to read it: while the project is 0.x a minor release may change the configuration or the formats; [upgrading.md](upgrading.md) lists what each one changed, and `hsmgate check -config ...` with the new binary tells whether your file still loads (it needs no PIN). What is sealed in a format that is still supported (`ecies2`, `ecies3`, `ecies4`: every suite is always read, [key-management.md](key-management.md)) stays readable across releases. The old `ecies1` was dropped at 0.4: `rewrap` such texts with 0.3.x first ([upgrading.md](upgrading.md)).

The Helm chart has the version of the release it was made with (`helm install ... --version 0.7.3` starts the image of the same release). Releases, their signatures and their SBOM: [GitHub releases](https://github.com/zystem/hsmgate/releases), [verifying-releases.md](verifying-releases.md).

This page is updated by each release ([releasing.md](releasing.md)).
