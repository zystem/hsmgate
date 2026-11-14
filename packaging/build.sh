#!/bin/sh
# Builds the packages: deb and rpm (nfpm) and the AppImage, from the programs in build/ (hsmgate, hsmgate-setup).
#
#   packaging/build.sh VERSION            for example 0.8.1 (no leading v); the files go to dist/
#
# BUILD_DIR (default build) is where the programs are, DIST_DIR (default dist) where the files go.
# Needs: the programs in build/ (see "Build" in .github/workflows/ci.yml for how a release builds them), Go (for nfpm), and for the AppImage curl, sha256sum and a tool that can unpack
# a squashfs image (appimagetool is itself an AppImage: it runs with --appimage-extract-and-run, so FUSE is not needed).
# The tools are pinned, and the downloaded one is checked against a hash that is written here.
set -eu

VERSION="${1:?usage: packaging/build.sh VERSION (for example 0.8.1)}"
VERSION="${VERSION#v}"
ARCH="${ARCH:-amd64}"
NFPM_VERSION="v2.48.0"
APPIMAGETOOL_URL="https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage"
APPIMAGETOOL_SHA256="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0"

cd "$(dirname "$0")/.."
BUILD_DIR="${BUILD_DIR:-build}"
DIST_DIR="${DIST_DIR:-dist}"
export BUILD_DIR
for f in "$BUILD_DIR/hsmgate" "$BUILD_DIR/hsmgate-setup"; do
    [ -x "$f" ] || { echo "missing $f: build the programs first" >&2; exit 1; }
done
mkdir -p "$DIST_DIR"

echo "== deb and rpm"
# nfpm expands environment variables only in some fields (not in the paths of the files), so the three placeholders are filled in here and the configuration goes to nfpm on its standard input
for kind in deb rpm; do
    sed -e "s|\${BUILD_DIR}|$BUILD_DIR|g" -e "s|\${VERSION}|$VERSION|g" -e "s|\${ARCH}|$ARCH|g" packaging/nfpm.yaml |
        go run "github.com/goreleaser/nfpm/v2/cmd/nfpm@${NFPM_VERSION}" package --config /dev/stdin --packager "$kind" --target "$DIST_DIR/"
done

echo "== AppImage"
command -v file >/dev/null || { echo "the AppImage needs the file(1) command (apt install file)" >&2; exit 1; }
tool="${TMPDIR:-/tmp}/appimagetool-1.9.1-x86_64.AppImage"
if [ ! -x "$tool" ]; then
    curl -fsSL -o "$tool" "$APPIMAGETOOL_URL"
    echo "$APPIMAGETOOL_SHA256  $tool" | sha256sum -c -
    chmod +x "$tool"
fi
appdir="$(mktemp -d)/hsmgate.AppDir"
mkdir -p "$appdir/usr/bin" "$appdir/usr/share/doc/hsmgate"
cp "$BUILD_DIR/hsmgate" "$BUILD_DIR/hsmgate-setup" "$appdir/usr/bin/"
cp packaging/appimage/AppRun "$appdir/AppRun"
cp packaging/appimage/hsmgate.desktop "$appdir/hsmgate.desktop"
cp packaging/appimage/hsmgate.png "$appdir/hsmgate.png"
cp deploy/hsmgate.example.yaml deploy/hsmgate.minimal.yaml README.md LICENSE "$appdir/usr/share/doc/hsmgate/"
chmod 755 "$appdir/AppRun"
ARCH=x86_64 "$tool" --appimage-extract-and-run --no-appstream "$appdir" "$DIST_DIR/hsmgate-${VERSION}-x86_64.AppImage"
ls -l "$DIST_DIR/"
