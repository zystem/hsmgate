#!/usr/bin/env bash
# The PKCS#11 backend against SoftHSM2: a throw-away token with an EC P-256 key, then the Go test that logs in and does ECDH on it.
# Needs softhsm2-util, pkcs11-tool (opensc) and the SoftHSM2 module. NOT run by the author (they are not installed on the development machine); CI runs it.
set -euo pipefail
MODULE="${SOFTHSM2_MODULE:-$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so 2>/dev/null | head -1)}"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
mkdir "$T/tokens"
printf 'directories.tokendir = %s\nobjectstore.backend = file\n' "$T/tokens" > "$T/softhsm2.conf"
export SOFTHSM2_CONF="$T/softhsm2.conf"
printf '123456' > "$T/pin"
softhsm2-util --init-token --free --label hsmgate-test --so-pin 87654321 --pin "$(cat "$T/pin")" >/dev/null
pkcs11-tool --module "$MODULE" --token-label hsmgate-test --login --pin "$(cat "$T/pin")" \
  --keypairgen --key-type EC:prime256v1 --id 01 --label master --usage-derive >/dev/null
cd "$(dirname "$0")/.."
HSMGATE_P11_MODULE="$MODULE" HSMGATE_P11_KEY_ID=01 HSMGATE_P11_TOKEN_LABEL=hsmgate-test HSMGATE_P11_PIN_FILE="$T/pin" \
  go test -count=1 -run 'RealModule' -v ./internal/backend
