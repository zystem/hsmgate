#!/usr/bin/env bash
# The PKCS#11 backend against SoftHSM2: a throw-away token with an EC P-256 key, then the Go test that logs in and does ECDH on it; then the built-in CA (hsmgate ca) with its
# key on the token (a signing key) and sealed to the token (the ECDH key), the certificates it makes checked with openssl.
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

# the built-in certificate authority (hsmgate ca), its key on the token and sealed to it; the certificates it makes are checked with openssl
pkcs11-tool --module "$MODULE" --token-label hsmgate-test --login --pin "$(cat "$T/pin")" \
  --keypairgen --key-type EC:prime256v1 --id 02 --label ca-sign --usage-sign >/dev/null
go build -o "$T/hsmgate" ./cmd/hsmgate
cat > "$T/hsmgate.yaml" <<YAML
tokens:
  - name: card
    type: pkcs11
    module: $MODULE
    token_label: hsmgate-test
    keys: {master: "01", ca-sign: "02"}
YAML
for mode in token sealed; do
  label=ca-sign
  [ "$mode" = sealed ] && label=master
  d="$T/ca-$mode"
  # sealing needs no PIN; a key on the token needs one to sign the certificate of the authority
  "$T/hsmgate" ca init -dir "$d" -mode "$mode" -config "$T/hsmgate.yaml" -token card -label "$label" -pin-stdin < "$T/pin"
  test ! -e "$d/ca.key"
  "$T/hsmgate" ca server -dir "$d" -out "$T/out-$mode" -ip 127.0.0.1 -config "$T/hsmgate.yaml" -pin-stdin < "$T/pin"
  "$T/hsmgate" ca client -dir "$d" -out "$T/out-$mode" -cn demo -config "$T/hsmgate.yaml" -pin-stdin < "$T/pin"
  openssl verify -CAfile "$T/out-$mode/ca.pem" -purpose sslserver "$T/out-$mode/server.pem"
  openssl verify -CAfile "$T/out-$mode/ca.pem" -purpose sslclient "$T/out-$mode/demo.pem"
done
echo "built-in CA on SoftHSM2: ok"
