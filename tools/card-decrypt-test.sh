#!/usr/bin/env bash
# Round trip through hsmgate on the real SmartCard-HSM: encrypt (public key only), then decrypt (login, then ECDH on the card).
#   PIN_FILE=/path/to/pin-file tools/card-decrypt-test.sh
# The PIN is read by hsmgate itself from the file, tried ONCE; this script never reads or prints it. A refused PIN costs one of the card's 3 tries.
set -euo pipefail
PIN_FILE="${PIN_FILE:?set PIN_FILE to the file that holds the user PIN}"
MODULE="${MODULE:-/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so}"
KEY_ID="${KEY_ID:-0123456789abcdef0123456789abcdef01234567}"
LABEL="${TOKEN_LABEL:-cinim}"
PORT="${PORT:-18302}"
here="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; pid=""
trap '[ -n "$pid" ] && kill "$pid" 2>/dev/null; rm -rf "$T"' EXIT
(cd "$here" && go build -o "$T/hsmgate" ./cmd/hsmgate)
cat > "$T/c.yaml" <<YAML
listen: 127.0.0.1:$PORT
insecure_loopback_client: tester
audit: {file: $T/audit.log}
tokens:
  - {name: card, type: pkcs11, module: $MODULE, token_label: $LABEL, pin_file: $PIN_FILE, keys: {m: $KEY_ID}}
keys:
  k: {versions: [{token: card, label: m}], aad: {mode: context, allow: ["cinim/dek/v1|"]}}
clients:
  - {name: tester, identity: {cn: tester}, keys: {k: {ops: [encrypt, decrypt]}}}
YAML
"$T/hsmgate" serve -config "$T/c.yaml" 2>"$T/err.log" & pid=$!
sleep 2
cat "$T/err.log"
CTX=$(printf 'cinim/dek/v1|t1' | base64)
PLAIN=$(printf '0123456789abcdef' | base64)
CT=$(curl -s -X PUT "localhost:$PORT/v1/transit/encrypt/k" -d "{\"plaintext\":\"$PLAIN\",\"context\":\"$CTX\"}" | python3 -c "import sys,json;print(json.load(sys.stdin)['data']['ciphertext'])")
echo "encrypt ok: ${CT:0:24}..."
s=$(date +%s.%N)
OUT=$(curl -s -X PUT "localhost:$PORT/v1/transit/decrypt/k" -d "{\"ciphertext\":\"$CT\",\"context\":\"$CTX\"}")
e=$(date +%s.%N)
GOT=$(printf '%s' "$OUT" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['data']['plaintext'] if 'data' in d else d)")
if [ "$GOT" = "$PLAIN" ]; then echo "decrypt on the card: OK ($(awk -v a="$s" -v b="$e" 'BEGIN{printf "%.3f", b-a}') s)"; else echo "decrypt FAILED: $GOT"; exit 1; fi
echo "wrong context must fail:"; curl -s -o /dev/null -w "  HTTP %{http_code}\n" -X PUT "localhost:$PORT/v1/transit/decrypt/k" -d "{\"ciphertext\":\"$CT\",\"context\":\"$(printf 'cinim/dek/v1|t2' | base64)\"}"
echo "audit:"; cut -c1-150 "$T/audit.log"
