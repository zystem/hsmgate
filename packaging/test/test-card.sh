#!/bin/sh
# The card path of the quick setup, on SoftHSM2 (a software token that speaks PKCS#11): the deb, a token with a key pair made by pkcs11-tool, `hsmgate-setup -auto -mode card`, the service as
# its own user with the PIN read from a file, and a client sealing and opening a text with the key that stays on the "card".
#   docker run --rm -v "$PWD/dist:/t:ro" -v "$PWD/packaging/test:/p:ro" debian:13 sh /p/test-card.sh
set -eu
. "$(dirname "$0")/lib.sh"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq softhsm2 opensc "$(ls /t/hsmgate_*.deb | head -n1)" >/tmp/i.log 2>&1 || { cat /tmp/i.log; fail "apt-get install"; }
MODULE=$(ls /usr/lib/softhsm/libsofthsm2.so /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so 2>/dev/null | head -n1)
[ -n "$MODULE" ] || fail "no SoftHSM2 module"

mkdir -p /var/lib/hsm-test/tokens
printf 'directories.tokendir = /var/lib/hsm-test/tokens\nobjectstore.backend = file\n' > /var/lib/hsm-test/softhsm2.conf
export SOFTHSM2_CONF=/var/lib/hsm-test/softhsm2.conf
softhsm2-util --init-token --free --label cardtest --so-pin 87654321 --pin 123456 >/dev/null
pkcs11-tool --module "$MODULE" --token-label cardtest --login --pin 123456 --keypairgen --key-type EC:prime256v1 --id 01 --label master --usage-derive >/dev/null
chown -R hsmgate:hsmgate /var/lib/hsm-test
printf '123456' > /etc/hsmgate/pin; chown hsmgate:hsmgate /etc/hsmgate/pin; chmod 0400 /etc/hsmgate/pin
ok "a token with a key pair is on the 'card'"

hsmgate-setup -auto -mode card -module "$MODULE" -token-label cardtest -card-key-id 01 -pin-file /etc/hsmgate/pin -key orders -client shop >/tmp/b.log 2>&1 || { cat /tmp/b.log; fail "hsmgate-setup -auto -mode card"; }
expect "the configuration names the card and the key pair" sh -c 'grep -q "type: pkcs11" /etc/hsmgate/hsmgate.yaml && grep -q "token_label: cardtest" /etc/hsmgate/hsmgate.yaml'
expect "no key file was made (the key stays on the card)" sh -c '! ls /etc/hsmgate/soft-*.hex'
expect "the setup did not open the card (a card is checked by the service, not by the setup)" sh -c '! grep -q "hsmgate check: the configuration is good" /tmp/b.log'

# the service opens the card with the PIN file, as its own user
SOFTHSM2_CONF=/var/lib/hsm-test/softhsm2.conf start_service /etc/hsmgate/hsmgate.yaml hsmgate
# a text sealed and opened below needs one ECDH on the card, so the round trip is the proof that the card was opened with the PIN file
roundtrip /tmp/b.log
kill "$SERVICE_PID" 2>/dev/null || true
echo "PASS (card on SoftHSM2)"
