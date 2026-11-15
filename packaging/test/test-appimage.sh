#!/bin/sh
# The AppImage as an ordinary user, with nothing installed and no FUSE (the AppImage unpacks itself: APPIMAGE_EXTRACT_AND_RUN=1).
#   docker run --rm -v "$PWD/dist:/t:ro" -v "$PWD/packaging/test:/p:ro" debian:13 sh /p/test-appimage.sh
set -eu
. "$(dirname "$0")/lib.sh"
IMG=$(ls /t/hsmgate-*.AppImage | head -n1)
id tester >/dev/null 2>&1 || useradd -m tester 2>/dev/null || adduser -D tester
cp "$IMG" /tmp/hsmgate.AppImage; chmod 755 /tmp/hsmgate.AppImage
run_as_tester() { runuser -u tester -- env APPIMAGE_EXTRACT_AND_RUN=1 HOME=/home/tester XDG_CONFIG_HOME=/home/tester/.config XDG_STATE_HOME=/home/tester/.state "$@"; }
expect "the AppImage runs the program" sh -c 'runuser -u tester -- env APPIMAGE_EXTRACT_AND_RUN=1 /tmp/hsmgate.AppImage version | grep -q "^hsmgate "'
expect "the AppImage runs the setup tool" sh -c 'runuser -u tester -- env APPIMAGE_EXTRACT_AND_RUN=1 /tmp/hsmgate.AppImage setup -version | grep -q "^hsmgate-setup "'
run_as_tester /tmp/hsmgate.AppImage setup -auto -listen 127.0.0.1:18443 >/tmp/b.log 2>&1 || { cat /tmp/b.log; fail "setup -auto"; }
expect "everything is in the home of the user" test -s /home/tester/.config/hsmgate/hsmgate.yaml
run_as_tester /tmp/hsmgate.AppImage serve -config /home/tester/.config/hsmgate/hsmgate.yaml >/tmp/serve.log 2>&1 &
SERVICE_PID=$!
i=0; while ! grep -q "listening on" /tmp/serve.log 2>/dev/null; do i=$((i+1)); [ $i -lt 100 ] || { cat /tmp/serve.log >&2; fail "the service did not start"; }; sleep 0.2; done
ok "the service listens: $(grep -m1 listening /tmp/serve.log)"
line=$(grep -m1 'export HSMGATE_ADDR' /tmp/b.log | tr -d '\r' | sed 's/^ *//')
[ -n "$line" ] || fail "no try-it commands"
run_as_tester sh -c "$line; echo 'my secret' | /tmp/hsmgate.AppImage encrypt > /tmp/s.txt && [ \"\$(/tmp/hsmgate.AppImage decrypt < /tmp/s.txt)\" = 'my secret' ]" || fail "the roundtrip"
ok "a client sealed and opened a text"
kill "$SERVICE_PID" 2>/dev/null || true
echo "PASS (appimage)"
