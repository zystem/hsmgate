#!/bin/sh
# The same for the rpm, in a Fedora or Rocky/Alma container.  docker run --rm -v "$PWD/dist:/t:ro" -v "$PWD/packaging/test:/p:ro" fedora:latest sh /p/test-rpm.sh auto
set -eu
. "$(dirname "$0")/lib.sh"
RPM=$(ls /t/hsmgate-*.rpm | head -n1)
# the minimal Fedora image has no runuser (the tests run the service as its own user with it)
dnf install -y -q util-linux >/dev/null 2>&1 || true
case "${1:?plain or auto}" in
plain)
    dnf install -y -q "$RPM" >/tmp/a.log 2>&1 || { cat /tmp/a.log; fail "dnf install"; }
    expect "the account hsmgate exists" getent passwd hsmgate
    expect "/etc/hsmgate is root:hsmgate 0750" sh -c '[ "$(stat -c "%U:%G %a" /etc/hsmgate)" = "root:hsmgate 750" ]'
    expect "no configuration was made" sh -c '[ ! -e /etc/hsmgate/hsmgate.yaml ]'
    expect "hsmgate runs" hsmgate version
    expect "hsmgate-setup runs" hsmgate-setup -version
    expect "the unit is installed" test -f /usr/lib/systemd/system/hsmgate.service
    expect "the polkit rule for the service account is installed" grep -q "s.user == \"hsmgate\"" /usr/share/polkit-1/rules.d/50-hsmgate.rules
    ;;
auto)
    HSMGATE_SETUP_AUTO=1 dnf install -y -q "$RPM" >/tmp/b.log 2>&1 || { cat /tmp/b.log; fail "dnf install"; }
    expect "the configuration was made" test -s /etc/hsmgate/hsmgate.yaml
    expect "hsmgate check passes as the service user" runuser -u hsmgate -- hsmgate check -config /etc/hsmgate/hsmgate.yaml
    start_service /etc/hsmgate/hsmgate.yaml hsmgate
    roundtrip /tmp/b.log
    kill "$SERVICE_PID" 2>/dev/null || true
    rpm -e hsmgate >/tmp/r.log 2>&1
    expect "removal keeps the configuration and the authority" sh -c '[ -e /etc/hsmgate/hsmgate.yaml ] && [ -e /etc/hsmgate/ca/ca.key ]'
    ;;
*) fail "plain or auto" ;;
esac
echo "PASS ($1)"
