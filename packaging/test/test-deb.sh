#!/bin/sh
# Installs the deb from /t in a clean Debian or Ubuntu container and checks what the package promises.
#   test-deb.sh plain   nobody at the keyboard: installed, not configured, a hint is printed, nothing is started
#   test-deb.sh wizard  somebody at a terminal: the quick setup starts by itself, its keys are pressed
#   test-deb.sh auto    HSMGATE_SETUP_AUTO=1: configured, the service runs as its own user, a client seals and opens a text; removal and purge keep the keys
# usage (from the repository):  docker run --rm -v "$PWD/dist:/t:ro" -v "$PWD/packaging/test:/p:ro" debian:13 sh /p/test-deb.sh auto
set -eu
. "$(dirname "$0")/lib.sh"
export DEBIAN_FRONTEND=noninteractive
DEB=$(ls /t/hsmgate_*.deb | head -n1)
apt-get update -qq >/dev/null 2>&1 || true
case "${1:?plain or auto}" in
plain)
    apt-get install -y -qq "$DEB" >/tmp/a.log 2>&1 || { cat /tmp/a.log; fail "apt-get install"; }
    expect "the account hsmgate is a system account with no login" sh -c 'getent passwd hsmgate | grep -q "nologin"'
    expect "/etc/hsmgate is root:hsmgate 0750" sh -c '[ "$(stat -c "%U:%G %a" /etc/hsmgate)" = "root:hsmgate 750" ]'
    expect "/var/log/hsmgate is hsmgate:hsmgate 0750" sh -c '[ "$(stat -c "%U:%G %a" /var/log/hsmgate)" = "hsmgate:hsmgate 750" ]'
    expect "no configuration was made" sh -c '[ ! -e /etc/hsmgate/hsmgate.yaml ]'
    expect "the installation said what to do" grep -q "Run 'sudo hsmgate-setup'" /tmp/a.log
    expect "hsmgate runs" hsmgate version
    expect "hsmgate-setup runs" hsmgate-setup -version
    expect "hsmgate setup -h works" sh -c 'hsmgate setup -h | grep -q hsmgate-setup'
    expect "the unit is installed" sh -c '[ -f /lib/systemd/system/hsmgate.service ] && grep -q "ConditionPathExists=/etc/hsmgate/hsmgate.yaml" /lib/systemd/system/hsmgate.service'
    expect "the polkit rule for the service account is installed" sh -c 'grep -q "s.user == \"hsmgate\"" /usr/share/polkit-1/rules.d/50-hsmgate.rules'
    ;;
auto)
    HSMGATE_SETUP_AUTO=1 apt-get install -y -qq "$DEB" >/tmp/b.log 2>&1 || { cat /tmp/b.log; fail "apt-get install"; }
    expect "the configuration was made" test -s /etc/hsmgate/hsmgate.yaml
    expect "the configuration is readable by the service group, not by others" sh -c '[ "$(stat -c "%U:%G %a" /etc/hsmgate/hsmgate.yaml)" = "root:hsmgate 640" ]'
    expect "the key file is the service's, mode 0400" sh -c '[ "$(stat -c "%U %a" /etc/hsmgate/soft-app-1.hex)" = "hsmgate 400" ]'
    expect "the authority's key is root's and private" sh -c '[ "$(stat -c "%U %a" /etc/hsmgate/ca/ca.key)" = "root 600" ]'
    expect "hsmgate check passes as the service user" runuser -u hsmgate -- hsmgate check -config /etc/hsmgate/hsmgate.yaml
    start_service /etc/hsmgate/hsmgate.yaml hsmgate
    roundtrip /tmp/b.log
    expect "the audit file belongs to the service and has the decisions" sh -c '[ "$(stat -c "%U" /var/log/hsmgate/audit.log)" = "hsmgate" ] && grep -q "\"op\":\"decrypt\",\"result\":\"ok\"" /var/log/hsmgate/audit.log'
    kill "$SERVICE_PID" 2>/dev/null || true
    apt-get remove -y -qq hsmgate >/tmp/r.log 2>&1
    expect "removal says the keys are kept" grep -q "are kept" /tmp/r.log
    apt-get purge -y -qq hsmgate >/tmp/p.log 2>&1
    expect "purge keeps the configuration, the authority and the account" sh -c '[ -e /etc/hsmgate/hsmgate.yaml ] && [ -e /etc/hsmgate/ca/ca.key ] && getent passwd hsmgate >/dev/null'
    ;;
wizard)
    # somebody is at the keyboard: apt-get runs on a terminal (script makes one), the quick setup starts by itself, and the keys of the wizard are pressed
    apt-get install -y -qq util-linux >/dev/null 2>&1 || true
    unset DEBIAN_FRONTEND
    TAB=$(printf '\t'); CR=$(printf '\r'); ESC=$(printf '\033'); F10="${ESC}[21~"
    t() { n=$1; while [ "$n" -gt 0 ]; do printf '%s' "$TAB"; n=$((n - 1)); done; }
    (
        sleep 12
        t 2; printf '%s' "$CR"; sleep 1.5      # 1: keys in files -> Next
        t 6; printf '%s' "$CR"; sleep 1.5      # 2: the place -> Next
        t 5; printf '%s' "$CR"; sleep 1.5      # 3: the key and the client -> Next
        t 5; printf '%s' "$CR"; sleep 1.5      # 4: the audit -> Next
        t 1; printf '%s' "$CR"; sleep 12       # 5: review -> Install; the setup works
        printf '%s' "$ESC"; sleep 1.5          # close the result page
        printf '%s' "$F10"; sleep 2            # leave the menus
    ) | TERM=xterm script -qec "apt-get install -y $DEB" /tmp/typescript >/dev/null 2>&1 || true
    expect "the wizard started by itself and made the configuration" test -s /etc/hsmgate/hsmgate.yaml
    expect "the wizard's text was on the terminal" grep -q "Quick setup" /tmp/typescript
    expect "hsmgate check passes as the service user" runuser -u hsmgate -- hsmgate check -config /etc/hsmgate/hsmgate.yaml
    start_service /etc/hsmgate/hsmgate.yaml hsmgate
    ;;
*) fail "plain, auto or wizard" ;;
esac
echo "PASS ($1)"
