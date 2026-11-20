#!/bin/sh
# After the files are unpacked. $1 is "configure" (deb; $2 is the old version, empty on a first installation) or the number of installed copies (rpm: 1 on a first installation).
#
# On a first installation with no configuration the quick setup is offered, when somebody is at the keyboard:
#   - a terminal is there (the controlling terminal can be opened, TERM is set and is not dumb) and DEBIAN_FRONTEND is not noninteractive: the wizard (hsmgate-setup -first-run) runs on it;
#   - HSMGATE_SETUP_AUTO=1 in the environment: the quick setup runs with its defaults and no screen (for Ansible, Dockerfiles, cloud-init);
#   - otherwise nothing is made, and what to do is printed. Nothing here ever fails the installation: a cancelled wizard leaves the package installed.
# The service is not started by the package: the unit starts only when /etc/hsmgate/hsmgate.yaml exists, and a card must not be locked by a restart nobody planned.
set -u

fresh=0
case "${1:-}" in
    configure) [ -z "${2:-}" ] && fresh=1 ;;
    1) fresh=1 ;;
esac

# the owners and modes the package declares, again: cheap, and right even when the packager could not set a group that did not exist yet
chown root:hsmgate /etc/hsmgate 2>/dev/null || true
chmod 0750 /etc/hsmgate 2>/dev/null || true
chown hsmgate:hsmgate /var/log/hsmgate 2>/dev/null || true
chmod 0750 /var/log/hsmgate 2>/dev/null || true

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi

if [ "$fresh" = 1 ] && [ ! -e /etc/hsmgate/hsmgate.yaml ]; then
    if [ "${HSMGATE_SETUP_AUTO:-}" = 1 ]; then
        hsmgate-setup -first-run || echo "hsmgate: the automatic setup did not finish: run 'sudo hsmgate-setup' to see why." >&2
    elif [ "${DEBIAN_FRONTEND:-}" != noninteractive ] && [ -z "${HSMGATE_NO_WIZARD:-}" ] && [ -n "${TERM:-}" ] && [ "${TERM}" != dumb ] && ( : </dev/tty ) 2>/dev/null; then
        echo "hsmgate: starting the quick setup (Esc cancels; run 'sudo hsmgate-setup' later)."
        hsmgate-setup -first-run </dev/tty >/dev/tty 2>&1 || true
    else
        echo "hsmgate: installed, not configured. Run 'sudo hsmgate-setup' (menus and a quick setup), or 'sudo hsmgate-setup -auto' for the defaults." >&2
    fi
elif [ "$fresh" = 0 ] && [ -d /run/systemd/system ] && systemctl is-active --quiet hsmgate 2>/dev/null; then
    echo "hsmgate: upgraded. The running service still has the old program: restart it when you are ready ('sudo systemctl restart hsmgate')." >&2
    echo "         A card without a pin_file starts locked after a restart: unlock it ('sudo hsmgate unlock -config /etc/hsmgate/hsmgate.yaml -token NAME')." >&2
fi
exit 0
