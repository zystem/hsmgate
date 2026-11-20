#!/bin/sh
# Builds and loads the SELinux module of the service (the domain hsmgate_t), then labels the files. Needs selinux-policy-devel (dnf install selinux-policy-devel) and root.
#   sudo /usr/share/hsmgate/selinux/install.sh            build, load, label
#   sudo /usr/share/hsmgate/selinux/install.sh remove     unload and label again
# The service is not restarted here: a card without a pin_file stays locked after a restart until `hsmgate unlock`. Restart when you are ready: systemctl restart hsmgate
set -eu
dir=$(cd "$(dirname "$0")" && pwd)
labels="/usr/bin/hsmgate /etc/hsmgate /var/log/hsmgate /run/hsmgate"
if [ "$(id -u)" -ne 0 ]; then echo "run as root" >&2; exit 1; fi
if [ "${1:-}" = remove ]; then
	semodule -r hsmgate
	# shellcheck disable=SC2086
	restorecon -R $labels 2>/dev/null || true
	echo "removed: the service runs as unconfined_service_t after its next start"
	exit 0
fi
[ -f /usr/share/selinux/devel/Makefile ] || { echo "selinux-policy-devel is needed: dnf install selinux-policy-devel" >&2; exit 1; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$dir/hsmgate.te" "$dir/hsmgate.fc" "$dir/hsmgate.if" "$work/"
make -C "$work" -f /usr/share/selinux/devel/Makefile hsmgate.pp >/dev/null
semodule -i "$work/hsmgate.pp"
# shellcheck disable=SC2086
restorecon -R $labels 2>/dev/null || true
echo "loaded the module hsmgate; the files are labeled. Restart the service when you are ready: systemctl restart hsmgate"
echo "check:  ps -eZ | grep -w hsmgate   (the domain is hsmgate_t)"
