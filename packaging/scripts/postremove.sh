#!/bin/sh
# After the files went. The configuration, the certificates, the keys and the audit log are NOT removed, not even by a purge: the CA key and the key files cannot be made again, and what was sealed under them
# cannot be opened without them. The account stays too, since it owns those files.
set -u
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
case "${1:-}" in
    remove|purge|0)
        if [ -d /etc/hsmgate ] || [ -d /var/log/hsmgate ]; then
            echo "hsmgate: the program is removed; /etc/hsmgate (configuration, certificates, keys) and /var/log/hsmgate (audit) are kept." >&2
            echo "         Delete them yourself when the keys are no longer needed (what was sealed under them cannot be opened without them)." >&2
        fi ;;
esac
exit 0
