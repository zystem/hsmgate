#!/bin/sh
# Before the files go. $1 is "remove" or "upgrade" (deb), or the number of copies left (rpm: 0 on a removal). Only a real removal stops the service; an upgrade leaves it running.
set -u
case "${1:-}" in
    remove|0)
        if [ -d /run/systemd/system ]; then
            systemctl stop hsmgate >/dev/null 2>&1 || true
            systemctl disable hsmgate >/dev/null 2>&1 || true
        fi ;;
esac
exit 0
