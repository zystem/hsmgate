#!/bin/sh
# Before the files are unpacked: the account the service runs as. A system account with no login and no home; it owns the keys and the audit log.
set -e
if ! getent group hsmgate >/dev/null 2>&1; then
    groupadd --system hsmgate
fi
if ! getent passwd hsmgate >/dev/null 2>&1; then
    useradd --system --gid hsmgate --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin --comment "hsmgate service" hsmgate
fi
exit 0
