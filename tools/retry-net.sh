#!/bin/sh
# Runs a command and runs it again when it failed because the network failed, and only then.
#
#   tools/retry-net.sh go mod download
#
# A failure that is not the network's (a compile error, a finding of a linter, a failed test) ends the command at once with its own exit status. A failure is the network's when what
# the command printed has one of the words of NET_PATTERN: the module proxy or the checksum database, a broken stream, a reset or timed out connection, a name that did not resolve, a
# 502 or 503 from a mirror. The command is run at most RETRY_TRIES times (default 4), with RETRY_DELAY seconds (default 5) before the second run, doubled before each next one.
# Used for what downloads: `go mod download`, `go run tool@version`, apt and pip. Not for the tests of the program: a test must not be run again until it passes.

NET_PATTERN='proxy\.golang\.org|sum\.golang\.org|stream error|unexpected EOF|TLS handshake timeout|connection reset|connection refused|i/o timeout|dial tcp|Temporary failure in name resolution|Could not resolve|Connection timed out|Failed to fetch|Read timed out|ReadTimeoutError|Max retries exceeded|502 Bad Gateway|503 Service|Service Unavailable'

tries=${RETRY_TRIES:-4}
delay=${RETRY_DELAY:-5}
if [ $# -eq 0 ]; then
	echo "usage: retry-net.sh command [argument...]" >&2
	exit 2
fi

tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.rc"' EXIT
n=1
while :; do
	{
		"$@" 2>&1
		echo $? >"$tmp.rc"
	} | tee "$tmp"
	rc=$(cat "$tmp.rc")
	if [ "$rc" -eq 0 ]; then
		exit 0
	fi
	if ! grep -Eq "$NET_PATTERN" "$tmp"; then
		exit "$rc" # not the network: no second run
	fi
	if [ "$n" -ge "$tries" ]; then
		echo "retry-net: the network failed $n times, giving up" >&2
		exit "$rc"
	fi
	echo "retry-net: the network failed (run $n of $tries), again in ${delay}s: $*" >&2
	sleep "$delay"
	delay=$((delay * 2))
	n=$((n + 1))
done
