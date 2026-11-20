#!/bin/sh
# Tests of tools/retry-net.sh: a network failure is run again, any other failure is not, and the status of the command is kept.
# shellcheck disable=SC2016  # the single quotes are on purpose: the inner shell expands
cd "$(dirname "$0")" || exit 1
export RETRY_DELAY=0
fail() { echo "FAIL: $1" >&2; exit 1; }
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT

# 1. a command that works runs once
printf 0 >"$d/n"
./retry-net.sh sh -c 'echo $(( $(cat '"$d"'/n) + 1 )) >'"$d"'/n' >/dev/null 2>&1 || fail "a good command failed"
[ "$(cat "$d/n")" = 1 ] || fail "a good command ran more than once"

# 2. the network fails twice, then works: three runs, status 0
printf 0 >"$d/n"
./retry-net.sh sh -c 'n=$(( $(cat '"$d"'/n) + 1 )); echo $n >'"$d"'/n; [ $n -ge 3 ] || { echo "read \"https://proxy.golang.org/x\": stream error: INTERNAL_ERROR"; exit 1; }' >/dev/null 2>&1 || fail "a network failure that passed at the third run did not end well"
[ "$(cat "$d/n")" = 3 ] || fail "expected 3 runs, got $(cat "$d/n")"

# 3. a failure that is not the network's is run once and keeps its status
printf 0 >"$d/n"
./retry-net.sh sh -c 'echo $(( $(cat '"$d"'/n) + 1 )) >'"$d"'/n; echo "main.go:3: undefined: x"; exit 7' >/dev/null 2>&1
rc=$?
[ "$rc" = 7 ] || fail "the status was $rc, not 7"
[ "$(cat "$d/n")" = 1 ] || fail "a compile error was run $(cat "$d/n") times"

# 4. the network fails every time: RETRY_TRIES runs, then the status of the command
printf 0 >"$d/n"
RETRY_TRIES=3 ./retry-net.sh sh -c 'echo $(( $(cat '"$d"'/n) + 1 )) >'"$d"'/n; echo "dial tcp: i/o timeout"; exit 5' >/dev/null 2>&1
rc=$?
[ "$rc" = 5 ] || fail "the status was $rc, not 5"
[ "$(cat "$d/n")" = 3 ] || fail "expected 3 runs, got $(cat "$d/n")"

# 5. no command is a mistake
./retry-net.sh >/dev/null 2>&1
[ $? = 2 ] || fail "no command did not give 2"
echo ok
