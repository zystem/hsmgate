# Shared by the package tests. Source it. Every check says what it checks and stops the test at the first failure.
fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }
expect() { # expect "what" command...  (what the command printed is shown when it fails)
    what="$1"; shift
    if out=$("$@" 2>&1); then ok "$what"; else echo "$out" | sed 's/^/      | /' >&2; fail "$what"; fi
}

# What a client of the service does with the commands the setup printed: the first "export HSMGATE_ADDR=..." line is run, then a text is sealed and opened.
roundtrip() { # roundtrip LOGFILE
    line=$(grep -m1 'export HSMGATE_ADDR' "$1" | tr -d '\r' | sed -e 's/^>>> //' -e 's/^ *//')  # rpm prefixes what a scriptlet prints with '>>> '
    [ -n "$line" ] || fail "the setup printed no try-it commands ($1)"
    eval "$line"
    echo 'my secret' | hsmgate encrypt > /tmp/sealed.txt || fail "hsmgate encrypt"
    got=$(hsmgate decrypt < /tmp/sealed.txt) || fail "hsmgate decrypt"
    [ "$got" = "my secret" ] || fail "decrypt gave '$got'"
    ok "the client sealed and opened a text with the certificate the setup made"
}

# the service as its own user, in the background; waits until it listens
start_service() { # start_service CONFIG [USER]
    if [ -n "${2:-}" ]; then
        runuser -u "$2" -- hsmgate serve -config "$1" >/tmp/serve.log 2>&1 &
    else
        hsmgate serve -config "$1" >/tmp/serve.log 2>&1 &
    fi
    SERVICE_PID=$!
    i=0
    while ! grep -q "listening on" /tmp/serve.log 2>/dev/null; do
        i=$((i + 1)); [ $i -lt 50 ] || { cat /tmp/serve.log >&2; fail "the service did not start"; }
        sleep 0.2
    done
    ok "the service listens: $(grep -m1 listening /tmp/serve.log)"
}
