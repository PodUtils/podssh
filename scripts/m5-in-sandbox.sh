#!/bin/sh
# M5's exit in a real sandbox (T-113, step 5; T-001's way: the operator's
# agent runs it there). Both ends run in the sandbox, and each byte goes out
# through its proxy to the live relay and back: `podssh relay pair`, then
# `podssh serve NAME` as the node (a tty that serve answers where no pty
# opens), and the operator's `podssh ssh -tt` with the keys typed one after
# another (`test -t 0`, `sleep 30` and Ctrl-C, vi, less, `exit 9`), then 200
# MiB up and down with `podssh cp` and SHA-256 at both ends. The pair is
# revoked at the end. Prints one line for each step and exits 0 when each
# passes; paste its output into the report.
#
#   sh scripts/m5-in-sandbox.sh [PODSSH]
set -u
bin=${1:-podssh}
work=$(mktemp -d) || exit 1
name=m5$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')
export HOME="$work/home"
mkdir -p "$HOME" "$work/far"
"$bin" --version 2>&1 | head -1
"$bin" doctor 2>&1 | grep -E ' pty' | sed 's/^/    /'
"$bin" keygen -q -t ed25519 -N '' -f "$work/op" >/dev/null 2>&1 || { echo "FAIL  no key"; exit 1; }
timeout 60 "$bin" relay pair "$name" --operator-file "$work/op.json" >"$work/pair.log" 2>&1 ||
    { echo "FAIL  relay pair: $(tail -1 "$work/pair.log")"; exit 1; }
timeout -k 5 3600 "$bin" serve "$name" --pty notify --shell /bin/sh --authorized-key "$(cat "$work/op.pub")" \
    </dev/null >/dev/null 2>"$work/serve.log" &
serve=$!
stop() {
    kill -INT "$serve" 2>/dev/null
    timeout 60 "$bin" relay revoke "$name" >/dev/null 2>&1 && echo "ok    the pair $name was revoked"
    rm -f "$work/big" "$work/down.bin" "$work/far/up.bin"
    # The logs stay for a failure, without the keys and the pair.
    if [ "${failed:-1}" = 0 ]; then rm -rf "$work"; else rm -f "$work/op" "$work/op.json"; echo "the logs: $work"; fi
}
i=0
until grep -q online "$work/serve.log" 2>/dev/null || [ "$i" -ge 120 ]; do
    sleep 1
    i=$((i + 1))
done
grep -q online "$work/serve.log" || { echo "FAIL  serve was not online: $(tail -1 "$work/serve.log")"; stop; exit 1; }
opts="-i $work/op -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$work/known -o BatchMode=yes --pair-file $work/op.json"
failed=0
{
    sleep 6
    printf 'test -t 0 && echo TTY-YES-$(stty size | tr " " x)\r'
    sleep 2
    printf 'sleep 30\r'
    sleep 2
    printf '\003'
    sleep 2
    printf 'echo AFTER-$?\r'
    sleep 2
    printf 'vi /etc/hostname\r'
    sleep 3
    printf '\033'
    sleep 1
    printf ':q!\r'
    sleep 2
    printf 'echo VI-DONE-$?\r'
    sleep 2
    printf 'less /etc/hostname\r'
    sleep 3
    printf 'q'
    sleep 2
    printf 'echo LESS-DONE-$?\r'
    sleep 2
    printf 'exit 9\r'
    sleep 8
} | timeout 120 "$bin" ssh -tt $opts "node://box@$name" >"$work/out" 2>"$work/err"
rc=$?
out=$(tr -d '\r' <"$work/out")
for want in TTY-YES AFTER-130 VI-DONE-0 LESS-DONE-0; do
    case $out in
        *"$want"*) echo "ok    $want" ;;
        *) echo "FAIL  no $want: $(tail -1 "$work/err")"; failed=1 ;;
    esac
done
if [ "$rc" = 9 ]; then echo "ok    exit 9 came back"; else echo "FAIL  exit $rc, where 9 was typed"; failed=1; fi
head -c 209715200 /dev/urandom >"$work/big"
want=$(sha256sum <"$work/big" | cut -c1-64)
t0=$(date +%s)
timeout 1800 "$bin" cp --timeout 28m $opts "$work/big" "node://box@$name:$work/far/up.bin" >"$work/up.log" 2>&1
up=$?
t1=$(date +%s)
timeout 1800 "$bin" cp --timeout 28m $opts "node://box@$name:$work/far/up.bin" "$work/down.bin" >"$work/down.log" 2>&1
down=$?
t2=$(date +%s)
far=$(sha256sum <"$work/far/up.bin" 2>/dev/null | cut -c1-64)
back=$(sha256sum <"$work/down.bin" 2>/dev/null | cut -c1-64)
if [ "$up" = 0 ] && [ "$far" = "$want" ]; then echo "ok    200 MiB up in $((t1 - t0)) s, SHA-256 equal"; else echo "FAIL  up: exit $up: $(tail -1 "$work/up.log")"; grep -v '^podssh: [0-9]' "$work/up.log" | tail -6 | sed 's/^/    /'; failed=1; fi
if [ "$down" = 0 ] && [ "$back" = "$want" ]; then echo "ok    200 MiB down in $((t2 - t1)) s, SHA-256 equal"; else echo "FAIL  down: exit $down: $(tail -1 "$work/down.log")"; failed=1; fi
stop
echo "m5-in-sandbox: exit $failed"
exit "$failed"
