#!/bin/sh
# On the host, for BOX_RUN=m5 of scripts/test_in_box.sh (T-113, M5's exit):
# the box made the pair m5 and runs `podssh serve m5 --pty notify` as its
# node, through its proxy and the live relay; this host is the operator,
# through the same relay. The shell: `podssh ssh -tt` with the keys typed one
# after another: `test -t 0`, `sleep 30` then Ctrl-C, vi and less on a file of
# the box, `exit 9`. The copy: 200 MiB of random bytes up with `podssh cp`,
# then down, with SHA-256 at both ends. Passes when each step does.
#
#   sh scripts/box/m5-session.sh BOX WORKDIR PODSSH
set -u
box=${1:?BOX}
work=${2:?WORKDIR}
bin=${3:?PODSSH}
xfer=$work/xfer
i=0
until [ -s "$xfer/operator.pair" ] && grep -q online "$xfer/serve.log" 2>/dev/null || [ "$i" -ge 180 ]; do
    sleep 1
    i=$((i + 1))
done
if ! grep -q online "$xfer/serve.log" 2>/dev/null; then
    echo "FAIL  serve m5 was not online within 180 s"
    tail -5 "$xfer/serve.log" 2>/dev/null | sed 's/^/    /'
    exit 1
fi
grep -E 'serving|pty' "$xfer/serve.log" | sed 's/^/    /'
cp "$xfer/operator.pair" "$work/op.json" && chmod 600 "$work/op.json"
export HOME="$work/home"
mkdir -p "$HOME"
opts="-i $xfer/op -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$work/m5-known -o BatchMode=yes --pair-file $work/op.json"
failed=0

# The shell, through the relay, on the tty that serve answers in the box.
start=$(date +%s)
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
    printf 'vi /etc/os-release\r'
    sleep 3
    # ESC alone, as a person types it: busybox vi reads ESC and the next
    # byte that comes with it as one escape sequence.
    printf '\033'
    sleep 1
    printf ':q!\r'
    sleep 2
    printf 'echo VI-DONE-$?\r'
    sleep 2
    printf 'less /etc/os-release\r'
    sleep 3
    printf 'q'
    sleep 2
    printf 'echo LESS-DONE-$?\r'
    sleep 2
    printf 'exit 9\r'
    sleep 8
} | timeout 120 "$bin" ssh -tt $opts node://box@m5 >"$work/m5-out" 2>"$work/m5-err"
rc=$?
took=$(($(date +%s) - start))
out=$(tr -d '\r' <"$work/m5-out")
echo "podssh ssh -tt node://box@m5: exit $rc after $took s"
printf '%s\n' "$out" | grep -aE 'TTY-YES|AFTER-|VI-DONE|LESS-DONE|NAME=' | sed 's/^/    /'
for want in TTY-YES-24x80 AFTER-130 VI-DONE-0 LESS-DONE-0 NAME=; do
    case $out in
        *"$want"*) echo "ok    $want" ;;
        *) echo "FAIL  no $want: $(tail -2 "$work/m5-err")"; failed=1 ;;
    esac
done
if [ "$rc" = 9 ]; then echo "ok    exit 9 came back"; else echo "FAIL  exit $rc, where 9 was typed"; failed=1; fi

# The copy: 200 MiB up, then down, and the digests of both ends.
head -c 209715200 /dev/urandom >"$work/big"
want=$(sha256sum <"$work/big" | cut -c1-64)
t0=$(date +%s)
timeout 1800 "$bin" cp --timeout 28m $opts "$work/big" node://box@m5:/state/home/up.bin >"$work/cp-up.log" 2>&1
up=$?
t1=$(date +%s)
timeout 1800 "$bin" cp --timeout 28m $opts node://box@m5:/state/home/up.bin "$work/down.bin" >"$work/cp-down.log" 2>&1
down=$?
t2=$(date +%s)
far=$(podman exec "$box" sha256sum /state/home/up.bin | cut -c1-64)
back=$(sha256sum <"$work/down.bin" 2>/dev/null | cut -c1-64)
echo "podssh cp 200 MiB: up exit $up in $((t1 - t0)) s, down exit $down in $((t2 - t1)) s"
tail -1 "$work/cp-up.log" | sed 's/^/    /'
tail -1 "$work/cp-down.log" | sed 's/^/    /'
if [ "$up" = 0 ] && [ "$far" = "$want" ]; then echo "ok    200 MiB up, SHA-256 equal in the box"; else echo "FAIL  up: exit $up, SHA-256 in the box $far"; failed=1; fi
if [ "$down" = 0 ] && [ "$back" = "$want" ]; then echo "ok    200 MiB down, SHA-256 equal here"; else echo "FAIL  down: exit $down, SHA-256 here $back"; failed=1; fi
rm -f "$work/big" "$work/down.bin"
[ "$failed" = 0 ] && echo "m5-session: a shell with vi, less and Ctrl-C, and 200 MiB each way, through serve m5 in the box"
exit "$failed"
