#!/bin/sh
# On the host, for BOX_RUN=notify of scripts/test_in_box.sh (T-776): OpenSSH's
# client with -tt reaches `podssh serve --stdio --pty notify` in the running
# box through `podman exec -i`, its ProxyCommand. The box has no /dev/ptmx
# and refuses unshare, so the shell's tty is one that serve answers by
# seccomp's user notification. The keys come one after another, as typed:
# `test -t 0` with `stty size`, `sleep 30`, then Ctrl-C, then `echo AFTER-$?`
# and `exit 9`. Passes with TTY-YES-24x80, AFTER-130 and exit 9 within 20 s.
#
#   sh scripts/box/notify-session.sh BOX WORKDIR
set -u
box=${1:?BOX}
work=${2:?WORKDIR}
if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "FAIL  no OpenSSH client on this host"
    exit 1
fi
podman exec "$box" podssh doctor 2>&1 | grep -E '^ *(ok|warn|fail)? *pty' | sed 's/^/    /'
rm -f "$work/notify-id" "$work/notify-id.pub"
ssh-keygen -q -t ed25519 -N '' -C notify-session -f "$work/notify-id" || exit 1
key=$(cat "$work/notify-id.pub")
proxy="podman exec -i $box podssh serve --stdio --pty notify --authorized-key '$key'"
start=$(date +%s)
{
    sleep 4
    printf 'test -t 0 && echo TTY-YES-$(stty size | tr " " x)\r'
    sleep 1
    printf 'sleep 30\r'
    sleep 1
    printf '\003'
    sleep 1
    printf 'echo AFTER-$?\r'
    sleep 1
    printf 'exit 9\r'
    sleep 5
} | timeout 40 ssh -tt -F none -i "$work/notify-id" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/notify-known" \
    -o "ProxyCommand=$proxy" podssh-box >"$work/notify-out" 2>"$work/notify-err"
rc=$?
took=$(($(date +%s) - start))
out=$(tr -d '\r' <"$work/notify-out")
echo "ssh -tt to a tty that serve answers: exit $rc after $took s"
printf '%s\n' "$out" | tail -10 | sed 's/^/    /'
failed=0
case $out in
    *TTY-YES-24x80*) echo "ok    test -t 0 and stty size on the tty that serve answers" ;;
    *) echo "FAIL  no TTY-YES-24x80: $(tail -3 "$work/notify-err")"; failed=1 ;;
esac
case $out in
    *AFTER-130*) echo "ok    Ctrl-C ended sleep 30, and the shell went on (AFTER-130)" ;;
    *) echo "FAIL  no AFTER-130"; failed=1 ;;
esac
if [ "$rc" = 9 ]; then echo "ok    exit 9 came back"; else echo "FAIL  exit $rc, where 9 was typed"; failed=1; fi
if [ "$took" -le 20 ]; then echo "ok    within 20 s"; else echo "FAIL  $took s, past 20 s"; failed=1; fi
exit "$failed"
