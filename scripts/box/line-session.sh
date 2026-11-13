#!/bin/sh
# On the host, for BOX_RUN=line of scripts/test_in_box.sh (T-111): OpenSSH's
# client with -tt reaches `podssh serve --stdio` in the running box through
# `podman exec -i`, its ProxyCommand. The box has no /dev/ptmx and refuses
# unshare, so serve's pty request falls to its line discipline (--pty auto,
# the default), with the box's own /bin/sh. The keys come one after another,
# as typed: `sleep 30`, then Ctrl-C, then `echo AFTER-$?` and `exit 9`. Passes
# with AFTER-130 and exit 9 within 15 s.
#
#   sh scripts/box/line-session.sh BOX WORKDIR
set -u
box=${1:?BOX}
work=${2:?WORKDIR}
if ! command -v ssh >/dev/null 2>&1 || ! command -v ssh-keygen >/dev/null 2>&1; then
    echo "FAIL  no OpenSSH client on this host"
    exit 1
fi
rm -f "$work/line-id" "$work/line-id.pub"
ssh-keygen -q -t ed25519 -N '' -C line-session -f "$work/line-id" || exit 1
key=$(cat "$work/line-id.pub")
proxy="podman exec -i $box podssh serve --stdio --authorized-key '$key'"
start=$(date +%s)
{
    sleep 4
    printf 'sleep 30\r'
    sleep 1
    printf '\003'
    sleep 1
    printf 'echo AFTER-$?\r'
    sleep 1
    printf 'exit 9\r'
    sleep 5
} | timeout 30 ssh -tt -F none -i "$work/line-id" -o IdentitiesOnly=yes -o BatchMode=yes \
    -o StrictHostKeyChecking=accept-new -o "UserKnownHostsFile=$work/line-known" \
    -o "ProxyCommand=$proxy" podssh-box >"$work/line-out" 2>"$work/line-err"
rc=$?
took=$(($(date +%s) - start))
out=$(tr -d '\r' <"$work/line-out")
echo "ssh -tt through serve's line discipline: exit $rc after $took s"
printf '%s\n' "$out" | tail -8 | sed 's/^/    /'
failed=0
case $out in
    *AFTER-130*) echo "ok    Ctrl-C ended sleep 30, and the shell went on (AFTER-130)" ;;
    *) echo "FAIL  no AFTER-130: $(tail -3 "$work/line-err")"; failed=1 ;;
esac
if [ "$rc" = 9 ]; then echo "ok    exit 9 came back"; else echo "FAIL  exit $rc, where 9 was typed"; failed=1; fi
if [ "$took" -le 15 ]; then echo "ok    within 15 s"; else echo "FAIL  $took s, past 15 s"; failed=1; fi
exit "$failed"
