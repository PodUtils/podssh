#!/bin/sh
# The measurements of T-248 (docs/research/serve-tty.md), again: build the
# probes with cc into OUT and run each route in each cage. Run as root on a
# Linux host (the cage drops to uid 65534 with no capabilities and
# NoNewPrivs=1); it needs no build of podssh. Each run has a time limit.
#
#   sh docs/research/serve-tty/run.sh [OUT]      (OUT defaults to .work/t248)
set -u
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-.work/t248}
mkdir -p "$out"
for p in cage route1 route2 route2b; do
    cc -O2 -Wall -pthread -o "$out/$p" "$here/$p.c" || exit 1
done
cc -static -O2 -o "$out/isatty-glibc" "$here/isatty.c" || exit 1
if command -v musl-gcc >/dev/null; then musl-gcc -static -O2 -o "$out/isatty-musl" "$here/isatty.c" || exit 1; fi
cd "$out" || exit 1
TERM=xterm-256color
export TERM
uname -sr
run() { echo "== $*"; timeout 30 "$@" 2>&1; echo "-- exit $?"; }
probe='test -t 0 && echo ISATTY || echo NOTTY; stty size 2>&1'

for f in "" "-n" "-l" "-P"; do run ./cage $f -- ./route1; done
ROUTE1_NOMAP=1 run ./cage -P -- ./route1
ROUTE1_THREAD=1 run ./cage -- ./route1

for f in "" "-n" "-n -p" "-n -p -v" "-n -p -P" "-n -p -v -P" "-n -l"; do
    run ./cage $f -- ./route2 -- sh -c "$probe"
done
ROUTE2_ID=pidfd run ./cage -n -p -P -- ./route2 -- sh -c "$probe"
ROUTE2_ID=proc run ./cage -n -p -P -- ./route2 -- sh -c "$probe"
for f in "-n" "-n -p" "-n -l"; do run ./cage $f -- ./route2b sh -c "$probe"; done

for l in glibc musl; do [ -x "./isatty-$l" ] && run ./cage -n -- ./route2 -- "./isatty-$l"; done
run ./cage -n -- ./route2 -- ./route2 bench-child
run ./cage -n -- ./route2b ./route2 bench-child

run ./cage -n -- ./route2 -s 'p:1500|r:100x30|p:300' -- python3 -c "
import os, signal, time
signal.signal(signal.SIGWINCH, lambda *a: print('WINCH', os.get_terminal_size(), flush=True))
print('isatty', os.isatty(0), os.get_terminal_size(), flush=True)
time.sleep(3)"
run ./cage -n -- ./route2 -s 'p:600|w:sleep 30\r|p:700|i|p:400|w:echo AFTER-INT $?\r|p:300|w:sleep 31\r|p:700|z|p:500|w:jobs\r|p:300|w:kill -9 %1\r|p:300|w:jobs\r|p:300|w:exit 7\r' \
    -- env PS1='$ ' HOME=/tmp bash --norc --noprofile -i
echo "== the same keys on a real pty of the host (bash prints the same)"
timeout 20 python3 "$here/realpty.py"
rm -f /tmp/t248-vi.txt
run ./cage -n -- ./route2 -s 'p:1000|w:ihello from vi\e|p:200|w::wq\r' -- vim -u NONE -N -i NONE /tmp/t248-vi.txt | grep -E '^\[route2\]|-- exit'
echo "the file vi wrote: $(cat /tmp/t248-vi.txt 2>&1)"
rm -f /tmp/t248-vi.txt
run ./cage -n -- ./route2 -s 'p:800|w: |p:500|w:q' -- less /etc/services | grep -E '^\[route2\]|tcpmux|-- exit' | head -6
run ./cage -n -- ./route2 -s 'p:1500|p:1000|w:q' -- top -d 1 | grep -oE '^\[route2\].*|Tasks:|-- exit.*' | sort -u
