#!/bin/sh
# Inside the box of BOX_RUN=reverse (T-085, M4's exit): two operators at
# once, through the relay, to the node of the pair m4 in the other box,
# which serves example.com:80. Each sends one request, holds its input 4 s
# so that the two sessions overlap, and keeps the reply. Passes when both
# exit 0 (a clean end: the relay's close 1000), both bodies are whole and
# alike (their digests; the headers carry a date of their own), and their
# times overlap.
set -u
pair=/xfer/operator.pair
i=0
while [ ! -s "$pair" ] && [ "$i" -lt 120 ]; do
    sleep 1
    i=$((i + 1))
done
if [ ! -s "$pair" ]; then
    echo "FAIL  no operator's part of the pair from the node's box within 120 s"
    exit 1
fi
# The operator's file is private, as podssh asks of a pair's file.
cp "$pair" /state/home/operator.pair && chmod 600 /state/home/operator.pair
# The node's start: its first ready at the relay.
sleep 3

session() {
    n=$1
    date +%s >"/state/home/start.$n"
    { printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n'; sleep 4; } |
        timeout 120 podssh operator --pair-file /state/home/operator.pair m4 \
            >"/state/home/reply.$n" 2>"/state/home/err.$n"
    echo $? >"/state/home/rc.$n"
    date +%s >"/state/home/end.$n"
}

session 1 &
one=$!
session 2 &
two=$!
wait "$one" "$two"

failed=0
for n in 1 2; do
    rc=$(cat "/state/home/rc.$n")
    # The body: what follows the blank line that ends the headers.
    body=$(sed '1,/^\r*$/d' "/state/home/reply.$n" | sha256sum | cut -c1-64)
    size=$(wc -c <"/state/home/reply.$n")
    eval "body_$n=$body"
    echo "session $n: exit $rc, $size bytes, the body's SHA-256 $body, $(cat "/state/home/start.$n") to $(cat "/state/home/end.$n")"
    if [ "$rc" != 0 ]; then
        echo "FAIL  session $n ended with $rc: $(tail -3 "/state/home/err.$n")"
        failed=1
    fi
    if ! grep -q '^HTTP/1\.[01] 200' "/state/home/reply.$n" || ! grep -qi '</html>' "/state/home/reply.$n"; then
        echo "FAIL  session $n has no whole page: $(head -c 200 "/state/home/reply.$n")"
        failed=1
    fi
done
if [ "$body_1" = "$body_2" ]; then
    echo "ok    the two bodies are alike: $body_1"
else
    echo "FAIL  the two bodies differ"
    failed=1
fi
s1=$(cat /state/home/start.1) e1=$(cat /state/home/end.1) s2=$(cat /state/home/start.2) e2=$(cat /state/home/end.2)
if [ "$s1" -lt "$e2" ] && [ "$s2" -lt "$e1" ]; then
    echo "ok    the two sessions overlapped: $s1 to $e1 and $s2 to $e2"
else
    echo "FAIL  the two sessions did not overlap: $s1 to $e1 and $s2 to $e2"
    failed=1
fi
[ "$failed" = 0 ] && echo "reverse-session: two sessions at once through the relay, both whole"
exit "$failed"
