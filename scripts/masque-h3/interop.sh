#!/bin/sh
# scripts/masque-h3/interop.sh - podssh's connect-ip over HTTP/3 (T-582)
# against a server that podssh did not write: connect-ip-go's integration
# proxy, of Diniboy1123's fork that usque takes (MIT), at a pinned commit.
#
#   sh scripts/masque-h3/interop.sh
#
# The fork is fetched at COMMIT and its HEAD checked; its proxy is built in
# images/derper's Go (CGO_ENABLED=0, its modules checked against Go's
# checksum database), and runs on images/box's Alpine with the tools of its
# run.sh (scripts/masque-h3/). As the fork's docker-compose.yml sets it: two
# bridges with no masquerade, the proxy on both (194.166.0.2 for clients,
# 194.166.100.2 as the server's gateway), assigning 194.166.0.10 and the
# route 194.166.100.0/24; the server, 194.166.100.3, runs sshd on 22 and an
# echo on 7, and reaches 194.166.0.10 through the proxy alone. The proxy's
# certificate is a P-256 one that openssl makes for the run (the fork's
# Makefile makes an Ed25519 one), pinned by its SHA-256.
#
# Then `cargo test -p podssh-warp --features h3 --test connect_ip_h3` on
# this host, which reaches the proxy over the client bridge: sshd's banner
# through the tunnel, and 1 MiB each way through the echo. The exit code is
# the test's, else 71 when the host lacks what the run needs.
#
# Needs docker (PODSSH_ENGINE names another engine), git, openssl, cargo and
# timeout; the subnets 194.166.0.0/24 and 194.166.100.0/24 free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)

# The fork's commit that usque's go.mod names
# (v0.0.0-20260613064811-66cba32d7d33), read on 2026-11-12.
FORK=https://github.com/Diniboy1123/connect-ip-go
COMMIT=66cba32d7d33e0fb3ba9d1cdaac664379271a54b
P=podssh-mh3
NAMES="$P-build $P-proxy $P-server"

die() {
    echo "masque-h3/interop.sh: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-docker}
timeout 60 "$ENGINE" info >/dev/null 2>&1 || die "$ENGINE does not answer here (PODSSH_ENGINE names an engine)"
for tool in git openssl cargo timeout sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done

W=$(mktemp -d) || die "no directory for the run"
cleanup() {
    for _c in $NAMES; do
        timeout 60 "$ENGINE" rm -f "$_c" >/dev/null 2>&1
    done
    timeout 60 "$ENGINE" network rm "$P-client" "$P-server" >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
cleanup
mkdir -p "$W" || die "no directory for the run"

# image_of DOCKERFILE: the image that its FROM line pins to a digest.
image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$REPO/scripts/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"
GO=$(image_of "$REPO/images/derper/Dockerfile") || die "Go's image did not pull"

# The fork at the pinned commit, and nothing else.
git init -q "$W/fork" || die "git init failed"
timeout 300 git -C "$W/fork" fetch -q --depth 1 "$FORK" "$COMMIT" || die "the fork's commit $COMMIT was not fetched"
git -C "$W/fork" checkout -q FETCH_HEAD || die "the fork's commit did not check out"
[ "$(git -C "$W/fork" rev-parse HEAD)" = "$COMMIT" ] || die "the fork's HEAD is not $COMMIT"
chmod -R a+rwX "$W/fork"

# The proxy, built in the open so that a failure says why; go.work at the
# fork's root builds integration/ against the fork's own code.
timeout 900 "$ENGINE" run --name "$P-build" -e CGO_ENABLED=0 -e GOFLAGS=-p=4 -v "$W/fork:/src" -w /src/integration \
    "$GO" go build -o /src/proxy-bin ./proxy >"$W/build.log" 2>&1 ||
    die "the proxy did not build: $(tail -5 "$W/build.log")"
timeout 60 "$ENGINE" rm -f "$P-build" >/dev/null 2>&1

# The proxy's image: its binary, a certificate of the run, and run.sh.
mkdir -p "$W/proxy" && cp "$HERE/proxy/Dockerfile" "$HERE/proxy/run.sh" "$W/proxy/" &&
    cp "$W/fork/proxy-bin" "$W/proxy/proxy" || die "the proxy's files were not gathered"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -subj /CN=proxy \
    -addext subjectAltName=DNS:proxy -keyout "$W/proxy/key.pem" -out "$W/proxy/cert.pem" >/dev/null 2>&1 ||
    die "openssl made no certificate"
chmod 644 "$W/proxy/key.pem"
PIN=$(openssl x509 -in "$W/proxy/cert.pem" -outform DER | sha256sum | cut -c1-64)
timeout 600 "$ENGINE" build -q --build-arg "BASE=$ALPINE" -t "$P-proxy" "$W/proxy" >/dev/null ||
    die "the proxy's image did not build"
timeout 600 "$ENGINE" build -q --build-arg "BASE=$ALPINE" -t "$P-server" "$HERE/server" >/dev/null ||
    die "the server's image did not build"

# The two bridges, with no masquerade, as the fork's compose file has them.
nomasq=com.docker.network.bridge.enable_ip_masquerade=false
timeout 60 "$ENGINE" network create --subnet 194.166.0.0/24 -o "$nomasq" "$P-client" >/dev/null ||
    die "the client bridge was not made"
timeout 60 "$ENGINE" network create --subnet 194.166.100.0/24 -o "$nomasq" "$P-server" >/dev/null ||
    die "the server bridge was not made"
timeout 120 "$ENGINE" run -d --name "$P-server" --cap-add NET_ADMIN --network "$P-server" --ip 194.166.100.3 \
    -e GATEWAY=194.166.100.2 "$P-server" >/dev/null || die "the server did not start"
timeout 120 "$ENGINE" create --name "$P-proxy" --cap-add NET_ADMIN --network "$P-client" --ip 194.166.0.2 \
    -e PROXY_ADDR=194.166.0.2 -e PROXY_PORT=443 -e ASSIGN_ADDR=194.166.0.10 -e ROUTE=194.166.100.0/24 \
    -e FILTER_IP_PROTOCOL=0 -e GATEWAY_IPV4=194.166.100.2 -e QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true \
    -e QUIC_GO_DISABLE_GSO=true "$P-proxy" >/dev/null || die "the proxy was not made"
timeout 60 "$ENGINE" network connect --ip 194.166.100.2 "$P-server" "$P-proxy" || die "the proxy took no server bridge"
timeout 60 "$ENGINE" start "$P-proxy" >/dev/null || die "the proxy did not start"

# sshd and the echo answer inside the server before the test starts.
i=0
until timeout 10 "$ENGINE" exec "$P-server" sh -c 'netstat -ltn | grep -q ":22 " && netstat -ltn | grep -q ":7 "' \
    >/dev/null 2>&1; do
    i=$((i + 1))
    [ $i -lt 30 ] || die "the server's sshd and echo did not answer: $("$ENGINE" logs "$P-server" 2>&1 | tail -5)"
    sleep 1
done
sleep 2

cd "$REPO" || die "the repository cannot be entered"
PODSSH_MASQUE_H3_URL=https://proxy:443/vpn PODSSH_MASQUE_H3_AT=194.166.0.2:443 PODSSH_MASQUE_H3_PIN=$PIN \
    PODSSH_MASQUE_H3_SSH=194.166.100.3:22 PODSSH_MASQUE_H3_ECHO=194.166.100.3:7 \
    timeout 900 cargo test --locked -p podssh-warp --features h3 --test connect_ip_h3 -- --nocapture \
    >"$W/test.log" 2>&1
rc=$?
cat "$W/test.log"
echo "--- the proxy's log"
timeout 60 "$ENGINE" logs "$P-proxy" 2>&1 | tail -40
if grep -q "did not run" "$W/test.log"; then
    echo "masque-h3/interop.sh: the test did not run" >&2
    exit 1
fi
grep -q "1 MiB each way" "$W/test.log" || { echo "masque-h3/interop.sh: no 1 MiB each way" >&2; [ $rc -ne 0 ] || rc=1; }
exit $rc
