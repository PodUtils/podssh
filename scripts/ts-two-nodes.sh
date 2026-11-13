#!/bin/sh
# scripts/ts-two-nodes.sh - the live test with two nodes of `podssh ts`
# (T-106), crates/podssh-cli/tests/ts_two_nodes.rs, against headscale as
# the control server: headscale in Podman, else Docker, on this host's
# network, with a CA of the run and a reusable pre-auth key, as
# scripts/ts-headscale.sh makes them (scripts/ts-headscale-lib.sh). The test
# runs node A in its process and the binary as node B, in relay mode pinned
# to `podssh relay serve --derp-keys` on the loopback, 1 MiB each way, and,
# where PODSSH_TS_TWO_TAILCAT names a server of tailcat's fleet (such as
# tc301a.ipn.dev), pinned to it, 64 KiB each way (Q58: short).
#
#   sh scripts/ts-two-nodes.sh
#
# The key goes from headscale's stdout into a file, and to the test by its
# path alone (PODSSH_TS_TWO_KEY_FILE); the run removes it. cargo builds the
# test with CARGO_BUILD_JOBS=4 unless it is set. The exit code is the
# test's: 0 when it passed; 1 when the stand-in did not start.
#
# Needs podman or docker, openssl, curl, python3, timeout and cargo; the
# ports PODSSH_HS_PORT (45380) to PODSSH_HS_PORT+3 of the loopback free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/ts-headscale-lib.sh
. "$HERE/ts-headscale-lib.sh"

PORT=${PODSSH_HS_PORT:-45380}
HS_NAME=podssh-hs-two
: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

die() {
    echo "ts-two-nodes: $*" >&2
    exit 1
}
for tool in timeout openssl curl python3 cargo; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done
ENGINE=$(hs_engine) || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"

W=$(mktemp -d 2>/dev/null || echo "/tmp/podssh-two-$$")
mkdir -p "$W/hs" "$W/keys" || die "cannot use the work directory $W"
cleanup() {
    timeout 60 "$ENGINE" rm -f "$HS_NAME" >/dev/null 2>&1
    rm -rf "$W"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
timeout 60 "$ENGINE" rm -f "$HS_NAME" >/dev/null 2>&1

echo "== a CA of the run; headscale on 127.0.0.1:$PORT"
hs_ca || { cat "$W/openssl.log"; die "openssl made no CA"; }
hs_config
HS_IMAGE=$(hs_pull "$REPO/images/headscale/Dockerfile") || die "headscale's image did not pull"
hs_start || { "$ENGINE" logs "$HS_NAME" 2>&1 | tail -20; die "headscale did not answer within 60 s"; }
hs_keys || { cat "$W/hs-cli.log"; die "headscale made no user or no pre-auth key"; }

echo "== the test with two nodes"
# No proxy of this host: each address of the test is on the loopback, but
# tailcat's, which a runner reaches directly.
(cd "$REPO" && env -u https_proxy -u HTTPS_PROXY -u all_proxy -u ALL_PROXY -u http_proxy -u HTTP_PROXY \
    PODSSH_TS_TWO_KEY_FILE="$W/keys/a.key" PODSSH_TS_TWO_CONTROL_URL="https://127.0.0.1:$PORT" \
    PODSSH_TS_TWO_CA_FILE="$W/ca.pem" timeout 3600 cargo test -q -p podssh-cli --features ts --test ts_two_nodes \
    -- --ignored --nocapture)
rc=$?
echo "ts-two-nodes: the test exited $rc"
exit "$rc"
