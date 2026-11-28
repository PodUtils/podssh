#!/bin/sh
# scripts/interop-filehost-0x0.sh - the file hosts' road (T-738) against
# 0x0.st's own server (mia/0x0, EUPL-1.2), pinned at a commit of
# git.0x0.st/mia/0x0 and built in a local container on images/box's Alpine
# with Waitress (--url-scheme=https) serving fhost:app directly (no nginx,
# FHOST_USE_X_ACCEL_REDIRECT=False) and a bind-mounted storage directory so
# the tests inspect the actual files written and unlinked on disk.
#
#   sh scripts/interop-filehost-0x0.sh
#
# Checks (each a line of scripts/interop-lib.sh):
#   filehost-0x0.upload_fetch_delete   HttpHost upload, download, X-Token delete -> 404
#   filehost-0x0.carrier_256k_failover 256 KiB each way, 429 failover to mia/0x0, pieces deleted
#   filehost-0x0.ciphertext_only       mia/0x0 disk storage holds ciphertext only
#   filehost-0x0.planted_unsealed      planted unsealed upload is caught on mia/0x0 disk
#   filehost-0x0.binary_session        optional full CLI session (PODSSH_0X0_BINARY=yes + mosquitto)
#
# Needs docker or podman (PODSSH_ENGINE names one), git, curl, timeout and
# cargo; port PODSSH_0X0_PORT (default 18490) free on 127.0.0.1. Set
# PODSSH_MOSQUITTO_TEST_BIN to also use Eclipse Mosquitto as the meeting point
# (auto-detected if on PATH or /usr/sbin/mosquitto). Exit 0 when all pass, 1
# when one fails, 71 when a host prerequisite is missing.

set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

ZEROX0_COMMIT=${PODSSH_0X0_COMMIT:-0cd289d9812675f60a9d81b0b9ce0a3d08cc4d35}
ZEROX0_REPO=${PODSSH_0X0_REPO:-https://git.0x0.st/mia/0x0.git}
PORT=${PODSSH_0X0_PORT:-18490}
IMAGE=localhost/podssh-0x0:0cd289d
NAME=podssh-filehost-0x0-interop
PLANT_PATCH="$REPO/scripts/plants/t738-unsealed-upload.patch"
: "${CARGO_BUILD_JOBS:=4}"
export CARGO_BUILD_JOBS

die() {
    echo "interop-filehost-0x0: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in git curl timeout cargo; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done

# image_of DOCKERFILE: the image pinned to a digest, pulled through pull-image.sh.
image_of() {
    _ref=$(tr -d '\r' <"$1" 2>/dev/null | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in
        *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;;
        *) return 1 ;;
    esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's pinned image did not pull"

W=$(mktemp -d) || die "cannot create temporary directory"
mkdir -p "$W/data/up" || die "cannot create data directory"
PLANT_APPLIED=0

remove_container() {
    timeout 60 "$ENGINE" rm -f "$NAME" >/dev/null 2>&1
}

# shellcheck disable=SC2317  # called by the EXIT/INT/TERM trap
cleanup() {
    if [ "$PLANT_APPLIED" -eq 1 ]; then
        git -C "$REPO" apply -R "$PLANT_PATCH" >/dev/null 2>&1 ||
            echo "interop-filehost-0x0: failed to revert $PLANT_PATCH" >&2
        PLANT_APPLIED=0
    fi
    remove_container
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
remove_container

echo "== mia/0x0 at pinned commit $ZEROX0_COMMIT"
git init -q "$W/0x0" || die "git init failed"
timeout 180 git -C "$W/0x0" fetch -q --depth 1 "$ZEROX0_REPO" "$ZEROX0_COMMIT" >"$W/git.log" 2>&1 || {
    cat "$W/git.log" >&2
    die "could not fetch $ZEROX0_REPO at $ZEROX0_COMMIT"
}
git -C "$W/0x0" checkout -q FETCH_HEAD || die "git checkout failed"
[ "$(git -C "$W/0x0" rev-parse HEAD)" = "$ZEROX0_COMMIT" ] || die "checked-out commit does not match $ZEROX0_COMMIT"

mkdir -p "$W/0x0/instance"
cat >"$W/0x0/instance/config.py" <<'EOF'
SQLALCHEMY_DATABASE_URI = "sqlite:////data/0x0.sqlite"
SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"timeout": 30}}
MAX_CONTENT_LENGTH = 64 * 1024 * 1024
PREFERRED_URL_SCHEME = "https"
USE_X_SENDFILE = False
FHOST_USE_X_ACCEL_REDIRECT = False
FHOST_STORAGE_PATH = "/data/up"
NSFW_DETECT = False
EOF

cat >"$W/entrypoint.sh" <<'EOF'
#!/bin/sh
set -eu
mkdir -p /data/up
python3 -c 'import fhost
with fhost.app.app_context():
    fhost.db.create_all()
'
exec waitress-serve --host=0.0.0.0 --port=8080 --url-scheme=https --threads=4 fhost:app
EOF
chmod 755 "$W/entrypoint.sh"

# Behind a re-signing proxy, pass SSL_CERT_FILE into the image build alone.
BUILD_CA_COPY=
BUILD_CA_ENV=
if [ -n "${SSL_CERT_FILE:-}" ] && [ -r "$SSL_CERT_FILE" ]; then
    cp "$SSL_CERT_FILE" "$W/build-ca.pem" || die "cannot copy SSL_CERT_FILE"
    BUILD_CA_COPY="COPY build-ca.pem /etc/ssl/certs/build-ca.pem"
    BUILD_CA_ENV="SSL_CERT_FILE=/etc/ssl/certs/build-ca.pem"
fi

cat >"$W/Containerfile" <<EOF
FROM $ALPINE
$BUILD_CA_COPY
RUN $BUILD_CA_ENV apk add --no-cache \
    python3 py3-flask py3-flask-sqlalchemy py3-alembic py3-magic \
    py3-requests py3-validators py3-waitress py3-pip && \
    $BUILD_CA_ENV pip install --no-cache-dir --break-system-packages --no-deps Flask-Migrate==4.1.0
WORKDIR /app
COPY 0x0 /app
COPY entrypoint.sh /entrypoint.sh
EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]
EOF

NET=
case "${HTTPS_PROXY:-${https_proxy:-}}" in
    *://127.* | *://localhost* | *://\[::1\]*) NET=--network=host ;;
esac
# shellcheck disable=SC2086  # $NET is one flag or empty
timeout 900 "$ENGINE" build -q $NET \
    ${HTTP_PROXY:+--build-arg "HTTP_PROXY=$HTTP_PROXY"} \
    ${HTTPS_PROXY:+--build-arg "HTTPS_PROXY=$HTTPS_PROXY"} \
    ${NO_PROXY:+--build-arg "NO_PROXY=$NO_PROXY"} \
    -t "$IMAGE" -f "$W/Containerfile" "$W" >"$W/build.log" 2>&1 || {
    tail -40 "$W/build.log" >&2
    die "mia/0x0 container image did not build"
}

echo "== starting mia/0x0 on 127.0.0.1:$PORT (storage: $W/data/up)"
USER_FLAG=
if [ "$ENGINE" = "docker" ]; then
    USER_FLAG="-u $(id -u):$(id -g)"
fi
# shellcheck disable=SC2086  # $USER_FLAG is two words or empty
timeout 60 "$ENGINE" run -d --name "$NAME" $USER_FLAG \
    -p "127.0.0.1:$PORT:8080" \
    -v "$W/data:/data" \
    "$IMAGE" >"$W/run.log" 2>&1 || {
    cat "$W/run.log" >&2
    die "mia/0x0 container did not start"
}

i=0
until timeout 5 curl -fsS --noproxy '*' --max-time 2 -o /dev/null "http://127.0.0.1:$PORT/robots.txt" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -ge 60 ]; then
        timeout 30 "$ENGINE" logs "$NAME" 2>&1 | tail -30 >&2
        die "mia/0x0 did not answer /robots.txt within 60 s"
    fi
    sleep 1
done
timeout 5 curl -fsS --noproxy '*' --max-time 5 -o /dev/null "http://127.0.0.1:$PORT/" || {
    timeout 30 "$ENGINE" logs "$NAME" 2>&1 | tail -30 >&2
    die "mia/0x0 did not answer /"
}

if [ -z "${PODSSH_MOSQUITTO_TEST_BIN:-}" ]; then
    for m in mosquitto /usr/sbin/mosquitto; do
        if command -v "$m" >/dev/null 2>&1; then
            PODSSH_MOSQUITTO_TEST_BIN=$(command -v "$m")
            export PODSSH_MOSQUITTO_TEST_BIN
            break
        fi
    done
fi

export PODSSH_0X0_TEST_PORT="$PORT"
export PODSSH_0X0_STORAGE_DIR="$W/data/up"

echo "== building filehost_0x0 tests"
timeout 1800 cargo test --locked --manifest-path "$REPO/Cargo.toml" \
    -p podssh-cli --features filehost --test filehost_0x0 --no-run >"$W/cargo-build.log" 2>&1 || {
    tail -40 "$W/cargo-build.log" >&2
    die "filehost_0x0 did not build"
}

run_test() {
    _fn=$1
    _log="$W/$_fn.log"
    timeout 300 cargo test --locked --manifest-path "$REPO/Cargo.toml" \
        -p podssh-cli --features filehost --test filehost_0x0 "$_fn" -- --exact --nocapture >"$_log" 2>&1
    _rc=$?
    [ "$_rc" -eq 0 ] && ! grep -q "did not run" "$_log" && return 0
    [ "$_rc" -ne 0 ] && return "$_rc"
    return 1
}

echo "== running filehost_0x0 tests against real mia/0x0"
run_test upload_fetch_and_delete_against_mia_0x0
rc=$?
if [ "$rc" -eq 0 ]; then
    ok filehost-0x0.upload_fetch_delete "upload, download, and X-Token delete -> 404 against real mia/0x0"
else
    bad filehost-0x0.upload_fetch_delete "exit $rc" "$W/upload_fetch_and_delete_against_mia_0x0.log"
fi

run_test carrier_moves_256_kib_each_way_with_429_failover_and_deletes_pieces
rc=$?
if [ "$rc" -eq 0 ]; then
    ok filehost-0x0.carrier_256k_failover "256 KiB each way with equal digests, 429 failover to mia/0x0, and delete"
else
    bad filehost-0x0.carrier_256k_failover "exit $rc" \
        "$W/carrier_moves_256_kib_each_way_with_429_failover_and_deletes_pieces.log"
fi

run_test stored_bytes_in_mia_0x0_hold_no_plaintext
rc=$?
if [ "$rc" -eq 0 ]; then
    ok filehost-0x0.ciphertext_only "mia/0x0 disk storage holds ciphertext only before receive deletes it"
else
    bad filehost-0x0.ciphertext_only "exit $rc" "$W/stored_bytes_in_mia_0x0_hold_no_plaintext.log"
fi

echo "== planted defect: unsealed piece uploaded to real mia/0x0"
_plog="$W/planted_unsealed.log"
if git -C "$REPO" apply --check "$PLANT_PATCH" >"$_plog" 2>&1 &&
    git -C "$REPO" apply "$PLANT_PATCH" >>"$_plog" 2>&1; then
    PLANT_APPLIED=1
    timeout 600 cargo test --locked --manifest-path "$REPO/Cargo.toml" \
        -p podssh-cli --features filehost --test filehost_0x0 \
        stored_bytes_in_mia_0x0_hold_no_plaintext -- --exact --nocapture >"$_plog" 2>&1
    _prc=$?
    git -C "$REPO" apply -R "$PLANT_PATCH" >>"$_plog" 2>&1 || die "failed to revert $PLANT_PATCH"
    PLANT_APPLIED=0
    # The planted run panics before receive deletes the unsealed file; tidy disk.
    rm -f "$W/data/up"/*
    if [ "$_prc" -ne 0 ] && [ "$_prc" -ne 124 ] && grep -q "plaintext found in mia/0x0 storage" "$_plog"; then
        ok filehost-0x0.planted_unsealed "planted unsealed upload caught on mia/0x0 disk (exit $_prc)"
    else
        bad filehost-0x0.planted_unsealed "plant was not caught (exit $_prc)" "$_plog"
    fi
else
    bad filehost-0x0.planted_unsealed "plant patch $PLANT_PATCH did not apply cleanly" "$_plog"
fi

if [ "${PODSSH_0X0_BINARY:-no}" = "yes" ] && [ -n "${PODSSH_MOSQUITTO_TEST_BIN:-}" ]; then
    echo "== full CLI binary session through Mosquitto and real mia/0x0"
    _blog="$W/carrier_filehost.log"
    timeout 1800 cargo test --locked --manifest-path "$REPO/Cargo.toml" \
        -p podssh-cli --features filehost --test carrier_filehost -- --nocapture >"$_blog" 2>&1
    _brc=$?
    if [ "$_brc" -eq 0 ] && ! grep -q "did not run" "$_blog"; then
        ok filehost-0x0.binary_session "full podssh node + ssh 256 KiB session through Mosquitto and real mia/0x0"
    else
        bad filehost-0x0.binary_session "exit $_brc" "$_blog"
    fi
else
    unmet filehost-0x0.binary_session "set PODSSH_0X0_BINARY=yes with mosquitto to also run full paced CLI session"
fi

timeout 30 "$ENGINE" logs "$NAME" >"$W/0x0.log" 2>&1 || true
# shellcheck disable=SC2154  # pass, fail and unmet are set by interop-lib.sh
echo "interop-filehost-0x0: $pass passed, $fail failed, $unmet unmet"
[ "$fail" -eq 0 ] || exit 1
