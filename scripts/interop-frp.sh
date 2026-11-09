#!/bin/sh
# scripts/interop-frp.sh - the frp road (T-498, the operator's ruling Q66):
# `podssh node NAME TARGET --frp FILE` behind frp's own frps, `podssh ssh
# node://NAME` with PODSSH_FRP visiting it, and podssh's visitor to a real
# frpc's STCP service of an sshd, against frps and frpc of a pinned release,
# in containers on a network of the run, with OpenSSH's sshd as the target
# and a plain squid as the host's own proxy (HTTPS_PROXY), which carries each
# connection to frps by its name.
#
#   sh scripts/interop-frp.sh PODSSH_BINARY
#
# frp's release is fetched from GitHub with its frp_sha256_checksums.txt,
# and the archive's SHA-256 is compared with that file's line at run time
# (or both are taken from PODSSH_FRP_DIR, a directory with copies of the
# two); its Linux binaries are static, and run on images/box's Alpine, which
# also runs sshd, squid and socat from its packages. frps serves frp's TCP
# with TLS on its port, with the run's certificate, and frp's WebSocket in
# the clear on the same port, behind socat as the user's TLS front end. frp's
# own frpc, as the user lab, serves sshd.test:22 as the STCP service sshd,
# which only the user guest may visit (allowUsers). The CA, the certificates,
# frps's token and both STCP secrets are made for the run in a directory
# that the run removes; podssh reads them from its private files alone,
# never argv, and no output of podssh may show one.
#
# The checks: the pinned frps and frpc run; frpc's service is up; a podssh
# node logs in and registers its service over frp:// through the squid; its
# door refuses a key that --allow does not hold, then lets it in; a session
# through frps, and 1 MiB each way with equal digests; a node and a session
# over wss:// through the TLS front end; podssh's visitor, logged in as
# guest, to frpc's service of sshd, with SSH on the visit; a user that the
# service does not allow, another secret and another token, each refused in
# frps's words; the squid carrying each connection by name; no output
# holding a secret. Each prints a line of scripts/interop-lib.sh; the exit
# code is 0 when each passed, else 1, and 71 when the host lacks what the run
# needs.
#
# Needs podman or docker (PODSSH_ENGINE names one), curl (unless
# PODSSH_FRP_DIR), tar, openssl, python3, sha256sum and timeout; the ports
# PODSSH_FRP_PORT (18480) to PODSSH_FRP_PORT+3 of the loopback free.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
# shellcheck source=scripts/interop-lib.sh
. "$HERE/interop-lib.sh"

BIN=${1:-}
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "usage: sh scripts/interop-frp.sh PODSSH_BINARY" >&2; exit 64; }
case $BIN in /*) ;; *) BIN=$PWD/$BIN ;; esac
PORT=${PODSSH_FRP_PORT:-18480}
FRPS_PORT=$PORT
FRONT_PORT=$((PORT + 1))
HOP_PORT=$((PORT + 2))
SSHD_PORT=$((PORT + 3))
NET=podssh-frp-net
NAMES="podssh-frp-check podssh-frp-sshd podssh-frp-frps podssh-frp-front podssh-frp-frpc podssh-frp-hop"
# frp's release read for T-498 (v0.71.1, 2026-10-14). Its digests are not
# kept here: each run reads them from the release's own checksums file.
FRP_VERSION=0.71.1
SUMS=frp_sha256_checksums.txt

die() {
    echo "interop-frp: $*" >&2
    exit 71
}

ENGINE=${PODSSH_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for e in podman docker; do
        command -v "$e" >/dev/null 2>&1 && timeout 60 "$e" info >/dev/null 2>&1 && { ENGINE=$e; break; }
    done
fi
[ -n "$ENGINE" ] || die "neither podman nor docker answers here (PODSSH_ENGINE names one)"
for tool in tar openssl python3 sha256sum timeout; do
    command -v "$tool" >/dev/null 2>&1 || die "$tool is missing"
done
case $(uname -m) in
    x86_64 | amd64) ARCH=amd64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) die "no frp release for $(uname -m)" ;;
esac

W=$(mktemp -d) || die "no directory for the run"
NODES=
stop_nodes() {
    for _p in $NODES; do
        kill "$_p" 2>/dev/null
    done
    for _p in $NODES; do
        wait "$_p" 2>/dev/null
    done
    NODES=
}
remove_all() {
    for _c in $NAMES; do
        timeout 60 "$ENGINE" rm -f "$_c" >/dev/null 2>&1
    done
    timeout 60 "$ENGINE" network rm "$NET" >/dev/null 2>&1
}
cleanup() {
    stop_nodes
    remove_all
    rm -rf "$W"
}
trap cleanup EXIT INT TERM
remove_all

# The archive and the release's checksums file, then the archive's digest
# against the file's line for it.
DIR=frp_${FRP_VERSION}_linux_$ARCH
TGZ=$DIR.tar.gz
for file in "$TGZ" "$SUMS"; do
    if [ -n "${PODSSH_FRP_DIR:-}" ]; then
        cp "$PODSSH_FRP_DIR/$file" "$W/$file" || die "PODSSH_FRP_DIR has no $file"
    else
        command -v curl >/dev/null 2>&1 || die "curl is missing (or give PODSSH_FRP_DIR)"
        url=https://github.com/fatedier/frp/releases/download/v$FRP_VERSION/$file
        timeout 300 curl -fsSL --retry 3 --max-time 240 -o "$W/$file" "$url" >"$W/fetch.log" 2>&1 ||
            die "$file did not download from $url: $(tail -5 "$W/fetch.log")"
    fi
done
want=$(tr -d '\r' <"$W/$SUMS" | awk -v f="$TGZ" '$2 == f || $2 == "*" f { print $1; exit }')
case $want in
    [0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
    *) die "$SUMS has no SHA-256 for $TGZ" ;;
esac
[ "${#want}" = 64 ] || die "$SUMS names no SHA-256 of 64 digits for $TGZ"
got=$(sha256sum "$W/$TGZ" | cut -d' ' -f1)
[ "$got" = "$want" ] || die "$TGZ has the SHA-256 $got, not the $want of the release's $SUMS"
mkdir -p "$W/unpack" "$W/frp"
tar -xzf "$W/$TGZ" -C "$W/unpack" || die "$TGZ does not unpack"
for b in frps frpc; do
    cp "$W/unpack/$DIR/$b" "$W/frp/$b" 2>/dev/null || die "$TGZ holds no $DIR/$b"
    chmod 755 "$W/frp/$b"
done

image_of() {
    _ref=$(tr -d '\r' <"$1" | sed -n 's/^FROM[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p')
    case $_ref in *@sha256:*) PULL_ENGINE=$ENGINE sh "$HERE/pull-image.sh" "$_ref" ;; *) return 1 ;; esac
}
ALPINE=$(image_of "$REPO/images/box/Dockerfile") || die "Alpine's image did not pull"

# The CA of the run, and one certificate for frps.test (frps's own TLS) and
# front.test (the TLS front end before frps's WebSocket).
mkdir -p "$W/tls" "$W/key" "$W/hop" "$W/frps" "$W/frpc"
printf '%s\n' '[req]' 'distinguished_name = dn' 'x509_extensions = ca_ext' 'prompt = no' '[dn]' \
    'CN = podssh frp test CA' '[ca_ext]' 'basicConstraints = critical,CA:TRUE' \
    'keyUsage = critical,keyCertSign,cRLSign' 'subjectKeyIdentifier = hash' >"$W/ca.cnf"
printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = frps.test' '[leaf]' \
    'basicConstraints = critical,CA:FALSE' 'keyUsage = critical,digitalSignature' 'extendedKeyUsage = serverAuth' \
    'subjectAltName = DNS:frps.test,DNS:front.test' 'authorityKeyIdentifier = keyid' >"$W/leaf.cnf"
{
    timeout 60 openssl req -x509 -config "$W/ca.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -keyout "$W/ca.key" -out "$W/ca.pem" -days 2 &&
        timeout 60 openssl req -new -config "$W/leaf.cnf" -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
            -keyout "$W/tls/leaf.key" -out "$W/leaf.csr" &&
        timeout 60 openssl x509 -req -in "$W/leaf.csr" -CA "$W/ca.pem" -CAkey "$W/ca.key" -CAcreateserial \
            -days 2 -extfile "$W/leaf.cnf" -extensions leaf -out "$W/tls/leaf.pem"
} >"$W/openssl.log" 2>&1 || die "openssl could not make the certificates: $(tail -3 "$W/openssl.log")"
chmod 644 "$W/tls/leaf.key"

# frps's token and the two STCP secrets, made here and never printed: the
# podssh nodes' secret, and frpc's service's.
token=$(openssl rand -hex 16) || die "no token"
secret=$(openssl rand -hex 16) || die "no secret"
secret_sshd=$(openssl rand -hex 16) || die "no secret"
umask 077
printf '%s\n' "$token" "$secret" "$secret_sshd" >"$W/secret.words"
umask 022
printf '%s\n' 'bindAddr = "0.0.0.0"' 'bindPort = 7000' 'auth.method = "token"' "auth.token = \"$token\"" \
    'transport.tls.certFile = "/etc/frp/tls/leaf.pem"' 'transport.tls.keyFile = "/etc/frp/tls/leaf.key"' \
    >"$W/frps/frps.toml"
printf '%s\n' 'serverAddr = "frps.test"' 'serverPort = 7000' 'user = "lab"' 'loginFailExit = false' \
    'auth.method = "token"' "auth.token = \"$token\"" '' '[[proxies]]' 'name = "sshd"' 'type = "stcp"' \
    "secretKey = \"$secret_sshd\"" 'localIP = "sshd.test"' 'localPort = 22' 'allowUsers = ["guest"]' \
    >"$W/frpc/frpc.toml"
chmod 644 "$W/frps/frps.toml" "$W/frpc/frpc.toml"
timeout 30 "$BIN" keygen -q -t ed25519 -N '' -f "$W/key/id" >/dev/null 2>&1 || die "podssh keygen failed"
chmod 644 "$W/key/id.pub"
printf '%s\n' 'http_port 3128' 'http_access allow all' 'cache deny all' 'access_log stdio:/tmp/access.log' \
    'cache_log /tmp/cache.log' 'pid_filename none' 'logfile_rotate 0' 'coredump_dir /tmp' >"$W/hop/squid.conf"

# The road's files of podssh, private: each node's and each visitor's.
mkdir -p "$W/node1" "$W/node2" "$W/client" "$W/files"
chmod 700 "$W/node1" "$W/node2" "$W/client" "$W/files"
road_file() { # FILE LINES...
    _f=$1
    shift
    (umask 077 && printf '%s\n' "$@" >"$_f")
}
road_file "$W/files/tls" '# the run of T-498' 'server frp://frps.test' "token $token" "secret $secret"
road_file "$W/files/wss" 'server wss://front.test:8443' "token $token" "secret $secret"
road_file "$W/files/wrong-secret" 'server frp://frps.test' "token $token" "secret $secret-wrong"
road_file "$W/files/wrong-token" 'server frp://frps.test' "token $token-wrong" "secret $secret"
road_file "$W/files/plain" 'server frp://frps.test' "token $token" "secret $secret_sshd" 'user guest' \
    'owner lab' 'name sshd' 'plain'
road_file "$W/files/stranger" 'server frp://frps.test' "token $token" "secret $secret_sshd" 'user stranger' \
    'owner lab' 'name sshd' 'plain'
printf '# the client keys of the run\n' >"$W/allow"

for b in frps frpc; do
    timeout 120 "$ENGINE" run --name podssh-frp-check -v "$W/frp:/f:ro" "$ALPINE" "/f/$b" --version \
        >"$W/version-$b.log" 2>&1
    timeout 60 "$ENGINE" rm -f podssh-frp-check >/dev/null 2>&1
done
grep -q "$FRP_VERSION" "$W/version-frps.log" && grep -q "$FRP_VERSION" "$W/version-frpc.log" &&
    ok frp.version "frps and frpc $FRP_VERSION run on Alpine, their archive checked by the release's $SUMS" ||
    bad frp.version "the pinned frps or frpc did not say $FRP_VERSION" "$W/version-frps.log"

timeout 60 "$ENGINE" network create "$NET" >/dev/null || die "the network $NET could not be made"
timeout 300 "$ENGINE" run -d --name podssh-frp-sshd --network "$NET" --network-alias sshd.test \
    -p "127.0.0.1:$SSHD_PORT:22" -v "$W/key:/k:ro" "$ALPINE" sh -c 'apk add --no-cache openssh-server >/dev/null &&
    ssh-keygen -A >/dev/null && mkdir -p /root/.ssh && cp /k/id.pub /root/.ssh/authorized_keys &&
    chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys && sed -i "s/^root:[^:]*:/root:*:/" /etc/shadow &&
    exec /usr/sbin/sshd -D -e' >/dev/null || die "sshd did not start"
timeout 300 "$ENGINE" run -d --name podssh-frp-frps --network "$NET" --network-alias frps.test \
    -p "127.0.0.1:$FRPS_PORT:7000" -v "$W/frp:/f:ro" -v "$W/frps:/etc/frp:ro" -v "$W/tls:/etc/frp/tls:ro" \
    "$ALPINE" /f/frps -c /etc/frp/frps.toml >/dev/null || die "frps did not start"
# The user's TLS front end: TLS on 8443, frps's port in the clear behind it.
timeout 300 "$ENGINE" run -d --name podssh-frp-front --network "$NET" --network-alias front.test \
    -p "127.0.0.1:$FRONT_PORT:8443" -v "$W/tls:/t:ro" "$ALPINE" sh -c 'apk add --no-cache socat >/dev/null &&
    exec socat openssl-listen:8443,reuseaddr,fork,cert=/t/leaf.pem,key=/t/leaf.key,verify=0 tcp:frps.test:7000' \
    >/dev/null || die "the TLS front end did not start"
timeout 300 "$ENGINE" run -d --name podssh-frp-hop --network "$NET" -p "127.0.0.1:$HOP_PORT:3128" \
    -v "$W/hop:/etc/podssh-squid:ro" "$ALPINE" \
    sh -c 'apk add --no-cache squid >/dev/null && exec squid -N -f /etc/podssh-squid/squid.conf' >/dev/null ||
    die "the host's squid did not start"

# ready PORT SECONDS MODE: the loopback's PORT answers frp's TLS (its byte
# 0x17 first), TLS, an SSH banner or bytes for a request.
ready() {
    _t0=$(date +%s)
    while :; do
        timeout 10 python3 -I -c 'import socket, ssl, sys
port, mode, ca = int(sys.argv[1]), sys.argv[2], sys.argv[3]
try:
    s = socket.create_connection(("127.0.0.1", port), 5)
    s.settimeout(5)
    if mode in ("frp", "tls"):
        if mode == "frp":
            s.sendall(b"\x17")
        name = "frps.test" if mode == "frp" else "front.test"
        ssl.create_default_context(cafile=ca).wrap_socket(s, server_hostname=name).close()
    elif mode == "ssh":
        sys.exit(0 if s.recv(8).startswith(b"SSH-") else 1)
    else:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        sys.exit(0 if s.recv(1) else 1)
except (OSError, ssl.SSLError):
    sys.exit(1)' "$1" "$3" "$W/ca.pem" && return 0
        [ $(($(date +%s) - _t0)) -lt "$2" ] || return 1
        sleep 1
    done
}
logs_of() {
    timeout 30 "$ENGINE" logs "$1" 2>&1 | grep -v -F -f "$W/secret.words" | tail -20
}
ready "$FRPS_PORT" 300 frp || { logs_of podssh-frp-frps; die "frps did not answer frp's TLS"; }
ready "$FRONT_PORT" 300 tls || { logs_of podssh-frp-front; die "the TLS front end did not answer"; }
ready "$HOP_PORT" 300 http || { logs_of podssh-frp-hop; die "the host's squid did not answer"; }
ready "$SSHD_PORT" 300 ssh || { logs_of podssh-frp-sshd; die "sshd did not answer"; }

# frp's own frpc, once frps answers, as the user lab with its STCP service.
timeout 300 "$ENGINE" run -d --name podssh-frp-frpc --network "$NET" -v "$W/frp:/f:ro" \
    -v "$W/frpc:/etc/frp:ro" "$ALPINE" /f/frpc -c /etc/frp/frpc.toml >/dev/null || die "frpc did not start"
t0=$(date +%s)
until timeout 30 "$ENGINE" logs podssh-frp-frpc 2>&1 | grep -q 'start proxy success'; do
    [ $(($(date +%s) - t0)) -lt 120 ] || break
    sleep 1
done
logs_of podssh-frp-frpc >"$W/frpc.log"
grep -q 'start proxy success' "$W/frpc.log" &&
    ok frp.frpc "frp's own frpc, as the user lab, serves sshd as the STCP service lab.sshd" ||
    bad frp.frpc "frpc did not start its STCP service" "$W/frpc.log"

# The settings of each podssh run: its own home, the squid as its proxy, and
# the roads of the run alone.
quiet_env() {
    env -u SSH_AUTH_SOCK -u NO_PROXY -u no_proxy -u ALL_PROXY -u all_proxy -u SSL_CERT_FILE \
        HTTPS_PROXY="http://127.0.0.1:$HOP_PORT" PODSSH_SSH_CONFIG=none PODSSH_SETTINGS=none \
        PODSSH_TRANSIT=no PODSSH_PIPING=no PODSSH_IROH_PKARR=off PODSSH_OPENTUNNEL=no PODSSH_DERP=no "$@"
}
# node_up NAME HOME FILE: a podssh node in front of sshd, once frps took its
# service; its lines in $W/node-NAME.err. env runs in this shell's child
# itself, not in a function's subshell, so that the kill of $! reaches
# timeout, which ends the node.
node_up() {
    env -u SSH_AUTH_SOCK -u NO_PROXY -u no_proxy -u ALL_PROXY -u all_proxy -u SSL_CERT_FILE \
        HTTPS_PROXY="http://127.0.0.1:$HOP_PORT" PODSSH_SSH_CONFIG=none PODSSH_SETTINGS=none \
        PODSSH_TRANSIT=no PODSSH_PIPING=no PODSSH_IROH_PKARR=off PODSSH_OPENTUNNEL=no PODSSH_DERP=no \
        HOME="$2" XDG_CACHE_HOME="$2/cache" timeout 900 "$BIN" node "$1" "127.0.0.1:$SSHD_PORT" \
        --frp "$3" --allow "$W/allow" --key "$2/node.key" --ca-file "$W/ca.pem" \
        </dev/null >"$W/node-$1.out" 2>"$W/node-$1.err" &
    NODES="$NODES $!"
    _t0=$(date +%s)
    until grep -q "waiting for visitors at" "$W/node-$1.err" 2>/dev/null; do
        [ $(($(date +%s) - _t0)) -lt 60 ] || return 1
        sleep 1
    done
    return 0
}
SSH_OPTS="-i $W/key/id -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$W/kh -o BatchMode=yes"
# client NAME FILE ARGS...: podssh ssh with PODSSH_FRP naming FILE.
client() {
    _n=$1
    _f=$2
    shift 2
    # shellcheck disable=SC2086  # the options are words
    quiet_env HOME="$W/client" XDG_CACHE_HOME="$W/client/cache" PODSSH_FRP="$_f" timeout 120 "$BIN" ssh -v \
        --ca-file "$W/ca.pem" --client-key "$W/client/client.key" $SSH_OPTS "$@" \
        </dev/null >"$W/$_n.out" 2>"$W/$_n.err"
}

echo
echo "== the frp road: frps and frpc $FRP_VERSION of frp's own release (T-498)"

node_up lab "$W/node1" "$W/files/tls" &&
    grep -q 'waiting for visitors at frp://frps.test:7000 as the STCP service lab' "$W/node-lab.err" &&
    ok frp.node "podssh node lab logs in to frps over frp:// through the squid, and registers its STCP service" ||
    bad frp.node "the node did not register its service at frps" "$W/node-lab.err"

# The first visit: the node's door holds no key of this client yet.
client door "$W/files/tls" node://root@lab 'echo through-frp'
rc=$?
print=$(sed -n "s|.*refused this client's key \(SHA256:[A-Za-z0-9+/=]*\).*|\1|p" "$W/door.err" | head -1)
[ "$rc" = 77 ] && [ -n "$print" ] &&
    ok frp.door "a client key that --allow does not hold: the node refuses it through frps (exit 77)" ||
    bad frp.door "the first visit, with no key let in: exit $rc" "$W/door.err"
[ -n "$print" ] && printf '%s the run of T-498\n' "$print" >>"$W/allow"

client session "$W/files/tls" node://root@lab 'echo through-frp'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/session.out")" = through-frp ] &&
    grep -q 'the frp road answered first' "$W/session.err" &&
    ok frp.session "a session to the node through frps, in the end-to-end channel and the layer" ||
    bad frp.session "a session through frps: exit $rc" "$W/session.err"

head -c 1048576 /dev/urandom >"$W/mib"
want=$(sha256sum <"$W/mib" | cut -d' ' -f1)
# shellcheck disable=SC2086
quiet_env HOME="$W/client" XDG_CACHE_HOME="$W/client/cache" PODSSH_FRP="$W/files/tls" timeout 120 "$BIN" ssh \
    --ca-file "$W/ca.pem" --client-key "$W/client/client.key" $SSH_OPTS node://root@lab cat \
    <"$W/mib" >"$W/bulk.out" 2>"$W/bulk.err"
rc=$?
got=$(sha256sum <"$W/bulk.out" | cut -d' ' -f1)
[ "$rc" = 0 ] && [ "$got" = "$want" ] && ok frp.bulk "1 MiB each way through frps, equal digests" ||
    bad frp.bulk "1 MiB through frps: exit $rc, $(wc -c <"$W/bulk.out") bytes back" "$W/bulk.err"

if node_up labws "$W/node2" "$W/files/wss" &&
    grep -q 'waiting for visitors at wss://front.test:8443/... as the STCP service labws' "$W/node-labws.err"; then
    client wss "$W/files/wss" node://root@labws 'echo through-wss'
    rc=$?
    [ "$rc" = 0 ] && [ "$(cat "$W/wss.out")" = through-wss ] &&
        ok frp.wss "a node and a session over wss:// through the user's TLS front end before frps" ||
        bad frp.wss "a session over wss://: exit $rc" "$W/wss.err"
else
    bad frp.wss "the node of wss:// did not register its service through the front end" "$W/node-labws.err"
fi

client plain "$W/files/plain" node://root@sshd 'echo plain-frp'
rc=$?
[ "$rc" = 0 ] && [ "$(cat "$W/plain.out")" = plain-frp ] &&
    grep -q 'the plain STCP service lab.sshd through frp://frps.test:7000' "$W/plain.err" &&
    ok frp.plain "podssh's visitor, logged in as guest, to frpc's STCP service of sshd, with SSH on the visit" ||
    bad frp.plain "the visit to frpc's service: exit $rc" "$W/plain.err"

client stranger "$W/files/stranger" node://root@sshd 'echo plain-frp'
rc=$?
[ "$rc" = 255 ] && grep -q 'frps refused the visit: ".*not allowed' "$W/stranger.err" &&
    ok frp.not-allowed "a user that the service's allowUsers does not name: refused in frps's words (exit 255)" ||
    bad frp.not-allowed "a user that the service does not allow: exit $rc" "$W/stranger.err"

client wrong-secret "$W/files/wrong-secret" node://root@lab 'echo through-frp'
rc=$?
[ "$rc" != 0 ] && grep -q 'frps refused the visit: "visitor connection of \[lab\] auth failed"' "$W/wrong-secret.err" &&
    ok frp.wrong-secret "another secret: frps refuses the visit in its words (exit $rc)" ||
    bad frp.wrong-secret "another secret: exit $rc" "$W/wrong-secret.err"

quiet_env HOME="$W/node1" XDG_CACHE_HOME="$W/node1/cache" timeout 120 "$BIN" node badtoken \
    "127.0.0.1:$SSHD_PORT" --frp "$W/files/wrong-token" --allow "$W/allow" --key "$W/node1/bad.key" \
    --ca-file "$W/ca.pem" </dev/null >"$W/wrong-token.out" 2>"$W/wrong-token.err"
rc=$?
[ "$rc" = 69 ] && grep -q "token in login doesn't match token from configuration" "$W/wrong-token.err" &&
    ok frp.wrong-token "a node with another token ends in frps's words (exit 69)" ||
    bad frp.wrong-token "a node with another token: exit $rc" "$W/wrong-token.err"

asked=$(timeout 30 "$ENGINE" exec podssh-frp-hop cat /tmp/access.log 2>/dev/null)
tls_asks=$(printf '%s\n' "$asked" | grep -c 'CONNECT frps.test:7000')
wss_asks=$(printf '%s\n' "$asked" | grep -c 'CONNECT front.test:8443')
[ "${tls_asks:-0}" -gt 0 ] && [ "${wss_asks:-0}" -gt 0 ] &&
    ok frp.hop "HTTPS_PROXY carries each connection to frps and its front end by name" ||
    bad frp.hop "the squid saw $tls_asks CONNECTs to frps.test:7000 and $wss_asks to front.test:8443"

stop_nodes
leaked=$(grep -l -F -f "$W/secret.words" "$W"/*.out "$W"/*.err 2>/dev/null | wc -l)
[ "$leaked" = 0 ] && ok frp.secret "no output of podssh holds the token or a secret" ||
    bad frp.secret "$leaked outputs hold the token or a secret"

echo "interop-frp: $pass passed, $fail failed, $unmet without what they need"
[ "$fail" = 0 ] || exit 1
exit 0
