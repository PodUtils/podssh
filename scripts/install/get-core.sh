#!/bin/sh
# scripts/install/get-core.sh - get the installer core (core.sh and
# core-net.sh) and pins.py of PodUtils/podcrates at their pinned commit, each checked by its
# SHA-256, into DIR (default: scripts/install, beside podssh.sh, which
# includes core.sh from its own directory; git ignores both). The release
# stamps podssh.sh with them; a local test does the same. It also gets
# release-index.py, which writes the release's release-index.json for
# pod-release's readers (T-850), at the tag that podssh's crates pin.
#
#   sh scripts/install/get-core.sh [DIR]
#
# A new pin: the commit of a podcrates tag, and the SHA-256 of each file at
# it. A file that does not agree is removed, and the run fails.
set -eu
COMMIT=d21fd638d8aa82465643eb33b80537a1d1ddd00f # podcrates v0.63.0
CORE_SHA=1ab8578a5e2e44982d8d8f4b37fd910261958afc8666e8b0415fc8a1071beaaa
NET_SHA=63d365203c9bb1a1f8d322f2b83187e21f400f4023e6084a49e54a8d99f0def8
PINS_SHA=7a3632c60494b4aace45db37e88b277a1353e8713d60c288430b452e16ea0205
INDEX_COMMIT=7cbe674e39aaa1673339e94ffcc2fcc3b7585bb4 # podcrates v0.77.0
INDEX_SHA=32726ae339de11b25a3903dd794120fe75a4fd894ae030ed3fb9be8a30d264c1
dir=${1:-$(dirname "$0")}
mkdir -p "$dir"
raw="https://raw.githubusercontent.com/PodUtils/podcrates"
# get NAME SHA256 [COMMIT [PATH]]: scripts/install/NAME at $COMMIT by default.
get() {
    at=${3:-$COMMIT}
    curl -qfsSL --retry 4 --max-time 60 -o "$dir/$1" "$raw/$at/${4:-scripts/install}/$1"
    got=$(sha256sum "$dir/$1" | cut -d' ' -f1)
    if [ "$got" != "$2" ]; then
        rm -f "$dir/$1"
        echo "get-core.sh: $1 at $at has SHA-256 $got, not $2" >&2
        exit 1
    fi
    echo "get-core.sh: $1 at $at: ok"
}
get core.sh "$CORE_SHA"
get core-net.sh "$NET_SHA"
get pins.py "$PINS_SHA"
get release-index.py "$INDEX_SHA" "$INDEX_COMMIT" scripts
