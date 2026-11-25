#!/bin/sh
# Prepare the hosted checkout and start its read-only GitHub watchers.
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$root"

sync_main() {
    changes=$(git status --porcelain) || return 1
    if [ -n "$changes" ]; then
        echo "session-start: keeping the checkout with local changes"
        return 0
    fi
    upstream=refs/remotes/origin/main
    if ! GIT_TERMINAL_PROMPT=0 timeout 60 git fetch -q origin "+refs/heads/main:$upstream" </dev/null; then
        echo "session-start: could not fetch origin/main. The checkout stays in place." >&2
        return 1
    fi
    if [ "$(git symbolic-ref --short -q HEAD || :)" != main ]; then
        if ! git merge-base --is-ancestor HEAD "$upstream"; then
            echo "session-start: keeping the checkout with local commits or incomplete history" >&2
            return 1
        fi
        if git show-ref --verify --quiet refs/heads/main; then
            git switch -q main || return 1
        else
            git switch -q -c main --track origin/main || return 1
        fi
    fi
    if ! git merge --ff-only -q "$upstream"; then
        echo "session-start: resolve the divergence between local main and origin/main" >&2
        return 1
    fi
}

# The watcher files and checksums come from podcrates v0.83.0.
pin=5fd6fb7e3495d5e9a591e36c5752e268309f6e4a
watcher_dir=".work/podcrates-agent/$pin"
fetch_watcher() (
    file=$1
    checksum=$2
    cd "$watcher_dir" || exit 1
    if printf '%s  %s\n' "$checksum" "$file" | sha256sum --check --status 2>/dev/null; then
        exit 0
    fi
    tmp=$(mktemp "$file.XXXXXXXX") || exit 1
    trap 'rm -f -- "$tmp"' EXIT
    url="https://raw.githubusercontent.com/PodUtils/podcrates/$pin/scripts/agent/$file"
    if ! curl -qfsSL --proto '=https' --proto-redir '=https' --max-time 30 \
        --retry 2 --retry-max-time 30 -o "$tmp" "$url" </dev/null; then
        printf 'session-start: could not fetch %s from podcrates at %s\n' "$file" "$pin" >&2
        exit 1
    fi
    if ! printf '%s  %s\n' "$checksum" "$tmp" | sha256sum --check --status; then
        printf 'session-start: %s failed the SHA-256 check\n' "$file" >&2
        exit 1
    fi
    mv -f -- "$tmp" "$file"
)

start_watcher() {
    name=$1
    shift
    lock=".work/$name.lock"
    log=".work/$name.log"
    if flock -n "$lock" true; then
        setsid -f flock -nF "$lock" python3 -I "$watcher_dir/$name.py" "$@" >>"$log" 2>&1 </dev/null 8>&-
        for _ in 1 2 3 4 5; do
            sleep 1
            if ! flock -n "$lock" true; then
                break
            fi
        done
    fi
    if flock -n "$lock" true; then
        printf 'session-start: %s did not start. See %s.\n' "$name" "$log" >&2
        return 1
    fi
    printf 'session-start: %s is running. Log %s\n' "$name" "$log"
}

git_dir=$(git rev-parse --absolute-git-dir)
common_dir=$(git rev-parse --path-format=absolute --git-common-dir)
if [ "$git_dir" != "$common_dir" ]; then
    echo "session-start: use the lead checkout for hosted startup"
    exit 0
fi

umask 077
mkdir -p "$watcher_dir"
exec 8>.work/session-start.lock
if ! flock -w 30 8; then
    echo "session-start: another startup still holds .work/session-start.lock" >&2
    exit 1
fi
git config --local user.name Azathothas
git config --local user.email ajamx101@gmail.com
git config --local commit.gpgsign false
status=0
sync_main || status=1
sh scripts/cloud-setup.sh --native || status=1
fetch_watcher watch.py 14702c073ba50d68572531f29dbbc10b366b25216ef69658da385ac60d4e9391
fetch_watcher watch_test.py ff8d8a3d6ebbbde57135e174ee93b0330c237f611f479451f76e1173280a7568
fetch_watcher runs.py 80754a64ba6281d7b0e03d59932bf6a7fe93aaab956bda907315854d81d13d36
timeout 20 python3 -I "$watcher_dir/watch.py" --self-test >/dev/null
timeout 20 python3 -I "$watcher_dir/runs.py" --self-test >/dev/null
start_watcher watch podssh --state .work/agent || status=1
start_watcher runs --repo PodUtils/podssh --branch main --every 120 || status=1
exit "$status"
