#!/bin/sh
# Source from the repository root in a hosted development shell.
if [ ! -f scripts/cloud-env.sh ] || [ ! -f Cargo.lock ]; then
    echo "cloud-env: source this file from the podssh checkout" >&2
    return 1
fi

export CARGO_HOME="${CARGO_HOME:-$PWD/.work/cloud/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-$PWD/.work/cloud/rustup}"
# The native hosted pin matches the workspace's minimum. The container gate
# uses the separate image digest in images/build/Dockerfile.
export RUSTUP_TOOLCHAIN=1.99.0
case ":$PATH:" in
    *":$CARGO_HOME/bin:"*) ;;
    *) export PATH="$CARGO_HOME/bin:$PATH" ;;
esac
export CARGO_NET_GIT_FETCH_WITH_CLI="${CARGO_NET_GIT_FETCH_WITH_CLI:-true}"
if [ -z "${CARGO_BUILD_JOBS:-}" ]; then
    podssh_cpus=$(nproc 2>/dev/null || printf 4)
    case "$podssh_cpus" in
        [1-3]) CARGO_BUILD_JOBS=$podssh_cpus ;;
        *) CARGO_BUILD_JOBS=4 ;;
    esac
    unset podssh_cpus
fi
export CARGO_BUILD_JOBS
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-line-tables-only}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-line-tables-only}"
