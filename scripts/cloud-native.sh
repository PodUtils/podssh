#!/bin/sh
# Install the native hosted tools without root or a container engine.
set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd -P)"
if [ "$(uname -s)" != Linux ]; then
    echo "cloud-setup: the hosted native setup requires Linux" >&2
    exit 2
fi
for tool in cc curl flock git python3 sha256sum timeout; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        printf 'cloud-setup: missing required tool %s\n' "$tool" >&2
        exit 1
    fi
done
# shellcheck source=scripts/cloud-env.sh
. ./scripts/cloud-env.sh

install_rustup() (
    version=1.29.3
    # SHA-256 pins from the Rust distribution for this version.
    case "$(uname -m)" in
        x86_64)
            arch=x86_64
            checksum=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55
            ;;
        aarch64|arm64)
            arch=aarch64
            checksum=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282
            ;;
        *)
            printf 'cloud-setup: install Rustup for %s\n' "$(uname -m)" >&2
            exit 1
            ;;
    esac
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/podssh-rustup.XXXXXXXX")
    trap 'rm -f -- "$tmp/rustup-init"; rmdir -- "$tmp"' EXIT
    url="https://static.rust-lang.org/rustup/archive/$version/$arch-unknown-linux-gnu/rustup-init"
    curl -qfsSL --proto '=https' --proto-redir '=https' --max-time 120 \
        --max-filesize 33554432 -o "$tmp/rustup-init" "$url" </dev/null
    if ! printf '%s  %s\n' "$checksum" "$tmp/rustup-init" | sha256sum --check --status; then
        echo "cloud-setup: Rustup installer failed the SHA-256 check" >&2
        exit 1
    fi
    chmod u+x "$tmp/rustup-init"
    timeout 120 "$tmp/rustup-init" -y --no-modify-path --default-toolchain none </dev/null
)

mkdir -p "$CARGO_HOME"
exec 9>"$CARGO_HOME/podssh-setup.lock"
if ! flock -w 120 9; then
    echo "cloud-setup: another setup still holds the Cargo cache lock" >&2
    exit 1
fi
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    install_rustup
fi
export RUSTUP_AUTO_INSTALL=0
if ! rustup which cargo >/dev/null 2>&1 ||
   ! cargo fmt --version >/dev/null 2>&1 ||
   ! cargo clippy --version >/dev/null 2>&1; then
    timeout 600 rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal \
        --component clippy,rustfmt --no-self-update </dev/null
fi
rustc --version
host=$(rustc -vV | sed -n 's/^host: //p')
if ! cargo fetch --locked --offline --target "$host" >/dev/null 2>&1; then
    GIT_TERMINAL_PROMPT=0 timeout 600 cargo fetch --locked --target "$host" </dev/null
fi
echo "cloud-setup: the native toolchain and locked dependencies are ready"
