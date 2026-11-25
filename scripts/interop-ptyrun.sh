# Sourced by interop.sh: an interactive terminal, a local pty driven by
# scripts/interop-pty.py, its ok and FAIL lines counted with interop.sh's;
# interop.sh then says whether the driver ran (ssh.pty.driver), with its rc.
echo
echo "== an interactive terminal (a local pty, driven by scripts/interop-pty.py)"
# Within PTY_LIMIT seconds (T-796): the driver's cases each have a limit, the sum of them has none.
# shellcheck disable=SC2086  # $BOUND_CMD is a command and its words
${BOUND_CMD:+timeout "${PTY_LIMIT:-900}"} env -u SSH_AUTH_SOCK HOME="$W" python3 "$HERE/interop-pty.py" "$BIN" "$KH" "$W/id_ed25519" >"$W/pty.log" 2>&1
rc=$?
cat "$W/pty.log"
pass=$((pass + $(grep -c '^ok ' "$W/pty.log")))
fail=$((fail + $(grep -c '^FAIL' "$W/pty.log")))
