#!/bin/sh
# Keep Claude available even when shared hosted startup needs recovery.
root=${CLAUDE_PROJECT_DIR:-"$(dirname -- "$0")/.."}
root=$(CDPATH='' cd -- "$root" && pwd -P) || exit 0
if ! sh "$root/scripts/session-start.sh"; then
    echo "session-start: run sh scripts/session-start.sh in the checkout. See TODO/RESUME.md." >&2
fi
if [ "${CLAUDE_CODE_REMOTE:-}" = true ] && [ -n "${CLAUDE_ENV_FILE:-}" ]; then
    quoted_root=$(printf '%s' "$root" | sed "s/'/'\\\\''/g")
    {
        printf "podssh_project_directory='%s'\n" "$quoted_root"
        cat <<'ENV'
podssh_previous_directory=$PWD
if cd "$podssh_project_directory"; then
    . ./scripts/cloud-env.sh
    cd "$podssh_previous_directory"
fi
unset podssh_project_directory podssh_previous_directory
ENV
    } >>"$CLAUDE_ENV_FILE"
fi
