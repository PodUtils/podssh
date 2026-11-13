#!/bin/sh
# The commit of main's last whole gate that passed: the newest successful run
# of build.yml whose job `gate (...)` passed, not one that a push of documents
# alone skipped. build.yml's plan diffs from it, so that a push of the record
# after a push of code, which cancels the code's gate, still builds that code.
# Prints the commit, or nothing when none is found (the plan then builds).
#
#   GH_TOKEN=... sh scripts/gate-base.sh OWNER/REPO [BRANCH]
set -u
repo=${1:?OWNER/REPO}
branch=${2:-main}

# The newest runs first; 30 reach back past a night of record pushes.
runs=$(gh api "repos/$repo/actions/workflows/build.yml/runs?branch=$branch&status=success&per_page=30" \
  --jq '.workflow_runs[] | "\(.id) \(.head_sha)"' 2>/dev/null) || exit 0

printf '%s\n' "$runs" | while read -r id sha; do
  [ -n "$id" ] || continue
  passed=$(gh api "repos/$repo/actions/runs/$id/jobs?per_page=100" \
    --jq '[.jobs[] | select((.name | startswith("gate (")) and .conclusion == "success")] | length' 2>/dev/null) || continue
  if [ "${passed:-0}" -gt 0 ]; then
    echo "$sha"
    break
  fi
done
