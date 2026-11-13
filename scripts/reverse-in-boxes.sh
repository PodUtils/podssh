#!/bin/sh
# M4's exit (T-085): two sessions at once from one box like the target
# sandbox, through the relay, into a node in another such box; then the
# pair is stopped. The boxes, their proxy and their profile are
# scripts/test_in_box.sh's, with BOX_RUN=reverse; the operators' side is
# scripts/box/reverse-session.sh.
#
#   sh scripts/reverse-in-boxes.sh [PODSSH_LINUX_BINARY]; echo "exit=$?"
set -u
BOX_RUN=reverse exec sh "$(dirname "$0")/test_in_box.sh" "$@"
