# The result lines of the interop harnesses (T-199), and the reference of an
# exit code (T-225). Sourced by scripts/interop.sh and scripts/interop-man.sh
# before their checks, and so used by each harness that interop.sh sources.
#
# A check prints one line: `VERDICT ID TEXT`. The verdict is padded to six
# columns: `ok`, `FAIL`, `skip`, or `env` for a precondition of the host that
# is missing. The ID is stable: dotted parts of [a-z0-9_-], the first naming
# the harness (`ssh` for interop.sh, else the name after `interop-`), with a
# loop's label in place of a value (`for srv in openssh:2201 ...` gives
# `${srv%%:*}`). The TEXT may hold values of the run: seconds, a tty, bytes.
# scripts/interop-baseline.txt holds the verdict that each ID must give, and
# `cargo todo interop` checks the scripts and the logs against it.
#
# Each helper returns 0, so `cond && ok ID T || bad ID T` prints one line.

pass=0
fail=0
skip=0
unmet=0

# ok ID TEXT
ok() {
    pass=$((pass + 1))
    printf 'ok    %s %s\n' "$1" "$2"
    return 0
}

# bad ID TEXT [LOG]: the first 20 lines of LOG follow, indented.
bad() {
    fail=$((fail + 1))
    printf 'FAIL  %s %s\n' "$1" "$2"
    if [ $# -gt 2 ]; then
        sed 's/^/      | /' "$3" | head -20
    fi
    return 0
}

# skipped ID TEXT: the check did not run, by the harness's choice.
skipped() {
    skip=$((skip + 1))
    printf 'skip  %s %s\n' "$1" "$2"
    return 0
}

# unmet ID TEXT: a precondition of the host is missing (not named `env`,
# which would hide env(1)).
unmet() {
    unmet=$((unmet + 1))
    printf 'env   %s %s\n' "$1" "$2"
    return 0
}

# expect_rc ID TEXT WANT GOT [LOG]
expect_rc() {
    if [ "$4" = "$3" ]; then
        ok "$1" "$2 (exit $4)"
    else
        bad "$1" "$2: wanted exit $3, got $4" "${5:-/dev/null}"
    fi
    # After p_ref or direct_ref (T-225): the case's id, its literal,
    # podssh's code, OpenSSH's code, its text and OpenSSH's command line,
    # for scripts/interop-reference.sh, and OpenSSH's stderr beside them.
    if [ -n "${stock_rc:-}" ]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$3" "$4" "$stock_rc" "$2" "$stock_cmd" >>"$W/refs"
        cp "$W/ref.err" "$W/ref.$1.err" 2>/dev/null
        stock_rc=
    fi
    return 0
}

# The bound of each podssh call of p, r and direct_ref (T-796): the gate's
# step has one bound for all the checks, and it names no check. A call that
# runs past P_LIMIT seconds (set it in the environment of interop.sh to move
# it) is stopped, so that its check fails by its own id with podssh's stderr,
# and bound_note leaves a line there and in $W/bound.log, which fails the run.
# $BOUND_CMD is the command that bounds, empty where `timeout` or its -k is
# not there: the call then has no bound, as before. busybox's timeout (the
# build image) runs the program in its own process, so $! and kill reach
# podssh; coreutils' timeout is a parent of it that passes a signal on.
P_LIMIT=${P_LIMIT:-300}
BOUND_CMD=
if timeout -k 5 5 true >/dev/null 2>&1; then
    BOUND_CMD="timeout -k 10 $P_LIMIT"
elif timeout 5 true >/dev/null 2>&1; then
    BOUND_CMD="timeout $P_LIMIT"
fi

# bound_note RC START WHAT...: after a bounded call. RC 124 is coreutils'
# word for a stop, 143 and 137 are busybox's (TERM, then KILL); podssh ends
# with 143 itself when the remote command was killed by TERM, so the time that
# the call took must have reached the bound too. The line goes to stderr, the
# log that a check hands to bad. Returns RC, so that a caller ends with it.
bound_note() {
    _bn_rc=$1
    _bn_t0=$2
    shift 2
    [ -n "$BOUND_CMD" ] || return "$_bn_rc"
    case $_bn_rc in 124 | 137 | 143) ;; *) return "$_bn_rc" ;; esac
    _bn_took=$(($(date +%s) - _bn_t0))
    [ "$_bn_took" -ge "$P_LIMIT" ] || return "$_bn_rc"
    _bn_msg=$(printf 'BOUND podssh ran %s s, past its bound of %s s, and was stopped (exit %s): %.200s' \
        "$_bn_took" "$P_LIMIT" "$_bn_rc" "$*")
    echo "interop: $_bn_msg" >&2
    echo "$_bn_msg" >>"${W:-/tmp}/bound.log" 2>/dev/null
    return "$_bn_rc"
}

# bound_report: before the summary, each call that was stopped, and one
# failure for them, so that a check that did not mind the exit code (one that
# wants any failure) cannot pass over a hang.
bound_report() {
    [ -s "${W:-/tmp}/bound.log" ] || return 0
    sed 's/^/interop: /' "$W/bound.log"
    fail=$((fail + 1))
    return 0
}

# p PORT [podssh ssh arguments...]: podssh with a fresh environment: no
# agent, test keys only, this run's known_hosts ($KH, set by the caller),
# never a prompt on a terminal, within P_LIMIT. With as_job=exec, podssh takes
# the place of the shell that runs p: a function run with & is a shell of its
# own, and kill would end that shell alone and leave podssh running. exec
# never returns, so the line after it runs only for a call, not for a job.
p() {
    _port=$1
    shift
    _p_t0=$(date +%s)
    # shellcheck disable=SC2086  # $BOUND_CMD is a command and its words
    ${as_job:-} $BOUND_CMD env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct -p "$_port" \
        -o UserKnownHostsFile="$KH" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes "$@"
    bound_note "$?" "$_p_t0" "ssh -p $_port $*"
}

# The reference of an exit code (T-225): OpenSSH's own client runs first,
# with the arguments that podssh then gets. p is above,
# $W, $BIN and $KH; the next expect_rc records both codes.
stock_rc=
stock_cmd=

# stock_raw [ssh arguments...]: OpenSSH's ssh with no ssh_config, the
# environment of p and stdin from /dev/null, ended at 60 s. Its code is in
# $stock_rc (`none` with no ssh), its stderr in $W/ref.err.
stock_raw() {
    stock_cmd="ssh -F /dev/null $*"
    if command -v ssh >/dev/null 2>&1; then
        timeout 60 env -u SSH_AUTH_SOCK HOME="$W" ssh -F /dev/null "$@" </dev/null >"$W/ref.out" 2>"$W/ref.err"
        stock_rc=$?
    else
        : >"$W/ref.err"
        stock_rc=none
    fi
    return 0
}

# stock PORT [arguments...]: stock_raw with the settings of p, but a
# known_hosts of its own, so that the host key checks read the keys that
# podssh recorded.
stock() {
    _sport=$1
    shift
    stock_raw -p "$_sport" -o UserKnownHostsFile="$W/known_hosts.openssh" -o StrictHostKeyChecking=accept-new \
        -o IdentityAgent=none -o IdentitiesOnly=yes "$@"
}

# wait_port PORT: wait up to 5 s for a listener on 127.0.0.1:PORT; a server
# that never listens fails the checks that follow, each with its reason.
wait_port() {
    _tries=0
    while ! python3 -c "import socket; socket.create_connection(('127.0.0.1', $1), 1).close()" 2>/dev/null; do
        _tries=$((_tries + 1))
        [ "$_tries" -ge 50 ] && return 0
        sleep 0.1
    done
    return 0
}

# p_ref PORT [arguments...]: stock, then p with the same arguments; its
# code is p's.
p_ref() {
    stock "$@"
    p "$@"
}

# direct_ref [arguments...]: stock_raw, then podssh ssh --direct with the
# same arguments and the environment of p, within P_LIMIT; its code is
# podssh's.
direct_ref() {
    stock_raw "$@"
    _dr_t0=$(date +%s)
    # shellcheck disable=SC2086  # $BOUND_CMD is a command and its words
    $BOUND_CMD env -u SSH_AUTH_SOCK HOME="$W" "$BIN" ssh --direct "$@"
    bound_note "$?" "$_dr_t0" ssh --direct "$@"
}

# INTEROP_ONLY="faults cp" sources only those parts of interop.sh (the name
# after `interop-`), once its servers run: a planted defect of T-251 runs the
# part that holds its check (scripts/plants/). Unset, each part runs.
part() {
    _part=${1#interop-}
    _part=${_part%.sh}
    case " ${INTEROP_ONLY:-$_part} " in
        # shellcheck disable=SC1090  # the part is named by its caller
        *" $_part "*) . "$HERE/$1" ;;
        *) echo "== $1: not run (INTEROP_ONLY=$INTEROP_ONLY)" ;;
    esac
}
