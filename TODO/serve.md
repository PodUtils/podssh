This file holds the work for `podssh serve`: the SSH server in the process for
a host whose only egress is the relay (milestone M5, `docs/ROADMAP.md:179-209`),
and the server features in the backlog. T-107 puts the server's core in
crates/podssh-ssh/src/server/, and each later entry builds on it. T-222 finds the
shell that T-108 runs.

# T-107: `podssh serve`: the russh server, its host key in a state file, and authorized keys

**Source:** `docs/ROADMAP.md:184-189` (M5), `docs/design.md:658-662`; GitHub #20
(Nemo-010, 2026-10-08: bssh-server and tty7 as references).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

podssh gets out of a cage, but not into one: no SSH server runs there, and
the siblings needed a patched dropbear and shims. This entry gives the server
core: the handshake, a host key that does not change, and key authentication.

## Premise

- Measured on `3ee70dc`: `timeout 20 target/debug/podssh.exe serve </dev/null`
  prints "unknown subcommand 'serve'" and exits 64.
- Read: no source in `crates/` uses `russh::server`. russh 0.64.1 builds its
  server module on each target except wasm, with no feature
  (`Eugeny/russh:russh/src/lib_inner.rs`, lines 69-70 at `22c3b88`), so
  `crates/podssh-ssh/Cargo.toml:15` has it. `run_stream` serves one
  connection over any stream, as `crates/podssh-ssh/src/run.rs:32-37` does.
  To reuse: `crates/podssh-ssh/src/keygen.rs:74-158` (a key, mode 0600, never
  over a file), `crates/podssh-ssh/src/known_hosts.rs:266-271` (a key line),
  `crates/podssh-relay/src/cache/dirs.rs:136-241` (the directories).

## Approach

1. Add crates/podssh-ssh/src/server/ (see Decision), files under 500 lines,
   with one entry point that takes a stream. Invariant: it never listens.
   Each request handler answers: russh's defaults send no reply, and a client
   waits (podssh: 30 s, `crates/podssh-ssh/src/session.rs:19-22`).
2. russh settings: `publickey` only (the default also offers `password`);
   the 512 KiB window of `crates/podssh-ssh/src/run.rs:26-30`; no inactivity
   cut (russh: 600 s); a keepalive every 60 s (`docs/relay.md:556`).
3. Host key: `--host-key FILE`, else a file in the first usable directory of
   the cache chain, made with `keygen::generate` and `keygen::write_pair`.
   Invariant: never overwritten; the loser of a `create_new` race reads the
   winner's key. Print the fingerprint; warn when the directory is temporary.
4. Authorized keys: `--authorized-key KEY` and `--authorized-keys FILE`, else
   `$HOME/.ssh/authorized_keys`. Lines with options wait for T-114. No usable
   key: exit 78. Invariant: no setting accepts each key. `auth_publickey`
   compares `key_data()`; the login name selects nothing.
5. The verb: rows in `crates/podssh-cli/src/flags.rs:378-452` and
   `crates/podssh-cli/src/positionals.rs:8-277`, an arm beside
   `crates/podssh-cli/src/dispatch.rs:351-425`, the manual, `docs/cli.md`,
   `docs/STATUS.md`. The first source is `--stdio`, as `sshd -i`: OpenSSH
   then tests serve in the gate through `ProxyCommand`, with no listener.
   `podssh serve NAME` follows on the node runner of T-079. Windows: exit 70.

## Decision

Recommendation: the server goes in crates/podssh-ssh/src/server/, and only
the command line in crates/podssh-cli/src/serve.rs. `docs/design.md:28-30`
gives `podssh-ssh` the "russh client and server"; the crate links aws-lc
already (`crates/podssh-ssh/Cargo.toml:10-15`), holds the helpers to reuse,
and is read by the variable test (`crates/podssh-cli/src/man/facts/tests.rs:16-29`).
A new crate lost: it repeats the russh dependency and its C exception, and
makes the helpers public. `podssh-cli` lost: it is the command line.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_auth
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib serve
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test flag_table --test man_flag_parity --test man_json
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
sh scripts/plant-each.sh --here t107-accept-each-key
sh scripts/dev.sh check
HOME=/nonexistent timeout 20 "$BIN" serve --stdio </dev/null; test $? -eq 78
```

crates/podssh-ssh/tests/serve_auth.rs reads key lines (good, bad, options);
eight starts at once keep one host key, of mode 0600; russh's client over
a pipe logs in with the listed key, is refused with another, and gets an
answer, a refusal, to exec and to direct-tcpip. crates/podssh-cli/tests/serve_stdio.rs:
OpenSSH's `ssh -N` with `ProxyCommand='podssh serve --stdio ...'` stays up
with an authorized key, and gets `Permission denied (publickey)` with
another; a restart keeps the host key (a strict client takes it), and a
command is refused at once (`exec request failed`, 255); on Linux each
thread of the server holds no capability after the start; with no key the
start exits 78 and makes no host key. The plant `t107-accept-each-key` (an
`auth_publickey` that accepts each key) fails the test of the server core.
With no key, the static binary (`$BIN`) exits 78.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-09. Step 6 of the Approach: at its start `podssh serve` calls the shared drop of T-698
(`crate::harden::give_up(&[])`, `crates/podssh-cli/src/harden.rs`), the keep-list empty: `--stdio`
before the runtime starts its threads, `--listen` after its bind. It refuses the start with exit 78
where a capability was held and a step failed. The Prove gains one check: after the start, under
both entry points and as root, each thread of `/proc/self/task` reports no capability. T-698's
shared module is done (2026-11-12); the call and its check are this entry's step 6, so nothing waits
on T-698.

2026-11-13. The Premise, read again at `f6c8ba7`:

- russh is 0.65.0, not 0.64.1, and the tree builds it from `vendor/russh` with podssh's patches,
  through `[patch.crates-io]` of the workspace (`Cargo.toml:216`). Its server module is still built
  on each target but wasm (`vendor/russh/src/lib_inner.rs:67-68`). `auth_publickey` now takes a
  `VerifiedPublicKey` (the key and the algorithm of its signature), and `auth_publickey_offered` a
  `PublicKeyOffer` (`vendor/russh/src/server/mod.rs:210-251`); a request handler that does not answer
  still sends no reply (`vendor/russh/src/server/mod.rs:688-693`), and a channel request that russh does
  not know is refused by russh itself (`vendor/russh/src/server/encrypted.rs:1864-1868`).
- "No source in `crates/` uses `russh::server`" holds for the code of the binary; the stand-ins of
  the tests do (`crates/podssh-cli/tests/pinggy_stand_in/mod.rs:26`,
  `crates/podssh-relay/tests/devtunnel.rs:19`).
- The lines moved: `keygen::generate` is at `crates/podssh-ssh/src/keygen.rs:76`. The verbs'
  table, `crates/podssh-cli/src/flags.rs`, was one file of 500 lines, so `Availability` and
  `VERB_OWNER` moved to `crates/podssh-cli/src/flags/availability.rs` beside it.
- `keygen::write_pair` does not keep Approach item 3's invariant: it writes `FILE.pub` too, and a
  second start that reads between its create and its write reads half a key. The host key is made
  with `podssh_relay::cache::create_private` (`crates/podssh-relay/src/cache/own.rs:67`): a whole
  private file through a hard link, never over one that is there, so of two starts one makes it and
  the other reads it. `podssh-ssh` does not depend on `podssh-relay`, so the caller passes the
  functions (`StateFiles`), as it passes `KeyFiles` to keygen. No `.pub` file is written: the
  fingerprint goes to stderr at each start.
- Approach item 5's script of the interop tests (`interop-serve.sh`, never written) is a test of the CLI crate instead,
  `crates/podssh-cli/tests/serve_stdio.rs`, as the other runs of OpenSSH's client against podssh
  are (`crates/podssh-cli/tests/node_carrier.rs:228-233`): the gate's tests run it where the
  image has OpenSSH, and it says that it did not run where a host has none. The Prove names it.
- Approach item 5's `podssh serve NAME` on the node runner of T-079, which is done, is not in this
  draft: `--stdio` alone. The form `serve NAME` stays an open step of this entry, after the merge
  of this draft.
- The Correction of 2026-11-09 names a `--listen` entry point: that is T-124's flag, so this entry
  makes the drop at the start of `--stdio` alone, before a file is read and before the runtime makes
  its threads; T-124 makes it after its bind.

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t107` (no build, no test run): the server core in
crates/podssh-ssh/src/server/ (`mod.rs`, `authorized.rs`, `host_key.rs`, `handler.rs`), the verb in
crates/podssh-cli/src/serve.rs with its flags (crates/podssh-cli/src/flags/serve.rs), its arms in the
parser and the dispatch, its notes and the file of its host key in the manual
(crates/podssh-cli/src/man/notes_serve.rs), `docs/cli.md` ("`podssh serve`"), a row of
`docs/STATUS.md`, the tests of the Prove and the plant `t107-accept-each-key`. Results:

Merged, built and run by the main session the same day:

- `cargo test -p podssh-ssh --test serve_auth`: 7 passed.
- `cargo test -p podssh-cli --test serve_stdio` (OpenSSH's client, `/usr/bin/ssh`): 3 passed.
- `cargo test -p podssh-cli --lib serve`: 72 passed (the filter takes more than serve's own); `--lib harden`: 14.
- The tests of the tables and the manual: `flag_table` 9, `man_flag_parity` 6, `man_json` 4 passed; the CLI's
  `--lib` 1,152 passed.
- The plant `t107-accept-each-key` (`sh scripts/plant-each.sh --here`): caught,
  `the_listed_key_logs_in_and_another_is_refused ... FAILED`.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,694 passed, 0 failed. Clippy (`--all-targets -D
  warnings`): three findings of the draft repaired (`std::slice::from_ref`, `expect_err`); rustfmt clean. The build
  image waits (T-251).
- `HOME=/nonexistent target/debug/podssh serve --stdio </dev/null`: exit 78, the line naming the keys it read;
  `serve` with no `--stdio`: 64.
- A defect of the draft, repaired at the merge: the first line was the relay role's tail of its own line, "podssh
  serve: , the capabilities of its start dropped after the bind, ... a user of its own with the file capability
  cap_net_bind_service binds the port", for a verb that binds nothing. `harden::give_up_at` takes the moment of
  the drop (`Moment::AtStart`), whose words say "dropped at the start, before any file is read" and "run it as a
  user of its own"; the test `the_words_of_a_drop_at_the_start_name_no_listener` holds them. A failed drop's refusal
  still says "after the bind" and "the role": `apply` does not know the moment, and that refusal comes only where a
  drop fails.

Left: `podssh serve NAME` on a node's road (Approach item 5); the merge runs
`cargo todo remap` on each cited file that the draft changed.

2026-11-13, with the draft of T-108 (branch `draft-t108`): a command runs since T-108, so the two
checks of this entry that a command is refused changed with it. In crates/podssh-ssh/tests/serve_auth.rs
the test `exec_and_direct_tcpip_are_refused_with_an_answer` is now
`a_subsystem_and_direct_tcpip_are_refused_with_an_answer` (SFTP waits for T-112); in
crates/podssh-cli/tests/serve_stdio.rs the strict client's `true` now exits 0 with no `exec request
failed`, and the helpers that it shares with T-108's test moved to crates/podssh-cli/tests/serve_kit/mod.rs.
The plant `t107-accept-each-key` has its context moved to the handler as T-108 left it.

# T-108: `podssh serve`: exec, a shell and the environment, as the sandbox's user

**Source:** `docs/ROADMAP.md:184-189` ("It supplies exec"),
`docs/target-environment.md:37-44`; GitHub #20 (Nemo-010, 2026-10-08).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

After T-107 a client can log in, but each session channel is refused. A user
expects a command and a shell to work as with sshd: the exit status, stdout
and stderr apart, and an environment that a cage can give.

## Premise

- Read: russh calls `exec_request`, `shell_request` and `env_request`, and
  the handler must answer each (`Eugeny/russh:russh/src/server/mod.rs`,
  lines 601-667). russh also gives each data message to the kept `Channel`,
  and waits when 100 wait unread (`Eugeny/russh:russh/src/server/encrypted.rs`,
  lines 1350-1356): an unread channel stops the whole connection.
- Read: the client side to match is `crates/podssh-ssh/src/io/msg.rs:11-76`;
  `crates/podssh-ssh/src/signals.rs:70-79` maps names to numbers only;
  `tokio` with `process` is a dependency (`crates/podssh-ssh/Cargo.toml:19`).

## Approach

1. `channel_open_session` accepts; each request gets success or failure.
   Read each kept `Channel` on its own task (stdin, EOF, `signal`).
2. The program: the shell that T-222 finds at the session start. With none,
   the request fails, and T-222's line goes to the channel's stderr. exec
   runs `SHELL -c COMMAND`; a shell runs as a login shell (argv[0] `-sh`).
3. The child: pipes for stdin, stdout and stderr; a new session (`setsid` in
   `pre_exec`); the working directory `HOME` when it exists, else `/`.
4. Environment: see Decision. `env` requests: only names that match
   `--accept-env PATTERN` (default `LANG`, `LC_*`), with the wildcard of
   `crates/podssh-ssh/src/known_hosts.rs:310-333`. Never `LD_*`, `PATH`,
   `HOME`, `SHELL`, `ENV`, `BASH_ENV` or `IFS`, whatever the pattern.
5. Output: stdout as data and stderr as extended data 1, through each
   channel's writer (T-118). After the child exits, read its pipes to their
   end within a stated limit: a background job can hold a pipe open.
6. The end: `exit-status`, or `exit-signal` with the SSH name and the core
   flag, then EOF and close. Invariant: one of the two always comes before
   the close (T-026 is the client side). Add the number-to-name direction
   to `crates/podssh-ssh/src/signals.rs:70-79`: one table, both ways.
7. A `signal` request (RFC 4254, section 6.9): `kill(-pgid, number)`. Same
   commit: `docs/cli.md` (the environment rules), the serve notes,
   `docs/STATUS.md`.

## Decision

Recommendation: the child gets serve's own environment minus podssh's
credentials (`PODSSH_RELAY_TOKEN`, the node's tokens), plus `USER`,
`LOGNAME`, `HOME`, `SHELL`, `TERM` and the accepted `env` requests. A cage's
environment holds what no login database gives again: `HTTPS_PROXY`, `PATH`.
A fresh environment, as sshd builds one, lost: the shell would have no proxy.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_exec --test serve_auth
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib -- server:: signals::
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_openssh --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test flag_table --test man_flag_parity --test man_json
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
sh scripts/plant-each.sh --here t108-whole-environment
sh scripts/dev.sh check
```

crates/podssh-ssh/tests/serve_exec.rs, with russh's client over a pipe, checks the order of the end
(each byte, then `exit-status` or `exit-signal`, then EOF, then close), stdout and stderr apart,
the statuses 3, 0, 1 and 127, a command killed by TERM and one ended by a `signal` request, 1 MB
through `cat`, the environment filter (`LANG` taken, `LD_PRELOAD` and `TZ` refused by default, `*`
still refusing `LD_LIBRARY_PATH` and `BASH_ENV`), a pty refused with the command run without one, a
login shell's argv[0], and a job in the background that holds the pipes but not the end. Against
OpenSSH's `ssh` with `podssh serve --stdio` as its ProxyCommand, crates/podssh-cli/tests/serve_openssh.rs
(the gate's tests, where the image has OpenSSH; "did not run" where a host has none): exit statuses 3, 0, 1
and 127; a command killed by TERM (OpenSSH's 255); stdout and stderr apart; 5,000,000 bytes up and
back whole; `SetEnv LANG=C.UTF-8` arrives, `SetEnv LD_PRELOAD=x` does not. With `PODSSH_RELAY_TOKEN`
set for serve, the child's `env` lacks it; the plant `t108-whole-environment`, a serve that passes
its whole environment, fails that check.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The Premise, read again at `4c98f8b`:

- russh is 0.65.0, built from `vendor/russh` (T-107's Correction). `env_request`, `shell_request` and
  `exec_request` are at `vendor/russh/src/server/mod.rs:660-732`, and still answer nothing by
  default. Each data message goes to the kept `Channel` at `vendor/russh/src/server/encrypted.rs:1520-1538`,
  into a queue of `channel_buffer_size` (`vendor/russh/src/server/mod.rs:120`, 100). Each channel
  request goes to that queue too before the handler sees it, `env` among them
  (`vendor/russh/src/server/encrypted.rs:1745-1756`): so a channel that nothing reads stalls the
  connection with no data at all, after 100 `env` requests, and the task that reads a channel
  starts at its open, not at its `exec` (Approach item 1).
- russh's server adjusts a channel's window when the data arrives, not when it is read
  (`vendor/russh/src/server/encrypted.rs:1509-1519`): no window of a channel apart holds a client
  back. The bytes for a child's stdin wait in a queue of 128 messages (about 4 MiB) of their own,
  written by a task of their own, which drains the rest after a broken pipe; past that queue the
  connection waits. The window of each channel apart is T-118's.
- `exit-signal` is not a method of russh's `ChannelWriteHalf`; the connection's `Handle` sends it
  (`vendor/russh/src/server/session.rs:440-461`) through the same queue as the channel's writers,
  so the order of Approach item 6 holds. `Sig` has no `PartialEq`, and its own `name` and
  `from_name` are private (`vendor/russh/src/lib_inner.rs:351-387`): `crates/podssh-ssh/src/signals.rs:26-64`
  becomes one table read both ways (`number` and `from_number`); a number with no name is sent as
  OpenSSH's `SIG@openssh.com`.
- The Decision's `TERM`: with no pty there is none, as under sshd; T-110 sets it from `pty-req`.
- podssh's credentials by name: `PODSSH_RELAY_TOKEN`, `PODSSH_CF_ACCESS_TOKEN`,
  `PODSSH_CF_ACCESS_CLIENT_ID` and `PODSSH_CF_ACCESS_CLIENT_SECRET`, and each `PODSSH_` name with
  `TOKEN`, `SECRET`, `PASSWORD` or `PASSPHRASE` that does not end in `_FILE` (a path is no secret).
  `USER` and `LOGNAME` join the names that no pattern lets in, as the login's own.
- The Prove's scripts/interop-serve.sh is a test of the CLI crate, crates/podssh-cli/tests/serve_openssh.rs,
  as T-107's Correction made serve_stdio.rs of it; the Prove names it.
- Approach item 5's "within a stated limit": after the child ends, each pipe is read until 2 s
  pass with no byte, 30 s at most in all. OpenSSH's sshd waits for the job instead.

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t108` (no build, no test run), with T-222: the
session channel in crates/podssh-ssh/src/server/ (`channel.rs`: the task that reads each channel from
its open, the stdin queue, the `signal` request; `child.rs`: the program on three pipes with
`setsid`, the pumps and the end; `env.rs`: the filter and the child's environment), the requests in
`handler.rs`, `Settings` and `serve_with` in `mod.rs`, `signals::from_number`; `--accept-env` and
`--no-shell` in crates/podssh-cli/src/flags/serve.rs and `serve.rs`; the manual (crates/podssh-cli/src/man/notes_serve.rs,
the exit code 78), `docs/cli.md` ("`podssh serve`"), a row of `docs/STATUS.md`, the tests of the Prove
and the plant `t108-whole-environment`. Merged, built and run by the main session the same day:

- `cargo test -p podssh-ssh --test serve_exec --test serve_auth`: 11 and 7 passed, after two repairs.
  `a_shell_that_does_not_run_is_named_on_stderr_and_fails_the_request` waited for a close that never came: a
  channel whose program did not start now gets its line, the failure, EOF and close (a second program on a channel
  that runs one is still refused alone). `stdin_comes_back_whole` stopped after 80 KiB every time: the test joined
  russh's client and the server by a pipe of 64 KiB, where the two russh loops stop each other; through 4 MiB it
  passes, OpenSSH moved 5,000,000 bytes each way through the server, and the stop is T-772.
- `cargo test -p podssh-ssh --lib server::`: 8 passed; `signals::`: 2.
- `cargo test -p podssh-cli --test serve_openssh --test serve_stdio` (OpenSSH 9.6's client): 7 and 3 passed. Repaired:
  the test of a pty expected OpenSSH to run the command after the refusal of a pty forced by `-tt`, but OpenSSH makes
  that refusal fatal (its `client_status_confirm` closes the channel; exit 255 after "PTY allocation request
  failed"): `a_forced_pty_is_refused_with_an_answer` holds that, and `serve_exec`'s
  `a_pty_request_is_refused_and_the_command_runs_without_one` the run without a pty.
- The tables and the manual: `flag_table` 9, `man_flag_parity` 6, `man_json` 4, `--lib man::` 60 passed, after the
  note's words: `-sh`, the patterns `PODSSH_*` and `*_FILE` and `SHELL=/x` read as names, so the note says them in
  words, and `BASH_ENV` has its line in ENVIRONMENT beside SHELL (the code names `ENV` and `BASH_ENV` outright, as
  the check of each documented variable reads them).
- The plant `t108-whole-environment`: caught; `t107-accept-each-key`, made again: caught.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,741 passed, 0 failed. Clippy and rustfmt clean. The
  build on Windows: the gate's job `windows`.

Left after the merge: `cargo todo remap` on each cited file that the draft changed (`docs/cli.md`,
`docs/STATUS.md`, `crates/podssh-ssh/src/signals.rs`, the handler, the CLI's files); the run in the
build image (T-251).

# T-109: `podssh serve`: direct-tcpip into the cage

**Source:** `docs/ROADMAP.md:184-189` ("direct-tcpip into the cage").
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

An operator often needs a TCP service inside the cage: a database, a
development server, the next SSH hop. Without `direct-tcpip`, `ssh -W` and
`-J` through `podssh serve` fail with "administratively prohibited", which
tells the user nothing.

## Premise

- Read: russh refuses a channel type that has no handler: the dropped reply
  handle sends `AdministrativelyProhibited`
  (`Eugeny/russh:russh/src/lib_inner.rs`, lines 570-620). A refusal can carry
  a reason with `ChannelOpenFailure::Other`.
- Read: the dialer to reuse: `crates/podssh-ws/src/dial.rs`, lines 196-242 at `927eb24` (a time
  limit; `HTTPS_PROXY` when it is set) and
  `PodUtils/podssh:crates/podssh-ws/src/dial.rs:105-112` (loopback never through a proxy).
  The client copies a forward with half-close in
  `crates/podssh-ssh/src/forward.rs:39-110`.
- Read: in the measured sandbox, `connect()` to loopback failed with `EACCES`
  (`docs/target-environment.md:22`). Such a refusal must reach the client
  with its reason.

## Approach

1. Implement `channel_open_direct_tcpip`: dial with
   `podssh_ws::dial::dial(host, port, &ProxyChoice::FromEnvironment, limit)`.
   Do not add a second dialer.
2. On success, accept, then copy between `channel.into_stream()` and the TCP
   stream in both directions. An EOF in one direction keeps the other open,
   as `crates/podssh-ssh/src/forward.rs:39-110` does.
3. On failure, reject with code 2 (connect failed) and the dial error in
   words: the errno, or the proxy's status and reason.
4. Limits: 20 s for the dial; a stated maximum of open forwards for each
   connection, with `ResourceShortage` past it.
5. `--no-forwarding` refuses each forward (for one key: T-114). Add it to
   `crates/podssh-cli/src/flags.rs` and the manual.

Pitfalls: `direct-streamlocal@openssh.com` (AF_UNIX) stays refused here; T-040
is the client side. A host name that `check_name` refuses
(`PodUtils/podssh:crates/podssh-ws/src/dial.rs:345-354`) gets that reason, not a generic one.

## Decision

Recommendation, followed by the draft of 2026-11-13: a forward dials any host and port that the
client asks for, as OpenSSH's sshd does by default (`AllowTcpForwarding yes`, `PermitOpen any`), and
`--no-forwarding` refuses each one. Whoever holds an authorized key is the cage's owner, and with
`exec` could dial the same target with any tool of the cage; the limits of one key (`permitopen=`,
`no-port-forwarding`, `restrict`) are T-114's, and the check sits in one function
(`server::direct::check`) for it to extend. No ruling of `docs/decisions.md` limits what a server in
the cage may dial: rule 2 of `AGENTS.md` is about podssh's own way out, and this dial is the payload
that the user asked for on each channel, as the relay role's dials of its clients' targets are
(`crates/podssh-relay/src/serve/sshd.rs:11-16`). The dial is podssh's own
(`crates/podssh-ws/src/dial.rs:86-88`), so it takes the cage's proxy where one is set, and the
loopback and `NO_PROXY` go directly.

Lost: the loopback alone (a cage's services are often on another host of its network, a database
or the next hop of `-J`, and a key with `exec` passes such a limit anyway); the relay role's policy
of targets, which refuses the loopback (its clients are not its owner, and the loopback is where a
cage's own services are); a list of targets on the command line (`--permit-open`), which T-114's
`permitopen=` gives for each key, and which no user has asked for.

Bounds: 20 s for each dial (the Approach), and 256 forwards open at once on one connection, past
which one more is refused with `ResourceShortage`: a browser through `-L` opens tens of connections
at once, and 256 keeps each descriptor of a cage from one client.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_forward --test serve_auth
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib server::direct
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_forward_openssh --test serve_openssh --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test flag_table --test man_flag_parity --test man_json
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
sh scripts/plant-each.sh --here t109-reason-dropped
sh scripts/dev.sh check
```

crates/podssh-ssh/tests/serve_forward.rs, with russh's client over a pipe: a forward to an echo
listener of the test carries 1,000,000 bytes both ways, equal, and the target sees the client's EOF
as a half-close; a target that ends first gives its bytes, then EOF, the other way stays open for
the client's bytes, and the close follows the client's EOF; a dial to a port where nothing listens
is refused with code 2 and words that name the target and the system's reason; a port of 0 or past
65535 and a name that is no host name are refused with code 2 and why; `--no-forwarding` refuses
with code 1 and names the flag; past the bound of open forwards, `ResourceShortage`, and the place
comes back when a forward ends. Against OpenSSH's client with `podssh serve --stdio` as its
ProxyCommand, crates/podssh-cli/tests/serve_forward_openssh.rs (the gate's tests, where the image has
OpenSSH; "did not run" where a host has none): `ssh -W 127.0.0.1:PORT` to an echo carries 1,000,000
bytes each way, equal, and exits 0; `-W` to a closed port exits 255 with `connect failed: podssh
serve: ... Connection refused`; `--no-forwarding` gives `administratively prohibited` and its name,
and a command still runs; `-N -L` carries 200,000 bytes through OpenSSH's own listener; `-J` reaches a
second `podssh serve --stdio` behind a listener of the test and exits 5 with its `exit 5`. The plant
`t109-reason-dropped` (a failed dial refused with russh's fixed `Connect failed`) fails the test of
the refused dial.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The Premise, read again at `1b5008e`:

- russh is 0.65.0 from `vendor/russh` (T-107's Correction). A `ChannelOpenHandle` that is dropped
  still refuses with `AdministrativelyProhibited` (`vendor/russh/src/lib_inner.rs:607-616`), and
  `ChannelOpenFailure::Other { code, reason }` sends its own code and words
  (`vendor/russh/src/lib_inner.rs:431-451`; the reply at `vendor/russh/src/server/session.rs:1127-1158`):
  so a refusal of code 2 with the dial's words is `Other { code: 2, .. }`, as `ConnectFailed` carries
  the fixed words "Connect failed". russh's client maps code 2 back to `ConnectFailed` and gives the
  words to its handler's `channel_open_failure` alone (`vendor/russh/src/client/encrypted.rs:582-612`),
  after it woke the opener: the test waits for them there.
- The dialer is no longer in `crates/podssh-ws/src/dial.rs` at the cited lines: `dial` is a thin call
  of `pod-proxy`'s `Dialer` (`crates/podssh-ws/src/dial.rs:86-88`, `PodUtils/podcrates:crates/pod-proxy/src/dial.rs`),
  which reads the proxy variables at each dial, sends a loopback target directly
  (`crates/podssh-ws/src/dial.rs:73-81`, `Rules::loopback_direct` of pod-proxy) and checks the name
  first. `check_name` is `pod-proxy`'s (`PodUtils/podcrates:crates/pod-proxy/src/host.rs`), re-exported
  at `crates/podssh-ws/src/dial.rs:21`; its refusal is a `DialError::InvalidTarget`, whose words
  ("invalid destination: ... is not a host name") reach the client as any dial's do. A dial's words
  are `DialError`'s own: "could not connect to HOST:PORT: Connection refused (os error 111)", the
  proxy's "refused CONNECT HOST:PORT: STATUS REASON", or "timed out after 20s".
- `crates/podssh-ssh/src/forward.rs:39-110` is the client's `-W` on stdin and stdout, not a copy
  with half-close to reuse: the server's copy is its own (`crates/podssh-ssh/src/server/direct.rs`),
  as it must tell the client's EOF from its close, which russh's channel stream reads alike; it ends
  the TCP connection when the client closes the channel, as `agent_forward::splice` ends its socket.
- Approach item 5's `crates/podssh-cli/src/flags.rs` is `crates/podssh-cli/src/flags/serve.rs` since
  T-107. `podssh serve` has no relay or node road (T-107's Done), so `--stdio` is the one way in.
- The Prove's scripts/interop-serve.sh is a test of the CLI crate, crates/podssh-cli/tests/serve_forward_openssh.rs,
  as T-107 and T-108 made theirs. It has no Dropbear and no OpenSSH sshd on fixed ports to reach,
  so `-W` reads an echo listener of the test, and `-J` reaches a second `podssh serve --stdio` behind a
  listener of the test, with OpenSSH's client at both hops; the Prove names it.
- T-108 left a test that waited for this entry: crates/podssh-ssh/tests/serve_auth.rs's
  `a_subsystem_and_direct_tcpip_are_refused_with_an_answer` is now `a_subsystem_is_refused_with_an_answer`,
  the subsystem still refused (T-112), and direct-tcpip's answers are `serve_forward`'s. The plant
  `t107-accept-each-key` has its hunk moved to the handler's new lines.
- russh's server adjusts a channel's window when the data arrives (T-108's Correction): the bytes
  for a target that reads slowly wait in the channel's queue of 100 messages, then the whole
  connection waits, as for a child's stdin; the window of each channel apart is T-118's.

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t109` (no build, no test run): the forward in
crates/podssh-ssh/src/server/direct.rs (the check of the policy and the port, the bound on open
forwards, the dial on a task of its own with `podssh_ws::dial::dial` and 20 s, the refusal of code 2
with the dial's words, the copy both ways with half-close), `channel_open_direct_tcpip` in the
handler, `no_forwarding` and `max_forwards` in `Settings`; `--no-forwarding` in
crates/podssh-cli/src/flags/serve.rs and `serve.rs`; the manual's note (crates/podssh-cli/src/man/notes_serve.rs),
`docs/cli.md` ("Forwards into the cage"), a row of `docs/STATUS.md`, the tests of the Prove, the plant
`t109-reason-dropped`, and the change of T-108's test in serve_auth.rs (Correction). Results:

Merged, built and run by the main session the same day:

- `cargo test -p podssh-ssh --test serve_forward --test serve_auth`: 6 and 7 passed.
- `cargo test -p podssh-ssh --lib server::direct`: 4 passed.
- `cargo test -p podssh-cli --test serve_forward_openssh --test serve_openssh --test serve_stdio` (OpenSSH 9.6's
  client: `-W`, `-N -L`, `-J` to a second serve, the refusals): 5, 7 and 3 passed.
- The tables and the manual: `flag_table` 9, `man_flag_parity` 6, `man_json` 4, `--lib man::` 60 passed.
- The plant `t109-reason-dropped`: caught; `t107-accept-each-key` and `t108-whole-environment`, their hunks moved:
  caught.
- Clippy: `fetch_update` of the forward's count is `try_update` on Rust 1.99; then clean, and rustfmt clean.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,756 passed, 0 failed.

Left after the merge: `cargo todo remap` on each cited file that the draft changed
(`crates/podssh-ssh/src/server/handler.rs`, `crates/podssh-ssh/src/server/mod.rs`, `docs/cli.md`,
`docs/STATUS.md`, the CLI's files) and `cargo todo counts`; the run in the build image (T-251).

# T-110: `podssh serve`: a real pty when `/dev/ptmx` exists

**Source:** `docs/ROADMAP.md:190-195`, `docs/design.md:663-667`,
`docs/terminal.md:92-102`; GitHub #20 (bound every PTY wait).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

An interactive shell, `vi`, `less` and Ctrl-C need a pty on the server side.
Without one, `ssh -t` to a node gets a shell with no prompt and no job
control. Many hosts that run `podssh serve` have `/dev/ptmx`; serve must use
it there.

## Premise

- Read: russh gives `pty_request` the terminal name, the size and the modes,
  and gives `window_change_request` each new size; both expect an answer
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 531-541 and 717-726).
- Read: the client sends its termios as RFC 4254 modes
  (`crates/podssh-ssh/src/terminal/unix.rs` lines 86-163 at `32bf8af`). That table is the one to
  read in reverse on the server; a second table would drift.
- Read: doctor already opens a pty to test the host
  (`crates/podssh-cli/src/doctor/unix.rs` lines 95-154 at `32bf8af`). The client continues
  without a pty when the server refuses (`crates/podssh-ssh/src/session.rs:88-103`).
- Read: the measured sandbox has no `/dev/ptmx` and no `/dev/pts`
  (`docs/target-environment.md:26`); there, T-111 applies.

## Approach

1. Move the pty code of `crates/podssh-cli/src/doctor/unix.rs` (lines 95-154 at `32bf8af`) into
   the server module, with `O_CLOEXEC`, and let doctor call it. Try
   `/dev/ptmx`, then `/dev/pts/ptmx`, at each `pty-req`; never keep the
   result for the next session. Failure: T-111, or failure until T-111 exists.
2. Apply the request's modes to the slave: move the table of
   `crates/podssh-ssh/src/terminal/unix.rs` (lines 86-163 at `32bf8af`) to a shared module and
   read it both ways. Skip a mode that the kernel refuses.
3. Size: `TIOCSWINSZ` on the master from `pty-req` and each `window-change`.
   A zero size becomes 80x24 (`docs/terminal.md:95-96`).
4. The child: `setsid`, `ioctl(TIOCSCTTY)`, the slave on descriptors 0 to 2,
   then exec, in `pre_exec`. The parent closes its copy of the slave, or the
   master never sees the end. `TERM` from the request (empty:
   `xterm-256color`, as `crates/podssh-ssh/src/terminal/mod.rs:115-120`);
   `SSH_TTY` names the slave.
5. I/O: the master is read without blocking through tokio's `AsyncFd`; output
   goes through the channel's writer (T-118). `EIO` after the child is gone
   is the end of the output, not an error.
6. The end: wait for the child, read the master to its end within a time
   limit (GitHub #20), then `exit-status` or `exit-signal`, EOF and close. A
   lost connection closes the master, and the kernel hangs up the session.
7. Unix only: on Windows a `pty-req` gets failure. Same commit: the serve
   notes, `docs/terminal.md` (the server side), `docs/STATUS.md`.

## Decision

The probe is the open of a master at each `pty-req`, and nothing else: a pair that opens is the pty
granted. Lost: a probe once at serve's start (a cage gains or loses its device while serve runs, and
the Approach asks for no cache), and a check of `/dev/ptmx`'s existence alone (a device that exists can
refuse its open, `EACCES` under a seccomp or a mount without it, or give no slave).

`Settings::ptmx`, the list of masters to try, is the test's way to see the refusal on a host that has a
pty; the command line has no flag for it. Lost: a flag `--no-pty` (no user has asked; T-114's
`no-pty` of a key is the place for it), and an environment variable (the manual's tables would gain
one that only a test reads).

On a pty, the client's EOF ends the writing alone and the master stays open, as OpenSSH's sshd keeps
the pty open at a channel's EOF; a pty has no half-close, and a `^D` sent in the client's place would
change what the program reads. A mode that the kernel refuses: the whole set is tried first, then each
mode alone, and each one refused is passed over, as the Approach asks.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_pty --test serve_exec
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib -- server:: terminal::modes
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_openssh --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib -- doctor:: man
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test flag_table --test man_flag_parity --test man_json
sh scripts/plant-each.sh --here t110-no-window-size
sh scripts/dev.sh check
```

crates/podssh-ssh/tests/serve_pty.rs, with russh's client over a pipe, where a pty opens on the
host ("did not run" where none does): a `pty-req` granted, then `exec`; `tty` names a slave under
`/dev`, `SSH_TTY` the same, `TERM` the request's; `stty size` gives the asked 30 by 100, 24 by 80
for a zero size, and 40 by 120 after a `window-change`; a second `pty-req` on one channel is refused;
the request's modes (ECHO off, VERASE 8, VINTR 3) read back from `stty -a`; Ctrl-C written to the
pty ends `sleep 25` by SIGINT within 20 s; stdout and stderr come as one stream, with the pty's CR
LF; 20,000 lines come whole before `exit-status`, EOF and close, after the client's EOF.
crates/podssh-ssh/tests/serve_exec.rs keeps the refusal on any host: a master that is missing
(`Settings::ptmx`) refuses the pty, and the command runs on pipes. The unit tests: the table of the
modes read both ways (`terminal::modes`), the probe and the size and modes on a real pair
(`server::pty`), `TERM` and `SSH_TTY` over serve's own (`server::env`). Against OpenSSH's client with
`podssh serve --stdio` as its ProxyCommand, crates/podssh-cli/tests/serve_openssh.rs: where a pty
opens, `ssh -tt` gets a terminal, 80x24 (OpenSSH sends a zero size with no local terminal), the
client's `TERM`, and Ctrl-C ends `sleep 25`; where none opens, the refusal and 255. The plant
`t110-no-window-size` (no `TIOCSWINSZ` at the request) fails the size check. In the build image
(T-251): `scripts/interop-pty.py` with a mode for `podssh serve --stdio` (resize, `vi`, `less`, `top`,
`~.`) and the `-tt` cases of `scripts/interop.sh:424-452` against serve.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The Premise, read again at `32bf8af`:

- russh is 0.65.0 from `vendor/russh` (T-107's Correction): `pty_request` and
  `window_change_request` are at `vendor/russh/src/server/mod.rs:590-602` and
  `vendor/russh/src/server/mod.rs:776-786`, and both still answer nothing by default. A
  `window-change` asks for no reply, so the handler sends none.
- The client's table of modes was at `crates/podssh-ssh/src/terminal/unix.rs` lines 86-163 at
  `32bf8af`; it is now `crates/podssh-ssh/src/terminal/modes.rs` (Approach item 2), one table that the
  client encodes its termios with and the server applies to the slave, and the client's
  `pty_modes_of` calls it. The doctor's probe was at `crates/podssh-cli/src/doctor/unix.rs` lines
  95-154 at `32bf8af`; it is now `podssh_ssh::server::pty` (`crates/podssh-ssh/src/server/pty.rs:62-121`),
  and the doctor's line `pty` calls it with the same words. The probe opens each master by path
  (`/dev/ptmx`, then `/dev/pts/ptmx`) where doctor called `posix_openpt`, which opens `/dev/ptmx` alone.
- The client's answer to a refused pty moved: since T-664 it may read the answer after the session's
  request (`crates/podssh-ssh/src/session.rs:94-103`); it still runs without a pty after a refusal.
- `TERM`'s default is `crates/podssh-ssh/src/terminal/mod.rs:115-120` now.
- Approach item 1's "Failure: T-111, or failure until T-111 exists": until T-111 the refusal stays, as
  T-108 made it; this entry does not do T-111.
- The Prove's crates/podssh-ssh/tests/serve_pty.rs drives a real pty through the server with russh's
  client (as T-108's serve_exec.rs does), and OpenSSH's `-tt` runs in crates/podssh-cli/tests/serve_openssh.rs,
  where the test of T-108 that held the refusal now holds the grant where a pty opens; the refusal
  through OpenSSH runs where none opens, and on each host in serve_exec.rs with a missing master.
  `scripts/interop-pty.py`'s mode for serve (`vi`, `less`, `top`, `~.`) needs the build image (T-251).

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t110` (no build, no test run): the probe and the
pty in crates/podssh-ssh/src/server/pty.rs (the masters tried by path, the slave, the size with a zero
one as 80x24, the modes through the shared table with each refused mode passed over, `TERM`'s
default); the child on the pty in crates/podssh-ssh/src/server/pty_child.rs (`Granted`, the slave on
descriptors 0 to 2 with `setsid` and `TIOCSCTTY`, the master read and written through tokio's
`AsyncFd`, `EIO` as the end); the table of modes in crates/podssh-ssh/src/terminal/modes.rs, read both
ways, with the client's `pty_modes_of` on it; `child.rs` split into the command, the spawn on pipes
and `Running::finish`, which both spawns share; the channel's input as any writer (`channel.rs`);
`pty_request` and `window_change_request` in the handler; `Settings::ptmx`; `env::with_tty`;
`podssh doctor`'s line `pty` on the same probe; the manual's note (crates/podssh-cli/src/man/notes_serve.rs),
`docs/cli.md` ("A pty (T-110)"), `docs/terminal.md` (the server side of `pty-req`), a row of
`docs/STATUS.md`, the tests of the Prove and the plant `t110-no-window-size`. Results:

Merged, built and run by the main session the same day:

- `cargo test -p podssh-ssh --test serve_pty --test serve_exec`: 6 and 11 passed, three runs, once
  `ctrl_c_on_the_pty_interrupts_the_command` presses Ctrl-C again each second until the channel closes: under the
  suite's load the first Ctrl-C landed while bash had forked the sleep and not yet exec'd it, when the child still
  runs bash's handler, and bash waited the 25 s of the sleep before it ended by INT (a race of the test's shell; run
  alone it passed in 0.05 s).
- `cargo test -p podssh-ssh --lib`: 377 passed.
- `cargo test -p podssh-cli --test serve_openssh --test serve_stdio --test serve_forward_openssh` (OpenSSH 9.6's
  client, a pty granted here): 9, 3 and 5 passed.
- `cargo test -p podssh-cli --lib -- doctor:: man`: passed once `SSH_TTY`, which serve sets now, has its line in
  ENVIRONMENT, beside TERM; that row took `facts.rs` past 500 lines, so the rows of the terminal, the pager, the
  editor and the shell are `crates/podssh-cli/src/man/facts/terminal.rs`. `flag_table`, `man_flag_parity`,
  `man_json`, `man_page`: passed.
- The plant `t110-no-window-size`: caught (`a_pty_is_granted_and_the_command_sees_a_terminal`).
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,773 passed, 0 failed. Clippy clean; rustfmt reflowed
  `channel.rs` and `terminal/modes.rs`. The build on Windows: the gate's job `windows`.

Left after the merge: `cargo todo counts` (the status moved by hand in the entry and the index) and
`cargo todo check`, as the citations were moved by a line diff of the draft, not by `cargo todo remap`;
the run in the build image (T-251): `scripts/interop-pty.py` against serve and the `-tt` cases of
`scripts/interop.sh`.

# T-111: `podssh serve` with no `/dev/ptmx`: the line discipline, and Ctrl-C to the child's process group

**Source:** `docs/ROADMAP.md:190-195`, `docs/design.md:663-667`,
`docs/decisions.md:102`; GitHub #20 (fux line-discipline notes).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** L
**Status:** partial

## Problem

The measured cage has no `/dev/ptmx` (`docs/target-environment.md:26`). There
a shell on pipes gives no echo, no editing and no prompt, and Ctrl-C reaches
nothing. Only the server side can turn Ctrl-C into a signal for the child's
process group (`docs/design.md:663-667`). Without it, a user cannot stop a
command, and the session must end.

## Premise

- Read: `PodUtils/podssh:crates/podssh-terminal` holds podbox's echo, editing and history
  rules (`docs/terminal.md:178-216`), and reports Ctrl-C and Ctrl-\ as
  `Event::Signal` (`PodUtils/podssh:crates/podssh-terminal/src/echo.rs:421-423`). No command
  uses it, and it has the defects T-125 to T-129, which come first.
- Read, at `cb94460`: the crate refuses to add `\r` before `\n`
  (`PodUtils/podssh:crates/podssh-terminal/src/echo.rs` lines 31-37,
  `PodUtils/podssh:crates/podssh-terminal/src/passthrough.rs:56-74`). Here the child writes
  to a pipe and the client's terminal is raw: the case where a lone `\n`
  must become `\r\n` (`docs/terminal.md:271-274`).
- Read: a signal to the group also stops a shell that does not catch it
  (`PodUtils/podssh:crates/podssh-terminal/src/session.rs:36-46`). Not measured yet: which
  shell mode survives.

## Approach

1. Selection: when the pty probe of T-110 fails, or with `--pty line`
   (values `auto`, `line`, `no`), answer the `pty-req` with success and run
   the session through `podssh-terminal` in serve (the server facts of
   T-125). Add the C-free crate to `crates/podssh-ssh/Cargo.toml`.
2. The child: pipes, its own session (`setsid`), so its group id is its pid.
   Start the shell so that SIGINT to the group stops the foreground command
   and not the shell. Measure `sh -i` with an empty `PS1` (an interactive
   shell catches SIGINT; its children get the default) with BusyBox `sh`,
   `dash` and `bash`. The discipline prints the prompt.
3. Keys from the channel go to `Session::on_local_bytes`: `ToRemote` to the
   child's stdin, `ToLocal` to the channel, `Signal(Int)` and `Signal(Quit)`
   to `kill(-pgid, SIGINT)` and `kill(-pgid, SIGQUIT)`, `Eof` closes stdin.
4. The child's output: a lone `\n` becomes `\r\n`; output during an edit
   redraws the line (T-129). The width comes from `pty-req` and
   `window-change` (T-126).
5. A full-screen program cannot run without a tty. When a submitted line
   starts with `vi`, `less`, `top` or `nano`, write one line on stderr
   ("needs a pty; this host has no /dev/ptmx"), then run it. T-248 studies
   how serve gives such programs a tty.
6. A `signal` request goes to the same group (T-108). Same commit:
   `docs/terminal.md`, the serve notes, `docs/STATUS.md`.

## Decision

- **The shell survives Ctrl-C by a trap, not by `-i`.** pod-term's cooked mode assumes a shell that prints no
  prompt (the discipline draws `$ `), as podvm's server runs it; an interactive shell (`sh -i`) prints its own
  prompt on its stderr and reads rc files that may set one. So the login shell runs non-interactive on its
  pipes, and serve's first line to it is `trap : INT QUIT`: a caught signal is the default again in the
  shell's children, so SIGINT to the group ends the command and the shell goes on (measured on dash and
  bash). Lost: `sh -i` with an empty `PS1` (a prompt of each shell's own, and rc files), and SIGINT to the
  foreground command alone (a pipe has no foreground group to read).
- **`--pty auto|line|no`**, default `auto`: the real pty, a devpts instance (T-775), then the line discipline;
  `line` for a test on a host that has a pty; `no` the refusal of T-110. As for T-775, a test's own `ptmx`
  leaves the fallback off unless the test asks for it, so that the refusal stays testable.
- **The child's stdin is fed by a task of its own** (128 lines), so a child that reads nothing holds no key
  of the client and no output.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_line
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test file crates/podssh-ssh/tests/serve_line.rs uses `--pty line`: Ctrl-C
ends `sleep 30` within 5 s, the next line runs, and output lines end in CR
LF. The gate runs the same through OpenSSH's `ssh -tt`, in the shape of
`scripts/interop.sh:433-442`: `AFTER-5` and exit 9 within 15 s. In the box
(no `/dev/ptmx`), a new step drives `podssh serve --stdio` with
`podman exec -i` from OpenSSH on the host. A planted serve that signals the
shell's pid and not its group fails the 15 s check.

## Correction

2026-10-09 (T-129): the crate now writes the child's output in the cooked
mode itself: each `\n` becomes `\r\n`, and output during an edit is written
around the line (`Session::on_remote_bytes`). So the second Premise no
longer holds, and step 4 is the crate's: serve passes the child's output to
`Session::on_remote_bytes`, and adds no `\r`. Each byte for the client
goes that way, the child's stderr and the line of step 5 included, or the
discipline's count of the screen is wrong.

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-05. `podssh-terminal` left this tree: its code is `pod-term` of PodUtils/podcrates, taken by
the git tag `v0.1.0` (T-684; `crates/podssh-cli` depends on it). Each `podssh-terminal` of this
entry reads `pod-term`, and a path under `PodUtils/podssh:crates/podssh-terminal/` is
`PodUtils/podcrates:crates/pod-term/` now, with its own line numbers. The echo discipline,
`Event::Signal`, the passthrough and the ring of T-221 are there. Rule Q3 holds: a change of the
terminal code is done in PodUtils/podcrates (or asked as an issue there), and podssh takes it by the
next tag. Approach item 1 reads: serve takes `pod-term` as a dependency of `podssh-ssh` (the "C-free
crate" is no rule now), and the Prove's tests of the discipline itself run in PodUtils/podcrates
(`cargo test -p pod-term`); `serve_line` stays podssh's.

## Done

Partial, 2026-11-13. `crates/podssh-ssh/src/server/line.rs`: a pty request that no pty serves (with `--pty
auto`, or always with `--pty line`) is granted as a `LineGrant` (the request's `TERM`, size and `IUTF8`);
the program then runs on pipes in a session of its own, with no `SSH_TTY`, and one task is its discipline:
pod-term's `Session` in the cooked mode reads the client's bytes (an in-memory pipe that the channel's
reader writes, so T-118's window holds), the child's stdout and stderr (each pumped into a pipe of its
own), the window changes, and the pause that closes a key left open (`IDLE`); its `ToLocal` go to the
channel as one stream, `ToRemote` to the child's stdin, `Signal` to the group as SIGINT or SIGQUIT, `Eof`
closes stdin. A login shell gets `trap : INT QUIT` first, and the prompt. A submitted line that starts a
program that draws on a tty gets a note through the discipline, then runs. `Settings::pty` (`PtyMode`) and
`podssh serve --pty`; `pod-term` is a dependency of `podssh-ssh` (Unix) at the tag of every podcrates crate;
the manual (`notes_serve.rs`, the flag's row) and `docs/cli.md` say so.

- `cargo test -p podssh-ssh --test serve_line`: 4 passed, three runs in three: the prompt, the echo, the
  output's lines in CR LF (no lone LF), `exit 9` as status 9; Ctrl-C ends `sleep 30` and the shell goes on
  (`AFTER-130`) on `/bin/sh` (dash), `/bin/dash` and `/bin/bash`, 1.2 to 2.1 ms after the key; a note for
  `less`; a command with `TERM` and no tty.
- `cargo test -p podssh-cli --test serve_line_openssh` (OpenSSH 9.6p1's `ssh -tt`, serve its ProxyCommand,
  the keys one after another as typed): `AFTER-130` and exit 9 in 4.1 s, within the Prove's 15 s.
- The plant `t111-signal-to-the-shell` (SIGINT to the shell's pid, not its group): caught.
- `cargo test -p podssh-cli --lib man`: 100 passed; `--test man_page --test man_flag_parity --test
  man_json`: passed. Clippy as the gate runs it on gnu and musl: clean; `cargo check --target
  x86_64-pc-windows-gnu`: clean; rustfmt: clean.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,856 passed, none failed.

The box's step, 2026-11-13: `BOX_RUN=line sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh`
(the binary of `scripts/box/build-podssh.sh`), exit 0: the box keeps running after its probe, and
`scripts/box/line-session.sh` on the host runs OpenSSH 9.6p1's `ssh -tt` into `podssh serve --stdio` in the box
through `podman exec -i`; with no `/dev/ptmx` and `unshare` refused there, serve took the line discipline by
itself (`--pty auto`), with the box's busybox `sh`: `AFTER-130` after Ctrl-C, and exit 9, in 12 s (11 s of them
the script's own pauses), within the Prove's 15 s.

The gate of `dfebaf0` (Linux, `gate (ssh)`) failed once in `the_prompt_the_echo_and_a_line_s_output_in_cr_lf`: the
shell's two `echo`s came in two reads, and the discipline drew the prompt again between them, so the test's one
needle `one\r\ntwo\r\n` never matched; it looks for each line on its own now. 5 runs in 5 passed.

Left: the Prove's `sh scripts/dev.sh check` (the build image, T-251; CI's gate runs the same at each push).

# T-112: An SFTP server in `podssh serve`

**Source:** `docs/ROADMAP.md:196`, `docs/design.md:668-672`; GitHub #20
(tty7 issue #1126: bound every SFTP wait); GitHub #21 (bssh pipelined SFTP).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

A cage has no `sftp-server`, `scp` or `rsync`, so files cannot move in or out
with standard tools. OpenSSH's `sftp`, and `scp` in its SFTP mode (the
default since OpenSSH 9.0), need an SFTP subsystem on the server.
`podssh cp` needs one too (T-134).

## Premise

- Read: no SFTP code exists, and `Cargo.lock` has no `russh-sftp`.
  `docs/ROADMAP.md:196` names `russh-sftp` for the client and the server.
- Read: russh gives a channel as a byte stream (`Channel::into_stream`), and
  `subsystem_request` must answer (`Eugeny/russh:russh/src/server/mod.rs`,
  lines 686-696 at `22c3b88`).
- Read: the client reaches an SFTP subsystem already: `-s sftp` gets
  `SSH_FXP_VERSION` from OpenSSH's `sftp-server` (`scripts/interop.sh:367-375`).
- Read in the report of GitHub #20, not verified here: tty7 issue #1126 is an
  SFTP wait that did not end; GitHub #15 is the same class in podssh.

## Approach

1. Add `russh-sftp` to `crates/podssh-ssh/Cargo.toml`, with a pinned version
   and a permissive license (podssh is 0BSD). Record the size cost in
   `docs/STATUS.md`.
2. `subsystem_request("sftp")`: success, then run the SFTP server on
   `channel.into_stream()`. Each other name gets failure.
3. A file-system handler in crates/podssh-ssh/src/server/sftp/: relative
   paths start at `HOME`, as OpenSSH's `sftp-server` does. Support open,
   read, write, close, stat, lstat, fstat, setstat, opendir, readdir,
   remove, mkdir, rmdir, rename, realpath, readlink and symlink, and the
   extensions `posix-rename@openssh.com` and `fsync@openssh.com` for T-134.
4. Invariants: each file-system call runs on a blocking thread with a time
   limit; past it, the reply is a failure with the reason, and the handle
   closes (a FIFO or a dead mount must not stop the session). At most 256
   handles and 256 KiB for each read; the memory of a session is bounded.
5. A cage has no chroot (`docs/target-environment.md:19`): the server reaches
   what the process user reaches. Say so in the manual.
6. `scp -O` (the old protocol) runs `scp -t` by exec and needs an `scp`
   program in the cage. Say that it fails with 127 there.

## Decision

Recommendations, followed by the draft of 2026-11-13; no ruling of `docs/decisions.md` touches them.

- **The wire is russh-sftp's packets, the loop is podssh's.** The server decodes and encodes with
  russh-sftp 3.0.1's `Packet` (the crate of the client, T-133), and reads the stream, answers and ends
  in its own loop (`crates/podssh-ssh/src/server/sftp/mod.rs`). Lost: the crate's own server loop
  (`russh_sftp::server::run`), which spawns a task of its own, goes on reading after a read that failed
  with anything but an end of file (a loop of warnings with no end), never closes the channel, and
  answers a packet past its limit with no way to find the next one; a codec of podssh's own, which would
  be a second copy of the client's.
- **Each call on the file system runs on a thread of the session's own, within 20 s.** A call past its
  limit is left on its thread, the reply says so, the handle that it used is closed, and the next call
  runs on a new thread; a session that left 8 ends, so that a client cannot make threads without
  bound. Lost: tokio's blocking pool, whose runtime waits at its end for each blocking task, so that a
  FIFO with no writer would hold serve's exit; a thread for each call, which costs a thread for each
  read of a large copy. 20 s is under the 30 s that podssh's client waits for a reply that carries no
  data (`crates/podssh-ssh/src/sftp/mod.rs`, `METADATA_WAIT`), so that the client reads the reason, not
  its own time limit; a test gives a shorter one (`Settings::sftp_limit`).
- **The extensions are `posix-rename@openssh.com` and `fsync@openssh.com`, which the Approach names,
  and `limits@openssh.com`.** The third costs a reply of 32 bytes and lets each client read and write
  255 KiB at a time instead of the 32 KiB that it takes without it (OpenSSH's `sftp` and podssh's own).
  Lost for now: `statvfs@openssh.com`, `hardlink@openssh.com`, `copy-data` and `expand-path@openssh.com`,
  which no client of the Prove needs; a client that asks gets "unsupported" with the name.
  `users-groups-by-id@openssh.com` and the owners' names in a listing need the passwd database, which
  serve never reads (`docs/cli.md`, the shell of `podssh serve`): a listing names owners by number.
- **Version 3's rename never goes over a name that exists**, as the draft says: an lstat of the new name,
  then rename(2). Lost: `sftp-server`'s link and unlink for a regular file, as a hard link fails on some
  file systems and in some cages, and its fallback has the same window between the check and the rename.
- **`--no-shell` leaves SFTP served.** The flag says that serve runs no command and no shell, and SFTP
  runs no program; the limits of one key (`restrict`, a forced command) are T-114's. Lost: a refusal of
  SFTP under `--no-shell`, which no user asked for and which would leave a cage that runs no shell with
  no way to move a file.
- **Requests are answered one at a time, in their order**, as `sftp-server` answers them; a client's
  requests in flight wait in the channel's queue. Windows refuses the subsystem with a line, as
  `podssh serve` serves on a Unix host only.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib server::sftp
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_sftp --test serve_auth --test serve_exec
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_sftp_openssh --test serve_openssh --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test flag_table --test man_flag_parity --test man_json
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
sh scripts/plant-each.sh --here t112-write-drops-last-byte
sh scripts/dev.sh check
```

The unit tests of `crates/podssh-ssh/src/server/sftp/` write and read the packets as bytes over a
pipe: the version reply (3, with the three extensions, to a client that asks for 6); a request before
the version request, and a second one, end the session; an unknown type and a packet that does not
parse are answered with their id (unsupported, bad message) and the session goes on; a length past
256 KiB ends it; a missing file is "no such file" with its name and the system's words; a relative path
and `realpath` of `.`, of an empty path and of a file to be made start at HOME; a read of 1 MiB is cut
to 255 KiB and a read at the end is EOF; 256 handles, then a failure that names the bound, and a close
makes room; a FIFO with no writer fails within its limit and an lstat of it follows; symlink takes the
target first; rename keeps an existing name and `posix-rename@openssh.com` replaces it; `limits` names
the four bounds; and a session of podssh's own client (a megabyte up and back, fsync, mkdir, rename,
a listing of `.`, `..` and the file, setstat, remove, rmdir); the worker leaves a stuck call and serves
the next on a new thread. crates/podssh-ssh/tests/serve_sftp.rs runs podssh's client over russh's
client and a pipe of 4 MiB to `serve_with` (T-772): 5,000,000 bytes up, on disk under HOME and back with
equal SHA-256 digests; mkdir with its mode, posix-rename, a link, a listing with its `ls -l` line,
setstat of the times, remove and rmdir; the codes of a missing name (2), a directory that is not empty
(4) and, not as root, a file of mode 000 (3); the bound of handles; a FIFO within a limit of 1 s, and
the session goes on. serve_auth.rs's `a_subsystem_is_refused_with_an_answer` asks for another name than
`sftp`. Against OpenSSH, crates/podssh-cli/tests/serve_sftp_openssh.rs ("did not run" where a host has no
`sftp` or `scp`): `sftp -b` with `podssh serve --stdio` as its ProxyCommand puts and gets 5,000,000
bytes with equal digests, then mkdir, rename, `ls -l` (the server's line), rm and rmdir, and nothing is
left under serve's HOME; `rmdir absent` exits 1 with "No such file"; `scp` up and down with equal
digests. The plant `t112-write-drops-last-byte` (a write that drops its last byte and answers OK) fails
the test of the whole file.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The Premise, read again at `32bf8af`:

- `Cargo.lock` has russh-sftp 3.0.1 since T-133 (`crates/podssh-ssh/Cargo.toml:32`), and podssh has
  an SFTP client (`crates/podssh-ssh/src/sftp/mod.rs`). So Approach item 1 adds no crate: the server
  takes the client's russh-sftp for its packets, and `bytes` (at the version that the tree builds for
  russh-sftp and russh) becomes a direct dependency for the codec's buffer type; the size cost is
  measured on the release binary.
- russh is 0.65.0 from `vendor/russh` (T-107's Correction): `subsystem_request` is at
  `vendor/russh/src/server/mod.rs:745-752`, and its default sends no reply, so the handler answers
  each name (success for `sftp`, failure for each other).
- russh-sftp's `Channel::into_stream` (Approach item 2) does not fit serve: each session channel is
  split at its open, and a task reads it from then on (T-108, `crates/podssh-ssh/src/server/channel.rs`).
  The task gives its data to a writer that a program or the SFTP server takes: a child's stdin, or one
  end of a pipe in the process whose other end the server reads; the replies go out through the
  channel's writing half, and the server sends EOF and close when the client's EOF ends its input.
- The client side (`scripts/interop.sh:366-375`) holds as read: `-s sftp` gets `SSH_FXP_VERSION`
  from OpenSSH's `sftp-server`.
- russh-sftp reads each path as text: a request whose path is not UTF-8 is a bad message, and a name
  in a listing that is not UTF-8 has U+FFFD in place of each bad byte, as the client's module says.
- The Prove's scripts/interop-serve.sh is a test of the CLI crate, crates/podssh-cli/tests/serve_sftp_openssh.rs,
  as T-107 to T-109 made theirs; `scp -O` (Approach item 6) is in the manual's note, not in a test, as
  the test host has `scp` and the cage's 127 needs a cage without one.

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t112` (no build, no test run): the server in
crates/podssh-ssh/src/server/sftp/ (the loop and its bounds in mod.rs, the answers and the handles in
answer.rs, the file-system calls in fs.rs, the session's thread in worker.rs, the unit tests in
tests.rs); `subsystem_request` in the handler; the reading task's writer made general
(`crates/podssh-ssh/src/server/channel.rs`); `sftp_limit` in `Settings`; `bytes` in
crates/podssh-ssh/Cargo.toml and `Cargo.lock`; the manual's note (crates/podssh-cli/src/man/notes_serve.rs),
`docs/cli.md` ("SFTP (T-112)"), a row of `docs/STATUS.md`, the tests of the Prove, the plant
`t112-write-drops-last-byte`, and serve_auth.rs's test of a refused subsystem moved to another name.
Results:

Merged, built and run by the main session the same day, beside T-110's pty (drafted from the same base; both
generalised the channel's input, kept as T-110's `Input` with `give_input` for SFTP), with three repairs:

- `cargo test -p podssh-ssh --lib server::`: 34 passed, once the unit tests read a reply's id themselves:
  russh-sftp's `Packet::get_request_id` reads requests alone and gives 0 for each reply, so each test that asked
  for its id failed though the server's replies carried it.
- `cargo test -p podssh-ssh --test serve_sftp --test serve_auth --test serve_exec --test serve_pty`: 5, 7, 11 and 6
  passed. Repaired: `the_open_handles_are_bounded` took only the server's refusal of the 257th handle, but podssh's
  own client reads the bound of `limits@openssh.com` and refuses it first; either refusal is the bound held.
- `cargo test -p podssh-cli --test serve_sftp_openssh` (OpenSSH 9.6's `sftp -b` and `scp`): 3 passed, after a
  defect of the server: it closed the sftp channel with no `exit-status`, so OpenSSH's ssh said `Exit status -1`
  and scp exited 1 after a whole copy. The session now sends 0 at a clean end and 1 at an end on an error, as
  sftp-server's exit does under sshd. `serve_openssh`, `serve_stdio`, `serve_forward_openssh`: 9, 3 and 5 passed.
- The tables and the manual: `flag_table` 9, `man_flag_parity` 6, `man_json` 4, `man_page` 11, `--lib man` 100.
- The plant `t112-write-drops-last-byte`: caught; `t110-no-window-size` and `t107-accept-each-key`: caught.
- Clippy: `Worker::limit` unused (removed) and a mode of 0 written `0o0`; then clean, and rustfmt clean.
- The size of the release binary: not measured here (no release build); russh-sftp was in the binary already
  (T-133), so the server adds its own code alone.

Left after the merge: `cargo todo remap` on each cited file that the draft changed
(`crates/podssh-ssh/src/server/handler.rs`, `crates/podssh-ssh/src/server/mod.rs`,
`crates/podssh-ssh/src/server/channel.rs`, `crates/podssh-ssh/Cargo.toml`, `docs/cli.md`,
`docs/STATUS.md`) and `cargo todo counts`; the run in the build image (T-251).

2026-11-13, after the gate of `f335255` failed on three jobs: the server's `sftp` module was built on
Windows (its Unix calls; now `#[cfg(unix)]`, as the handler's refusal there already was), `libc::time_t`
is deprecated on musl (the time now cast to the field's own type), and the tests of the server left
their scratch directories in the temporary directory (each now removed as its test's thread ends).
`cargo check --target x86_64-pc-windows-gnu -p podssh-ssh -p podssh-cli --all-targets`: clean; clippy on
`x86_64-unknown-linux-musl` as the gate runs it: clean; `cargo test -p podssh-ssh --test serve_sftp`
and `--lib -- sftp`: 5 and 30 passed, no `podssh-*` left in `/tmp`.

# T-113: M5 exit: a usable shell and 200 MiB each way from a sealed sandbox

**Source:** `docs/ROADMAP.md:205-209` (the exit criteria of M5).
**Category:** measurement
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** blocked

## Problem

M5 ends with a measurement on a real host, not with passing unit tests. The
criterion: from a sealed sandbox (no ptmx, no passwd, no bind), an operator
gets a shell where `vi`, `less` and Ctrl-C work, and copies 200 MiB in and
out with matching digests.

## Premise

- Read: `podssh serve` runs in the sandbox as a node (T-107 on the runner of
  T-079), and the operator connects through the relay (T-084).
- Read: `vi`, `less` and `top` need a real pty (`docs/terminal.md:257-261`).
  The measured sandboxes have no `/dev/ptmx` (`docs/target-environment.md:26`,
  `docs/STATUS.md:522`). With no pty device, no podssh code can give the child
  a tty: shims are excluded (`docs/decisions.md:101`).
- Read: one relay session carries 64 MiB, both directions together
  (`docs/relay.md:557`; measured: `docs/STATUS.md:530`). 200 MiB each way
  needs the new sessions of T-137.
- Read: the box matches the sandbox, except the `EACCES` on loopback
  `connect()` (`scripts/test_in_box.sh:55-62`).

## Approach

1. Preconditions: T-107 to T-112, T-117, T-118, T-222, T-248 (with the work
   that it names) and T-133 to T-138 are done.
2. In the box first: a new step in `scripts/test_in_box.sh` starts
   `podssh serve NAME` in the box, and the host connects as the operator
   through the live relay.
3. The shell: `vi`, `less` and Ctrl-C work through the tty that T-248 gives
   where `/dev/ptmx` is missing (see Decision). Ctrl-C stops `sleep 30`, and
   the session continues.
4. The copy: 200 MiB of random data in, then out, with `podssh cp`. Compare
   SHA-256 at both ends, and count the relay sessions used.
5. Then the operator's real sandbox, with the same steps (the procedure of
   T-001).
6. Record each result with its date and command in `docs/STATUS.md`.

## Decision

Ruling of the operator (Q11, 2026-10-08): the exit criterion stays as it is,
with `vi`, `less` and Ctrl-C in a sealed sandbox. T-248 decides how a tty
exists where `/dev/ptmx` is missing, and this entry measures with the route
that T-248 chooses.

## Prove

```sh
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
grep -n 'podssh serve' docs/STATUS.md
```

The box run exits 0 when each serve step passes: `vi`, `less`, Ctrl-C, the
session that continues, and two 200 MiB copies with equal digests. The grep
shows the rows recorded for the box and for the real sandbox, with their
dates.

## Blocker

The Prove's `vi` and `less` need a tty in the box, which has no `/dev/ptmx` and refuses `unshare` (T-778), as
the real sandboxes do: only route 2 of T-248 gives one there (T-776, T-777), and those wait for PodUtils/podcrates
to give `pod-term` a line discipline that follows a termios (COORD-055, #232; podcrates' entry 539, in work).
Once podssh takes that tag and T-776 is done, this entry opens again.

## Correction

The premise that no podssh code can give the child a tty where `/dev/ptmx` is
missing is too strong. The operator allows two routes, each after a probe at
run time (Q11, 2026-10-08), and T-248 studies them. The ban on `LD_PRELOAD`
stays (`docs/decisions.md:101`).

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

# T-114: `podssh serve`: access rules for each key and command

**Source:** GitHub #21 (agent-ssh-cli: command allow and deny lists);
GitHub #18 (sandhole: forwarding restrictions; iroh-ssh issue #47: a
hardened service); GitHub #19 (slingshot: a key for each client).
**Category:** feature
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

After T-107, each authorized key gets everything: a shell, each command, each
forward and a pty. An operator who gives a CI job or an agent one key cannot
limit it to one command or one port. T-107 skips each key line with options,
so a key with limits cannot be used at all.

## Premise

- Read: T-107 skips option lines, so that no key is used without its limits.
  OpenSSH's `authorized_keys` options are the format that users know
  (sshd(8), section "AUTHORIZED_KEYS FILE FORMAT").
- Read: the patterns of `from=` are those of `known_hosts`, which
  `crates/podssh-ssh/src/known_hosts.rs:274-297` matches (negation included).
- Read: on the reverse road, serve does not know the client's address: the
  stream comes from the relay (`docs/relay.md:635-659`).
- Read in the reports of GitHub #21 and #18, not verified here: agent-ssh-cli
  checks regex lists before exec; sandhole limits local forwarding.

## Approach

1. Parse the options field: options separated by commas, quoted values with
   `\"`. Invariant: a line with an unknown or malformed option is skipped
   with a log line; it is never used without the option.
2. Support `restrict`, `command="..."` (forced; `SSH_ORIGINAL_COMMAND` holds
   the client's command), `no-pty` and `pty`, `no-port-forwarding` and
   `port-forwarding`, `permitopen="host:port"` (T-109), `from="patterns"`,
   and `expiry-time="YYYYMMDD[HHMM[SS]]"`. Accept `no-agent-forwarding` and
   `no-X11-forwarding` with no change: serve offers neither.
3. `from=` with no client address (the reverse road) never matches, so the
   key is refused there. It matches on a listener (T-124).
4. Refuse by name `environment=`, `tunnel=`, `principals=`, `cert-authority`
   and `permitlisten=` (see Decision).
5. Apply the rules where each request is answered (T-108 to T-112). Log a
   refusal with the fingerprint and the rule.
6. Same commit: `docs/cli.md` (the supported options), the serve notes.

## Decision

Recommendation: OpenSSH's options, not podssh's own regex lists. A regex list
of commands is easy to pass with shell syntax (`cmd; other`), while
`command=` with a wrapper is the known pattern, and users have such files.
`environment=` and `permitlisten=` stay refused until a need is recorded: the
first sets variables that T-108 filters, and the second needs a listener.

2026-11-13, made with the draft:

- **`from=` on a stream with no address.** serve takes the client's address from its stdin alone,
  where stdin is a TCP socket (`getpeername`, as `sshd -i` under an inetd takes it); on a pipe, which
  a ProxyCommand and the relay give, it has none, and no `from=` matches: the key is refused, and
  serve's stderr says why. A pattern is matched as sshd's `match_host_and_ip` with `UseDNS no` (its
  default): an address with `*` and `?`, a CIDR block, `!` that refuses whatever else matched; a host
  name matches nothing, as serve looks up no name. Lost: `SSH_CONNECTION` of serve's environment
  (whoever starts serve sets it: no fact about the client); `from=` that always matches where no
  address is known (fails open: the key gets in from anywhere); refusing the line at the read (it
  would also refuse the key where a socket gives an address, and T-124's listener will).
- **A forced command and the `sftp` subsystem**, as sshd's `do_exec`: the forced command runs in
  place of the subsystem too, with `SSH_ORIGINAL_COMMAND=internal-sftp` (sshd sets the subsystem's
  command; serve's SFTP server is in the process, as `internal-sftp` is). A forced `internal-sftp`
  serves SFTP and refuses a command or a shell ("this key is for SFTP alone", as sshd's
  `SUBSYSTEM_INT_SFTP_ERROR`); with arguments (`-R`, `-d`) it refuses SFTP too, as serve's SFTP
  server takes none and would serve more than the line allows. Lost: ignoring the arguments (fails
  open), running nothing for the subsystem (sshd runs the command).
- **`SSH_ORIGINAL_COMMAND` belongs to the forced command alone**: a client's `env` request for it is
  refused whatever `--accept-env` says, and serve's own (serve under another sshd's forced command)
  never reaches a child. A wrapper decides by that variable; a client that sets it would choose the
  wrapper's branch.
- **The flags of a security key.** serve does not read the flags of a security key's signature
  (russh verifies through ssh-key, whose `make_sk_signed_data` in `vendor/ssh-key/src/signature.rs`
  signs over them and checks none). So `touch-required` and `verify-required` ask for a check that
  serve does not make, and refuse the line; `no-touch-required` asks for less, and changes nothing.
- **Where a refusal is said.** A request that a rule refuses: on the channel (its stderr line, or
  the reason of a refused forward with code 1) and on serve's stderr with the key's fingerprint and
  the option. A key that lines name and refuse at login: on serve's stderr alone, with the line and
  the option; the client hears `Permission denied (publickey)`, as from sshd. Lost: a banner with the
  reason, which would tell each client that tries a key whether that key is listed.
- **`--authorized-key` takes a line with options** as a file does; one that serve cannot use is a
  usage error (64) there, as the command line is the operator's own typing, while a file's line is
  passed over and said. A refused line never refuses the start: the start needs one key that is used.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib server::
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_options --test serve_auth --test serve_exec --test serve_forward --test serve_pty --test serve_sftp
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_options_openssh --test serve_openssh --test serve_forward_openssh --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib serve
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test man_page --test man_flag_parity --test man_json
sh scripts/plant-each.sh --here t114-forced-command-ignored
sh scripts/plant-each.sh --here t114-restrict-keeps-pty
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_options.rs parses the option
examples of sshd(8) and skips malformed lines. In the gate, OpenSSH through
`podssh serve --stdio`: `command="echo forced"` runs `echo forced` for each
request and sets `SSH_ORIGINAL_COMMAND`; `no-pty` gives `ssh -tt` no pty;
`permitopen="127.0.0.1:2201"` lets `-W 127.0.0.1:2201` through and refuses
`-W 127.0.0.1:2203`; `restrict` refuses a pty and a forward; a past
`expiry-time` refuses the key. A planted parser that ignores `restrict` fails
the pty check.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

2026-11-13. The Premise and the Approach, read again at `97d6fac`:

- T-107 to T-112 are partial, not done: each is merged with its native tests passed, and waits for
  the build image (T-251) or a later step. The server that this entry needs exists
  (crates/podssh-ssh/src/server/), so the draft starts on it.
- Premise item 1 holds: `crates/podssh-ssh/src/server/authorized.rs` counted each line with options
  and used none of them ("T-114 reads them").
- Premise item 2 holds at `crates/podssh-ssh/src/known_hosts.rs:274-297`, but `from=` does not reuse
  `matches`: that function matches host names with no CIDR block (a `from=` pattern may be one) and
  reads hashed names (a `from=` list has none). The draft matches with the same `wildcard` and a
  block of its own (`crates/podssh-ssh/src/server/rules.rs`).
- Premise item 3's citation of `docs/relay.md` moved: those lines now hold the rank of the hosts and
  the open questions. Its fact holds: on the reverse road the stream comes from the relay, and with
  `--stdio` it is a pipe, which has no peer address either. Approach item 3 reads: no address, no
  match; an address where stdin is a TCP socket (Decision), as well as T-124's listener.
- Approach item 1's "skipped with a log line": at the start, each line that is not used is said on
  serve's stderr with its number and why (the option named), as T-107 says a line that is no key.
- Approach item 2 adds `no-user-rc` and `no-touch-required` to the options taken with no change, and
  item 4 adds `touch-required` and `verify-required` to those refused by name (Decision). sshd(8)
  also documents them, and a line that has one must not be refused as unknown nor used without it.
- The Prove: the parser's tests, sshd(8)'s examples among them, are unit tests of the library
  (`server::options`, `crates/podssh-ssh/src/server/options_tests.rs`), as they test private parts;
  crates/podssh-ssh/tests/serve_options.rs is russh's client against the effects. "In the gate,
  OpenSSH" is the CLI crate's test crates/podssh-cli/tests/serve_options_openssh.rs, as T-107 to T-112
  made theirs, run where the host has OpenSSH's client. Two plants: a forced command ignored (the
  property that a wrapper of `command=` relies on) and a `restrict` that leaves the pty on (the
  Prove's own).

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t114` (no build, no test run): the parser of the
options in crates/podssh-ssh/src/server/options.rs (OpenSSH's `sshauthopt_parse`, its quoting and its
order; each unknown or unhonoured option refuses the line, named) with its unit tests in
crates/podssh-ssh/src/server/options_tests.rs; the rules in crates/podssh-ssh/src/server/rules.rs
(`expiry-time=`, `from=` with CIDR blocks and negation, `no-pty`, `no-port-forwarding`,
`permitopen=`, the plan of a forced command and of `internal-sftp`); `authorized.rs` keeps each line
with its rules, and the first line of a key that lets it in holds; the handler takes the rules at the
login and applies them at each pty, forward, exec, shell and sftp request, each refusal said on the
channel and on serve's stderr (`Settings::say`); `SSH_ORIGINAL_COMMAND` in `env.rs`; the client's
address of a TCP socket on stdin in `crates/podssh-cli/src/serve.rs`; the manual's note and the row of
`SSH_ORIGINAL_COMMAND` in ENVIRONMENT; `docs/cli.md` ("The options of a key line"); a row of
`docs/STATUS.md`; the tests of the Prove; the plants `t114-forced-command-ignored` and
`t114-restrict-keeps-pty`. Results:

Merged, built and run by the main session the same day:

- `cargo test -p podssh-ssh --lib server::`: 48 passed.
- `cargo test -p podssh-ssh --test serve_options --test serve_auth --test serve_exec --test serve_forward --test
  serve_pty --test serve_sftp`: 7, 11, 6, 8, 6 and 5 passed.
- `cargo test -p podssh-cli --test serve_options_openssh --test serve_openssh --test serve_forward_openssh --test
  serve_stdio --test serve_sftp_openssh` (OpenSSH 9.6's client): 5, 9, 5, 3 and 3 passed.
- `cargo test -p podssh-cli --lib serve`: 74 passed; the manual's (`--lib man` 99, `man_page` 11, `man_flag_parity`
  6, `man_json` 4, `flag_table` 9): passed.
- The plants `t114-forced-command-ignored` and `t114-restrict-keeps-pty`: caught; `t107-accept-each-key` (its hunk
  moved to `Served::admit`) and `t109-reason-dropped`: caught.
- Clippy and rustfmt: clean.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,827 passed, 0 failed.

Found, not repaired here: serve does not check the user-presence flag of a security key's signature, which sshd
checks by default (Decision): T-774. Since T-774's draft, `touch-required` and `verify-required` no longer refuse
their line: serve checks the flags at login, as sshd does (T-774's Decision).

Left after the merge: `cargo todo remap` on each cited file that the draft changed
(`crates/podssh-ssh/src/server/authorized.rs`, `crates/podssh-ssh/src/server/handler.rs`,
`crates/podssh-ssh/src/server/mod.rs`, `crates/podssh-ssh/src/server/env.rs`,
`crates/podssh-ssh/src/server/direct.rs`, `crates/podssh-cli/src/serve.rs`, `docs/cli.md`,
`docs/STATUS.md`) and `cargo todo counts` (the status moved by hand in the entry and the index); the
run in the build image (T-251).

# T-115: `podssh serve`: a TOTP second factor

**Source:** GitHub #18 (VLOD-ZDOV/quic-ssh `src/totp.rs`: TOTP with no PAM).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A key file that leaks gives full access to a node. Some operators want a
second factor, as sshd with PAM gives, but a cage has no PAM. A time-based
one-time code (TOTP) needs only a shared secret and a clock.

## Premise

- Read: russh supports a second method after the first: a key accepted with
  partial success, then `auth_keyboard_interactive`
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 175-208 and 309-318).
- Read: podssh's client answers keyboard-interactive after a partial success
  (`crates/podssh-ssh/src/auth.rs:146-157`,
  `crates/podssh-ssh/src/auth.rs:242-326`), through the terminal or
  `SSH_ASKPASS`.
- Read: HMAC and SHA-1 are dependencies already
  (`crates/podssh-ssh/Cargo.toml:22-23`).
- Read in the report of GitHub #18, not verified here: quic-ssh has TOTP in
  `VLOD-ZDOV/quic-ssh:src/totp.rs`.

## Approach

1. `--totp FILE`: the secret (base32) in a file of mode 0600. serve refuses
   to start when others can read the file. Never print the secret.
2. `--totp-new FILE` writes a new secret (`create_new`, mode 0600) and prints
   only the path; the user loads the file into an authenticator. Invariant:
   no secret in output, logs or argv.
3. Authentication: a good key gives partial success with
   `keyboard-interactive` next; one prompt "One-time code: " with no echo;
   RFC 6238 (HMAC-SHA-1, 30 s, 6 digits), one step of clock skew each way.
4. Refuse a code that was used in its step (a replay). Count the failures of
   each key, and wait longer after each one.
5. Same commit: the flags in `crates/podssh-cli/src/flags.rs`, the manual,
   `docs/cli.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_totp
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_totp.rs checks the SHA-1 vectors
of RFC 6238 appendix B, the skew window and the replay refusal. In the gate,
OpenSSH's client gets the code from `SSH_ASKPASS` that runs
`oathtool --totp -b` (an Alpine package), so the code does not come from
podssh: the login works, a second use of the same code is refused, and a
wrong code is refused. A planted check that ignores the step fails the
replay test.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-116: `podssh serve`: an audit log

**Source:** GitHub #25 (ImKKingshuk/USBoverSSH `usboverssh/src/audit.rs`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

The owner of a node cannot see who logged in, with which key, and what each
session did. sshd writes this to the system log, but a cage often has no
syslog and no `/var`. A record must not leak secrets or session data.

## Premise

- Read: podssh's log goes to stderr or to a file
  (`crates/podssh-ssh/src/log.rs:46-62`), as lines with no structure.
- Read: `serde_json` is a workspace dependency (`Cargo.toml:123`), but not a
  dependency of `podssh-ssh` yet.
- Read in the report of GitHub #25, not verified here: USBoverSSH writes an
  audit log of connection events.

## Approach

1. `--audit-log FILE`: one JSON object for each line, appended, mode 0600;
   off by default. Fields: the time (UTC, RFC 3339), the event, the session
   number, the key fingerprint, the request (shell, exec, subsystem, forward
   target), the exit status or signal, the bytes each way, the duration.
2. Events: authentication accepted and refused (fingerprint, method), a
   session start and end, a forward opened or refused, serve's start and
   stop.
3. Invariants: never key material, tokens, environment values or session
   data. The command line of an exec is written only with `--audit-commands`,
   because a command line can hold a password.
4. A failed write (a full disk) is reported once on stderr, and never stops
   a session.
5. Same commit: the flags, the manual, `docs/cli.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_audit
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_audit.rs reads each line as JSON
and checks the fields of each event. In the gate, a session through
`podssh serve --stdio --audit-log FILE` runs `echo SECRET-MARKER`: the file
has the login and the exit status, and `grep -c SECRET-MARKER` on it prints 0.
With `--audit-commands` it prints 1. A planted log of each command line by
default fails the first count. A file that cannot be written does not stop
the session.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-117: `podssh serve`: a clean stop, and SIGHUP reads the settings again

**Source:** GitHub #20 and GitHub #19 (gold-silver-copper/fux: a clean server
lifecycle); GitHub #22 (Petyok/SSHub: hot reload).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

A node that stops must not leave shells behind, and must not cut sessions
with no word. An operator who adds a key must not have to restart the node:
a restart ends each session on it (`docs/design.md:698-701`).

## Premise

- Read: the client ends its session properly on SIGTERM and SIGHUP
  (`crates/podssh-ssh/src/terminal/termination.rs:26-93`). The server has no such handling.
- Read: russh can end a connection with a reason: `Handle::disconnect`
  (`Eugeny/russh:russh/src/server/session.rs`, line 457 at `22c3b88`).
- Read: in `--stdio` mode one process serves one connection. The node mode
  (`podssh serve NAME`, after T-079) serves many, so a reload matters there.

## Approach

1. SIGTERM and SIGINT: take no new session (the node leaves the relay
   cleanly, T-079). Send each connection a disconnect with the reason
   "podssh serve is stopping", and SIGHUP to each child's process group.
   Wait 5 s at most, then SIGKILL. Exit 0.
2. SIGHUP: read the authorized keys and the settings files again. New
   connections use the new set; open sessions continue. A file that does not
   parse keeps the old set and logs one line. Invariant: a reload never gives
   access that the new files do not give, and never drops a session.
3. A second SIGTERM during the stop sends SIGKILL at once.
4. Same commit: the exit codes and messages in the serve section of the
   manual, `docs/cli.md`.

## Decision

2026-11-13, made with the draft (see Correction for what the Approach reads as in `--stdio`):

- **A channel that closes while its child runs hangs the child up** (SIGHUP, then SIGCONT), as a
  stop does, with no kill after it. OpenSSH's sshd leaves a child on pipes running when its client
  goes; a cage has nobody to clean up after a client that is gone, and T-118's Approach item 3 asks
  for the hangup on the client's end. `nohup` still keeps a job that asks for it. Lost: sshd's way,
  which leaves `sleep 100` behind each killed `ssh`; a kill after a grace, which would kill a
  `nohup` job too.
- **A reload reads each line as the start does** (T-114's `Authorized`, rules per line): a line that is
  not used, no key or options that serve cannot all honour, is passed over and said, and each other
  line keeps its rules. A file that is gone or cannot be read, or a set with no key, keeps the set
  before, with one line: a reload must not lock each new login out. A session that logged in keeps
  the rules it logged in with: its handler holds them from its login. The invariant "a reload never
  gives access that the new files do not give" holds for each line that is read: the set in use is
  that of one reading of the files. Lost: refusing the whole reload at a bad line (the draft before
  T-114 did so), which would drop the rules of each good line of the file with the bad one, and differ
  from the start's reading; an empty set, which locks each new login out.
- **The disconnect waits 1 s at most, on a task of its own.** russh takes a `Handle` message only
  while no channel holds data past its window (Premise of T-118), so a client that reads nothing
  would hold the reason back; the stop does not wait on it, and the hangup goes at once.
- **SIGINT is SIGTERM**, as the Approach has it, and a second of either kills at once.
- **The stop sits beside T-114's rules.** Once stopping, the handler's `rules()` gives the refusal
  `podssh serve is stopping` in the place of a key's rules, so each request that T-114 checks (exec,
  shell, subsystem, pty, direct-tcpip) is refused with that reason; a new session channel is refused
  at its open.
- **The keys are one set shared by each connection** (`podssh_ssh::server::Keys`), and the stop one
  `Control` shared by each connection, so that the node form and T-124's listener take both as
  they are.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_lifecycle
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib server::stop
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib serve_keys
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib serve
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_lifecycle_openssh --test serve_openssh --test serve_stdio --test serve_options_openssh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_exec --test serve_pty --test serve_auth --test serve_forward --test serve_sftp --test serve_options
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test man_page --test man_flag_parity --test man_json
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
sh scripts/plant-each.sh --here t117-stop-without-hangup
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_lifecycle.rs serves several streams
in memory from one server: a reload adds a key for a new stream and
keeps the first session, and a set with no key replaces nothing; a stop sends the
reason, hangs up two children before the grace and ends serve with `Ok`; a child that
ignores SIGHUP is killed after the grace, and at once on a second stop; a closed channel
hangs up its child. The unit tests of crates/podssh-cli/src/serve_keys.rs read the files: a new key
taken, a removed one dropped, a line that is not used passed over and said, a missing file keeping the set before with one line,
a key of the command line kept. Against OpenSSH's client
(crates/podssh-cli/tests/serve_lifecycle_openssh.rs, where the host has one), `sleep 100` runs through
`podssh serve --stdio`; a SIGHUP keeps it; a SIGTERM to serve ends the client within 5 s with the
reason, serve exits 0, and the child is gone. The plant `t117-stop-without-hangup` (no SIGHUP to a
group, at the stop or at a close) fails the in-memory test of the stop, as the child then lives
until the kill after the grace.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The draft rebased onto `a5b4204` (T-114 on main): `Keys` holds T-114's `Authorized`
and answers `admit`; the reload reads as the start does (Decision); the pty's glue of the handler moved
to crates/podssh-ssh/src/server/pty_grant.rs, so that `handler.rs` stays under 500 lines with the stop.

2026-11-13. The Premise, read again at `97d6fac`:

- The client's handling holds: `crates/podssh-ssh/src/terminal/termination.rs:26-93` ends a
  session on SIGTERM and SIGHUP. The server had none: a SIGTERM killed `podssh serve` by its default,
  and each child on pipes ran on (`sleep 100` after its client was gone).
- russh is 0.65.0 from `vendor/russh` (T-107's Correction); `Handle::disconnect` is in
  `vendor/russh/src/server/session.rs`, and it goes through the session's bounded queue, which the
  session reads only while no channel holds data past its window (the Premise of T-118): the stop
  sends it on a task of its own with 1 s (Decision).
- "The node mode (`podssh serve NAME`, after T-079) serves many": that form is not built (T-107's
  Done, left), and `podssh serve` serves one connection on stdin and stdout; a listener is T-124's.
  So in `--stdio` the Approach reads: item 1's "take no new session" refuses a session channel and a
  forward opened after the stop, and there is no relay to leave; item 2's reload is seen by a login
  that comes after it (a connection that has not logged in yet), and the server core keeps one set of
  keys and one stop for each of its connections (`Keys`, `Control`), so the node form and T-124 take
  them; the test of two streams from one server runs in memory, as the Prove has it.
- Item 2's "the settings files": serve reads no settings file; its settings are its command line.
  A reload reads the authorized keys files, each `--authorized-keys`, or `~/.ssh/authorized_keys`
  when no flag names a key; `--authorized-key` is the command line's and stays.
- The Prove's `pgrep -f 'sleep 100'` would find any other `sleep 100` of the host: the test has the
  command write its own pid first, and reads `/proc` for it (a zombie counts as gone); "in the gate"
  is the CLI crate's test crates/podssh-cli/tests/serve_lifecycle_openssh.rs, as T-107 to T-112 made theirs,
  run where the host has OpenSSH's client.

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t117` (no build, no test run): the stop and the
shared keys in crates/podssh-ssh/src/server/stop.rs (`Keys`, `Control`, `Stage`, the groups of the
children, `wind_down`: the disconnect, the hangup, the grace of 5 s, the kill); `serve_under` in
`crates/podssh-ssh/src/server/mod.rs` (`serve_with` calls it); the handler reads the keys at each
attempt and takes no session or forward once stopping; each channel's group in the stop's list
(`channel.rs`); a child whose channel closes is hung up and reaped (`child.rs`); the keys' sources,
the reload and the signals in crates/podssh-cli/src/serve_keys.rs, called by `serve.rs`; the manual's
notes (crates/podssh-cli/src/man/notes_serve.rs), `docs/cli.md` ("The stop, and SIGHUP"), a row of
`docs/STATUS.md`, the tests of the Prove, `openssh_proxy` and `serve_command` in
crates/podssh-cli/tests/serve_kit/mod.rs, and the plant `t117-stop-without-hangup`. Results:

Merged, built and run by the main session the same day (its rebase on T-114 by the drafting agent), with two
repairs:

- `cargo test -p podssh-ssh --test serve_lifecycle --test serve_options --test serve_auth --test serve_exec --test
  serve_pty --test serve_sftp --test serve_forward`: 5, 7, 11, 6, 8, 6 and 5 passed.
- `cargo test -p podssh-cli --lib serve` (`serve_keys` among them): 77 passed.
- The manual: the SIGHUP paragraph of `notes_serve.rs` had lost its closing quote in the rebase, so the crate did
  not build; restored. `--lib man` 100, `man_page` 11, `man_flag_parity` 6, `man_json` 4, `flag_table` 9: passed.
- `cargo test -p podssh-cli --test serve_lifecycle_openssh` (OpenSSH 9.6): passed twice, after two repairs of its
  ProxyCommand wrapper. A command of `&` in sh gets /dev/null as its stdin before its own redirections (POSIX, no
  job control), so `serve <&0 &` read /dev/null and the session ended at once ("the SSH connection failed:
  Disconnected"); the client's pipe now goes by descriptor 3. And OpenSSH sends its ProxyCommand SIGHUP as it
  ends, which killed the wrapper's shell before it wrote serve's status; the shell now ignores SIGHUP once serve
  runs. `serve_options_openssh`, `serve_openssh`, `serve_stdio`, `serve_sftp_openssh`, `serve_forward_openssh`: 5,
  9, 3, 3 and 5 passed.
- Seen at the merge: where serve is itself the ProxyCommand, OpenSSH's SIGHUP at the end of the session reaches
  serve, which reads its keys again and says so on stderr as the connection ends; harmless, as nothing follows.
- The plant `t117-stop-without-hangup`: caught; `t114-forced-command-ignored` and `t107-accept-each-key`: caught.
- Clippy: clean; rustfmt reflowed `pty_grant.rs`.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,839 passed, 0 failed.

Left after the merge: `cargo todo remap` on each cited file that the draft changed
(`crates/podssh-ssh/src/server/handler.rs`, `crates/podssh-ssh/src/server/mod.rs`,
`crates/podssh-ssh/src/server/channel.rs`, `crates/podssh-ssh/src/server/child.rs`,
`crates/podssh-cli/src/man/notes_serve.rs`,
`crates/podssh-cli/src/serve.rs`, `docs/cli.md`, `docs/STATUS.md`) and `cargo todo counts` (the status
moved by hand in the entry and the index); the run in the build image (T-251).

# T-118: `podssh serve`: a slow client cannot stall a pty or fill the memory

**Source:** GitHub #20 (gold-silver-copper/fux `tests/pressure.rs`: bound the
queue; detach on a failed write).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

A program in the cage can write faster than the relay and the client read
(`yes`, a large `cat`). If serve reads the pty or the pipe faster than it
sends, its memory grows until the cage stops it. A client that stops reading
must slow the child down, and a client that is gone must end the session.

## Premise

- Read: russh keeps data past the peer's window in a list for each channel
  (`Eugeny/russh:russh/src/session.rs`, lines 591-612). While any channel has
  such data, the session loop takes no message from `Handle`
  (`Eugeny/russh:russh/src/server/session.rs`, lines 676-700 and 791): one
  slow channel then stops the other channels of that connection.
- Read: a channel's writer waits for that channel's own window
  (`Eugeny/russh:russh/src/channels/io/tx.rs`, lines 82-105).
- Read: russh opens the window again when half of it has arrived, whether or
  not the program read it (`Eugeny/russh:russh/src/session.rs`, lines
  305-330). A child that does not read its stdin is held only by the channel
  buffer of 100 messages (T-108).
- Read: the comment on the SSH window said that the relay drops a frame
  past 1 MiB with 1011 (`crates/podssh-ssh/src/run.rs` lines 25-29 at
  `80f20bf`); `docs/relay.md:570-582` says that it closes with 1013 at
  2 MiB. T-024 corrected the comment; T-062 measures whether the relay's
  check operates.

## Approach

1. Output (the pty, stdout, stderr): write only through each channel's
   writer (`make_writer`, `make_writer_ext(Some(1))`); never `Session::data`
   in a loop. Read the child again only after the last chunk was written.
   Invariant: for each channel, serve holds one read buffer (32 KiB) past
   the window.
2. A stalled client then stops the reads, the pty or pipe buffer fills, and
   the kernel blocks the child's write. That is the flow control.
3. A failed write (the client is gone) ends the channel: close the master or
   the pipes, and send SIGHUP to the child's group.
4. Input: copy each channel into the child on its own task, with a stated
   cap. Measure whether a child that never reads stalls the other channels
   of its connection; if it does, write an entry for it with the russh lines,
   and close only that channel past the cap.
5. State the bounds in the serve notes and in `docs/STATUS.md`.

## Decision

2026-11-13, made with the draft. Approach item 4's measure is answered by reading (Correction): a
child that never reads stalls each channel of its connection. In the place of an entry and a close
of that channel past a cap, **a patch of russh opens a channel's window as its reader takes the
bytes** (`vendor/patches/russh/0009-server-window-on-read.patch`): `server::Handler::window_on_read`
tells russh to count a channel's data and adjust nothing, and `Handle::grant_window` opens the window
by the bytes that serve wrote to the child, the pty, the SFTP server or the target, or dropped. serve
answers true for each channel that it takes (sessions and forwards).

- Lost: closing the channel past a cap. A child that reads slowly but reads (`cat > file` on a slow
  disk, a shell busy while the user pastes, an SFTP upload to a slow mount) would lose its channel and
  its data, and the connection would still wait while the cap fills. SSH's window is the protocol's
  own flow control for this case; sshd adjusts its window as its child takes the bytes.
- Lost: an entry left for russh with no change here. The repository patches russh where podssh needs
  it (vendor/README.md), and this patch is small: two methods of the session's `Encrypted`, one of the
  handler, one of the `Handle`, one message.
- The grant goes on russh's queue of the session's own replies (`priority_sender`), not its bounded
  queue of data, which russh does not read while a channel's output waits for the client's window: so
  a client that stalls one channel's output never holds another channel's window.
- The window stays podssh's own (512 KiB, `crate::run::WINDOW`): the bytes that wait in serve for one
  channel are at most that, and an upload to one child runs at most one window each round trip. sshd's
  2 MiB would give more speed on a long path for four times the memory of each channel; measuring the
  rate is left to the merge (the 5,000,000 bytes of `serve_openssh.rs`, timed before and after).
- A failed write of output (Approach item 3) ends its pump; the hangup of the child's group is the one
  that T-117 sends when the channel closes or the connection ends (T-117's Decision), so a killed
  client ends `yes` by SIGHUP as well as by its broken pipe.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_pressure
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_pressure_openssh --test serve_lifecycle_openssh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_exec --test serve_pty --test serve_sftp --test serve_forward --test serve_auth --test serve_lifecycle
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_openssh --test serve_sftp_openssh --test serve_forward_openssh --test serve_stdio
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test man_page --test man_flag_parity --test man_json
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib man
sh scripts/plant-each.sh --here t118-window-on-arrival t118-read-ahead
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_pressure.rs runs `yes` on pipes and on a pty
with a client that reads nothing for 20 s: the resident memory of the test's process (`VmRSS`
in `/proc/self/status`, the client's buffers with serve's, from before the command starts, the client
holding 8 messages of a channel) grows by less than 8 MiB, the session then
continues, and a closed channel ends `yes` within 5 s. A child that reads none of the client's 32 MiB
holds no other channel: a command beside it on the same connection runs to its end within 10 s.
Against OpenSSH's client (crates/podssh-cli/tests/serve_pressure_openssh.rs, Linux, where the host has one),
`yes` runs through `podssh serve --stdio` with a reader that stops for 20 s: serve's own memory (its
`/proc/PID/status`) grows by less than 8 MiB, the output goes on, and a killed client ends `yes` and
serve within 5 s. The plant `t118-window-on-arrival` (russh's own window, opened on arrival) fails the
test of the channel beside; the plant `t118-read-ahead` (a buffer of 1 GiB between a child's stdout and
its channel) fails the memory bound. The tests of T-107 to T-112 and T-117 run again over the new
window, and the 5,000,000 bytes each way of `serve_openssh.rs` with it.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The draft rebased onto `a5b4204` with T-117's (T-114 on main): the window on read holds
for each channel that a key's rules let open; a forward that the rules refuse never gets one.

2026-11-13. The Premise, read again at the draft's tree (russh 0.65.0 from `vendor/russh`, T-107's
Correction):

- Data past a peer's window still waits in each channel's `pending_data`
  (`vendor/russh/src/lib_inner.rs:510`), and the server's loop takes no message from a `Handle` while
  any channel holds some (`vendor/russh/src/server/session.rs:704` and `vendor/russh/src/server/session.rs:814`).
  But serve's output never puts data there: each output goes through a channel's writer, which waits
  for that channel's window (`vendor/russh/src/channels/io/tx.rs:82`, `poll_writable`), and T-108
  already wrote it so: `pump` (`crates/podssh-ssh/src/server/child.rs:230`) reads 32 KiB, and reads
  again only after `write_all` (`crates/podssh-ssh/src/server/child.rs:257`). Approach items 1 and 2
  were done by T-108 and T-110; this entry proves them. A `Handle::data` loop is held too: russh's
  loop stops taking from the `Handle` while data waits, so the Prove's planted `Session::data` loop
  would grow no memory and pass. The plant of the memory bound is a read-ahead instead: a buffer of
  1 GiB between the child's stdout and its channel (`t118-read-ahead`).
- The server opens a window on arrival (`vendor/russh/src/session.rs:305`, `adjust_window_size`, which
  its data path calls), and gives each data message to the kept `Channel` with a send that waits
  (`vendor/russh/src/server/encrypted.rs:1534`). So Approach item 4 is measured by reading: a child
  that reads nothing fills the pipe (64 KiB), serve's queue of its stdin (128 messages, T-108), and
  russh's queue of the channel (100), then russh's loop waits in that send, inside its handling of a
  packet, and serves no other channel of the connection. The Decision repairs it in russh rather than
  closing the channel.
- Approach item 3: a write of output that fails ends its pump, and the dropped pipe ends a writer
  with EPIPE; the pty's master closes with its channel. The hangup of the group is T-117's
  (its Decision): sent when the channel closes or the connection ends.
- The relay's comment (`crates/podssh-ssh/src/run.rs:26-30`) holds as T-024 corrected it; the window
  of serve's channels is that `WINDOW`.
- "In the gate" is the CLI crate's test crates/podssh-cli/tests/serve_pressure_openssh.rs, as T-107 to
  T-112 made theirs, run where the host has OpenSSH's client; it reads serve's memory in its own
  `/proc/PID/status` (serve runs in the background of a shell that writes its pid). The in-memory
  test reads the test's own process, so it counts the client's buffers with serve's: it gives the
  client 8 messages of a channel, and measures from before the command starts.

## Done

Partial: merged 2026-11-13 from the draft of the branch `draft-t117`: the patch of russh
`vendor/patches/russh/0009-server-window-on-read.patch`, applied to `vendor/russh`
(`server::Handler::window_on_read`, `Handle::grant_window`, `Msg::GrantWindow`, `Encrypted::take_window`
and `Encrypted::grant_window`) with its row in `vendor/README.md` and the count in `AGENTS.md`; the
handler's `window_on_read` (true); the grants of each channel's reader in
`crates/podssh-ssh/src/server/channel.rs` (`Window`, the feeder, the bytes dropped or never read)
and of each forward in `crates/podssh-ssh/src/server/direct.rs`; the manual's note
(crates/podssh-cli/src/man/notes_serve.rs), `docs/cli.md` ("A slow client, a slow child"), a row of
`docs/STATUS.md`, the tests of the Prove, the helpers of serve's pid and memory in
crates/podssh-cli/tests/serve_kit/mod.rs (T-117's test moved onto them), the plants
`t118-window-on-arrival` and `t118-read-ahead`, and the plant `t109-reason-dropped` with its context
moved to the forward's new lines. Results:

- `cargo test -p podssh-ssh --test serve_pressure`: 3 passed (47.3 s).
- `cargo test -p podssh-cli --test serve_pressure_openssh --test serve_lifecycle_openssh` against
  OpenSSH 9.6p1's client: 1 passed (20.2 s) and 1 passed.
- The tests of T-107 to T-112 and T-117 over the new window: `cargo test -p podssh-ssh --test
  serve_lifecycle --test serve_options --test serve_auth --test serve_exec --test serve_pty --test
  serve_sftp --test serve_forward`, each passed; against OpenSSH, `serve_openssh` 9, `serve_options_openssh`
  5, `serve_sftp_openssh` 3, `serve_forward_openssh` 5 and `serve_stdio` 3 passed.
- The rate of the 5,000,000 bytes of `serve_openssh.rs`, three runs each: 0.28 to 0.34 s with the
  window on read, 0.28 to 0.32 s with the window on arrival (the plant `t118-window-on-arrival` applied):
  no cost that this test sees.
- `cargo test -p podssh-ssh --lib`: 412 passed; `cargo test -p podssh-cli --lib -- serve man`: 173
  passed; `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,843 passed, none failed.
- The plants `t118-window-on-arrival` and `t118-read-ahead` caught (`sh scripts/plant-each.sh --here`),
  and `t117-stop-without-hangup` and `t114-forced-command-ignored` still caught after the merge.
- The build of `vendor/russh` with the patch; rustfmt clean; clippy as the gate runs it (`-D warnings
  -A clippy::collapsible_if`) clean on both crates after one needless `mut` of the test was dropped.

The citations of the changed files were moved by `cargo todo remap` at the merge. Left: the Prove's
`sh scripts/dev.sh check`, the run in the build image (T-251); CI's gate runs the same at each push.

2026-11-13, after the gate of `d4966a3` (Linux, `gate (ssh)`): `yes_on_a_pty_with_a_client_that_reads_nothing_holds_the_memory`
asked for 1 MiB within 2 s after the stall, and that runner's debug build gave 383,937 bytes: a rate, not the
property. The test now reads until 1 MiB, more than two windows, within 30 s, and says the time it took.
`cargo test -p podssh-ssh --test serve_pressure`: 3 passed.

# T-119: `podssh serve`: the MOTD and `~/.hushlogin`

**Source:** GitHub #19 (menhera-org/ssh-obi: the MOTD before the login shell,
and `~/.hushlogin`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

sshd shows the message of the day before an interactive login shell, and
skips it when `~/.hushlogin` exists. Users expect the same from a node: for
example, a notice that the host is a sandbox that expires.

## Premise

- Read: T-108 starts a login shell, and nothing prints before it.
- Read: a cage may have no `/etc/motd` and no `/var`
  (`docs/target-environment.md:16-29`); serve reads only what exists.
- Read: podssh already makes server text safe for a terminal:
  `crates/podssh-ssh/src/handler.rs:189-192` uses `podssh_ws::text::multi_line`.
- Read in the report of GitHub #19, not verified here: ssh-obi prints the
  MOTD before the login shell and honours `~/.hushlogin`.

## Approach

1. For a shell request with a pty (or the line discipline of T-111), print
   the file of `--motd FILE`, else `/etc/motd` when it can be read, before
   the shell starts. Never for exec or a subsystem.
2. Skip it when `$HOME/.hushlogin` exists (the home from `HOME`).
3. Limits: 64 KiB at most; control characters other than tab and newline
   are removed with `podssh_ws::text::multi_line`.
4. Same commit: the flag in `crates/podssh-cli/src/flags.rs`, the manual.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_motd
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_motd.rs checks the cap and the
removed control characters. In the gate, with a `--motd` file, an interactive
`ssh -tt` session shows it before the first prompt; an exec session does not;
with `$HOME/.hushlogin`, the shell does not. A planted serve that prints it
for exec fails the second check.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-120: `podssh serve`: shell integration marks, when asked

**Source:** GitHub #20 (l0ng-ai/tty7
`l0ng-ai/tty7:crates/tty7-core/src/daemon/shell_integration.rs`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Terminals use OSC 133 marks (prompt, command, output, exit status) and OSC 7
(the working directory) to jump between commands and to open a new tab in
the same directory. Over a node, the shell sends no marks unless its start
files add them, and many cage images have none.

## Premise

- Read: in the line discipline mode (T-111), serve prints the prompt and
  sees each submitted line (`PodUtils/podssh:crates/podssh-terminal/src/echo.rs:324-341`),
  so it knows where each mark goes.
- Read: with a real pty (T-110), only the shell knows; it needs hooks in its
  start files.
- Read in the report of GitHub #20, not verified here: tty7 adds shell
  integration when a pane starts.

## Approach

1. `--shell-integration`, off by default.
2. Line discipline mode: write `OSC 133;A` before the prompt, `B` after it,
   `C` when a line is submitted, and `D` when the next prompt comes. With no
   help from the shell, the exit status is not known: write `D` with none.
3. Real pty: start `bash` with `--rcfile` set to a temporary file that reads
   `~/.bashrc` and adds the hooks; start `zsh` with `ZDOTDIR` set to a
   temporary directory that reads the user's files. Other shells get no
   marks. Invariant: never write the user's own start files.
4. Remove the temporary files when the session ends.
5. Same commit: the flag, the manual, `docs/terminal.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_marks
sh scripts/dev.sh check
```

The test file crates/podssh-ssh/tests/serve_marks.rs checks the bytes of the
marks in the line discipline mode. In the gate, `ssh -tt` through
`podssh serve --stdio --shell-integration` to `bash` shows `ESC ] 133;A` and
`ESC ] 7;file://` in the output, and the SHA-256 of `~/.bashrc` is the same
before and after. Without the flag, no mark appears. A planted run that
appends to `~/.bashrc` fails the digest check.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. `podssh-terminal` left this tree: its code is `pod-term` of PodUtils/podcrates, taken by
the git tag `v0.1.0` (T-684; `crates/podssh-cli` depends on it). Each `podssh-terminal` of this
entry reads `pod-term`, and a path under `PodUtils/podssh:crates/podssh-terminal/` is
`PodUtils/podcrates:crates/pod-term/` now, with its own line numbers. The echo discipline,
`Event::Signal`, the passthrough and the ring of T-221 are there. Rule Q3 holds: a change of the
terminal code is done in PodUtils/podcrates (or asked as an issue there), and podssh takes it by the
next tag. The Premise's line of `echo.rs` that shows where a mark goes is `pod-term`'s
`src/echo.rs`.

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-121: Install `podssh serve` or `podssh node` as a service with no privileges

**Source:** GitHub #20 (l0ng-ai/tty7: a one-time install with no privileges);
GitHub #18 (adonm/zuko `zuko install`; rustonbsd/iroh-ssh: a Linux and
Windows service).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A node that must outlive a logout or a reboot needs a service. The usual ways
(`systemctl enable`, a Windows service) need root or an administrator. A user
with no privileges needs a way that the host allows, found by a probe.

## Premise

- Read: podssh never assumes a tool or a privilege; it starts a program only
  when a probe found it (`AGENTS.md:330-367`).
- Read: a credential never goes on argv or into output (`AGENTS.md:287-292`).
  The command line of a unit file is argv, so it must hold no token.
- Read in the reports of GitHub #20 and #18, not verified here: tty7, zuko
  and iroh-ssh install services, and iroh-ssh adds a firewall rule (which
  needs privileges).

## Approach

1. `--install` and `--uninstall` for `serve` and `node`; settle the names in
   `crates/podssh-cli/src/flags.rs`.
2. Probe in order: `systemctl --user` answers (then a user unit in
   `~/.config/systemd/user/`, and `systemctl --user enable --now`); a
   `crontab` program (an `@reboot` line); else print the command to run at
   login, and exit 69. Windows: `schtasks` with a task at logon, which needs
   no administrator; never a Windows service.
3. The unit or task runs the binary at its absolute path with the node name.
   The tokens stay in the 0600 state file of T-078. Invariant: no credential
   in the unit file, the crontab or the task's command line.
4. A user unit stops at logout unless lingering is on. Say so, and never run
   `loginctl` for the user.
5. `--uninstall` removes exactly what `--install` wrote, and nothing else.
6. Same commit: the manual, `docs/cli.md`.

## Decision

- `podssh serve` has no command yet (the operator holds it, Q32): the flags
  go on `node` now, in `crates/podssh-cli/src/node_install/`, and `serve`
  takes the same module when it comes.
- A service starts with none of the shell's variables, and a node behind a
  proxy reaches no relay without them: the node's go into `node-NAME.env`, a
  private file beside the pair, which `--env-file` reads before anything
  else. Lost: `Environment=` lines in the unit, a file that others read,
  with a proxy's password in it; systemd's `EnvironmentFile=`, systemd's
  alone, with its own quoting, and nothing for cron or a task; no
  variables, which leaves a node behind a proxy dead at each boot.
- No token of the environment is carried: `PODSSH_RELAY_TOKEN` and the
  secrets of Cloudflare Access (whose file, `PODSSH_CF_ACCESS_TOKEN_FILE`,
  is). The node's credentials are its pair's, in its own file. A proxy's
  password is carried, in the private file: a proxy that asks for one is
  not reached without it.
- podssh's own variables are carried by their prefix, but for the secrets
  and `PODSSH_OFFLINE`. Lost: a list of names, which a new variable would
  miss.
- systemd: `daemon-reload`, `enable`, then `restart`. Lost: `enable --now`,
  which leaves a running node on its old words when `--install` runs
  again. `RestartPreventExitStatus=64 77 78`: no restart changes a refused
  flag, pair or setting.
- cron: the `@reboot` line runs at the next boot, and the node is not
  started now: podssh leaves no process of its own behind. The table goes
  to `crontab` through a private file of the cache, as it holds the user's
  other lines.
- Windows: a task made from XML (UTF-16), with a logon trigger and a
  principal that name `USERDOMAIN\USERNAME`, `InteractiveToken` and
  `LeastPrivilege`: a user with no privilege may make a task at logon for
  itself alone. Lost: `schtasks /SC ONLOGON`, which reports say a user with
  no privilege is refused; the Startup folder, a console window at each
  logon; a Windows service, which needs an administrator.
- `--uninstall` removes the files that `--install` wrote, not the
  directories that it made.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_install
```

The test file crates/podssh-cli/tests/serve_install.rs writes the unit, the
crontab line and the task XML into a temporary home with fake probe answers.
Each holds the absolute path and the name, and none holds the token that the
test puts in the environment. `--uninstall` leaves the home as it was. A
planted unit with the token on its command line fails. A run on a host with
systemd is recorded in `docs/STATUS.md`.

## Done

2026-10-30. `podssh node NAME TARGET --install` makes the node a service of
its user by the first way that a probe finds, and `--uninstall` removes what
it wrote (`crates/podssh-cli/src/node_install/`); `--env-file FILE` reads the
node's variables from a private file before anything else. The unit, the
line and the task run the binary by its absolute path with the node's
TARGET and flags and `--env-file`, and hold no token. `podssh serve` takes
the same module when it comes (Decision).

- Linux, 2026-10-30: `cargo test -p podssh-cli --test serve_install`, 5
  passed (fake `systemctl` and `crontab` on PATH, made of shell builtins:
  the unit and the line hold the binary's absolute path, NAME and
  `--env-file`, and no token of the pair or of the environment; the private
  `node-NAME.env` holds the proxy with its password and no token; the
  user's other lines of the crontab stay, and a second `--install` leaves
  one line; with neither program, the command to run at login and 69; the
  refusals; `--env-file` read first, a file that others can read and a
  token in it refused); `--lib node_install::`, 5 (each quoting, the unit,
  the crontab's lines, the task's XML, the variables); the lib 362, `node`
  11, `node_plain` 3, `node_routes` 2, `flag_table` 8, `man_page` 10;
  clippy and rustfmt clean.
- Planted: a token in the unit; the test failed at its check of tokens;
  restored, it passed.
- A host with systemd, 2026-10-30: the workflow `service live` (run
  41066805844, a GitHub runner, ubuntu-24.04) made a pair on the live relay,
  and `--install` gave "a user unit of systemd, ...podssh-node-svc-....service,
  enabled and started" and "lingering is on for runner"; no token of the
  pair was in the unit or its file of variables; systemd had the unit
  active, the node's journal said "online: the relay takes this pair's
  sessions", and `relay status` "online, 0 sessions"; `--uninstall` said
  "removed the user unit ... (stopped and disabled)" and "removed the file
  of its variables", and nothing was left.
- Not measured: the task of Windows (its XML is tested on each system, and
  `schtasks` runs in no test), and a crontab of a real cron at boot.
- 2026-10-30, later: the release build for Windows on ARM (T-218, run
  41074530703) warned that six items of `node_install/text.rs` are never
  used there: the unit's mark and writer, and the crontab's, which only Unix
  reaches. Each now allows dead code on Windows, as the task's XML does on
  Unix. Linux: clippy with `-D warnings`, `--lib node_install` 5 passed; the
  next Windows builds of CI show the warnings gone.

# T-122: `podssh serve`: each pty child in its own transient scope when systemd is there

**Source:** GitHub #20 and GitHub #19 (menhera-org/ssh-obi `src/systemd.rs`:
no systemd assumption).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

On a host with systemd, the children of a service live in the service's
cgroup. A stop of the `podssh serve` unit (T-121) then stops each user's shell
too, and their memory counts against serve. sshd moves each session to its
own scope; serve does nothing like it.

## Premise

- Read: podssh must not assume systemd, and starts a program only when a probe
  found it (`AGENTS.md:330-367`, `docs/target-environment.md:116-118`).
- Read: T-110 and T-111 start each child with `setsid`, in serve's cgroup.
- Read in the report of GitHub #19, not verified here: ssh-obi moves its pty
  children into a transient scope when systemd is there, and works without
  it.

## Approach

1. Probe once at the start of serve: `systemd-run` on `PATH`, and
   `systemctl --user is-system-running` answers within 2 s.
2. When both pass, start each pty child through
   `systemd-run --user --scope --unit=podssh-serve-<session> -- SHELL ...`.
   The scope keeps the child's process tree; `setsid` and the controlling
   tty work as before.
3. When the probe fails, start the child directly, as now, with one log line
   at the start. Invariant: no session fails because systemd is absent or
   slow.
4. A failure of `systemd-run` for one session falls back to a direct start,
   with one log line.
5. Same commit: the serve notes, `docs/STATUS.md`.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_scope
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test file crates/podssh-ssh/tests/serve_scope.rs checks the command line
that is built, and the fallback when the probe fails. The box has no systemd,
so its serve steps show that sessions work and the log names the fallback. On
a host with systemd, `systemctl --user list-units 'podssh-serve-*'` lists the
scope of an open session; that run is recorded in `docs/STATUS.md`.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-123: `podssh serve` accepts `tcpip-forward` from a standard `ssh -R`

**Source:** GitHub #18 (EpicEric/sandhole: reverse proxying through a stock
`ssh -R`, with no other software on the client).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

A user who runs `ssh -R 8080:localhost:3000 node` expects a port of the node
to reach the user's local service. In a cage, `podssh serve` cannot do it in
the usual way: the server must listen, and the cage refuses `bind`. Today the
default of russh refuses each `tcpip-forward` with no reason.

## Premise

- Read: the default `tcpip_forward` of russh answers false
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 771-779).
- Read: the cage refuses `bind` (`docs/target-environment.md:25`; the box:
  `scripts/box/probe.sh:109-117`). The operator's ruling on Q1 (2026-10-08)
  allows a listener only when the user asks and a probe allows the bind.
- Read: `docs/design.md:1188-1190` allows a listener on the far side. The relay
  is a listener that podssh does not run: a node name takes operator
  sessions (`docs/relay.md:635-659`).
- Read in the report of GitHub #18, not verified here: sandhole publishes
  services through a stock `ssh -R`.

## Approach

1. No bind in the cage. Answer `tcpip-forward` with a new pair at the relay
   (T-078). Each operator session on that name opens a `forwarded-tcpip`
   channel to the client, toward the address and port of the request.
   Invariant: serve binds no socket for `-R`.
2. Answer success, with a port number for a request of port 0. Give the relay
   name in serve's log, and on stderr of the client's session when one is
   open. Measure what OpenSSH shows of an `SSH_MSG_DEBUG` with
   `always_display` set.
3. `cancel-tcpip-forward` stops the pair (`POST /v1/stop`, T-078). The tokens
   of the pair never go to output.
4. A real listener on the node only when serve's user turns it on and the
   bind probe of T-124 passes (loopback by default); else the pair of step 1.
5. Limits: a stated number of forwards for each connection; each forward
   ends with its connection.
6. Same commit: `docs/cli.md`, the serve notes.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_remote_forward
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_remote_forward -- --ignored
```

The first runs the mapping from a request to a pair and a channel, against a
stand-in relay in memory. The second uses the live relay: OpenSSH's
`ssh -R 0:127.0.0.1:2201` through `podssh serve --stdio`, then
`podssh operator NAME` reads the banner of the client's port 2201. A planted
serve that binds a socket fails a check that counts the open sockets of serve.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-124: `podssh serve --listen`: SSH on a TCP port on a host that allows it

**Source:** GitHub #18 (EpicEric/sandhole `src/config.rs`, lines 197-210:
`connect_ssh_on_https_port`; VLOD-ZDOV/quic-ssh: TLS over TCP on one port);
the operator's ruling on Q1 (2026-10-08).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** open

## Problem

Outside a cage, an operator may want `podssh serve` as a plain SSH server: on
a VM with no sshd, or on a network that lets only port 443 in. Without
`--listen`, serve reaches clients only through `--stdio` and the relay.

## Premise

- Read: the operator ruled on Q1 (2026-10-08): a local listener is allowed
  when the user asks for it and a probe at run time allows the bind. The
  default is loopback and AF_UNIX; the user can set the address and can turn
  listening off. The rules still say that podssh never listens
  (`AGENTS.md:332-360`, `docs/architecture.md:284-301`).
- Read: russh has the listener: `Server::run_on_socket` and `run_on_address`
  (`Eugeny/russh:russh/src/server/mod.rs`, lines 900-1010 at `22c3b88`). doctor binds a
  TCP and an AF_UNIX socket to test the host, listens once on each, and closes them at once
  (`crates/podssh-cli/src/doctor/unix.rs:124-247`).
- Read in the report of GitHub #18, not verified here: sandhole can take SSH
  on its HTTPS port, and quic-ssh falls back to TLS over TCP on one port.

## Approach

1. The probe first. Before each bind, run doctor's bind probe for that exact
   address. When it fails, exit 69 with one line that names the address, the
   errno and the remedy, for example "cannot listen on 127.0.0.1:2222: bind
   refused (Permission denied); use --stdio or podssh serve NAME". Invariant:
   no listener without the flag and a probe that passed.
2. `--listen ADDR`, which can be given more than once: `PORT` alone is
   loopback, `unix:PATH` is AF_UNIX, and another address only when the user
   writes it. Listening is off unless asked; `--no-listen` turns off a
   listener that a settings file asks for (T-048).
3. Each accepted connection goes to the entry point of `--stdio` (T-107).
   `from=` of T-114 now has a client address to match.
4. Limits: a cap on connections at once and on connections that have not
   authenticated, and russh's constant rejection time.
5. Later step: SSH and TLS on one port. Read the first bytes: `SSH-2.0-` goes
   to SSH; a TLS ClientHello (0x16) is refused.
6. Same commit: the flags, the manual, `docs/cli.md`, and the rules in
   `AGENTS.md:332-360` and `docs/architecture.md:284-301`, which then name this
   exception and the ruling.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_listen
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test file crates/podssh-ssh/tests/serve_listen.rs binds loopback port 0
and an AF_UNIX path, and checks the connection caps. In the gate, OpenSSH's
`ssh -p PORT` logs in to `podssh serve --listen PORT`. In the box, where the
seccomp filter refuses `bind`, a new step shows that serve exits 69 with the
line that names the address and the errno. A planted serve that binds before
the probe, or with no `--listen`, fails a check of its open sockets.

## Start condition

T-107 to T-112 are done: `podssh serve` exists, with its authorized keys and its answer to each
request. The operator holds them (Q32, `docs/decisions.md`), so this entry waits as they wait.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

# T-222: `podssh serve` finds a shell with no passwd entry and no `/etc/shells`, and names each candidate that failed (GitHub #32)

**Source:** GitHub #32 (2026-10-08); each claim read again here on the tree
of 2026-10-08 (code at `3ee70dc`).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

`podssh serve` runs with no passwd entry and no `/etc/shells`
(`docs/ROADMAP.md:184-189`), so no user database names a shell. A shell that
does not exist lets the login succeed, then ends the session at once, with
no reason (`docs/target-environment.md:88-89`).

## Premise

- Read: no source in `crates/` reads `SHELL` or selects a shell; `serve` is
  not a verb (`crates/podssh-cli/src/flags.rs:378-452`). The line numbers in
  the report are older; the content is at the lines given here.
- Read: the report says that `docs/cli.md` records why podssh does not call
  `getpwuid`. It does not; that record is `docs/target-environment.md:37-44`.
- Read: a sandbox mounts `/tmp` and `$HOME` noexec (`docs/STATUS.md:522`):
  the mode bits pass there, the exec fails, and `access(X_OK)` fails. doctor
  runs a real copy, as "only a real attempt tells them apart"
  (`crates/podssh-cli/src/doctor/host.rs:238-240`).
- Read in the report, not verified here: `rssh-org/rssh:src-tauri/src/terminal/pty.rs`
  checks the exec bit; a directory `sh` and a data file `dash` pass `exists()`.

## Approach

1. A function in crates/podssh-ssh/src/server/shell.rs gives the shell, or
   each failure. Order: the named shell (`--shell PATH`, or a later field of
   the pairing record of T-078), `SHELL`, then `/bin/sh`, `/usr/bin/sh`,
   `/bin/bash`, `/usr/bin/bash`, `/bin/ash` and `/bin/dash`.
2. Each candidate: an absolute path, a regular file after its links, and
   `faccessat(X_OK, AT_EACCESS)`; `exists()` is not the test. Read access is
   not needed. A spawn that still fails (`ENOEXEC`, a missing loader) fails
   that candidate, and the next one is tried.
3. One line names each failure and why, for example
   `SHELL=/x: not executable (noexec mount); /bin/bash: no such file`.
4. Probe at each session start, with no cache: the answer can change in the
   same image (`docs/target-environment.md:116-118`). Probe at the start of
   serve too (see Decision).
5. doctor gets a `shell` line in its host checks
   (`crates/podssh-cli/src/doctor/host.rs:12-28`) from the same function.
6. T-108 runs the result. Never call `getpwuid`. Same commit: `--shell` in
   `crates/podssh-cli/src/flags.rs`, `SHELL` in
   `crates/podssh-cli/src/man/facts.rs:46-272`, `docs/cli.md`.

## Decision

Recommendation: a shell that the operator names is strict: when it fails,
serve refuses (exit 78 at the start, failure for a session) and uses no
other. `SHELL` and the list fall back in order, and the line names each
failure, so no probe changes the behaviour in silence
(`docs/target-environment.md:116-118`). At the start, no usable shell is exit
78, unless `--no-shell` says that the node serves only SFTP and forwards.
Starting with a warning lost: that is the login that ends at once.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test serve_shell
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --lib -- server::shell
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --lib serve_shell
CARGO_BUILD_JOBS=4 cargo test -p podssh-cli --test serve_openssh -- shell
sh scripts/plant-each.sh --here t222-exists-test
sh scripts/dev.sh check
"$BIN" serve --stdio --authorized-keys ak --shell /nonexistent </dev/null 2>err; test $? -eq 78
grep -q '/nonexistent: no such file' err
```

crates/podssh-ssh/tests/serve_shell.rs gives the function a directory `sh`,
a data file `dash` (mode 0644), a data file with mode 0755 (the spawn or its
run fails), a link to a missing file and a good shell: each failure is
named, and the good shell wins. A planted `exists()` test fails the
directory case (`t222-exists-test`). A copy of `/bin/sh` in `/dev/shm`
(noexec: `docs/STATUS.md:469`) is refused as `--shell`, in serve_shell.rs
and through the binary in crates/podssh-cli/tests/serve_openssh.rs, each
"did not run" where `/dev/shm` is not noexec. The binary refuses a missing
named shell with 78, and OpenSSH's client meets the same line. The static
binary (`$BIN`) refuses a missing named shell.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-13. The Premise, read again at `4c98f8b`:

- "No source in `crates/` reads `SHELL`" no longer holds:
  `crates/podssh-cli/src/ssh/local_command.rs:20` reads it for `LocalCommand` on the client, with
  `/bin/sh` after it. That choice is the client's, and stays apart; the server's search is
  crates/podssh-ssh/src/server/shell.rs. `serve` is a verb since T-107, with its flags in
  `crates/podssh-cli/src/flags/serve.rs` (Approach item 6's `flags.rs` is that file).
- `docs/STATUS.md:521` is now the head of a table of two sandboxes and says nothing of noexec. The
  noexec mount that the record measured is `/dev/shm` (`docs/STATUS.md:469`, `docs/STATUS.md:489`),
  and a home that runs no program is podvm's `/state/home` (`docs/target-environment.md:37-44`).
  The Prove's `docs/STATUS.md:467` is `docs/STATUS.md:469`.
- doctor's "only a real attempt tells them apart" moved to `crates/podssh-cli/src/doctor/host.rs:224`.
- Approach item 2's spawn that fails: glibc's `execvp`, which Rust's `Command` calls with a
  `pre_exec`, hands a file that the kernel refuses with ENOEXEC to `/bin/sh` as a script, so the
  start of a data file of mode 0755 can succeed, and only its status tells. Each candidate is
  therefore run once, `CANDIDATE -c 'exit 0'`, with its standard files on pipes (a cage may have
  no `/dev/null`), within 5 s, and passes with status 0; then the session's own spawn runs it. The
  search runs on a blocking thread of the session's runtime, as it waits for the run.
- Approach item 1's later field of T-078's pairing record is not in this draft: `--shell` alone.
- The line at the start is said only when a candidate was passed over: a ProxyCommand's stderr is
  the client's terminal, and the host key's line is there at each start already. doctor's line
  `shell` is `ok` with no shell too, a fact as no pty is: serve then runs with `--no-shell` alone.

## Done

Not done. Drafted 2026-11-13 on the branch `draft-t108` (no build, no test run), with T-108: the
search in crates/podssh-ssh/src/server/shell.rs (the candidates, the checks with
`faccessat(X_OK, AT_EACCESS)` and `statvfs`'s noexec flag, the run of `-c 'exit 0'`, the line of the
failures), its call at each session's start in the handler, the check at serve's start in
crates/podssh-cli/src/serve_shell.rs (78), `--shell` and `--no-shell`, doctor's line `shell`
(`crates/podssh-cli/src/doctor/host.rs`), the manual (`SHELL` in ENVIRONMENT, the notes of serve, exit
code 78), `docs/cli.md`, the row of `docs/STATUS.md` with T-108, the tests of the Prove and the plant
`t222-exists-test`. Merged, built and run by the main session the same day:

- `cargo test -p podssh-ssh --test serve_shell`: 4 passed.
- `cargo test -p podssh-ssh --lib server::`: 8 passed; `cargo test -p podssh-cli --lib serve_shell`: 2 passed.
- `cargo test -p podssh-cli --test serve_openssh` (the missing shell, and `/dev/shm` where it is noexec): passed
  with the others (7).
- The plant `t222-exists-test`: caught (`each_failure_is_named_and_the_good_shell_wins` failed).
- The gate's job `ssh` (Alpine's build image, run of `33b22e5`) failed `each_failure_is_named_and_the_good_shell_wins`:
  its good shell was a link named `good` to `/bin/sh`, busybox there, which picks its applet by the name it runs as
  and ran nothing (127). The link is now named `sh`, in a directory of its own; the search was right to refuse it.
- `target/debug/podssh serve --stdio --authorized-keys ak --shell /nonexistent`: exit 78, "no shell runs here:
  --shell /nonexistent: no such file: --shell names the one shell, and no other is tried".

# T-248: A tty for `podssh serve` where `/dev/ptmx` is missing: a new devpts instance, or a tty in user space

**Source:** the operator's ruling of 2026-10-08 on T-113 (`docs/decisions.md`):
the exit criterion of M5 keeps `vi`, `less` and Ctrl-C, and two routes to a
tty are allowed after a probe; "the boxes don't have user namespaces, but
sure if it works". The study of rio-vt in the same session found that a VT
library cannot give a child a tty.
**Category:** research
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

In a cage with no `/dev/ptmx`, `podssh serve` can give a child only pipes.
For the child, `isatty()` is false, termios calls fail, no SIGWINCH comes, and
there is no job control. `vi`, `less` and `top` do not work, and the exit
criterion of M5 (T-113) needs them.

## Premise

- Read: `podssh doctor` asks for a pty with `posix_openpt`
  (`crates/podssh-cli/src/doctor/unix.rs:95-127`). Both real sandboxes have no
  `/dev/ptmx` (`docs/STATUS.md:522`), and the target has no `/dev/pts`
  (`docs/target-environment.md:26`).
- Read: the box and the sandboxes run with `NoNewPrivs=1` and a seccomp
  filter (`docs/STATUS.md:485`). With `NoNewPrivs=1`, a process can add a
  filter of its own; a filter is inherited by each child.
- Read, not measured here: for a program, a tty is the success of the tty
  `ioctl` calls on its descriptors. musl's `isatty` calls `TIOCGWINSZ`;
  glibc's calls `TCGETS`.
- Not measured: whether a sandbox allows `unshare(CLONE_NEWUSER)`, a devpts
  mount in that namespace, seccomp user notification, `process_vm_writev` to
  a child, or `ptrace` of a child. The operator: the boxes have no user
  namespaces.

## Approach

1. Probes, each one line in `podssh doctor` and a check at the start of
   `podssh serve`, each in a child process that exits at once:
   - route 1: `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, a private tmpfs, a
     devpts mount with `newinstance` on it, then `ptmx` from that mount;
   - route 2a: a filter that returns `SECCOMP_RET_USER_NOTIF` for `ioctl`
     only, its notification descriptor, and `process_vm_writev` into the
     child;
   - route 2b: `PTRACE_TRACEME` with a filter that returns
     `SECCOMP_RET_TRACE` for `ioctl` only.
2. Route 1: when its probe passes, the child runs in the new namespaces with
   a pty of the new instance. The rest is T-110.
3. Route 2: the child's descriptors 0, 1 and 2 are pipes. podssh answers the
   tty calls on them: `TCGETS`, `TCSETS`, `TCSETSW`, `TCSETSF`,
   `TIOCGWINSZ`, `TIOCSWINSZ`, `TIOCGPGRP`, `TIOCSPGRP`, `TIOCSCTTY`,
   `TIOCNOTTY`, `TIOCGSID`, `FIONREAD`, `TCFLSH`, `TCXONC` and `TIOCOUTQ`.
   Each other call goes on to the kernel. Invariant: podssh puts no code into
   the child, and it answers only for the descriptors that it gave.
4. The answered termios state drives the line discipline of
   `podssh-terminal`: canonical mode, echo, `ISIG`, `VMIN` and `VTIME`
   (T-111, after T-125 to T-129). A window change sends SIGWINCH to the
   foreground process group. Ctrl-C, Ctrl-Z and Ctrl-\ send SIGINT, SIGTSTP
   and SIGQUIT to that group.
5. Name what still fails: `ttyname()` (a pipe has no tty name), a program
   that opens `/dev/tty`, and a child that clears the filter (it cannot: a
   seccomp filter cannot be removed).
6. Measure each route in the box, with both profiles of T-245, and in both
   real sandboxes: `vi`, `less`, `top`, Ctrl-C, Ctrl-Z and a window change.
   Write the results in `docs/STATUS.md`, the order of the routes in
   `docs/decisions.md`, and the entries for the implementation.

## Decision

Recommendation: route 1 first where its probe passes, because it is a real
pty with no emulation. Route 2 where route 1 fails: user notification first
(only `ioctl` stops the child), `ptrace` as the fallback. `LD_PRELOAD` lost:
the decisions forbid it, and it does nothing to a static binary.

## Prove

```sh
podssh doctor                                      # one line for each route: ok, or the errno
cargo test -p pod-term                            # the line discipline, in PodUtils/podcrates (T-684)
cargo test -p podssh-cli --test serve_tty          # a child under route 2: test -t 0, stty size
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The test in the box runs `vi`, `less` and `top` through `podssh serve
--stdio` with no `/dev/ptmx`, and reads the screen of each. Planted defect:
answer `TCGETS` with an error; `test -t 0` in the child then fails, and the
test fails.

## Correction

2026-11-03. The blocker cleared: the operator released the hold (Q92, `docs/decisions.md`);
the entry joins the work order by its priority.

2026-11-05. `podssh-terminal` left this tree: its code is `pod-term` of PodUtils/podcrates, taken by
the git tag `v0.1.0` (T-684; `crates/podssh-cli` depends on it). Each `podssh-terminal` of this
entry reads `pod-term`, and a path under `PodUtils/podssh:crates/podssh-terminal/` is
`PodUtils/podcrates:crates/pod-term/` now, with its own line numbers. The echo discipline,
`Event::Signal`, the passthrough and the ring of T-221 are there. Rule Q3 holds: a change of the
terminal code is done in PodUtils/podcrates (or asked as an issue there), and podssh takes it by the
next tag. The Prove's `cargo test -p podssh-terminal` named a package that is gone; its line is
dropped, and the line discipline's own tests run in PodUtils/podcrates (`cargo test -p pod-term`).

2026-11-13 (T-110's draft). `podssh doctor`'s line `pty` is now `podssh serve`'s own probe,
`podssh_ssh::server::pty::open` (`crates/podssh-ssh/src/server/pty.rs:62-121`): it opens `/dev/ptmx`,
then `/dev/pts/ptmx`, by path, where it called `posix_openpt`; route 1's `ptmx` of a new devpts
instance can be one more path of that list, and serve grants a `pty-req` on whatever it opens.

2026-11-13 (T-248's draft; the measurements are [docs/research/serve-tty.md](../docs/research/serve-tty.md)).

- The citations of the Premise moved: the sandboxes' "no `/dev/ptmx`" is `docs/STATUS.md:521`, the
  box's `NoNewPrivs=1` and seccomp `docs/STATUS.md:484`, and the refusals of `unshare`, `mount` and
  `chroot` `docs/target-environment.md:19`.
- The third Premise holds, measured: a static glibc 2.39 `isatty` asks `TCGETS` and a static musl one
  `TIOCGWINSZ`.
- The fourth Premise is measured on this host in a cage that stands for the target (uid 65534, no
  capabilities, NoNewPrivs=1, no `/dev/ptmx` and no `/dev/pts`), not in a sandbox: route 1 needs
  neither a uid map nor `/proc`, but a process of one thread (EINVAL from serve's threads, so a forked
  helper); route 2a needs `seccomp` with a listener (EBUSY where the sandbox's filter has one),
  `kcmp` or `pidfd_getfd` or `/proc`, and `process_vm_writev` or `/proc/PID/mem`.
- The Correction of the same day above is wrong in one point: the `ptmx` of a new instance is not one
  more path of `PTMX`. The instance is mounted in a helper's namespace, which is gone when the child
  runs, and `ptsname` names `/dev/pts/N` of the host's instance (absent in the cage, another pty
  where it exists): the slave comes by `TIOCGPTPEER`, the pair from a forked helper by `SCM_RIGHTS`,
  and the slave has no path (no `SSH_TTY`).
- Approach item 3: the child's descriptors 0 to 2 are one `AF_UNIX` stream socket, not pipes (a
  slave is one file read and written, and `/dev/tty` must be the same file); the kernel answers
  `FIONREAD` and `TIOCOUTQ` on it; the filter also sends `open`, `openat` and `openat2`, and serve
  gives a copy of the socket for `/dev/tty` by `SECCOMP_IOCTL_NOTIF_ADDFD` (less reads its keys
  there, bash opens it); the termios2 family (`TCGETS2` to `TCSETSF2`) is answered too; a descriptor
  is known by its open file description (`kcmp`), never its number.
- Approach item 5: a program that opens `/dev/tty` works on route 2a (measured with less and bash).
  What still fails is in the research document, "What fails on each route 2".
- The box's seccomp profiles let `unshare`, `mount` and `ptrace` pass (`scripts/box/seccomp.json`),
  where the real sandboxes refuse the first two: Approach item 6 needs a profile that refuses them.

## Done

Not done. The study, drafted 2026-11-13 on the branch `draft-t248` (no build of podssh): C probes
under docs/research/serve-tty/ (`cage.c`, `route1.c`, `route2.c` with `route2.h`, `route2b.c`,
`isatty.c`, `realpty.py`), run by `sh docs/research/serve-tty/run.sh` as root on Linux 6.18.44 (a
Firecracker VM, Ubuntu 24.04, glibc 2.39), and their results in
[docs/research/serve-tty.md](../docs/research/serve-tty.md). Measured in the cage:

- Route 1 works: a pair of a new devpts instance from a helper that exits in 0.5 to 5.8 ms; the
  child, in no namespace of its own, has a controlling terminal, `stty size` `43 132`, and a resize
  reaches its `trap ... WINCH`. Refused where `unshare` is (EPERM), from a threaded process (EINVAL),
  and at the uid map with no `/proc` (it works with no map).
- Route 2a works with `test -t 0`, `stty`, static glibc and musl, Python's SIGWINCH, bash's job
  control (Ctrl-C ends `sleep 30` with 130, Ctrl-Z stops `sleep 31`, `jobs`, `kill -9 %1`), vim
  (`:wq` wrote the file), less (keys from `/dev/tty`) and top. It works with `ptrace` refused, with
  `process_vm_writev` refused (through `/proc/PID/mem`), with no `/proc` (`kcmp`); it fails with
  neither `process_vm_writev` nor `/proc`, and is refused (EBUSY) under a filter with a listener of
  its own. A call sent to podssh costs 3.4 to 27 µs, one passed straight 0.13 µs.
- Route 2b works where `ptrace` is allowed, also under a listener; refused (EPERM) where it is not.

The recommendation (the research document, "Recommendation"): the order real pty, route 1, route 2a,
route 2b, route 3 (T-111's discipline with no tty), each after its probe, each probe a line of doctor
(`pty`, `pty devpts`, `pty notify`, `pty ptrace`); route 1 into T-110's `pty::open` as a forked helper
with `TIOCGPTPEER`; and for T-111, pod-term's discipline driven by the termios that route 2 answers
(an issue in PodUtils/podcrates, Rule Q3).

Merged 2026-11-13. The main session ran `sh docs/research/serve-tty/run.sh .work/t248` again as root
on the same kind of host (Linux 6.18.44): each route gave the study's result in each cage (route 1:
works, EPERM with `unshare` refused, EINVAL from a thread, the map refused with no `/proc`; route 2a:
works with `ptrace` refused, through `/proc/PID/mem` with `process_vm_writev` refused, NOTTY and "Bad
address" with neither, EBUSY under a listener; route 2b: works, also under a listener, EPERM with
`ptrace` refused), static glibc and musl `isatty` true, SIGWINCH at 100x30, Ctrl-C's 130, the file that
vim wrote, less and top. A call sent to serve cost 25 to 34 µs here (the study: 3.4 to 27 µs); one
passed straight, 0.12 to 0.13 µs. Route 2b's `open("/dev/tty")` gave a descriptor that is not a tty.

The entries of the implementation are filed: T-775 (route 1 in `pty::open`, the line `pty devpts`),
T-776 (route 2a with pod-term's discipline, the line `pty notify`, the test `serve_tty`), T-777 (route
2b, the line `pty ptrace`) and T-778 (the box's profile that refuses `unshare`, `mount`, `setns` and
`ptrace`); the order of the routes is written in T-775's Decision, as it changes no ruling of
`docs/decisions.md`; pod-term's mode that follows a termios is asked of podcrates as COORD-055 (#232).
Left: this entry's Prove, which needs T-775 to T-778, and the doctor lines in both real sandboxes,
run by the operator's agents.

# T-393: `--install` that always restarts: systemd without a start limit, a cron watchdog, a LaunchAgent; and `ssh -N -R --persist`

**Source:** the operator, 2026-11-01: the study of Nemo-010/d-mon (T-389's Source); its fifth
finding.
**Category:** feature
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

An installed node is the tunnel that a server keeps across reboots, and each way it stays down
locks the server out: systemd's unit restarts only `on-failure` and gives up after 5 starts in 10 s
(its default start limit); the cron line runs only `@reboot`, so a node that ends is not started
again before the next boot; macOS has no way of `--install`; a Windows task of logon waits for a
logon after a reboot; and a reverse tunnel of `podssh ssh -N -R --persist` cannot be installed.

## Premise

- Read: `Restart=on-failure`, `RestartSec=10`, no `StartLimitIntervalSec`
  (`crates/podssh-cli/src/node_install/text.rs:149`).
- Read: the cron line is `@reboot` alone (`crates/podssh-cli/src/node_install/unix.rs:137`).
- Read: the Windows task restarts each minute, 999 times, at a logon
  (`crates/podssh-cli/src/node_install/text.rs:294`).

## Approach

systemd: `Restart=always`, `RestartSec=5`, `StartLimitIntervalSec=0`, with
`RestartPreventExitStatus=64 78` (77 stays a refusal that the user must see). cron: beside
`@reboot`, a `*/5` line that starts the node when its lock (T-392) is free. macOS: a LaunchAgent of
the user with `KeepAlive` and `RunAtLoad`, loaded by `launchctl bootstrap gui/UID`. Windows: the
task's line says that it waits for a logon, and names the task of `schtasks /ru SYSTEM` that an
administrator may make. `podssh ssh --install NAME -N -R ... --persist` writes the same units.

## Decision

- **The watchdog's test of "not running": a lock of the service's own.** A run with `--env-file
  FILE` holds an exclusive lock on `FILE.lock` (`File::try_lock`: `flock` on Unix, `LockFileEx` on
  Windows) for its life, with its pid in the file (`crates/podssh-cli/src/node_install/lock.rs`).
  Each service runs with the `--env-file` that `--install` wrote, so each way gets one run at a
  time, and the crontab's line each 5 minutes is the same command as the line at boot. T-392's
  `detached/NAME.lock` is not there yet, and is a lock of `--detach --name`; when it comes, it can
  take this one's place, which is taken in one function (`lock::enter`). Lost: a file of the pid
  and `kill -0` in the cron line (a pid is reused, and a stale file keeps a dead service down until
  the next boot); `pgrep` or `ps` (a tool that the host may lack, rule 1 of `AGENTS.md`, and a name
  that another program matches); `flock(1)` in the line (util-linux's, absent from busybox and
  macOS); the relay's 409 for a second node of a pair (a node retries a 409 for 10 minutes before
  it ends, so a copy each 5 minutes would run beside the first, and a tunnel of ssh has no such
  refusal, only a port in use on the server).
- **A held lock ends the second run with 0, and says so only on a terminal.** cron mails each
  output, which would be a mail each 5 minutes while the service runs; the code changes nothing for
  systemd or launchd, which start it again either way, and 0 keeps the Windows task from its
  restart after a failure. Lost: a line always; 75, T-392's code for its own lock.
- **A lock that cannot be taken lets the run go on**, with a line: a service that never starts
  locks its server out, and two runs are the lesser fault.
- **One way for each install, as T-121; a new install removes what another way made for the same
  NAME.** Lost: the crontab beside systemd or launchd as a second supervisor: a person's
  `systemctl --user stop` would be undone within 5 minutes by cron, and the two would start runs
  that the lock ends, each 5 s.
- **macOS: a LaunchAgent where `launchctl print gui/UID` answers, else the crontab.** The probe's
  order on each Unix is systemd, launchd, cron: a Linux host has no `launchctl`, and a Mac no
  `systemctl`. Lost: the background domain `user/UID` with no login session: an agent there is not
  loaded again after a reboot either, and its session types are its own (UNVERIFIED), where the
  crontab's line at boot needs no login.
- **`RestartPreventExitStatus=64 78`, as the Approach says.** 77 starts again, so that a pair made
  again is taken at the next start with no new `--install`. Lost: a start after each code, which
  would fill the journal each 5 s with a refusal that no start changes. `StartLimitInterval=0` in
  `[Service]` too, where a systemd older than 230 reads the limit.
- **`ssh --install`: the typed words but `--install NAME`, in the directory where they were
  typed**, after `-o BatchMode=yes`, `-o ForkAfterAuthentication=no`, `-o ControlPath=none`,
  `-o ExitOnForwardFailure=yes` and `--env-file` (`crates/podssh-cli/src/node_install/ssh.rs`).
  Lost: the words built again from the parsed flags, as a node's are: ssh has some 80 flags and
  keywords, and a list built from them drops each flag that a later entry adds. `-N` and
  `--persist` are asked for, not added, so that the service runs what the user can run in the
  foreground; `--persist` connects again within the process, sooner than a new start. T-391's
  `--persist=always`, when it comes, goes into the service as typed.
- **Windows: a time trigger each 5 minutes** (`IgnoreNew` for a running instance) is the task's
  watchdog, as its restart after a failure ends after 999, about 16 hours; a task at boot needs an
  administrator, and its line says so.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib node_install::
cargo test -p podssh-cli --test serve_install
cargo test -p podssh-cli --lib man::notes
```

The units are checked by `systemd-analyze verify` where it exists, and the plist by `plutil -lint`
on macOS in CI.

## Correction

The Premise holds. The cron line is made by `cron_line`, in
`crates/podssh-cli/src/node_install/text.rs` (line 128 at `ea2bd4f`), and given to crontab by
`cron`, at the line that the Premise cites. The lock of T-392 that the Approach names does not
exist (T-392 is open): the watchdog takes a lock of the service's own (Decision).

## Done

2026-11-01: drafted (`worktree-agent-aac2458476d4808b9`), merged, built and run the same day. At the
merge the tunnel's service gained `--persist-forever` (T-391, done meanwhile) after `--env-file`,
unless the words hold it, so that an outage never ends it between two starts; and a sentence of the
note of `ssh --install` that named -W and -R together, which the manual's test of the note of -R
refuses, became two.

- systemd: `Restart=always`, `RestartSec=5`, `RestartPreventExitStatus=64 78`, and
  `StartLimitIntervalSec=0` in `[Unit]` (with `StartLimitInterval=0` in `[Service]`); a tunnel's
  unit has `WorkingDirectory=-DIR` (`unit` in `crates/podssh-cli/src/node_install/text.rs`).
- cron: two lines under one mark, `@reboot` and `*/5 * * * *`, the same command; the mark of T-121
  above its one line is still found, and a line of the user's after it stays (`cron_lines`,
  `cron_table`).
- A LaunchAgent, `~/Library/LaunchAgents/dev.podssh.VERB.NAME.plist`, with `RunAtLoad`,
  `KeepAlive`, `ThrottleInterval` 5 and its stderr in `VERB-NAME.log`, loaded by `launchctl
  bootstrap gui/UID` after a `bootout` and an `enable`, removed by `bootout`
  (`crates/podssh-cli/src/node_install/launchd.rs`).
- Windows: a time trigger each 5 minutes beside the logon; the line names the task at boot that
  only an administrator can make (`crates/podssh-cli/src/node_install/windows.rs`).
- The lock of a service's run, and `podssh ssh --install NAME`, `--uninstall NAME` and
  `--env-file FILE` (`crates/podssh-cli/src/flags/node.rs`, `crates/podssh-cli/src/ssh/args.rs`);
  the manual's notes of `node` and `ssh` and its FILES; `docs/cli.md`; `docs/STATUS.md`.
- `cargo test -p podssh-cli --lib node_install::`: 12 passed (7 of them new:
  `a_unit_restarts_after_each_end_with_no_limit_of_starts`,
  `a_tunnel_s_unit_runs_in_its_directory_and_names_its_own_removal`,
  `the_line_of_an_earlier_install_is_replaced_and_the_user_s_next_line_stays`,
  `a_tunnel_s_lines_change_to_its_directory_first`,
  `the_launch_agent_reads_back_as_its_program_and_keeps_it_alive`,
  `a_tunnel_s_words_are_the_typed_ones_but_install`,
  `a_second_try_of_a_lock_is_refused_until_the_first_lets_it_go`).
- `cargo test -p podssh-cli --test serve_install`: 9 passed (4 of them new:
  `a_launch_agent_where_launchctl_has_a_login_session`,
  `a_tunnel_of_ssh_becomes_a_user_unit_of_its_typed_words`,
  `what_cannot_be_a_tunnel_s_service_is_refused_and_nothing_is_written`,
  `a_second_start_of_a_service_ends_at_once_while_its_lock_is_held`; the crontab's test asks for
  the watchdog's line).
- `cargo test -p podssh-cli --lib man::`: 36 passed (each flag, keyword and variable that the
  new notes name exists). Clippy `-D warnings`, here and for `x86_64-pc-windows-gnu`: clean.
- Planted, each failed its test: `Restart=on-failure` back in the unit (the unit's test); the
  watchdog's line dropped (three tests of the crontab); a lock that takes nothing (the lock's
  test); `SERVICE_OPTIONS` empty (the words' test).
- `systemd-analyze verify` (systemd 255 here) of the unit that `podssh ssh --install bastion -N -R
  2222:127.0.0.1:22 --persist me@example.org` wrote, with a stand-in `systemctl`: no finding.
- Not measured here: `plutil -lint` of the plist and a real `launchctl bootstrap` (macOS), a real
  cron's watchdog after a kill, and the task of Windows; the record of each is T-251's.

# T-631: `podssh serve --listen`: a deadline from the accept for a client that never logs in, and a cap on those that have not

**Source:** GitHub #129 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** open

## Problem

A listener's first callers are handshakes that never end. The plan of `podssh serve` asks russh for no
inactivity cut, and russh's own bounds stop at the version line or count activity, so a client that
connects and says nothing, or one that sends a byte now and then, holds a task and a descriptor for as
long as it likes; a few of them fill a cap on connections.

## Premise

Read at `2042200`:

- The head of this file said "No server code exists yet." (T-107 changes it), and T-107's step 2 asks russh for
  `TODO/serve.md:43-44`, which says "no inactivity cut (russh: 600 s)".
- russh bounds the client's version line alone with its `inactivity_timeout`:
  `vendor/russh/src/server/mod.rs:1162` says "tokio::time::timeout(t, read.read_client_ssh_id()).await??",
  and the key exchange and the login run in the session that
  `vendor/russh/src/server/mod.rs:1152` spawns.
- In the session, the inactivity timer starts again at each event
  (`vendor/russh/src/server/session.rs:860-864`): a cut for silence, not a deadline.
- T-124's step 4 asks for a cap with no time: `TODO/serve.md:2251-2252` says "a cap on connections at
  once and on connections that have not authenticated".
- What a deadline needs is there: `vendor/russh/src/server/session.rs:475` (`Handle::disconnect`) and
  `vendor/russh/src/lib_inner.rs:315` says "TooManyConnections = 12,".

## Approach

1. In the server of T-107 (crates/podssh-ssh/src/server/, as T-107 decides), a module of the limits:
   one instant taken at the accept; a permit of a cap on connections not yet logged in, taken before a
   byte is read, and past it `TooManyConnections` and the end.
2. The deadline wraps `run_stream` and goes on into the session: a waiter on the same instant, which the
   first successful authentication cancels, and which else sends `ByApplication` with one line that
   names the limit, then drops the session; it ends with the session, so a login of 5 ms keeps no
   sleeping task.
3. `--login-timeout SECS` (default 60, as OpenSSH's `LoginGraceTime` is 120 and a sandbox's link is
   short) and `--pending-max N` (default 16) on `podssh serve --listen`; each reaped connection is a
   line of the server's log.
4. `--stdio`, a node's sessions and the operator's road take no listener and keep their one client.

## Decision

2026-11-04 (the drafting agent of the triage). Milestone backlog, as T-124: the deadline is for
`--listen` alone, whose entry is in the backlog, and a deadline in M5 would come before the listener
that it bounds. Lost: M5, as the serve entries of the cage are, which would order it before T-124.

2026-11-05 (a drafting agent). The entry waits for T-124, as its Start condition says, and is a row of
"Parked open work" in `TODO/PROGRESS.md`. Read on 2026-11-05: no source has a server of `podssh
serve` (no crates/podssh-ssh/src/server/; `russh::server` only in the tests' harness of
`crates/podssh-cli/tests/ssh_harness/`), T-107 is open and T-124 is parked behind T-107 to T-112,
and this Prove extends T-124's test of the listener. Each line of the Premise holds there. Lost: a
module of the limits drafted now with no server (T-107 decides where the server goes and the shape
of its handler, where the first authentication cancels the waiter, and a deadline with no listener
to bound is code that nothing calls); the entry open with no condition (the work order would take
it, and nothing could be done).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test serve_listen
```

In T-124's new test of the listener, on the loopback: a client that says nothing is gone within the
limit and a margin, and the line names the limit; one that sends a byte each second is gone at the
same limit; a login inside the limit outlives it; one past `--pending-max` gets `TooManyConnections`
before the key exchange; the count of the server's tasks comes back after each. Planted: the deadline
as a timer of inactivity, and the test of the byte each second fails.

## Start condition

T-124 is done: `podssh serve --listen` exists, with the server of T-107 whose session the deadline
follows and the test of the listener that this Prove extends. T-124 waits for T-107 to T-112.

# T-698: `podssh serve` drops each capability of its start, with the relay role's drop in a module that both share

**Source:** GitHub #168 (2026-11-07).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`podssh relay serve` gives up each capability of its start after its bind (T-629, GitHub #127).
`podssh serve` (T-107) plans no such drop. It runs a command for each authenticated client, so it
holds more authority than a relay that pumps bytes. A start of `serve --stdio` by a supervisor
that runs as root (inetd, a systemd unit) would keep every capability for the life of the
connection.

## Premise

- `crates/podssh-cli/src/relay_serve.rs` said `mod harden;` before this entry: the drop was private to
  `relay_serve`. Its only call is `crates/podssh-cli/src/relay_serve.rs:151`
  (`harden::give_up()`); `crates/podssh-cli/src/relay_serve/certs.rs:123` only reads
  `harden::dropped()`. The files are `harden.rs` (284 lines), `harden_sys.rs` (118) and
  `harden_tests.rs` (228).
- `crates/podssh-cli/src/first_thread.rs` and `crates/podssh-cli/src/main.rs:29` hold the hand-off
  of the first thread. A drop on the calling thread alone is not enough (T-629's Correction); a
  drop of `serve` inherits this.
- T-107's Approach (`TODO/serve.md:36`, steps 1 to 5) does not mention capabilities. No entry
  plans a drop for `serve`.
- T-631 covers the deadline and the cap of pending connections for `--listen` only. The drop asks
  for no listener, so it needs no parking.
- No file here is in a module that PodUtils/podcrates took. The work stays in podssh.

## Approach

1. Move `harden.rs`, `harden_sys.rs` and `harden_tests.rs` to a shared module of `podssh-cli`
   beside `first_thread.rs`. Keep each file at 500 lines or fewer. Keep `status_sets` nameable,
   so that a later report of `doctor` can read the same sets.
2. Add one parameter: what the caller keeps. It is empty for the relay role. It is empty for
   `serve` until a measurement says that a pty or a child needs one (T-110, T-248).
3. The relay role calls the drop after its bind, as today. `serve --stdio` calls it at start,
   before the runtime starts its threads. `serve --listen` calls it after its bind.
4. Keep the convention of `harden.rs`: probe first; where a capability was held, a failed step
   refuses the start (exit 78); `EPERM` and `EINVAL` of the bounding-set drop are taken as done;
   each thread of `/proc/self/task` is read again. A start as root keeps uid 0, and the first
   line of the start says so.
5. Do the extraction now. The call from `serve` goes into T-107's Approach, and T-107's Prove
   gets one check: after the start, under both entry points and as root, the process reports no
   capability. T-107 gets a Start condition: this entry is done.
6. Run `cargo todo remap` on each moved file, and correct the citations of T-629 in the same
   change.

## Decision

2026-11-09 (Q-168), the call of the triage:

- This is its own entry, and T-107 waits for it. Lost: a step inside T-107's Approach. T-107 is
  large and open; the extraction touches only the relay role and needs no listener, so it can be
  done now and T-107 meets a finished module.
- The keep-list is a parameter that is empty today. Lost: a keep-list with a guess of what a pty
  needs. It is not known; a measurement fills it, not a default.
- A start as root keeps uid 0, as T-629 decided for the relay role. Lost: a change of uid, which
  is a different feature.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
cargo test -p podssh-cli --lib harden
```

The relay role's tests pass after the move, unchanged. (The check of `serve` as root on every thread of
`/proc/self/task` moved to T-107's Prove: see the Correction of 2026-11-12.)

## Correction

2026-11-09 (the drafting agent of T-698). The Premise holds at `739d851d`: `mod harden;` is at
`relay_serve.rs:22`, the call at `:239`, the read of `dropped()` at `certs.rs:123`, and the three
files have 284, 118 and 228 lines. Step 2 is made as `give_up(keep: &[u32])`: the numbers become a
mask, which `plan` leaves in the bounding set and `Calls::clear(keep)` leaves in the effective and
permitted sets (only what the thread holds, as `capset` refuses a raise), and `threads_holding(keep)`
does not count. The module is `crate::harden` (`crates/podssh-cli/src/harden.rs`, `harden_sys.rs`,
`harden_tests.rs`); the words of the first line and of the refusals still say "after the bind", which
is `serve`'s to make general (T-107). The plant `scripts/plants/t629-capset-failure-taken.plant` follows the
new path; `t629-drop-after-runtime.patch` was already stale. T-107's Approach got its call as a
`## Correction` of 2026-11-09.

2026-11-12 (main session). The Prove named the interop script of `serve` (`interop-serve.sh` under `scripts/`) and its test `serve_auth`, which do not exist yet: T-107 writes
them with `serve` itself, and their check as root is T-107's step 6. This entry closes on its own two
commands.

## Done

Partial, 2026-11-09. The extraction (steps 1, 2, 4, 6 of the Approach) is drafted (DRAFT T-698,
`450f0021`) and merged by the main session, with no repair; the
call of `serve` (steps 3 and 5) waits for T-107.

- Moved: `PodUtils/podssh:crates/podssh-cli/src/relay_serve/harden{,_sys,_tests}.rs` to
  `crates/podssh-cli/src/`, declared in `lib.rs` beside `first_thread`; `relay_serve.rs` calls
  `crate::harden::give_up(&[])`, `certs.rs` reads `crate::harden::dropped()`. No change of behaviour.
- `cargo test -p podssh-cli --lib harden`: 13 passed. New test:
  `a_kept_capability_stays_in_the_bounding_set_and_reaches_the_clearing`.
- `cargo test -p podssh-cli --test relay_serve`: 27 passed. The plant of T-629 at its new path
  (`sh scripts/plant-each.sh --here t629-capset-failure-taken`): caught.
- clippy (the gate's lints): no warning; rustfmt: no change. The build image's run waits for the gate.
- `cargo todo remap` for the files that cite `harden.rs`: done (`TODO/cli.md` cited
  `relay_serve/harden.rs:234`, moved by hand to `harden.rs:245`).
- The call from `serve` and its check as root on each thread of `/proc/self/task` are T-107's step 6
  (its Correction of 2026-11-09), as `serve` does not exist yet to call it.

Done, 2026-11-12: the entry's own part, a drop that both roles share with a keep-list, is complete and
tested; the two entries waited on each other, so the call now lives in T-107 alone, which owns `serve`.

# T-709: A node as a hardened system service of a named user: `--print-unit`, `--install --system --run-as`

**Source:** PodUtils/podcrates#35, cfb's ask A-S-02 (COORD-014, PodUtils/podcrates#38)
**Category:** feature
**Milestone:** M10
**Priority:** P1
**Effort:** M
**Status:** open

## Problem

A server of cfb runs its node as one user, under systemd as root's unit, with no way to read the unit before
it is installed. `podssh node --install` writes a user unit only. It needs `systemctl --user`, and a host
without a user manager gets a cron line. The unit has no hardening.

## Premise

- Read: the ways are a user unit, a LaunchAgent, cron and a Windows task
  (`crates/podssh-cli/src/node_install/mod.rs:116-125`); the probe is `systemctl --user show-environment`
  (`crates/podssh-cli/src/node_install/unix.rs:19-27`); the units go to `~/.config/systemd/user`
  (`unix.rs:29-36`).
- Read: the unit has `Restart=always` and no `User=`, `NoNewPrivileges` or `ProtectSystem`
  (`crates/podssh-cli/src/node_install/text.rs:130-158`).
- Read: no token is in a unit now. The variables go to a private file beside the pair, and a secret is
  never carried (`crates/podssh-cli/src/node_install/env.rs:36`, `:7-9`). Keep that.
- Read: T-593 made the cache follow `HOME` into another user's home; a system unit of a named user must name
  that user's `HOME` and `XDG_CACHE_HOME`.
- Not measured: the hardening set on a systemd of 2026's hosts.

## Approach

1. `podssh node --print-unit NAME ...`: print the unit to stdout and write nothing, for any OS. Same words
   as `--install` would write. Add `podssh serve --print-unit`.
2. `--install --system --run-as USER`: write `/etc/systemd/system/podssh-node-NAME.service`, with `User=`,
   `Environment=HOME=`, `StateDirectory=` and the private env file of the user, then `systemctl daemon-reload`
   and `enable --now`. Probe first: root, `/run/systemd/system`, a passwd entry of USER (rule 1). Else a
   refusal with 77 or 69 and the words of the missing part. `--uninstall --system` removes it.
3. Hardening in the unit: `NoNewPrivileges`, `CapabilityBoundingSet=` (empty), `ProtectSystem=strict`,
   `ProtectHome=tmpfs` with `BindPaths` of the cache directory, `PrivateTmp`, `PrivateDevices`,
   `ProtectKernel*`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `SystemCallFilter=@system-service`,
   `LockPersonality`, `MemoryDenyWriteExecute`, and the `Restart` words of T-393. A node with `--exit` or
   `--routes` or a roost needs fewer limits: name each relaxed line in the unit's comment.
4. No token in the unit. A test reads the unit text for the names in `env::SECRET`.
5. Later, on `pod-unit` (PodUtils/podcrates T-102): when it is released and taken, the text of the unit moves
   there and this entry's command stays. Until then podssh writes the text itself.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib node_install::
cargo test -p podssh-cli --test node_install
```

New tests on the text: the unit holds `User=`, the hardening lines and no secret; `--print-unit` writes no
file. A run in the build image (`scripts/test_in_box.sh`, systemd as PID 1 where it exists) lists
`systemd-analyze security` for the unit with a score under 3.0. The run waits for T-251's image checks
where the box has no systemd.

## Start condition

Items 1 to 4 start now. Item 5 waits for podcrates T-102 (`pod-unit`) and its release.

# T-774: `podssh serve` checks the user-presence flag of a security key's signature, as sshd does by default

**Source:** the draft of T-114 (2026-11-13): serve does not read the flags of a security key's signature.
**Category:** defect
**Milestone:** M5
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A login with a security key (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`) signs a flags
byte; bit 0 says that the user touched the key. sshd refuses a signature without it unless the key's line says
`no-touch-required`. podssh serve takes the signature with no look at the flags, so a key that signs without a
touch (malware on the client host with the key plugged in) logs in where sshd would refuse.

## Premise

- russh verifies a security key's signature through ssh-key, whose `make_sk_signed_data`
  (`vendor/ssh-key/src/signature.rs`) signs over the flags and checks none.
- T-114's options: `no-touch-required` is taken with no change; `touch-required` and `verify-required` refuse
  their line (`crates/podssh-ssh/src/server/options.rs`).

## Approach

Read the flags of an sk signature at login (the signature blob of the `publickey` request, before russh's check,
or after it by a hook of `vendor/russh` or `vendor/ssh-key`, a patch beside the others). Refuse a signature with
bit 0 clear unless the key's line says `no-touch-required`, with the reason on serve's stderr; take
`verify-required` where bit 2 (verified) is set. The options of T-114 then mean what sshd's do.

## Decision

2026-11-13, made with the draft:

- **Where the flags are read: a hook of russh, `VerifiedPublicKey::sk_flags`** (a new patch,
  `vendor/patches/russh/0010-sk-flags.patch`). russh decodes the signature (`ssh_key::Signature`, whose bytes for
  an sk algorithm end with the flags byte and the counter, as ssh-key's `Decode` appends them), verifies it over
  the flags, and then calls `Handler::auth_publickey` with the key and the algorithm alone. The patch puts the
  flags byte of the signature it just verified into the struct that it passes; the struct is `#[non_exhaustive]`
  and built by russh alone, so no caller changes, and the flags that serve reads are the ones that the key signed.
  Lost:
  - reading the signature blob of the `publickey` request before russh's check: the handler never sees the
    packet, so it would take a hook of its own all the same, and the flags read there would not yet be proven;
  - a hook in ssh-key (a `Signature::sk_flags()` or a check in its `Verifier`): ssh-key already keeps the byte
    where any caller can read it, and a check inside the verifier knows no key line, so it could not honour
    `no-touch-required`;
  - refusing every sk key at login until a hook exists: it would refuse what sshd takes.
- **The line that decides**, as sshd's `userauth_pubkey`: the options of the line that admitted the key (the
  first that lets it in now, T-114) hold; a signature that falls short of them refuses the login, and no later
  line of the same key is tried. sshd reads the flags after `user_key_allowed` chose the line, the same way. Lost:
  trying the next line (a second line with `no-touch-required` would then waive the first's touch, which sshd
  does not do).
- **The meaning of each option**, as OpenSSH's `auth-options.c`: `touch-required` is the default (a line may name
  it; `no-touch-required` waives it, and of two the last holds); `verify-required` asks for bit 2 and
  `no-verify-required` takes it back; `restrict` changes neither. A security key's signature whose flags could
  not be read is read as no bit set, so it fails closed. The reason goes to serve's stderr with the key's
  fingerprint ("refused: the security key signed with no touch ... no-touch-required", or "verify-required:
  ..."), and the client hears `Permission denied (publickey)`, as for each other refusal at login (T-114).
- **The test's key** is a security key in software in the test itself (an Ed25519 key of aws-lc-rs that signs
  the hash of the application, the flags, the counter and the hash of the message, as a FIDO device does), so
  each flag is chosen; podssh's own `sk::soft` is private to the crate. Against OpenSSH, with a real device, no
  test is possible here: no device, and OpenSSH's client sets the flags that the device gives.

## Prove

```sh
cargo test -p podssh-ssh --test serve_options -- touch
```

A login whose sk signature has the flag of presence clear is refused, and taken with `no-touch-required`; a plant
that skips the check fails the test.

## Done

Done 2026-11-13, merged from the draft of the branch `draft-t774`, built and tested by the main session:

- russh: `VerifiedPublicKey::sk_flags`, the flags byte of a verified sk signature
  (`vendor/patches/russh/0010-sk-flags.patch`, applied to `vendor/russh/src/server/mod.rs` and
  `vendor/russh/src/server/encrypted.rs`; its row in `vendor/README.md`, and the count in `AGENTS.md`'s map).
- serve: `Rules::no_touch_required` and `Rules::verify_required` read from the line
  (`crates/podssh-ssh/src/server/options.rs`; `touch-required` and `verify-required` no longer refuse it);
  `Rules::sk_refusal` (`crates/podssh-ssh/src/server/rules.rs`); `auth_publickey` refuses a signature that falls
  short, with the reason on serve's stderr (`crates/podssh-ssh/src/server/handler.rs`).
- Tests: the unit test `the_flags_of_a_security_key_are_read_as_sshd_reads_them` and the changed examples
  (`crates/podssh-ssh/src/server/options_tests.rs`); three tests of `crates/podssh-ssh/tests/serve_options.rs`
  whose names hold `touch`, with a security key in software that signs with chosen flags.
- The manual's note of serve and `docs/cli.md` ("The options of a key line"); a row of `docs/STATUS.md`; the plant
  `t774-touch-unchecked`; the hunks of the plants `t114-forced-command-ignored` and `t114-restrict-keeps-pty` moved
  to their new lines.

Results:

- `cargo test -p podssh-ssh --test serve_options -- touch`: 3 passed (a software key of the test that signs with
  chosen flags: no touch refused, taken with `no-touch-required`; `verify-required` with bit 2 clear refused).
- `cargo test -p podssh-ssh --lib server::`: 53 passed.
- `cargo test -p podssh-ssh --test serve_options --test serve_auth`: 11 and 7 passed.
- `cargo test -p podssh-cli --test serve_options_openssh` against OpenSSH 9.6p1's client: 5 passed.
- `cargo test -p podssh-cli --lib man`: 100 passed; `--test man_page --test man_flag_parity --test man_json`:
  6, 4 and 11 passed.
- `sh scripts/plant-each.sh --here t774-touch-unchecked`: caught; `t114-forced-command-ignored` and
  `t114-restrict-keeps-pty` still caught.
- Clippy as the gate runs it on `x86_64-unknown-linux-gnu` and `-musl`: clean; rustfmt: clean; `cargo check
  --target x86_64-pc-windows-gnu -p podssh-ssh -p podssh-cli --all-targets`: clean.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,849 passed, none failed.

The citations of each file that the draft changed were moved by `cargo todo remap` at the merge, and the root
`Cargo.toml`'s comment of russh's patches counts ten.

# T-775: `podssh serve` gives a pty from a new devpts instance where `/dev/ptmx` is missing and `unshare` is allowed

**Source:** T-248's study (2026-11-13, [docs/research/serve-tty.md](../docs/research/serve-tty.md), route 1).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Where the host has no `/dev/ptmx` and no `/dev/pts/ptmx`, T-110's `pty::open` finds no master, and a
`pty-req` is refused. Where the host allows an unprivileged `unshare(CLONE_NEWUSER | CLONE_NEWNS)`, a new
devpts instance gives a real pty of the kernel with no device of the host: T-248 measured it in a cage
that stands for the target (a pair in 0.5 to 5.8 ms, a controlling terminal, `stty size`, SIGWINCH).

## Premise

- T-110's `pty::open` tries the paths of `PTMX` and nothing else (`crates/podssh-ssh/src/server/pty.rs`).
- The study: a forked helper of one thread (serve's threads make `unshare` fail with EINVAL) mounts
  devpts `newinstance`, opens its `ptmx`, unlocks it, takes the slave by `TIOCGPTPEER` and sends both by
  `SCM_RIGHTS`; `ptsname` names no path that the child could open, so there is no `SSH_TTY`.

## Approach

One more source after the paths of `PTMX`: the helper of the study, forked before any thread of its own,
its pair sent back and the helper reaped within a time limit; the `Pair`'s name says "a devpts instance of
podssh"; the child gets the slave as with T-110, and no `SSH_TTY`. `podssh doctor` gets the line `pty
devpts`, each step named with its errno where it fails (`unshare`, `mount`, `ptmx`, `TIOCSPTLCK`,
`TIOCGPTPEER`). The probe runs again at each `pty-req`, as T-110's does (AGENTS.md section 5, rule 1).

## Decision

The order of the routes is the study's: the real pty, then this one, then T-776, then T-777, then T-111
(no tty). This route comes first of the new ones because it is the kernel's own tty, with nothing answered
by podssh. The order is written in each entry, not in `docs/decisions.md`: it changes no ruling there.

## Prove

```sh
cargo test -p podssh-ssh --test serve_pty -- devpts
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

In a cage with no `/dev/ptmx` and `unshare` allowed, `test -t 0` is true in the child, `stty size` gives
the request's size, and a `window-change` reaches a `trap ... WINCH`; where `unshare` is refused, the line
`pty devpts` names EPERM and the request falls to the next route. Planted defect: the slave opened by
`ptsname` in place of `TIOCGPTPEER`; the test fails.


## Done

Done 2026-11-13. `crates/podssh-ssh/src/server/pty_devpts.rs` (Linux): a helper forked for each
request makes a user and a mount namespace, makes `/` private, mounts devpts `newinstance` on `/dev/pts`,
`/dev` or `/tmp` (the first that takes it), opens its `ptmx`, unlocks it (`TIOCSPTLCK`), takes the slave
by `TIOCGPTPEER`, and sends both by `SCM_RIGHTS` over a `SOCK_SEQPACKET` pair, or the step that failed
with its errno; the parent waits 2 s at most, then kills and reaps the helper. After the fork the helper
makes only system calls, on values made before it. `pty::open_with(paths, devpts)` tries the host's
masters, then the instance; a test's `Settings::ptmx` keeps its meaning (`Settings::devpts`: None tries
the instance with the default masters only). The pair says it has no path (`Pair::path`), and
`env::with_tty` then sets no `SSH_TTY` and drops serve's own. `podssh doctor` has the line `pty devpts`,
and the fact of `--tier` counts a pty of either; the manual (`notes_serve.rs`) and `docs/cli.md` say so.
Decision on the plant: the Prove's "slave by `ptsname`" opens the new instance's slave inside the helper's
namespace, so it would pass; the plant is the route never tried (`t775-devpts-never-tried`).

- `cargo test -p podssh-ssh --test serve_pty -- devpts` as root on this host (Linux 6.18.44): passed, a
  pty of 132x43 with `test -t 0` true, no `SSH_TTY`, and a `window-change` that reached the child's
  `trap ... WINCH` (`30 100`); the same binary in T-248's cage with `unshare` refused (`cage -n`): passed
  on its other branch, the request refused (`unshare: Operation not permitted`) and the command on pipes.
- `cargo test -p podssh-ssh --test serve_pty --test serve_exec`: 7 and 11 passed; `--lib -- pty_devpts
  env:: pty::`: 10 passed (the instance's pair a tty, its size set).
- `podssh doctor` here: `pty devpts  a pty of a devpts instance of podssh's own can be made here`;
  `cargo test -p podssh-cli --lib -- doctor man`: 213 passed; `--test doctor --test man_page --test
  man_flag_parity --test man_json`: 13, 6, 4 and 11 passed.
- The plant `t775-devpts-never-tried`: caught (`sh scripts/plant-each.sh --here`).
- clippy as the gate runs it, on `x86_64-unknown-linux-gnu` and `-musl`: clean; `cargo check --target
  x86_64-pc-windows-gnu -p podssh-ssh -p podssh-cli --all-targets`: clean; rustfmt clean.
- `cargo test -p podssh-ssh -p podssh-cli --no-fail-fast`: 2,845 passed, none failed.
- The box (`sh scripts/test_in_box.sh`, `unshare` refused since T-778): exit 0, 22 properties, sandbox-check 14 ok; doctor there: `pty devpts  none: unshare: Operation not permitted (os error 1); podssh serve gives no pty of its own here`.

# T-776: `podssh serve` answers a child's tty calls by seccomp user notification where no pty opens

**Source:** T-248's study (2026-11-13, [docs/research/serve-tty.md](../docs/research/serve-tty.md), route 2a).
**Category:** feature
**Milestone:** M5
**Priority:** P2
**Effort:** L
**Status:** blocked

## Problem

The real sandboxes have no `/dev/ptmx` and refuse `unshare`, so neither T-110 nor T-775 gives a tty there.
A child whose descriptors 0 to 2 are one `AF_UNIX` stream socket, under a seccomp filter that sends its
`ioctl` and `open` calls to serve, sees a tty: T-248 measured `test -t 0`, `stty`, static glibc and musl,
SIGWINCH, bash's job control, vim, less and top this way, at 3.4 to 34 µs a call that is sent to serve.

## Premise

- The study's probe `docs/research/serve-tty/route2.c` with `route2.h`: the calls answered, a descriptor
  known by `kcmp` (or `pidfd_getfd`, or `/proc`), the answer written by `process_vm_writev` (or
  `/proc/PID/mem`), `/dev/tty` given by `SECCOMP_IOCTL_NOTIF_ADDFD`; EBUSY where a filter with a listener
  already stands.
- The discipline that the answered termios drives is T-111's, in `pod-term` (PodUtils/podcrates): it
  needs a mode that follows a termios (asked of podcrates by a COORD issue, Rule Q3).

## Approach

The study's "Recommendation": a supervisor task in serve for each such child, the probe `pty notify` as a
line of `podssh doctor` and at each `pty-req`, the calls of the study answered from one termios state that
drives pod-term's discipline, SIGINT, SIGQUIT and SIGTSTP to the foreground group that `TIOCSPGRP` set, and
SIGWINCH on a `window-change`. podssh puts no code into the child, and answers only for the descriptors
that it gave. What still fails is named in the manual (the study, "What fails on each route 2").

## Decision

After T-775 in the order (T-775's Decision). Taken over `LD_PRELOAD`, which the decisions forbid and which
does nothing to a static binary.

## Prove

```sh
cargo test -p podssh-cli --test serve_tty
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

Through `podssh serve --stdio` with no `/dev/ptmx` and `unshare` refused: `test -t 0`, `stty size`, Ctrl-C
ending `sleep 30` with 130, and vi, less and top with their screens read. Planted defect: `TCGETS`
answered with an error; `test -t 0` then fails, and the test fails.

## Blocker

PodUtils/podcrates must give `pod-term` a line discipline that follows a termios state (asked as COORD-055,
#232; podcrates' entry 539, in work for a later tag, as its COORD-080 says): its supervisor answers the tty calls from a termios state that drives that mode. podssh takes it by
that tag (work on a taken crate is done in PodUtils/podcrates), then this entry opens again.

# T-777: `podssh serve` answers a child's tty calls by ptrace where user notification is refused

**Source:** T-248's study (2026-11-13, [docs/research/serve-tty.md](../docs/research/serve-tty.md), route 2b).
**Category:** feature
**Milestone:** M5
**Priority:** P3
**Effort:** M
**Status:** blocked

## Problem

Where a seccomp filter with a listener already stands (EBUSY), T-776 cannot start, but `ptrace` with a
`SECCOMP_RET_TRACE` filter can answer the same calls: T-248 measured it under a listener; refused (EPERM)
where `ptrace` is.

## Premise

- The study's probe `docs/research/serve-tty/route2b.c`; its `open("/dev/tty")` gave a descriptor that is
  not a tty (measured again 2026-11-13), so a program that reads its keys from `/dev/tty` does not work on
  this route as probed.

## Approach

The calls and the state of T-776, stopped by `PTRACE_O_TRACESECCOMP` in place of a notification, with the
probe `pty ptrace` as a line of `podssh doctor` and at each `pty-req`; `/dev/tty` made to work, or named in
the manual as failing on this route.

## Decision

After T-776 in the order (T-775's Decision): it stops the child at each tty call, and takes `ptrace` from
the user.

## Prove

```sh
cargo test -p podssh-cli --test serve_tty -- ptrace
```

With user notification refused and `ptrace` allowed, `test -t 0` and `stty size` in the child. Planted
defect: `TIOCGWINSZ` passed to the kernel; `stty size` fails, and the test fails.

## Blocker

PodUtils/podcrates must give `pod-term` a line discipline that follows a termios state (asked as COORD-055,
#232; podcrates' entry 539, in work for a later tag, as its COORD-080 says): it answers the same calls from the same state as T-776, whose mode is that one. podssh takes it by
that tag (work on a taken crate is done in PodUtils/podcrates), then this entry opens again.

