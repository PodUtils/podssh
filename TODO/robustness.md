The work that makes the tests of podssh find more defects: fuzzing of the
parsers, a scored interop harness, a terminal oracle, stated resource limits,
property tests, a fault-injection harness for M6, and expected exit codes
that come from stock OpenSSH. Each entry changes tests and harnesses, not
what a user sees. The main sources are GitHub #25 and GitHub #34.

# T-198: Fuzz each parser

**Source:** GitHub #25 (Nemo-010, 2026-10-08); the quic-ssh report in GitHub #18
(`VLOD-ZDOV/quic-ssh:fuzz/fuzz_targets/`) and the fux report in GitHub #19
(`gold-silver-copper/fux:diff/fuzz/`), read in the reports, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh parses bytes from a relay, a proxy, an SSH server, and files that
other programs wrote. Each parser has tests with inputs that a person chose.
No test gives a parser input that nobody chose, so a panic or a wrong
acceptance on rare input stays hidden. The release build aborts on a panic
(`panic = "abort"` in `Cargo.toml`), so such a panic stops the process.

## Premise

Read, the parsers that take input from a peer or a file: WebSocket frames
(`PodUtils/podssh:crates/podssh-ws/src/frame.rs:144`); HTTP heads and chunked bodies
(`PodUtils/podssh:crates/podssh-ws/src/http.rs:125`, line 183 at `e892b0f`); the upgrade answer
(`PodUtils/podssh:crates/podssh-ws/src/handshake.rs:195`); proxy URLs
(`PodUtils/podssh:crates/podssh-ws/src/proxy.rs:82`), `NO_PROXY` and the CONNECT status
(`crates/podssh-ws/src/dial.rs`, lines 178 and 334 at `22c3b88`); since T-070 (2026-10-11), a
SOCKS5 proxy's answers (`PodUtils/podssh:crates/podssh-ws/src/socks5.rs:156`); close
reasons (`crates/podssh-ws/src/close.rs:48`); PEM bundles
(`PodUtils/podssh:crates/podssh-ws/src/bundle.rs:72`); relay lists and the pool document
(`PodUtils/podssh:crates/podssh-relay/src/relay.rs:173`, `PodUtils/podssh:crates/podssh-relay/src/pool.rs:153`);
`known_hosts` lines, in a private function
(`crates/podssh-ssh/src/known_hosts.rs:250`); the escape filter
(`crates/podssh-ssh/src/escape.rs:94`); IRC lines and frames
(`crates/podssh-core/src/irc/encode.rs:88`,
`crates/podssh-core/src/irc/framing.rs:110`); the command line
(`crates/podssh-cli/src/tree.rs:128`). No fuzz target exists. libFuzzer is
C++, and the message of commit `a378863` says that `rust:1-alpine` has no C++
compiler.

## Approach

1. Add fuzz/ in the layout of cargo-fuzz, as its own workspace that the root
   workspace excludes (as it excludes `vendor/tailscale-rs`). It is not a
   library crate, so the no-C rule (`docs/decisions.md`) does not apply,
   and the library crates get no new dependency. Invariant: the gate builds
   nothing new.
2. One target for each parser. Each asserts more than "no panic": `decode`
   consumes at most its input, and a control frame has FIN and 125 bytes or
   fewer (fails until T-063); `forward_path` after `parse_relay_list` has the
   form `/connect/HOST/PORT`; `one_line` leaves no control character
   (`SECURITY.md:259-262`); `Reassembler::push` stays under a stated limit
   (fails until T-096); the command line target calls `parse`, never the
   dispatch, so no target reaches the network.
3. Reach a private parser through a wrapper under `#[cfg(fuzzing)]`, which
   cargo-fuzz sets, so the public API does not change.
4. Seeds from bytes that podssh did not make:
   `crates/podssh-core/tests/fixtures/grammar.txt`,
   `crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt`, and the
   frames of `PodUtils/podssh:crates/podssh-ws/tests/rfc6455.rs`.
5. A scheduled workflow (also by hand) runs each target for 120 s with a
   pinned nightly toolchain and `-rss_limit_mb=512`, and keeps a crash input
   as an artifact; it is not in the gate (nightly Rust and C++). Each crash
   becomes a unit test first, then a repair. docs/development.md and
   docs/STATUS.md name the targets and the last run.

## Decision

Recommendation: cargo-fuzz (libFuzzer) in its own workspace: its coverage
guidance reaches parser states that random input seldom reaches. Property
tests alone (T-202) lost: they explore the bytes blindly. Both stay: T-202 in
the gate on stable Rust, the fuzzer on a schedule.

Decided in the work (2026-10-11):
- The targets run on Linux with glibc and the address sanitizer only. On
  Windows the link of libFuzzer's coverage needs MSVC's sanitizer runtime,
  which these build tools lack; on musl, the build image's C library, each
  target died of a signal within five inputs. This machine runs them in
  `docker.io/library/rust:1-trixie` through `scripts/dev.sh` and its
  `PODSSH_BUILD_IMAGE`, and CI on `ubuntu-24.04`. A target with no
  sanitizer on musl lost: its crashes were the C library's, not podssh's.
- The fuzz crate depends on `podssh-cli`, for the target of the command line,
  and so builds aws-lc: a second fuzz crate for one target lost, as cargo-fuzz
  builds the targets of one crate once.
- A private parser is reached through a function under `cfg(fuzzing)`, and
  its crate declares the cfg (`[lints.rust]`), so that clippy's
  `unexpected_cfgs` passes with `-D warnings`. Making the parsers public
  lost: the public API would grow for the fuzzer alone.
- An input that a target found is kept as a unit test in the crate of its
  parser (`crates/podssh-core/tests/fuzz_found.rs`, and next to the tests of
  each other parser), so the gate runs it on stable Rust at each push.

## Prove

```sh
cargo +nightly fuzz list                                  # one target for each parser of the Premise
cargo +nightly fuzz run ws_frame -- -max_total_time=120 -rss_limit_mb=512
cargo +nightly fuzz run close_reason -- -max_total_time=120 -rss_limit_mb=512
sh scripts/dev.sh check                                   # the gate does not change
```

The list names each target, and each run ends with no crash (`ws_frame`
after T-063). Planted defect: remove the length guard of
`close_code_and_reason` (`crates/podssh-ws/src/close.rs:21-23`);
`close_reason` must crash within its 120 s.

## Correction

2026-11-10. The targets `ws_frame`, `ws_upgrade` and `close_reason` fuzzed the WebSocket code of
`crates/podssh-ws`, which went to `pod-ws` of PodUtils/podcrates when podssh took it (T-684,
`v0.13.0`): they run in podcrates' `fuzz/` now, beside the code that they read, and podssh's copies
are gone (`fuzz/Cargo.toml`, `fuzz/fuzz_targets/`). The Prove's runs of `ws_frame` and
`close_reason` and the counts below are this entry's history; a run of them is podcrates'.

## Done

2026-10-11, in the commit that closes this entry.
- `fuzz/` (its own workspace; the root excludes it, so the gate builds none of it): 18 targets,
  one for each parser of the Premise, each with checks beyond the absence of a panic, written in
  its first lines; `fuzz/src/lib.rs` checks text that is safe on one line. `scripts/fuzz.sh` (a
  pinned nightly, cargo-fuzz 0.13.2, the address sanitizer, glibc only),
  `scripts/fuzz-seeds.py` (seeds from RFC 6455's frames, the IRC grammar fixture and the hosts
  of the relay's document), `.github/workflows/fuzz.yml` (each Monday and by hand), and the
  section "Fuzzing" of `docs/development.md`. `cargo +nightly fuzz list` names the 18.
- Each target ran 120 s on glibc with the address sanitizer
  (`PODSSH_BUILD_IMAGE=docker.io/library/rust:1-trixie sh scripts/dev.sh run -- 'sh
  /work/scripts/fuzz.sh 120'`), with no crash: ws_frame 53.0 M inputs, known_hosts_line 32.0 M,
  pem_bundle 29.0 M, connect_status 22.8 M, socks5_answer 22.3 M, one_line 19.2 M, proxy_url
  17.3 M, http_chunked 15.4 M, escape_filter 13.4 M, relay_pool 11.4 M, ws_upgrade 10.3 M,
  close_reason 10.0 M, http_head 6.2 M, relay_list 4.4 M, no_proxy 2.9 M, irc_message
  3.4 M, irc_framing 2.2 M, cli_args 0.5 M.
- Found, each repaired with a test first:
  - `irc_message`: a line `:prefix :text`, a trailing with no command, stopped the IRC parser
    with a panic, which the release build turns into an abort: one line of a server ended
    `podssh chat --irc`. `Message::parse` now refuses it, and `parse_command` no longer slices
    past a missing command (`crates/podssh-core/tests/fuzz_found.rs`; planted, the refusal
    removed, the test fails).
  - `irc_message`, again: `@ @ :` parsed as a command named `@`, which `to_wire` wrote as it
    was, and which a server reads back as tags. The encoder now takes a command of letters or
    three digits only (RFC 2812, section 2.3.1), and the test of the same file checks it.
  - `ws_upgrade`: a refused upgrade kept the peer's head whole, ESC included, in its message;
    it is now made safe for one line (`tests/rfc6455.rs`).
  - `proxy_url`: a host such as `]_::` parsed, and its URL did not parse back; a host with a
    bracket, `@`, `/`, `?`, `#`, a space or a control character is now refused (`tests/socks5.rs`).
  - Read for `http_chunked`: a chunk size near the largest number wrapped the sums of
    `decode_chunked`, a panic with overflow checks and, in the release build, a slice that ends
    before it starts (`tests/http.rs`; the old code fails the test).
  - Read for `pem_bundle`: an empty CERTIFICATE block passed as a certificate; it is refused by
    name (`tests/bundle.rs`).
- Three checks of the targets were wrong and were corrected: the escape filter holds an escape
  across reads, so its bound is for the stream; a Latin-1 line is two bytes of UTF-8 for each
  byte above 0x7f; the count of a lost IRC line depends on where the frames were cut. The IRC
  message target drops NUL first, as the byte layer does.
- Planted, in the build image's copy only: with the length guard of `close_code_and_reason`
  removed, `close_reason` crashed at its first input; with `decode_chunked` as it was,
  `http_chunked` crashed after 6.9 M inputs.
- Native, Windows: `cargo test -p podssh-core` and `-p podssh-ws`, each suite passed (185 in
  podssh-ws); `cargo clippy --all-targets -D warnings` for the five crates that changed.
- CI, `.github/workflows/fuzz.yml`, started by hand: the run of `5a88857` (38115715408) built
  the targets for musl, the default of cargo-fuzz's release binary, where the sanitizer does
  not work; `scripts/fuzz.sh` names the host's target since `6529789`, whose run (38115798595)
  passed: 18 targets, 120 s each, with the address sanitizer on glibc and no crash, from 0.5 M
  inputs (cli_args) to 50.6 M (ws_frame).

# T-199: A scored interop harness

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for a scored
interop harness; `lablup/bssh:docs/openssh-regress.md` and
`lablup/bssh:tests/openssh-regress/baseline.json`, read in the report, not
verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The interop harnesses print `ok`, `FAIL` and `skip` lines, and the gate fails
only on `FAIL`. A check that becomes `skip` because the environment changed
passes with no word. A check that someone deletes lowers the total, and
nothing sees it. The totals in docs/STATUS.md ("62 of 62", "98 of 98") are
counted and typed by hand.

## Premise

Read, at `b81480d`: `scripts/interop.sh` defines `ok`, `bad` and `skipped`
(lines 22-24), and fails only when a check failed (lines 445-446). With no
`sshd.pam` in the image, the PAM check becomes `skip` and the gate stays
green (lines 180-186). A name carries values of the run (the seconds at
line 350, the tty at line 391), so it is not a stable key. The formats
differ: `ok` and four spaces in `scripts/interop.sh` (line 22) and
`scripts/interop-pty.py` (line 34), three in `scripts/interop-man.sh` (line
23). The gate shows the last 80 result lines only (`scripts/gate.sh`, line
337). The totals are typed in `docs/STATUS.md` (line 21 at `b81480d`, line
57 at `3cbf215` and line 196 at `22c3b88`).

## Approach

1. Give each check a stable id as its first word, in each harness
   (`PodUtils/podssh:scripts/interop*.sh`, `scripts/interop-pty.py`,
   `scripts/interop-conpty.py`), for example `ok    ssh.exit.dropbear.143 ...`.
   The text after the id can keep values of the run.
2. One line format for all: `VERDICT ID TEXT`, with the verdicts `ok`, `FAIL`,
   `skip` and `env`. `env` names a precondition of the host that is missing
   (the PAM case becomes `env`).
3. A committed baseline (proposed: scripts/interop-baseline.txt): one line for
   each id with the verdict that it must have (`pass`, or `env-allowed` with
   the reason), and a floor of passes for each harness.
4. A scorer reads the whole output of each harness. It fails when an id that
   must pass did not pass (also as `skip` or `env`), when an id is missing or
   unknown, or when a floor is not met. It prints one table: pass, fail, env
   and skip for each harness.
5. `scripts/gate.sh` runs the scorer after the interop and man steps, with
   `run` (`scripts/gate.sh:64-78`). docs/STATUS.md quotes its table, and
   docs/development.md says that the baseline changes with the check, in the
   same commit.

Pitfall: `scripts/interop-conpty.py` runs on Windows only
(`scripts/interop-conpty.py:27-28`). The job `windows` of CI runs it at each
push, through `scripts/interop-conpty-msys2.py` (T-214); this entry adds its
ids to the baseline, and scores that job's output.
T-225 is another question: where each expected exit code comes from.

## Decision

Recommendation: the scorer as a Rust integration test (proposed:
crates/podssh-cli/tests/interop_score.rs). With no log, it checks that the
scripts and the baseline have the same ids, so each `cargo test` (on Windows
too) sees a new or a deleted check; with the logs named by a variable, the
gate scores them. A Python scorer beside `scripts/check-repo.py` lost: its
static half would run only where the gate runs.

Taken otherwise, with these calls made in the work (2026-10-11). The scorer
is a command of the record's checker, `cargo todo interop`
(`crates/podssh-todo/src/interop/mod.rs`): with no log, it compares the ids
that the scripts can print with the baseline; with `--logs FILE...`, it
scores a run, each log by its name (`interop.log` is the run `interop`).
`crates/podssh-todo/tests/interop.rs` runs the check on this repository's
scripts, so each `cargo test` of the workspace sees a new or a deleted
check, on Windows too. A test of `podssh-cli` lost: the step `release` has
the logs and builds no test of the CLI, and the test would build the CLI
only to read text; `podssh-todo` already reads the repository's text, and
builds with no C compiler. An id is read as the scripts are written
(`crates/podssh-todo/src/interop/words.rs`): the first word after `ok`,
`bad`, `expect_rc`, `skipped`, `unmet` or `no_part`, quoted or not, outside
comments and heredocs, with `${VAR}` and `${VAR%%:*}` taken from the
nearest `for VAR in WORDS` above, whose words must be literal; in Python,
the literal first argument of `check(`. Each line that printed only on a
failure became a pair, so that each id prints one line in each run. The
PAM check is `pass` in the baseline, not `env-allowed`: `scripts/interop.sh`
installs `openssh-server-pam` itself, so a missing `sshd.pam` is the change
of the host that the scorer must catch.

## Prove

```sh
cargo test -p podssh-todo --test interop                     # the ids of the scripts equal the baseline
cargo todo interop                                           # the same check, by hand
sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh release'  # the step scores each harness against the baseline
```

The test passes with no log, and the step prints a row `score` for each
harness and exits 0. Planted defect 1: delete the check
`ssh.exit.signal_named` from `scripts/interop.sh`; `cargo todo interop` must
fail and name the id. Planted defect 2: the PAM check gives `env`, as with
no `/usr/sbin/sshd.pam` in the container; the scorer must fail.

## Correction

2026-10-11: the Premise named the tty at line 334 of `scripts/interop.sh`,
which at `b81480d` was a comment of the `-s sftp` check; the tty was at line
391. The Premise now reads at `b81480d`, the tree before this entry's work.

## Done

2026-10-11. Each check of the harnesses prints `VERDICT ID TEXT`
(`scripts/interop-lib.sh`, which `scripts/interop.sh` and
`scripts/interop-man.sh` source; `check()` in the two pty scripts), with an
id of the harness's prefix: 322 ids in 18 harnesses. A loop's label stands
in the id for a value (`ssh.exit.${srv%%:*}.${spec%%:*}`), and a check that
printed only on a failure is now a pair. The PAM case prints `env` when
`sshd.pam` is missing. `scripts/interop-baseline.txt` names each harness
with its run and floor, and each id with `pass`. `cargo todo interop`
(`crates/podssh-todo/src/interop/`) checks the scripts against it, and with
`--logs` scores a run; the step `release` of `scripts/gate.sh` shows every
result line and scores the logs of the interop and man runs; CI's job
`windows` scores the console checks (`--log` of
`scripts/interop-conpty-msys2.py`). `docs/development.md` says that the
baseline changes with its check.
- `cargo test -p podssh-todo`: each suite passed, `tests/interop.rs` 11 (the
  repository's own scripts against the baseline, and a planted case of each
  disagreement and of each way a run misses it). `cargo todo interop`: "322
  ids of 18 harnesses meet scripts/interop-baseline.txt".
- In the build image, `sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh
  release'` (11 min): interop 301 passed, 0 failed, 0 skipped, 0 env; the
  man page 7 of 7; each harness at its floor (ssh 71, status 6, keygen 28,
  agent 18, local 6, control 13, faults 27, ping 3, relay 4, socks 4, cp 68,
  mv 18, sftp 5, resume 9, pipe 9, pty 12, man 7); "gate green (release)".
- Planted defect 1: with `ssh.exit.signal_named` deleted from
  `scripts/interop.sh`, `cargo todo interop` exits 1: "ssh.exit.signal_named
  is printed by no line of scripts/interop.sh". Planted defect 2, on the
  lines of that run: with the PAM check as `env`, the scorer exits 1:
  "ssh.auth.kbdint_pam gave env, where ok is due", and ssh passed 70 checks,
  under its floor of 71.
- CI at `72ca309` (run 38118496778): every job passed; the step `release`
  scored interop 301 of 301 and the man page 7 of 7, and the job `windows`
  the console checks, conpty 14 of 14, each at its floor.

# T-200: A terminal oracle

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for a real-terminal
oracle; the fux report in GitHub #19 and GitHub #20
(`gold-silver-copper/fux:diff/oracle/`), read in the report, not verified
here.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

podssh writes to a terminal in three places: its own messages in raw mode,
text from a peer after the sanitizer, and (in M5) the echo of its line
discipline. The tests compare these bytes with expected bytes. No test asks
what a terminal shows after the bytes: where the cursor is, and which rows
changed. A wrong cursor column, or lines that step down like stairs, passes a
byte test that a person wrote with the same mistake.

## Premise

Read:

- `crates/podssh-ssh/src/log.rs:157-173` turns LF into CR LF when the terminal
  is raw. The help of `~?` (`crates/podssh-ssh/src/escape.rs:141-150`) goes
  through it. The raw state is a global (`raw_active`), so a test cannot set
  it from outside.
- `crates/podssh-ws/src/text.rs:12-51` is the one sanitizer for text from a
  peer (`SECURITY.md:259-262`).
- docs/terminal.md gives the redraw sequence and the refusals of the line
  discipline (`docs/terminal.md:178-274`). T-127 (the cursor counts bytes) and
  T-129 (Home and End do not move the screen's cursor) are screen defects.
- Read in the message of commit `a378863`: `rio-vt` needs `simdutf`, a C++
  library, so it cannot be a dependency of a library crate.

## Approach

1. A model of a VT terminal for the tests: the `vt100` crate (pure Rust, over
   `vte`) as a dev-dependency. The gate's library test step runs under
   `CC=/nonexistent` and `CXX=/nonexistent` (`scripts/gate.sh:207-210`), so it
   shows that no C or C++ comes with it.
2. A helper: bytes in, screen out (rows, cursor, attributes). Each case
   compares screens, not bytes.
3. Cases for the default build first. (a) A message and the `~?` help in raw
   mode: each line starts at column 0. Make the newline rule a pure function
   first, so that the test does not touch the global state. (b) `one_line` of
   hostile text (ESC, CSI, BEL, CR, bidirectional controls): the screen shows
   the text on one row, and the cursor moved only by its width.
4. Cases for M5, with T-125 to T-129: after any sequence of keys, the screen
   shows the prompt and the buffer, and the cursor is at the buffer's cursor,
   also with UTF-8 text. These cases are the regression tests of T-127 and
   T-129.
5. Calibrate the model once: a fixed corpus of sequences goes through `tmux`
   in the gate's container (installed with apk, as `scripts/interop-man.sh:22`
   installs groff) and through `vt100`. The two must give the same screens
   before the model judges podssh.
6. docs/terminal.md, section "Tests" (`docs/terminal.md:575`), names the
   oracle.

## Decision

Recommendation: `vt100` in unit tests, calibrated against tmux. It is fast,
needs no process and no pty, and runs on Windows too. tmux alone lost: each
case would need a pty and a process. A model with C++ dependencies (`rio-vt`)
lost by the no-C rule.

Decided in the work (2026-10-12):
- `vt100` 0.15 (MIT, pure Rust over `vte`), a dev-dependency only. Its
  `Parser`, rows, cursor and cells are all that the tests use, so a later
  release, which may share `unicode-width` 0.2 with the workspace where 0.15
  brings 0.1 into the tests, is a change of one line.
- One model, `PodUtils/podssh:crates/podssh-terminal/tests/screen/mod.rs`, which the tests
  of podssh-ws and podssh-ssh read through `#[path]`, as podssh-ts reads a
  test of the fork. A copy in each crate lost: three models can disagree, as
  two sanitizers once did. A crate of its own for tests lost: a workspace
  member for one file.
- What the screen must show comes from the model too: the prompt and the
  line drawn on an empty screen, and the cursor where a mark after the text
  before the line's cursor lands. Each cell from the prompt's row down must
  agree. A model of the wrap written in the test lost: it would be a second
  copy of the rules of `PodUtils/podssh:crates/podssh-terminal/src/echo/screen.rs`, and the
  oracle would judge the discipline by its own rules.
- The runs of keys come from a fixed xorshift, as `pseudo_random` in
  `PodUtils/podssh:crates/podssh-relay/tests/session_replay.rs`, with the seed in each
  failure. proptest lost here: T-202 brings it to other crates, and a run of
  keys needs no shrinking to be read.
- The runs leave out the control bytes that the discipline types into the
  line (TAB, VT, FF and the like) and an accent typed alone. A terminal
  moves its cursor for the first in its own way, where T-127 decided one
  cell; and an accent echoed after a row that the line filled lands on the
  next row, where a terminal has no letter to put it on. The oracle would
  show both; neither is a regression of T-127 or T-129.
- The calibration runs in the gate's step `libs`, in the tests of the
  library crates, with `PODSSH_TEST_TMUX` as `PODSSH_TEST_OPENSSL` is set
  there. A script beside `scripts/interop-man.sh` lost: the comparison needs
  the model, which is Rust. No sequence of the corpus ends with the cursor
  past the last column, which tmux and the model report each in its own way,
  and which the discipline never leaves.

## Prove

```sh
cargo test -p podssh-ssh --test terminal_oracle   # raw-mode messages and the ~? help, as screens
cargo test -p podssh-ws --test terminal_oracle    # sanitized peer text, as screens
sh scripts/dev.sh check                           # the model and tmux agree on the corpus
```

Each command exits 0. Planted defect: remove the CR LF conversion
(`crates/podssh-ssh/src/log.rs:169-171`); the help case must fail. After M5,
`cargo test -p podssh-terminal --test oracle` must fail while T-127 is open.

## Correction

2026-10-12: the oracle's first run found a defect of the line discipline,
which the draft could not see, as it had not run. With IUTF8 on 8 and 16
columns, `screen_runs_of_keys_with_iutf8_on_8_columns` (seed 1016) and its
neighbour on 16 columns failed: a redraw over rows wrote the prompt and the
line in one piece, and where a wide character did not fit in the last cell
of a row, the terminal took it to the next row and kept what that cell
held, a `7` of the line before. `PodUtils/podssh:crates/podssh-terminal/src/echo/screen.rs`
said that the terminal leaves the rest of such a row blank; the `vt100`
model keeps it. `redraw_rows` now writes the line a step at a time, with
`ESC [ K` before a wide glyph that starts the next row, and the module's
note says so. tmux agreed with the model after the change (the calibration
below).

2026-10-12: tmux 3.7c's `capture-pane -p` gives the cells that a tab
skipped as the tab itself, so the case `bell-and-tab` differed in its text
and not in its screen (the cursor in column 9 in both).
`PodUtils/podssh:crates/podssh-terminal/tests/calibration.rs` reads each tab of tmux's rows
as the blanks up to the next stop of 8.

## Done

2026-10-12. Written as a draft, then merged over T-183: `message_text` stays
pure, and the prefix of a host (T-183) goes on each line in `host_text`.
- The model: `vt100` 0.15 in `[workspace.dependencies]` (`Cargo.toml`), a
  dev-dependency of podssh-terminal, podssh-ws and podssh-ssh.
  `PodUtils/podssh:crates/podssh-terminal/tests/screen/mod.rs`: bytes in, a screen out (each
  row, the cursor, each cell's character and attributes, the other screen).
- The newline rule is a pure function, `podssh_ssh::log::message_text`
  (`crates/podssh-ssh/src/log.rs`), which `Log::write` calls with the state
  of raw mode; the test touches no global state.
- `PodUtils/podssh:crates/podssh-terminal/tests/oracle.rs` (M5, T-125 to T-129 being done):
  `screen_t127_a_wide_character_and_an_accent_take_their_cells`,
  `screen_t127_backspace_takes_a_whole_character_off_the_screen`,
  `screen_t126_a_wide_character_that_does_not_fit_starts_the_next_row`,
  `screen_t129_home_end_and_delete_on_a_line_of_three_rows`,
  `screen_t129_output_goes_above_the_line_under_edit`,
  `screen_t129_history_and_ctrl_c_on_rows`, and 1100 runs of up to 48 steps
  from a fixed xorshift: `screen_runs_of_keys_with_iutf8_on_16_columns`,
  `screen_runs_of_keys_with_iutf8_on_8_columns`,
  `screen_runs_of_keys_without_iutf8_on_20_columns` and
  `screen_runs_with_no_width_known_stay_on_one_row`. Each checks the screen
  after each key, and after output that ended its row.
- `crates/podssh-ws/tests/terminal_oracle.rs`:
  `hostile_text_through_one_line_stays_on_its_row` (16 hostile texts: ESC
  and C1 sequences, BEL, BS, CR, LF, VT, FF, DEL, NUL, the bidirectional
  controls), `a_hostile_banner_through_multi_line_shows_its_lines_as_rows`,
  and the control `the_model_shows_what_the_sanitizer_prevents`.
- `crates/podssh-ssh/tests/terminal_oracle.rs`:
  `the_help_of_tilde_question_shows_each_line_from_the_first_column`,
  `a_message_of_several_lines_shows_each_from_the_first_column`,
  `after_the_server_s_output_a_message_and_the_help_start_on_rows_of_their_own`,
  and the control
  `without_raw_mode_the_text_keeps_its_line_feeds_which_a_raw_terminal_shows_as_stairs`.
- The calibration: `PodUtils/podssh:crates/podssh-terminal/tests/screen/corpus.txt`, 33
  sequences of the kinds that podssh writes, and
  `PodUtils/podssh:crates/podssh-terminal/tests/calibration.rs`:
  `the_corpus_reads_and_the_model_draws_each_case`,
  `the_model_and_tmux_show_the_same_screens` (each sequence raw in a tmux
  pane of its own, each call of tmux within 10 s) and
  `the_scratch_directory_goes_when_the_server_goes`. `scripts/gate.sh`, step
  `libs`, installs tmux and names it with `PODSSH_TEST_TMUX`.
- `docs/terminal.md` ("Tests"), `docs/development.md` (the step `libs`) and
  `docs/STATUS.md`.
- Here (Windows 11): `cargo test -p podssh-terminal` (the oracle 10
  passed, with the redraw of the Correction; the calibration said that it
  did not run, with no tmux), `cargo test -p podssh-ws --test
  terminal_oracle` 3 passed, `cargo test -p podssh-ssh --test
  terminal_oracle` 4 passed; clippy of the three crates clean. Planted: the
  CR LF conversion of `message_text` removed, 3 of the 4 cases of
  podssh-ssh failed, the help's among them; the cells of a step counted as
  its bytes in `PodUtils/podssh:crates/podssh-terminal/src/echo/units.rs`, 6 of the 10
  cases of the oracle failed. Both were taken out.
- In the build image (Alpine, tmux 3.7c, `CC` and `CXX` at `/nonexistent`
  as in the gate's step `libs`): the calibration 3 passed (the model and
  tmux show the same screens for the 33 sequences), the oracle 10, the
  oracle of podssh-ws 3, and of podssh-ssh 4; clippy clean. `vt100` 0.15.2
  and `vte` 0.11.1 built with no C compiler.

# T-201: Resource limits, stated and tested

**Source:** GitHub #25 (Nemo-010, 2026-10-08), the request for explicit
resource bounds; the rose report in GitHub #18 (`nikhiljha/rose:doc/spec.md`,
line 125) and the MobaRust report in GitHub #21
(`OthmaneBlial/MobaRust:apps/desktop/src-tauri/src/ssh_backpressure_test.rs`),
read in the reports, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh keeps many bounds on memory and time, but no document lists them, and
few tests push a peer past one. A user cannot know how much memory a session
can use, or what happens at a limit. A change that removes a bound passes the
tests.

## Premise

Read, the bounds today:

- A frame: 262144 bytes (`PodUtils/podssh:crates/podssh-ws/src/frame.rs:30`, refused at lines
  180-194). A message in fragments: 16 MiB
  (`PodUtils/podssh:crates/podssh-ws/src/session.rs:36`, checked at lines 240-242 at `23b5d82`).
- A response head: 16 KiB for HTTP (`PodUtils/podssh:crates/podssh-ws/src/http.rs:13`), for the
  proxy (`PodUtils/podssh:crates/podssh-ws/src/dial.rs:25`) and for the upgrade
  (`PodUtils/podssh:crates/podssh-ws/src/handshake.rs:144`).
- The pool document: 256 KiB (`PodUtils/podssh:crates/podssh-relay/src/pool.rs:37`). A cache
  file: 64 KiB (`crates/podssh-relay/src/cache.rs:51`).
- The SSH window: 512 KiB (`crates/podssh-ssh/src/run.rs:30`). The relay pipe:
  256 KiB each way, frames of 64 KiB
  (`crates/podssh-ssh/src/relay_stream.rs:36-39`). Pump buffers: 32 KiB
  (`crates/podssh-cli/src/pipe/pump.rs:24`).
- Time: `crates/podssh-ws/src/client.rs:29-46`,
  `PodUtils/podssh:crates/podssh-relay/src/open.rs:33-37`, `crates/podssh-ssh/src/session.rs:22`.
- No limit: a `known_hosts` file was read whole (`crates/podssh-ssh/src/known_hosts.rs`,
  lines 186-192 at `72ca309`); the IRC buffer (T-096).
- Two texts disagreed until T-024. The comment on the SSH window
  (`crates/podssh-ssh/src/run.rs` lines 25-28 at `80f20bf`) said that the
  relay drops a frame when more than 1 MiB waits (`1011 relay
  backpressure`): the row of the reverse path in the relay's document
  (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`). It
  now gives the forward path's rule (`crates/podssh-ssh/src/run.rs:26-29`):
  `docs/relay.md:570-582` says that backpressure closes with `1013` at
  2 MiB and drops no frame. T-062 measures whether that check operates.

## Approach

1. A section "Limits" in docs/architecture.md: one row for each bound, with
   its value, its file, and what podssh does at the bound (the error and its
   exit code). Name the two missing limits as missing.
2. The table states the forward path's bound, as the comment at
   `crates/podssh-ssh/src/run.rs:26-29` does since T-024, and the result of
   T-062 when it exists.
3. Tests in the process, with a peer over `tokio::io::duplex`, so no network
   (`docs/development.md:591-594`): a proxy head that never ends stops at
   16 KiB, and an upgrade head too; fragments past 16 MiB give the error, not
   more memory; a pool body over 256 KiB is refused; a cache file over 64 KiB
   is ignored.
4. A slow reader in the interop harness: `podssh ssh` whose stdout nobody
   reads for 30 s while the server writes 50 MB. First measure the peak memory
   (`VmHWM` in `/proc/PID/status`) with a fast reader. The bound is that value
   plus a margin; the check fails above it.
5. Give `known_hosts` a read limit (16 MiB, far above a real file) with a
   message that names the file, or state in the table that it has none.
6. In M6, the replay buffer joins the table (T-152, 2026-10-09): 4 MiB in
   each direction of each resumable session by default, 16 MiB at most with
   `PODSSH_REPLAY_BUFFER` (`PodUtils/podssh:crates/podssh-relay/src/session/replay.rs`); at
   the bound the writer waits for an `ACK`, and no byte is dropped. A node
   keeps 64 MiB of them at most, a whole buffer for each session that it
   keeps (`PodUtils/podssh:crates/podssh-relay/src/reverse/layered.rs`, T-153).

## Prove

```sh
cargo test -p podssh-ws --test limits      # each head and message bound, against a peer that never stops
cargo test -p podssh-relay --test limits   # the pool body and the cache file
sh scripts/dev.sh check                    # interop: the slow reader stays under the stated peak memory
```

Each command exits 0. Planted defect: set `WINDOW`
(`crates/podssh-ssh/src/run.rs:30`) to 64 MiB, and russh's queue of a
channel (`channel_buffer_size`, `crates/podssh-ssh/src/run_config.rs:69-83`) to
2^20 messages; the slow-reader check must fail. The window alone is not
enough: the queue is a second bound (Correction). A second plant: remove the
check at `PodUtils/podssh:crates/podssh-ws/src/session.rs:476-478`; the fragment test must
fail.

## Correction

2026-10-11, read against the Premise; each holds at the cited lines:

The test target `limits` of `podssh-ws` moved to `pod-ws` of PodUtils/podcrates when podssh took the crate: `cargo test -p pod-ws --all-features` there runs it, with its names.

- The frame's bound refuses a 64-bit length (`PodUtils/podssh:crates/podssh-ws/src/frame.rs:221-223`). The check
  after it (`PodUtils/podssh:crates/podssh-ws/src/frame.rs:229-231`) cannot fire: a shorter length is at most 65535.
- The upgrade that podssh sends is `client::upgrade`, whose bound was a literal; it is
  `UPGRADE_HEAD` now (`crates/podssh-ws/src/client.rs:49`). `MAX_HANDSHAKE_RESPONSE`
  (`PodUtils/podssh:crates/podssh-ws/src/handshake.rs:144`) bounds `handshake::handshake`, which no command calls.
- The steps of the connection wait `CONNECT_TIMEOUT` each (`PodUtils/podssh:crates/podssh-relay/src/open.rs:33`).
  `DEFAULT_TIMEOUT` (`crates/podssh-ws/src/client.rs:29`) is a default for an embedder, which no
  command of podssh takes.
- The IRC buffer has a bound since T-096: 8192 bytes for a line
  (`crates/podssh-core/src/irc/framing.rs:52`).
- `known_hosts` was read whole a second time, under the lock of a record (`append`); the bound
  covers both reads.
- A pool body past its bound, and a file of the cache past its bound, are dropped with no word:
  the refresh's error goes nowhere (`PodUtils/podssh:crates/podssh-relay/src/open.rs:417`), and the cache reads a
  file that it cannot use as none (`crates/podssh-relay/src/cache.rs:226-228`). Each is made again,
  so the table says so, and nothing is added.
- `PODSSH_REPLAY_BUFFER` above 16 MiB gives 4 MiB, the default, not 16 MiB
  (`PodUtils/podssh:crates/podssh-relay/src/session/replay.rs:27-31`), as its comment says: another value is
  ignored. The table says so.
- The window is not the only bound of a reader that takes nothing: russh queues at most 100
  messages of a channel (`channel_buffer_size`, its default, which
  `crates/podssh-ssh/src/run_config.rs:69-83` leaves), each of 32 KiB at most, and its task then reads
  no more from the server. Measured in the build image on 2026-10-11, with the Prove's plant: the
  window at 64 MiB gave a peak of 8948 KiB, held by the queue; the queue at 2^20 messages as well
  gave 62708 KiB, and even a reader that took each byte held 62084 KiB, as the server outran the
  output.
  So the check compares no reader with another: its ceiling is half of what the server writes,
  and the plant is both bounds.

## Done

2026-10-11. `docs/architecture.md`, "Limits": each bound of memory and of time, with its value,
its constant and file, and what podssh does past it; the relay's forward path, russh's queue of
a channel and the replay buffers of M6 among them. The upgrade's bound has a name,
`UPGRADE_HEAD` (`crates/podssh-ws/src/client.rs:49`); `known_hosts` has a bound of 16 MiB, in
both of its reads (`crates/podssh-ssh/src/known_hosts.rs:25`); the pool's request takes a stream
(`pool::request`), so that a test can serve it. `scripts/interop-limits.sh` measures a session
whose output nobody reads; `scripts/interop-baseline.txt` has its two ids.
- `cargo test -p podssh-ws --test limits`: 6 passed. Against a peer that never stops, the heads
  of the upgrade, of HTTP and of a proxy's CONNECT stop at 16 KiB, and the peer wrote less than
  the bound and 8 KiB before podssh stopped reading; a body of each framing is read at its bound
  and refused one byte past it; a frame of 262144 bytes is read, and a header of one byte more
  ends the session with a Close 1002 before its payload; 16 MiB of fragments are read whole, and
  one byte more ends the session with a Close 1009.
- `cargo test -p podssh-relay --test limits`: 3 passed. A pool of 256 KiB is read and one byte
  more refused, an endless pool body stops past the bound, and a file of the cache of 64 KiB is
  read and one byte more ignored, the pool's and a token's.
- `cargo test -p podssh-ssh --test known_hosts`: 17 passed. A file of 16 MiB is read; one byte
  more is unreadable, with its reason, and a record into it is refused, the file unchanged.
- Planted, natively: without the check of fragments
  (`PodUtils/podssh:crates/podssh-ws/src/session.rs:476-478`), a message of 16777217 bytes came through, and the
  test failed; without the bound of `known_hosts`, the larger file was read, and the test failed.
- In the build image, `scripts/interop-limits.sh` alone with the Prove's plants: as the code is, a
  reader that took each byte peaked at 6884 KiB, and one that took nothing for 30 s at 7460 KiB,
  under the ceiling of 24414 KiB; with the window at 64 MiB, 9444 and 8948 KiB, held by russh's
  queue; with the queue at 2^20 messages as well, 62084 and 62708 KiB, and both checks failed. The
  step `release` (`sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh release'`): interop 303
  passed, 0 failed, the reader that took each byte at 6836 KiB and the other at 7160 KiB, each
  harness at its floor (limits 2), and "gate green (release)".

# T-202: Property tests for the state machines

**Source:** the MobaRust report in GitHub #21
(`OthmaneBlial/MobaRust:crates/mobarust-core/tests/property_invariants.rs`),
read in the report, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The state machines of podssh are tested with chosen examples. A property that
must hold for each input (a round trip, or the same result for each split of
a stream) is checked only for those examples. A defect that appears with one
split of the input only is not found.

## Premise

Read: the candidates, each a pure function or a state machine with no I/O.

- WebSocket frames: `encode` and `decode` (`PodUtils/podssh:crates/podssh-ws/src/frame.rs:98`,
  `PodUtils/podssh:crates/podssh-ws/src/frame.rs:144`).
- The joining of fragments (`PodUtils/podssh:crates/podssh-ws/src/session.rs:470-494`). It is
  private, but `RelaySession::new` (`PodUtils/podssh:crates/podssh-ws/src/session.rs:114`) takes
  any stream, so a test can drive it.
- Relay lists and paths (`PodUtils/podssh:crates/podssh-relay/src/relay.rs:173-266`, `crates/podssh-ws/src/names.rs:8-85`).
- `known_hosts` patterns (`crates/podssh-ssh/src/known_hosts.rs:277-333`).
- The escape filter, which keeps its state from one read to the next
  (`crates/podssh-ssh/src/escape.rs:94-138`).
- The sanitizer (`crates/podssh-ws/src/text.rs:12-57`).

Read: no crate uses a library for property tests. `proptest` is pure Rust;
the gate must show it.

## Approach

1. `proptest` as a dev-dependency of podssh-ws, podssh-relay and podssh-ssh.
   The gate's library test step runs under `CC=/nonexistent` and
   `CXX=/nonexistent` (`scripts/gate.sh:207-210`), so it shows that no C comes
   with it. Commit the regression files of proptest as seeds.
2. One test file for each crate (tests/properties.rs), with these properties:
   - frames: for each opcode, FIN, role, mask and payload up to 262144 bytes,
     `decode(encode(f))` gives `f` and uses each byte; each shorter prefix gives
     `Ok(None)`;
   - fragments: a message cut into any fragments arrives whole; a total over
     16 MiB gives the error;
   - relay lists: the order stays, duplicates go, each host passes
     `check_host`, and `forward_path` has the form `/connect/HOST/PORT`;
   - `known_hosts`: a negated pattern that matches always rejects; a hashed
     pattern made from a name matches that name; the case of the letters does
     not change a match;
   - escapes: the input cut at any point gives the same bytes and commands as
     the whole input;
   - the sanitizer: `one_line` leaves no control or bidirectional character
     and no double space, and a second pass changes nothing.
3. Later, with their entries: the IRC reassembler (T-096) and the line
   discipline (T-125 to T-129).
4. 256 cases for each property by default, so the time of the gate stays
   bounded.

## Decision

Decided in the work (2026-10-12):
- proptest 1.11 with no default features and `std`: no fork of each case
  and no timeouts, which bring `rusty-fork`, `tempfile` and `wait-timeout`;
  `std` keeps the regression files and the strategies of regular
  expressions. Its minimum Rust is 1.85, the workspace's. A generator of
  the repository's own, as the xorshift of the terminal oracle (T-200),
  lost: the entry asks for the smallest input that fails, which is
  proptest's shrinking.
- Each failing input goes to `tests/properties.proptest-regressions`, beside
  its test (`FileFailurePersistence::WithSource`). proptest's default looks
  for a `lib.rs` above the test, finds none for a test of `tests/`, and
  says so on each run.
- Item 3 is done here: T-096 and T-125 to T-129 are done.
  `crates/podssh-core/tests/properties.rs` cuts the IRC framing anywhere;
  `PodUtils/podssh:crates/podssh-terminal/tests/properties.rs` cuts the keys anywhere and
  checks the line, the cursor and the history. What the screen shows is the
  terminal oracle's (T-200).
- The property of a message past 16 MiB takes 4 inputs: each moves more
  than 16 MiB through the session. Its bound is
  `PodUtils/podssh:crates/podssh-ws/tests/limits.rs` too, at 16 MiB and one byte more.
- A long payload of a frame comes from a seed (a fixed xorshift), and its
  length leans to where the length field changes (125, 126, 65535, 65536)
  and to the forward cap: a payload of 262144 bytes made byte by byte by
  proptest costs a megabyte of state.
- The IRC framing's losses are not compared between cuts: how much of a
  lost line a loss names depends on the cut (T-198). Its lines are, and a
  stream with no line past the limit loses none.
- With IUTF8, the cursor between characters is a property of whole keys: a
  lone byte of a character, which a terminal of UTF-8 never sends alone,
  can make a line of UTF-8 from bytes typed apart, with the cursor between
  them.

## Prove

```sh
cargo test -p podssh-ws --test properties
cargo test -p podssh-relay --test properties
cargo test -p podssh-ssh --test properties
sh scripts/dev.sh check     # proptest builds under CC=/nonexistent and CXX=/nonexistent
```

Each command exits 0. Planted defect: in `encode`, mask with
`masking_key[(i + 1) % 4]` (`PodUtils/podssh:crates/podssh-ws/src/frame.rs:131`); the round
trip of frames must fail and print the smallest frame that fails.

## Correction

The test target `properties` of `podssh-ws` moved to `pod-ws` of PodUtils/podcrates when podssh took the crate: `cargo test -p pod-ws --all-features` there runs it, with its names.

## Done

2026-10-13, in the commit that closes this entry.
- `proptest` 1.11 in `[workspace.dependencies]` (`Cargo.toml`), a
  dev-dependency of podssh-ws, podssh-relay, podssh-ssh, podssh-core and
  podssh-terminal.
- `PodUtils/podssh:crates/podssh-ws/tests/properties.rs`:
  `a_frame_reads_back_whole_and_no_prefix_is_a_frame`,
  `a_control_frame_that_rfc_6455_forbids_is_refused`,
  `a_message_cut_into_any_fragments_arrives_whole` (fragments, Pings
  between them, writes of any size, through `RelaySession` over an
  in-memory stream),
  `a_message_past_16_mib_in_any_fragments_ends_the_session_with_1009`,
  `one_line_leaves_one_line_and_a_second_pass_changes_nothing` and
  `multi_line_leaves_lines_and_a_second_pass_changes_nothing`.
- `PodUtils/podssh:crates/podssh-relay/tests/properties.rs`:
  `a_list_keeps_its_order_and_drops_its_duplicates` (each spelling: a
  scheme, a port, a `/`, capitals, spaces),
  `any_text_parses_only_to_hosts_that_pass_the_check`,
  `a_forward_path_is_three_segments_and_nothing_more` and
  `each_host_name_and_ipv6_address_is_a_target`.
- `crates/podssh-ssh/tests/properties.rs`:
  `a_negated_pattern_that_matches_rejects_the_name`,
  `a_hashed_pattern_matches_its_name_in_any_case`,
  `the_case_of_the_letters_changes_no_match`,
  `the_input_cut_anywhere_gives_the_same_bytes_and_commands` and
  `input_with_no_escape_character_passes_as_it_came`.
- `crates/podssh-core/tests/properties.rs`:
  `a_stream_cut_anywhere_gives_the_same_lines`,
  `a_stream_of_lines_within_the_limit_loses_none` and
  `any_bytes_cut_anywhere_stay_under_the_limit`.
- `PodUtils/podssh:crates/podssh-terminal/tests/properties.rs`:
  `keys_cut_anywhere_give_the_same_events`,
  `after_any_bytes_the_line_and_the_history_hold` and
  `with_iutf8_the_cursor_stays_between_characters`.
- `docs/development.md` ("Property tests") and `docs/STATUS.md`.
- Native, Windows 11, 2026-10-13: the five commands
  `cargo test -p CRATE --test properties` passed, 6 (podssh-ws), 4
  (podssh-relay), 5 (podssh-ssh), 3 (podssh-core) and 3
  (podssh-terminal). No property failed on the code, so no regression file
  is committed. Planted, the mask of `encode` with
  `masking_key[(i + 1) % 4]`: 3 of the 6 properties of podssh-ws failed,
  the round trip of frames first, each with its smallest input
  (`minimal failing input: f = Frame {`); restored, 6 passed.
- In the build image (`sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh
  lint libs msrv'`, 2026-10-13): the tests of the library crates with
  `CC=/nonexistent` and `CXX=/nonexistent` passed, so proptest brings no
  C, and the library crates checked on Rust 1.85. Clippy 1.99 refused two
  lines of `crates/podssh-ssh/tests/properties.rs` that clippy 1.98 here
  passed (`manual_ignore_case_cmp` and `byte_char_slices`); they use
  `eq_ignore_ascii_case` and a byte string now, and the step `lint` passed
  after it. `cargo deny` passed with proptest's crates.

# T-203: The fault-injection harness: latency, jitter, bandwidth, a new address

**Source:** `docs/design.md:765-767` (layers 2 and 3 need the harness
extended), and the exit criteria of M6 (`docs/ROADMAP.md`, M6; T-156).
**Category:** chore
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The fault harness tests the failures of one connection attempt: a relay host
that is down or silent, a 503, a proxy 502, a Close, a stall, a host that
stops. It cannot delay bytes, vary the delay, limit the bandwidth, or bring a
session back from a new address. The exit of M6 needs a session that
survives a stopped relay host, a new address of the client and a stall of 3
minutes, and no harness can test that yet.

## Premise

Read:

- The modes of the stand-in relay: `normal`, `refuse`, `blackhole`, `silent`,
  `stall` and `close` (`scripts/fake-relay.py:18-36`). The stand-in proxy maps
  names and answers a status (`scripts/fake-proxy.py:1-32`). Neither shapes
  the traffic.
- `scripts/interop-faults.sh:35-44` starts one stand-in for each fault; its
  checks are at lines 73-182 at `8d668b7` (`docs/STATUS.md:824-844`, 14 of 14 since T-236).
- The time limits that latency meets today: the SSH handshake, 60 s
  (`crates/podssh-ssh/src/options.rs:390`, enforced at
  `crates/podssh-ssh/src/run.rs:402-405`); a reply, 30 s
  (`crates/podssh-ssh/src/session.rs:22`); a write, 60 s, and liveness, three
  times 10 s (`crates/podssh-ws/src/client.rs:42-46`).
- The gate's container gets no added capability
  (`.github/workflows/build.yml:112-123`).

## Approach

1. New modes in `scripts/fake-relay.py`, applied in `pump` (lines 173-293 at `981b8fc`), in
   each direction: `delay:MS`; `jitter:MIN:MAX:SEED`, from a seeded generator,
   so that a run repeats; `rate:BYTES_PER_SECOND`, a token bucket;
   `cut:BYTES`, the TCP connection closed with no Close frame.
2. A new address: an option of `scripts/fake-proxy.py` binds its upstream
   socket to another loopback address (127.0.0.2), so the stand-in relay sees
   the client come back from a new address. The harness binds; podssh does
   not.
3. Checks for layer 1 now, each with a time limit: with 2 s each way, a
   command and its exit status come back (the handshake takes about five
   round trips); with a jitter of 0 to 1.5 s, 5,000,000 bytes up and back keep
   their digest; at 64 KiB/s, 2 MB arrive within the computed time plus 50 %;
   with `cut`, exit 255 and the relay is named.
4. With T-151 to T-155: a stand-in relay host stopped during a session, the
   session back from 127.0.0.2, and a stall of 3 minutes, each with the digest
   of a running transfer intact. T-156 uses these checks as its measurement.
5. Update docs/development.md (item 8 of the gate, item 9 since T-156,
   `docs/development.md:377-389`) and the faults table of docs/STATUS.md.

Pitfall: each check must show that its fault was injected (see Prove).

## Decision

Recommendation: shape the traffic in the stand-ins. They need no privilege,
and they run the same in the gate's container, in CI and on Windows. Linux
`tc netem` lost: it needs `CAP_NET_ADMIN`, which the gate's container does not
get, and it shapes all loopback traffic, the OpenSSH servers too.

2026-10-10, before the work:

- The new modes shape each direction in the stand-in relay's pump with a
  queue and a sender, so that order is kept: a jittered chunk waits for the
  one before it, as a TCP stream does. `rate` is a token bucket over each
  direction alone, as a link's capacity is.
- One more mode for T-156, which needs a stall that ends: `pause:AFTER:FOR`,
  each byte held both ways after AFTER seconds for FOR seconds, then let
  through. And the stand-in proxy's `--move SECONDS:ADDRESS`: SECONDS after
  the first tunnel, the open tunnels go silent with no RST, and each new
  tunnel leaves from ADDRESS (127.0.0.2), as a client whose address changed.
- The checks of item 3 also run natively, in an ignored Rust test that
  drives `podssh ssh` through the stand-in relay to the tests' SSH server
  (`crates/podssh-cli/tests/faults.rs`): a Windows run measures the modes now,
  where the gate's run waits for T-251.

## Prove

```sh
sh scripts/dev.sh check     # interop-faults: the delay, jitter, rate and cut checks pass
```

The faults section shows each new check as `ok`. Planted defect, built into
the harness as a control: the delay check of 2 s runs again with
`-o ConnectTimeout=5`, and it must fail with "did not finish within 5 s".
This shows that the delay was injected. After M6, the checks of T-156 must
fail when the resume layer is off.

## Correction

Item 4 needs the reverse road in the stand-in relay, which serves the
forward road only (`scripts/fake-relay.py:163-164`). T-156 builds it (its
item 1) and makes those checks its measurement (its items 2 to 5). T-203
gives T-156 the faults that those checks need: `pause:AFTER:FOR` for the
stall that ends, `cut` for a host stopped mid-session, and `--move` for the
new address.

## Done

2026-10-10.

- `scripts/fake-relay.py`: the modes `delay:MS`, `jitter:MIN:MAX:SEED`,
  `rate:BYTES`, `cut:BYTES` and `pause:AFTER:FOR`. Each direction has a
  shaper, a bounded queue in order: each frame to the client (data, Pongs,
  keepalives, Closes) and each chunk to the target goes through it, so a
  pause holds the Pongs too, and a Close waits for the bytes before it.
- `scripts/fake-proxy.py`: `--from ADDRESS` and `--move SECONDS:ADDRESS`;
  the log names the address of each tunnel.
- `scripts/interop-faults.sh`: four stand-ins more, and the checks of item
  3 with the planted control of the delay.
- `crates/podssh-cli/tests/faults.rs`, ignored: the same checks natively,
  through the tests' SSH server (which gained `echo`), and checks of `pause`
  and `--move`; the harness of T-157 starts a stand-in relay of any mode.
- Prove, native, Windows: `cargo test -p podssh-cli --test faults --
  --ignored --test-threads 1`: 6 passed, in about 3.5 minutes; the table is
  in `docs/STATUS.md`. `sh -n` and `scripts/check-scripts.py` (dash): the
  script parses. `cargo test --no-fail-fast`: 1014 passed, 0 failed, 30 ignored.
- Waits for T-251: `sh scripts/dev.sh check`, whose step of the faults runs
  the new checks with OpenSSH in the build image. The checks of item 4 are
  T-156's (the Correction).

# T-225: The interop gate takes each expected exit code from stock OpenSSH, beside the literal (GitHub #34)

**Source:** GitHub #34 (2026-10-08); the reporter read the workflow of
iroh-ssh (`rustonbsd/iroh-ssh:.github/workflows/build.yml`, lines 385-434),
read in the report, not verified here.
**Category:** chore
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The interop harness writes each expected exit code as a literal. A literal
is a claim about a server and a client. When a server, its configuration or
a release of OpenSSH changes the right code, the gate keeps its pass, and
nobody measures again.

## Premise

Read, each claim of GitHub #34 at the lines as they are now:

- The matrix is at `scripts/interop.sh:117-127`. It expects 3, 0, 1, 127 and
  143, against OpenSSH (port 2201) and Dropbear (port 2203). `grep -c` gives
  17 lines with `expect_rc`, each a call; the helper is
  `scripts/interop-lib.sh:53-126` (T-199). `scripts/interop-keygen.sh` has 6
  more, for `podssh keygen`.
- `scripts/interop.sh` (lines 31-32 at `5c7a1ad`) installed `openssh-server`,
  `openssh-keygen` and others, but no client package. No harness ran the stock `ssh`; only
  `scripts/sandbox-check.sh:318-331` does, in a sandbox. Nobody knows whether
  the gate's image has `/usr/bin/ssh`.
- `crates/podssh-ssh/src/io/msg.rs:35-42`, with `crates/podssh-ssh/src/io.rs:72-74`,
  maps an exit status that does not fit
  (the -1 of `railway.new`) to 255, and an exit signal to 128 plus its number
  (`docs/STATUS.md:247`, `docs/STATUS.md:253`).
- A correction to the framing of #34: for a signal, podssh differs from
  OpenSSH on purpose. `docs/cli.md:6481-6482` says 128 plus the signal's number,
  and that OpenSSH gives 255. `crates/podssh-ssh/src/lib.rs:16` says that the
  codes follow OpenSSH, with 128 plus a signal. The two texts disagree, and no
  record measures the code of OpenSSH.

## Approach

1. Settle the client first: in the gate's container, run `command -v ssh`
   before the package line. If it is missing, add the client package to
   `scripts/interop.sh:24`, and print its version (as `:98` does for the
   servers).
2. For each call of `podssh ssh` in the matrix and in the refusals (lines
   146-196), run the stock `ssh` first, with the same server, port, key,
   `known_hosts`, `BatchMode` and command, and a time limit. Record its exit
   code. Then run podssh and compare.
3. A table of the intended differences, each with its reason. Today one row:
   a signal (OpenSSH's code, against 128 plus the number;
   `docs/cli.md:6481-6482`). A difference that the table does not name fails,
   with both codes and the command.
4. Keep each literal as a second check with its own name, so that a change
   gives two named failures: "differs from OpenSSH" and "differs from the
   promise".
5. Refuse a reference of 0 for a case that must fail, so that a broken
   reference cannot pass.
6. Make `crates/podssh-ssh/src/lib.rs:16` and `docs/cli.md:6481-6482` agree with
   the measurement, and record the codes of OpenSSH in docs/STATUS.md.

Relation: T-199 (GitHub #25) scores the harness against a committed
baseline. This entry decides where each expected value comes from. With
T-199, each derived check gets its own id.

## Prove

```sh
sh scripts/dev.sh check     # interop: for each case, the code of OpenSSH, of podssh and the literal agree
```

The interop section shows, for each case, the reference code, podssh's code
and the literal, and the signal row as a named difference. Planted defect 1:
map an exit signal to 255 at `crates/podssh-ssh/src/io/msg.rs:42`; the literal
check of 143 must fail, and the table must report its signal row as broken.
Planted defect 2: let the reference run `true` in place of `exit 3`; the
derived check must fail.

## Correction

2026-10-12: the second item of the Premise no longer holds. Since `5521cbf`
(T-238, 2026-10-08), `scripts/interop.sh:24` installs
`openssh-client-default`, OpenSSH's `ssh`, for the % tokens of `ssh -G`,
and harnesses run it: `scripts/interop-status.sh` compares four exit codes
of a session with no status with it (T-026), and `ssh.config.jump_alias`
the code of `-J` through a `-F` file. The image has `ssh` because the
script installs it, so item 1 of the Approach needs no new package; the run
prints the client's path and version (`ref.client`). Also,
`scripts/interop-keygen.sh` has 20 calls of `expect_rc` now, none of them
for `podssh ssh`.

2026-10-12: "Today one row" is two rows short. Read in OpenSSH's source
(openssh-portable at its default branch, 2026-10-12; read, not run):
`client_input_channel_req` in `clientloop.c` takes `exit-status` and no
`exit-signal`, and `client_loop` starts its status at -1, so a signal gives
255, as `docs/cli.md:5657-5658` says. `check_host_key` in `sshconnect.c`
goes on past a changed key under `StrictHostKeyChecking=no`: it turns off
password and keyboard-interactive login and the forwardings, then accepts
the key, so `ssh.hostkey.changed_refused` gives 0 with OpenSSH. In
`hostfile.c`, a failed read ends the loop of `hostkeys_foreach_file` as the
end of the file does, so a directory named by `UserKnownHostsFile` reads as
empty; the key's add fails with a message only, and
`ssh.hostkey.unreadable_refused` gives 0 too. podssh refuses both on
purpose (`docs/cli.md`, "Prompts and time limits"; T-028), so the table
has three rows.

## Done

2026-10-13. What was made:
- `scripts/interop-lib.sh`: `stock_raw` runs OpenSSH's `ssh` with
  `-F /dev/null`, the environment of `p`, stdin from `/dev/null` and a
  limit of 60 s, and keeps its code (`none` with no `ssh`) and its stderr;
  `stock` adds the settings of `p`, with a `known_hosts` of its own;
  `p_ref` and `direct_ref` run it first and podssh after with the same
  arguments, and give podssh's code. The next `expect_rc` writes the case's
  id, literal, both codes, text and OpenSSH's command line to `$W/refs`.
- `scripts/interop.sh`: each case of the matrix (`ssh.exit.*`, 10), of the
  refusals of authentication (10) and of the host keys (5:
  `strict_known`, `changed_refused`, `unreadable_refused`,
  `unrecordable_connects` and `cert_accepted`) runs through `p_ref` or
  `direct_ref`. Its literal check `ssh.ID` stays as it was: "differs from
  the promise".
- `scripts/interop-reference.sh`, a new harness (`ref`, floor 26, in
  `scripts/interop-baseline.txt`), sourced after the host keys.
  `ref.client` names the client's path and version. `ref.ID` checks each
  of the 25 cases, "differs from OpenSSH": podssh's code must be OpenSSH's,
  or meet the row of the table (`differs`) that names the case, with
  OpenSSH's code, podssh's and the reason. Each line shows OpenSSH's code,
  podssh's and the literal. A difference that no row names fails with the
  three codes and OpenSSH's command line; a row that the run does not meet
  fails as broken; a reference of 0 for a case whose literal is not 0 fails
  as a broken reference (item 5).
- The rows, from the reading of the Correction: `signal` (OpenSSH 255,
  podssh 143), `changed_key` (OpenSSH 0, podssh 255) and
  `unreadable_known_hosts` (OpenSSH 0, podssh 255).
- `crates/podssh-ssh/src/lib.rs:16` now agrees with
  `docs/cli.md:5657-5658`: 128 plus the signal's number, where OpenSSH
  gives 255. `docs/cli.md` names the two differences of the host keys
  beside their rules; `docs/development.md` (item 7 of the gate) says that
  each code is checked twice; `docs/STATUS.md` has a row for OpenSSH's
  codes, measured below.

A defect found and repaired: `ssh.hostkey.strict_known` gave
`-o StrictHostKeyChecking=yes` to `p`, whose `accept-new` came first, and
the first value of a keyword wins (`docs/cli.md:1005` says "the first value
of each"), so the check ran under `accept-new`. It now names each option
itself, through `direct_ref`, with the run's `known_hosts`, which OpenSSH
reads too.

The calls made where the Approach left a choice:
- The derived checks are a harness of their own, `ref.ID` beside `ssh.ID`,
  so a change gives two named failures, and `scripts/interop.sh` stays
  under the limit of 500 lines (499). Their ids are the literal words of
  one loop, which the reader of `cargo todo interop` expands as it is; a new
  helper would have changed that reader
  (`crates/podssh-todo/src/interop/words.rs:14-15`).
- OpenSSH runs first at each site, and `p_ref` and `direct_ref` give both
  clients one list of arguments, so that the two cannot drift apart.
- `stock` keeps its own `known_hosts` (`$W/known_hosts.openssh`): with the
  file of `p`, OpenSSH's `accept-new` would record each key before podssh,
  and `ssh.hostkey.recorded` would count OpenSSH's lines. A case that names
  its own file (the host keys) gives both clients that file.
- Not compared: `-J` (OpenSSH gives a hop of `-J` none of the `-o`
  options; `ssh.config.jump_alias` compares the `-F` form already),
  `--host-key-fingerprint` (podssh's own), the refused `-R` (no
  `expect_rc`, and run under its own `timeout`), `-N` (ended by
  `timeout`), the ptys through pipes, and `podssh keygen`.
- With no `sshd.pam`, `ref.auth.kbdint_pam` says `env`, as
  `ssh.auth.kbdint_pam` does; the baseline wants `pass` for both.
- No probe of `ssh` before the package line: the script installs it, and
  a missing client fails `ref.client` and each `ref.ID` ("no reference").

Measured, 2026-10-13, the step `release` in the build image
(`sh scripts/dev.sh run -- 'sh /work/scripts/gate.sh release'`): green,
interop 504 passed, 0 failed, 1 env; `ref` 26 of 26, with
OpenSSH_10.3p1. OpenSSH's codes agree with podssh's in 22 of the 25
cases; the other three are the rows of the table, as read in OpenSSH's
source: a signal (OpenSSH 255, podssh 143, on both servers), a changed key
under `StrictHostKeyChecking=no` (OpenSSH 0, podssh 255), and a directory
as `known_hosts` (OpenSSH 0, podssh 255). `docs/STATUS.md` has each code.
Planted, in one run: the signal mapped to 255 at
`crates/podssh-ssh/src/io/msg.rs:42`, and OpenSSH's code for `exit 3` given
as 0 in `stock_raw`. 8 checks failed, as due: `ssh.exit.openssh.143` and
`ssh.exit.dropbear.143` ("wanted exit 143, got 255"), `result.*.signal`,
`ref.exit.*.143` ("the row 'signal' is broken") and `ref.exit.*.3` ("the
reference is broken"). Restored, the run above. Native: `cargo todo
interop` (532 ids of 36 harnesses meet the baseline), `cargo todo check`
and `cargo test -p podssh-todo` passed. `scripts/interop.sh` had grown to
503 lines with main's later checks; the wait for the sshd of port 2211 is
the helper `wait_port` of `scripts/interop-lib.sh` now, and the script has
498.


# T-313: The tests of the stand-in relay take the machine's proxy

**Source:** the native tests of 2026-10-30 in a Claude Code cloud container
(T-311), where `HTTPS_PROXY` names the session's agent proxy: 16 tests of
`attach`, `node_copy`, `node_plain`, `node_routes`, `pipe_remote`,
`pipe_udp`, `roost` and `upgrade` (`crates/podssh-cli/tests/`) failed with
"TLS with the relay failed: Connection reset by peer"; each passes with
`HTTPS_PROXY` unset.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The harness of these tests keeps the machine's proxy on purpose, as the
throughput runs measure the place (`crates/podssh-cli/tests/throughput_harness/mod.rs`,
`Session::command`). The stand-in relay is a name, `relay-a.test`, that only
`--relay-addr` pins to 127.0.0.1: through a proxy podssh sends the name, and
the proxy cannot reach it. A developer or a CI runner with a proxy gets 16
failures that say nothing about podssh. Six other test files already clear
the proxy variables by hand.

## Premise

Measured on 2026-10-30: `attach`'s test passes with `HTTPS_PROXY` unset,
and fails with it set; `NO_PROXY` alone changes nothing, as the name is not in
it.

## Approach

1. `Session::stand_in` in the harness: the command of `Session::command`,
   the stand-in's CA in `SSL_CERT_FILE`, and no proxy variable (`https_proxy`,
   `HTTPS_PROXY`, `all_proxy`, `ALL_PROXY`, `no_proxy`, `NO_PROXY`), with the
   reason in a comment.
2. Each command of a test that runs against the stand-in relay uses it; the
   live cells keep the machine's proxy.

## Prove

```sh
cargo test -p podssh-cli --test attach --test node_copy --test node_plain --test node_routes --test pipe_remote --test pipe_udp --test roost --test upgrade
```

The tests pass with the container's `HTTPS_PROXY` set, as with none.
Planted: the proxy variables kept; the 16 tests fail as before.

## Done

2026-10-30. `PROXY_VARS`, `without_proxy` and `Session::stand_in` in
`crates/podssh-cli/tests/throughput_harness/mod.rs`; each run against the
stand-in relay in `attach`, `node_copy`, `node_plain`, `node_routes`,
`pipe_remote`, `pipe_udp`, `roost` and `upgrade` takes them, and the pseudo
console of `attach` on Windows clears the same variables. The live cells keep
the machine's proxy.

- With the container's `HTTPS_PROXY` set, the 16 tests passed, in the run of
  `cargo test --no-fail-fast` (2069 passed).
- Planted: the harness as it was, with the machine's proxy kept, which the
  baseline of the same day ran: the 16 tests failed with "TLS with the relay
  failed: Connection reset by peer".

# T-314: The test of the man page waits for ever on a real groff

**Source:** the native tests of 2026-10-30 on a host with groff 1.23.0:
`a_real_renderer_shows_each_flag_name`
(`crates/podssh-cli/tests/man_page.rs`) ran for 13 minutes, until groff was
stopped by hand.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`render` writes the whole page to the renderer's stdin before it reads the
renderer's stdout. The page is larger than a pipe's buffer, and groff writes
as it reads: groff waits for its stdout to drain, the test waits for its
stdin to drain, and neither returns. No other host of the tests had groff
when cargo ran them: Windows has none, and the build image gets groff only
in `scripts/interop-man.sh`, after the tests.

## Premise

Measured on 2026-10-30: groff, troff and grotty waited 13 minutes in the
state `S`; with them stopped, the test went on. mandoc reads its whole input
before it writes, so it cannot meet the wait.

## Approach

1. The input goes to the renderer from a thread of its own, and the output
   is read meanwhile; the whole run has a time limit of 120 s, after which the
   renderer is stopped and the test fails with the reason (`AGENTS.md`,
   section 6, rule 4).
2. A failed write fails the test with the reason: it is not "not on this
   host".

## Prove

```sh
cargo test -p podssh-cli --test man_page
```

The test passes in seconds with groff and mandoc installed, and says
"skipped" for each that is missing. Planted: the renderer's output never
read; the test fails at its limit of 120 s instead of waiting.

## Done

2026-10-30. `render` (`crates/podssh-cli/tests/man_page.rs`) writes the page
from a thread of its own while two threads read stdout and stderr, and waits
at most `RENDER_LIMIT`, 120 s, after which it stops the renderer and fails; a
write that fails fails the test with its reason.

- With groff 1.23.0 and mandoc installed, `a_real_renderer_shows_each_flag_name`
  passed in the run of the whole suite; before, it waited 13 minutes, until
  groff was stopped by hand.
- Planted: the renderer's output never read: the test failed at its limit
  with "groff did not finish within 120 s" (150 s with the build), and did
  not wait for ever.

# T-403: The Cap'n Proto reader allocates for each element of a list before it reads one; fuzz targets for the quick tunnel's parsers

**Source:** the operator, 2026-11-01: the study of Azathothas/cfrs (T-398's Source); its finding C8
(cfrs's GitHub #5: a list of zero-size structs of count 2^24 made 80 MiB from 96 bytes).
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

podssh's reader charges a list of structs its count of words, against a budget of 8 Mi words, and
builds a vector of each element at once: a list of zero-size structs of a few words can allocate
some hundreds of MB. No fuzz target reads Cap'n Proto, a ConnectRequest or WARP's capsules.

## Premise

- Read: `BUDGET` is 8 Mi words (`crates/podssh-relay/src/quick/capnp.rs`, line 12 at `ea2bd4f`);
  a list is charged `words.max(count)` and collected at once (line 458 at `ea2bd4f`).
- Read: the fuzz targets (`fuzz/fuzz_targets/`) hold none of these parsers.

## Approach

A list is iterated, not collected, or its count is capped for a control message (the edge sends
none longer than a few hundred elements); a budget of words of its own for the control stream. Fuzz
targets for the reader, the ConnectRequest and the capsules, run with `-malloc_limit_mb=64`.

## Decision

- **Both: the elements are made as they are asked for, and the control stream's messages and a
  stream's request are read within 64 Ki words** (`CONTROL_BUDGET`). The first bounds the reader
  at any budget; the second bounds what a caller keeps of a list, as a request keeps each pair,
  and ends a loop of pointers sooner. A request is 64 KiB at most (`MAX_REQUEST` of the QUIC
  road), so 64 Ki words is eight reads of each of its words; the edge's control messages are some
  hundreds of bytes. Lost: a cap of each list's count alone, which the budget gives already, and
  which would refuse a visitor's request of many headers at a number of no reason; cfrs's budget
  of eight words read for each word of the message, which would change the limit of each message
  of the reader where the stream's limit is what the edge needs.
- **The tag of a list of structs must be a struct pointer**, as capnp reads it; and the sizes of
  a list and of a frame are summed in 64 bits, as a usize of 32 bits would wrap them.
- **`podssh-warp` in the fuzz workspace** for the capsules' target: a feature crate that the
  default `podssh-cli` leaves out. Lost: a copy of the capsule reader in the fuzz crate, which would
  fuzz a copy.
- **A fourth target, `quick_control`**: the control stream's RPC, cut anywhere in two, is a
  parser of the edge's bytes as the ConnectRequest is.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --lib quick::capnp
cargo test -p podssh-relay --lib quick::
```

A unit test: a list of zero-size structs of count 2^23 is refused or read in bounded memory. The
fuzz targets, 120 s each under `-malloc_limit_mb=64`, with no crash:

```sh
sh scripts/fuzz.sh 120 capnp_message quick_connect_request quick_control warp_capsule
```

Planted: `get_struct_list` collecting each element into a vector again: `capnp_message` stops at
its limit of 64 MiB.

## Done

2026-11-01: drafted in a worktree (branch `worktree-agent-a6aea62e1b3910649`), merged, built and
run the same day.

- `crates/podssh-relay/src/quick/capnp.rs`: `get_struct_list` gives a `StructList`
  (`crates/podssh-relay/src/quick/capnp_list.rs`), `Copy`, whose elements are made as they are
  asked for, its `nth` a jump; the count is charged as before; a tag that is no struct pointer is
  refused; the list's and the frame's sizes are summed in u64. `Message::read_within` reads
  within a budget of the caller's; `CONTROL_BUDGET` is 64 Ki words, which `Control::feed` and
  `connect::read_request` use.
- Tests: `a_list_of_structs_of_no_size_is_charged_a_word_each_and_holds_none` (2^23 structs of no
  size in 32 bytes refused; 2^23 − 1 within capnp's limit read with no element made, the last
  reached by `nth`; the same at the control budget),
  `a_list_of_structs_must_hold_its_elements_and_a_struct_tag`,
  `a_frame_of_segments_too_large_to_add_is_refused`; in `quick::connect`,
  `a_request_of_more_pairs_than_the_budget_is_refused`; in `quick::control`,
  `a_message_past_the_control_stream_s_budget_is_refused`.
  `cargo test -p podssh-relay --features quick --lib quick::`: 49 passed. Planted, a list charged
  its words alone (not its count): the first test failed.
- Fuzz targets `capnp_message`, `quick_connect_request`, `quick_control` and `warp_capsule`
  (`fuzz/Cargo.toml` names `podssh-warp`; `fuzz/Cargo.lock` takes podssh-warp, smoltcp and their own, at
  the root lock's versions); `scripts/fuzz.sh` runs the four under `-malloc_limit_mb=64`, and
  `scripts/fuzz-seeds.py` seeds them with the reference encoder's 17 messages
  (`crates/podssh-relay/tests/fixtures/quick/`) and connect-ip-go's capsules (the seed script ran:
  17 messages, 7 capsules). The targets compile (`RUSTFLAGS='--cfg fuzzing' cargo check
  --manifest-path fuzz/Cargo.toml --bins`); their runs of 120 s, on the pinned nightly with
  libFuzzer, are `fuzz.yml`'s: at `9b72e7d` (run 41298174096) each of the four ran 120 s with no
  crash (`warp_capsule` 820,413 runs), and the 19 others too.
- `docs/development.md` ("Fuzzing", item 7) and `docs/STATUS.md` (the quick tunnel's row, the
  row of fuzzing).

# T-465: `pipe`'s test of `unix-connect` waited past its 10 s once on macOS

**Source:** the gate's job `macos` at `1a38dfa` (2026-11-02, run 41435556148).
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

`unix_connect_passes_the_end_of_input_on_and_the_answer_comes_back` of `podssh-cli`'s test
`pipe` failed once on macOS: `podssh pipe stdio unix-connect:PATH`, with 1,000,000 bytes on its
stdin, had not ended after 10 s, while the gates before it passed it on the same runner. A test
that fails at random hides a defect, or teaches the reader to rerun.

## Premise

- The test (`crates/podssh-cli/tests/pipe.rs:101`) gives the bytes to podssh's stdin from a
  thread and waits 10 s for podssh to end; its server answers the digest once its input ends
  (`crates/podssh-cli/tests/pipe_seen/mod.rs:170`).
- The pump shuts the other side's write half down when its input ends
  (`crates/podssh-cli/src/pipe/pump.rs:94`), and reads more of the input that is ready at once
  without waiting (`crates/podssh-cli/src/pipe/pump.rs:163`).

## Approach

1. Reproduce it on a runner of macOS: `suite-repeat.yml` with `runner=macos-15`, `package=
   podssh-cli`, `test=pipe`, 50 runs; the test says podssh's stderr when its limit passes.
2. Name the cause (the end of stdin lost, a half-close that macOS does not pass on, or a pump
   that waits) and repair it, not the limit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pipe
```

50 runs in a row on macOS (`suite-repeat.yml`), and the cause planted again fails it.

## Done

Partial, 2026-11-02: step 1 ran. `suite-repeat.yml` with `runner=macos-15`, `package=podssh-cli`,
`test=pipe`, 50 runs (run 41440982404): 50 of 50 passed, so the failure did not come again; the
job was red only because the summary's `grep` found no failure under `pipefail`, which the
workflow now allows. The test now says podssh's stderr when its 10 s pass, so that the next
failure names where podssh waited. The cause is not named yet: the entry stays partial for the next
failure's words, or for more runs.

2026-11-03: 50 more runs on `macos-15` at `a003af3` (run 41560477021), after the merges of
T-460 to T-509: 50 of 50 passed, so 100 in a row since the one failure, with no word of where
podssh waited. It stays partial for the next failure's words.

2026-11-04: it failed again, on Windows, in the gate of `dbde47e` (run 41769967226, the job
`windows`): `unix-connect:C:\...\podssh-digest-6616.sock: no end within 10 s`, and podssh had said
nothing on stderr, so the words named no place. On the same runner the gates before and after it
passed. The failure is not of one system's sockets, as macOS's AF_UNIX is a socket of the kernel and
Windows' is afunix's through WinSock. The test now says, at its limit, how many bytes it gave
podssh's stdin and whether it closed it, and how many bytes its server read, whether the server's
input ended, and whether it answered: so the next failure tells a pump that stopped reading stdin, a
half-close that did not reach the server, and an answer or an exit that podssh did not finish apart.
`cargo test -p podssh-cli --test pipe`: 10 passed here. It stays partial for those words.

2026-11-04, later: the words came. `suite-repeat.yml` with `runner=windows-2025`, `package=podssh-cli`,
`test=pipe`, 50 runs at `e5eb6cf` (run 41783492970): run 49 failed, the other 49 passed, and the test
said: "the test gave stdin 1000000 bytes (closed: yes); the server read 1000000 bytes (its input
ended: no, it answered: no); podssh said: Ok("")". So each byte crossed, and the end of input did
not: either podssh's read of stdin never gave its end, or the half-close of the AF_UNIX socket did
not reach the server; the server's read neither failed nor ended. From outside the two look alike.
`podssh pipe -v` now says, for each direction, when its input ended, after how many bytes, and
whether the other side's write half took the shutdown (`crates/podssh-cli/src/pipe/pump.rs`), and
the test runs podssh with `-v`, so the next failure names the half. Two repeats on Windows follow:
the test alone, and the suite with its other tests beside it, as a handle that another child of
the test inherited would hold an end open only beside them. `cargo test -p podssh-cli --test
pipe`: 10 passed here; by hand, 300,000 bytes to a Python AF_UNIX server: both lines said, the
digest the same.

2026-11-04, the repeats with `-v`: at `d7e4985`, Windows' suite (run 41792149853) and the test alone
(run 41792153337), 50 of 50 each; at `22da36c`, Windows' suite (run 41793576380) and macOS's (run
41793580299) failed 2 runs in 50 each, macOS's test alone passed 50 of 50 (run 41795256104), and
Windows' test alone failed 2 in 50 (run 41795259467): beside no other test, so no handle that
another child inherited holds an end. Each failure on Windows: podssh said "A's input ended after
1000000 bytes; the other side's write half shut down", and the server read the 1,000,000 bytes and
no end. On macOS the server's input ended and its answer had not gone when the test read its
words, which fits an end that came only with the kill of podssh at the limit. So podssh's
shutdown was taken and its peer heard no end, on two systems. The test now says the time of each
step (the last read, the end, the answer, the kill), in `crates/podssh-cli/tests/pipe_seen/mod.rs`;
at `501999f`, Windows' suite and macOS's passed 50 of 50 each (runs 41800167739, 41800171933). A
probe of the platform, `crates/podssh-cli/tests/af_unix_eof.rs` (Windows, ignored; run by
`suite-repeat.yml` with `ignored=yes`), sends 1 MB and shuts the sending half 100 times by a
blocking client and 100 times by tokio's, as podssh does, and counts the ends lost: it tells
Windows' AF_UNIX from podssh's road to it.

2026-11-04, the probe's runs: `suite-repeat.yml` with `runner=windows-2025`, `test=af_unix_eof`,
`ignored=yes`, 3 runs at `a6f3351` (run 41802845998): each said "blocking 0 of 100 lost the end;
tokio 0 of 100", so 600 ends in all and none lost. Windows' AF_UNIX and tokio's shutdown on it pass
the end on, in one process; podssh's `unix-connect` opens its socket as the probe does
(`crates/podssh-cli/src/pipe/unix.rs`). Left between them: a client in another process than its
server, as podssh is the test's child, and the test's own server. It stays partial for a failure
that says the time of each step.

2026-11-06: the failure of T-688 on macOS (run 42035545363, `67c0768`) had the times: stdin closed
at 50 ms, the server's last read at 50 ms with each byte, podssh said its shutdown was taken, and
the server's input ended at 10,076 ms, after the kill at 10,074 ms. From outside, a lost wakeup of
the server's blocked read (the end queued, its reader not woken until the kill woke it again) and
an end never queued look alike. The test now keeps a clone of its server's socket
(`crates/podssh-cli/tests/pipe_seen/mod.rs`) and, at its limit and before the kill, reads it once
without waiting: "the end is queued, and the server's read was not woken" or "nothing is queued:
the end never came". The server drops the clone once it answered, so that its close still reaches
podssh. Planted here: the pump's shutdown skipped and its writer leaked (a drop of tokio's write
half shuts it down too, so a skip alone passes): the test failed at 10 s with "nothing is queued:
the end never came", the same times as macOS's; put back, `cargo test -p podssh-cli --test pipe`:
10 passed. GitHub Actions start no workflow for this account on 2026-11-06, so the repeats on
`macos-15` and `windows-2025` wait for a run; it stays partial for a failure that says which.

2026-11-09: it failed again on Windows, in the gate of `91977803` (run 42707316166, the job
`windows`), and passed at the next commit, which changed a shell script alone: stdin closed at 88
ms, the server's last read at 89 ms with each of the 1,000,000 bytes, podssh said "A's input ended
after 1000000 bytes; the other side's write half shut down", and the server's input never ended
before the kill at 10,072 ms. Windows has no read of the clone (it says "not read on this system"),
so the two causes still looked alike there. The test's server now reads with a timeout of 250 ms
and reads again after each one (`crates/podssh-cli/tests/pipe_seen/mod.rs`, `Timed`, `answer`),
and says how many of its reads timed out: an end that the platform queued without waking the
blocked read is found by the next read (the test passes, and the count says it waited), and an end
that never came still fails at 10 s, now with a count of reads that found nothing, on each system.
Measured 2026-11-10: `cargo test -p podssh-cli --test pipe`, 10 passed. Planted, the pump's shutdown
skipped and its writer leaked: the test failed at 10 s with "its reads timed out 38 times" and
"nothing is queued: the end never came"; put back, it passes. It stays partial for the next failure
on Windows or macOS, whose count says which cause it was.

# T-564: podssh never raises its soft limit of open files, so a wide `cp --parallel` or `each` meets `EMFILE`

**Source:** GitHub #111 (a tester, 2026-11-02).
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

podssh runs under the soft limit of the shell that started it, 256 on macOS by default, while
`cp --parallel`, `each`, `job`, `session` and `-L` hold a descriptor each; past it, one operation
fails with `EMFILE` and nothing says that the limit was the reason.

## Premise

- `crates/podssh-cli/src/detach/child.rs:221` says "let max = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {":
  the limit is read there alone, and no `setrlimit` is called in `crates/`.

## Approach

1. At start, on Unix, the soft limit of `RLIMIT_NOFILE` goes up to the hard one, capped on macOS
   at `OPEN_MAX` (macOS refuses more for `setrlimit`); a refusal is a note at `-v`, never an error.
2. `-v` says it once: "open file limit: 256 -> 10240".
3. `podssh status` gives both numbers, so that a report carries them.
4. An `EMFILE` that still comes names the limit in its line.

## Decision

The process's own limit, raised within the hard limit that the host set: no privilege, and the
call's answer is the probe (rule 1 of `AGENTS.md`). Lost: a flag to ask for it, which each tester
would have to know; nothing on Windows, whose handles have no such soft limit.

Calls of the draft (2026-11-02, Q86), with what lost:

- **For the operator to confirm (Q86): the raise stops at 65,536 on each Unix.** Each program that
  podssh starts (a pager, an editor, `SSH_ASKPASS`, `LocalCommand`, a command of `pipe`, `systemctl`,
  podssh again for `--detach`) inherits the soft limit, and a container's hard limit is often
  1,048,576 or 2^30: a program that closes each descriptor up to its limit before it starts
  another would take seconds there, where a run of podssh needs a few hundred descriptors. Lost:
  the hard limit with no cap, as Go's runtime does, which needs the old soft limit put back in
  each child, at each of the twenty places that start a program (`pre_exec` in each, which makes
  the standard library fork and exec where it would spawn), and still gives podssh's own runs a
  soft limit of 2^30; the old soft limit put back in each child under the cap, the same twenty
  places for no gain.
- **For the operator to confirm (Q86): on macOS, within `kern.maxfilesperproc`, then `OPEN_MAX`
  (10,240) after a refusal.** Apple's `setrlimit(2)` says to ask for `min(OPEN_MAX, rlim_max)`, and
  an older release refuses more with `EINVAL`; a newer one takes up to `kern.maxfilesperproc`,
  which Go's runtime asks for. Lost: `OPEN_MAX` alone, the Approach's, which keeps a newer macOS at
  10,240 where it takes more; `kern.maxfilesperproc` alone, which an older release refuses.
- The line of `-v` and the hint go through `podssh-ssh`'s log: a line said once, before the first
  line of the first log at `-v`, and a hint after an error line that a function of the binary's
  explains, both set by the binary at its start; so each command that logs as `podssh ssh` does
  (`cp`, `each`, `job`, `session`, `run`, `sftp`, `edit`, `health`, `containers`) says them with no
  change of its own. Lost: a line in each command (the files of `cp` and `each` wait for other
  drafts, and `crates/podssh-cli/src/ssh/resolve.rs` is at its 500 lines); the hint inside the
  error's own line, as the Approach wrote, which would change the text of each error that tests
  and users read: the hint is the line after it. `podssh proxy` and `podssh pipe`, which write their
  lines with no log, say neither.
- The hint follows an error with `(os error 24)`, `EMFILE` of the libc crate, or the words "Too
  many open files" without "in system": `ENFILE`, the whole system's table, which no limit of the
  process moves, gets none.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test status
```

Under `ulimit -n 64` with a hard limit above it, `podssh status` shows the raised soft limit; with
the hard limit at 64 it shows 64 and says so at `-v`. Planted: the raise skipped, and the test
fails.

## Done

Drafted 2026-11-02 by a drafting agent, not built; merged and run by the main session on
2026-11-03.

- `crates/podssh-cli/src/nofile.rs`: `start`, which `main` calls once after a detached child let go
  of what it inherited, raises the soft limit to `target` (the hard limit within `CAP`, 65,536, and
  on macOS within `kern.maxfilesperproc`; never lower than now), says its line once at `-v` ("open
  file limit: 256 -> 10240"; "open file limit: 64, the hard limit of this host"; a refusal with the
  host's error) and gives the log its hint of too many open files; `limits` is what `status`
  reads. `crates/podssh-cli/src/nofile_unix.rs`: `getrlimit` and `setrlimit` of `RLIMIT_NOFILE`,
  read again after a raise, `OPEN_MAX` asked after a refusal on macOS, and `sysctlbyname` for
  `kern.maxfilesperproc`; on Windows, nothing.
- `crates/podssh-ssh/src/log.rs`: `say_once_at_verbose` and `hint_errors`, which `Log::at` uses.
- `podssh status`: `open_files` (`soft`, `hard`, null for none, `at_start`, `raised`, `refused`),
  null on Windows. The manual's note of `status` names it, and `session_log`, `relay_failures` and
  `relay_opened`, which it did not name (`crates/podssh-cli/src/man/notes.rs`); `docs/cli.md`
  (`podssh status`).
- Tests: in `crates/podssh-cli/tests/status.rs`, `open_files::a_soft_limit_below_the_hard_one_is_raised_to_it`
  (64 under a hard limit of up to 4096: raised to it) and
  `open_files::a_hard_limit_at_the_soft_one_keeps_it_and_v_says_so` (64 and 64: kept, and
  `podssh ssh -v`, offline, says the line once and first), each limit set in the child by
  `setrlimit` before exec; in `nofile`, the target, the lines and the hint (`ENFILE` gets none); in
  `nofile_unix`, the asks and a read of this process's limits. 2026-11-03: `cargo test -p
  podssh-cli --test status`: 7 passed, both of `open_files` among them; `cargo test -p podssh-cli
  --lib nofile`: 5 passed; the whole lib, 662 passed; `-p podssh-ssh --lib`, 283 passed; the
  manual's `man_page` and `flag_table`, 9 and 10 passed; clippy `--all-targets -D warnings` on
  Linux: clean. This host has no linker for `x86_64-pc-windows-gnu` or `aarch64-apple-darwin`:
  the Windows build (`platform` is the stub there) and macOS's (`kern.maxfilesperproc`, `OPEN_MAX`)
  are the gate's jobs `windows` and `macos` at the push.
- Planted, `scripts/plants/t564-no-raise.patch` (the start reads and never raises): caught,
  `open_files::a_soft_limit_below_the_hard_one_is_raised_to_it` failed.
- `docs/STATUS.md`: a row in "Build, tests, CI".
- Repaired after the push, 2026-11-03 (the gate's step `release` at `0d0c22c`, run 41605642217:
  `scripts/interop-mv.sh`'s `mv.notice.sftp` and `mv.notice.exec`): the limit's line came before
  the notice of `mv`, a line of the default level that must come first; it is now said before the
  first line at `-v` or more alone (`crates/podssh-ssh/src/log.rs`). `mv -v` to a port that
  refuses: the notice first, the limit's line second; `cargo test -p podssh-cli --test status`: 7
  passed.

# T-627: The relay role's test of a resume by the next token of one leg timed out once in the relay crate's suite

**Source:** the main session, 2026-11-04: `cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code`, at T-173's second part.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

`a_resume_takes_the_next_token_that_the_node_gave_and_a_replayed_one_is_refused` of
`crates/podssh-relay/tests/relay_serve_once.rs` (T-615) waited past its 20 s for the echo after
the cut ("the echo in time: Elapsed(())"), once, in a run of the crate's whole suite; alone and
beside its own suite it passed each time after. A test that fails at random hides a defect, or
teaches the reader to rerun.

## Premise

- The test cuts the operator's leg after the first echo, and the session resumes on a new leg
  by the next connect token of one leg that the node's verdict gave (T-615); the echo after the
  cut waits [`LIMIT`] of the role's harness, 20 s (`crates/podssh-relay/tests/role_harness/mod.rs:28`).

## Approach

1. The test says, at its limit, the role's events so far: whether the new leg was refused for its
   token (`reverse leg token refused`), took one (`reverse leg token`), or never came.
2. Name the cause from the next failure's words (a resume before the node registered the next
   tokens with the role, a refused token that the client counts as spent, or a slow leg) and
   repair it, not the limit.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features serve,plain-ws,quick,pair,grant,piping,code --test relay_serve_once
```

The whole suite of the crate with those features, many runs in a row, and the cause planted again
fails it.

## Correction

2026-11-05. The code of this entry (the relay role (`podssh-relay`'s `serve/`) and its test harness)
goes to `pod-relay-serve` of PodUtils/podcrates (T-684; the waves are in Q101 of `TODO/PROGRESS.md`,
and the module map is `PodUtils/podcrates:docs/design.md`). Rule Q3 (`docs/decisions.md`, "The
crates of PodUtils/podcrates") applies: from the import podssh makes fixes only, and once podssh
takes the crate the work is done in PodUtils/podcrates, which podssh takes by the next tag; a test
of the moved code then runs there.

## Done

Partial, 2026-11-04: step 1. The echo's timeout now panics with the role's events
(`crates/podssh-relay/tests/relay_serve_once.rs`, `echoed`). Not reproduced here: the test alone 24
times, 8 at once, and its whole binary 32 times, 8 at once: each passed. It stays partial for the
next failure's words.

2026-11-06, at `ebcdb9d` on Rust 1.99.1: the crate's whole suite with
`serve,plain-ws,quick,pair,grant,piping,code`, 6 runs in a row: each passed, 962 tests a run. Not
reproduced; it stays partial for the next failure's words.

# T-640: A service's lines reach the journal at one priority, so `journalctl -p warning` shows none of them

**Source:** GitHub #138 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A node or a tunnel installed as a unit of systemd writes its lines to stderr, which the journal files
at one priority. The read that an owner makes of a service that does not work, the warnings and above,
shows nothing that podssh said.

## Premise

Read at `2042200`:

- podssh writes text with no level past its own process: `crates/podssh-ssh/src/line.rs:22-24` writes a
  line to stderr, and `crates/podssh-ssh/src/log.rs:32-37` holds a level and stderr or a file; the
  level stops in the process.
- `crates/podssh-cli/src/flags.rs:293` says "podssh does not write to syslog", for `-y`.
- The unit that the install writes restarts the node (`crates/podssh-cli/src/node_install/text.rs:167`)
  and stops on 64 and 78 (`crates/podssh-cli/src/node_install/text.rs:169` says
  "RestartPreventExitStatus=64 78"): a fault of the journal must never become one of those.
- No source reads `JOURNAL_STREAM` (searched).

## Approach

1. A module of `podssh-ssh`, Linux alone: a probe that compares `JOURNAL_STREAM`'s device and inode with
   those of descriptor 2, so that a child that inherited the variable does nothing; with a match, a
   socket of `AF_UNIX` datagrams, bound to nothing, that sends each line to the journal's socket as one
   entry: `PRIORITY` from the line's level (fatal 2, error 3, quiet and info 6, verbose and debug 7),
   `SYSLOG_IDENTIFIER=podssh`, `MESSAGE` last, a value with a line break in the journal's binary form.
2. `err_line` and `Log` keep their stderr first, and send to the journal after it, with their level; a
   send that fails is dropped, and never an exit code.
3. Installed once, in `main`, before a thread starts; no flag. `-y`'s row and the manual say that the
   journal gets the levels where stderr is the journal's.

## Decision

2026-11-04 (the drafting agent of the triage). For the operator to confirm (Q86): a datagram to the
journal's own socket, only where stderr is already that journal's stream, is no outbound connection of
rule 2 of `AGENTS.md` and no helper: it reaches the same service that each line reaches now, on the
host, and binds nothing. Lost: stderr alone (the defect); syslog's `/dev/log` (another protocol, which
the `-y` row refuses for its own reasons); a flag that turns it on (a unit's owner would not know to
set it, and a line's level is no secret).

2026-11-04 (the drafting agent), within that call:

- The module is `crates/podssh-cli/src/journal.rs`, not one of `podssh-ssh`: each line by which a node
  or a command fails is written in `podssh-cli`, through `Refusal::report` (each command's refusals, and
  most ends of a node's roads), the end of a node by a fault (`node`, `node_carrier`, `node_piping`) and
  the refusal of a retired variable (T-634); `err_line` and `Log` keep their signatures. Lost: a level
  in `err_line` and `Log` of `podssh-ssh`, which another agent's draft held that day, and which carry
  no error line of a node; the lines of the SSH client (`Log`, a tunnel's session) keep one priority,
  for an entry of their own (see Done).
- Only a line above the stream's `info` (an error 3, a fatal one 2) is copied, after the stream's own
  line. Lost: a copy of each line, which `journalctl -u` would show twice, each at `info` already;
  the copy in place of the stream's line, as `JOURNAL_STREAM`'s documents propose, as the journal
  reads a datagram's unit from its sending process, which a node ends just after its last line, so
  `systemctl status` could lose the line that says why, and the order of the two sockets' lines would
  mix; sd-daemon's `<N>` prefix on the stream (one line, no socket), which a unit with
  `SyslogLevelPrefix=no` would show as text, and which the call above did not take.
- The stream is compared with descriptor 2 at the start and again at each line (a copy of the
  descriptor, `fstat`, closed after it), as a detached run moves its stderr to its log after the start.
  The socket for entries is `socket` beside the stream's far end when that is a `stdout` of systemd
  (a journal's namespace has its own), else `/run/systemd/journal/socket`. The socket does not block:
  a journal that reads too slowly loses the copy, and the line never waits.
- `JOURNAL_STREAM` is a variable that podssh reads, so the manual lists it (ENVIRONMENT), and `-y`'s
  row names it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib journal
cargo test -p podssh-cli --lib relay_settings
cargo test -p podssh-cli --lib man::
```

With a datagram socket of the test in a temporary directory and its device and inode given to the
probe: each level's number; `PRIORITY` first and `MESSAGE` last; a message with a line break is one
entry; a variable that does not match descriptor 2 installs nothing; a line reaches stderr and the
journal, and stderr alone when the socket is gone. Planted: the probe that trusts the variable alone,
and the test of the child that inherited it fails.

## Done

2026-11-04, merged from its draft (`2ec6c95`).

- Where stderr is the journal's own stream (`JOURNAL_STREAM`'s device and inode match stderr's,
  read again at each line, as a detached run moves its stderr), a line above `info` of a node, a
  refusal or the end of a node's fault goes to the journal's socket as a native datagram with its
  priority, from a socket bound to nothing, after the stderr line (`crates/podssh-cli/src/journal.rs`);
  elsewhere the lines are as before. The manual names `JOURNAL_STREAM`. The SSH client's own lines
  keep one priority: T-674.
- `cargo test -p podssh-cli --lib journal`: passed (82 with the other modules of the merge); the CLI
  crate whole: 1,903 passed. Plant `t640-probe-trusts-the-variable` caught. Clippy and rustfmt clean;
  `scripts/check-repo.py` takes the test's socket in a temporary directory
  (`scripts/repo_listeners.py`).

# T-674: The SSH client's own lines keep one priority in the journal

**Source:** the draft of T-640, 2026-11-04 (GitHub #138).
**Category:** feature
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

T-640 gives a node's lines, a refusal and a node's fault their priority in the journal where
stderr is the journal's stream. The SSH client's own lines (`podssh ssh` and a tunnel's session,
written by podssh-ssh's log) still reach the journal at one priority, so a unit that runs `podssh
ssh -N -L` sees its warnings and errors at `info`.

## Premise

- `crates/podssh-cli/src/journal.rs` serves the CLI's lines; podssh-ssh's log writes to stderr
  itself.

## Approach

1. podssh-ssh's log takes a sink of the CLI's, which sends a line above `info` to the journal as
   T-640 does, where stderr is the journal's stream.

## Decision

2026-11-05 (a drafting agent). The Premise holds (read on 2026-11-05): T-640's sink serves the
lines that `journal::line` writes, and `Log` writes its own to stderr. The client's log has no level
of warnings: `crates/podssh-ssh/src/options.rs:115-124` lists the levels of `-o LogLevel`, as
OpenSSH's, and the client's "Warning:" lines are written at INFO, as OpenSSH's `logit` writes them
(`crates/podssh-ssh/src/hostkey.rs:263` says "Warning: Permanently added"). So:

- The sink is a function that the binary gives podssh-ssh's log once
  (`crates/podssh-ssh/src/log.rs:202`, `copy_lines`), as it gives the hint of an error
  (`hint_errors`), and only where `journal::install` found the journal
  (`crates/podssh-cli/src/journal.rs:46-48`); each line that a log puts on stderr goes to it with
  its priority, in stderr's words, and T-640's sink keeps only what is above `info`. Lost: a sink in
  each `Log` (the CLI makes a `Log` in some thirty places, and one made without the sink would keep
  one priority with no sign of it); `journal::line` around each call (podssh-ssh writes most of its
  lines itself, inside the session).
- The table of the levels' priorities is podssh-ssh's (`crates/podssh-ssh/src/log.rs:19`), and the
  CLI re-exports it (`crates/podssh-cli/src/journal/entry.rs:7`): one table. Lost: two tables and a
  test that they agree.
- A warning has its own priority, 4 (`crates/podssh-ssh/src/log.rs:30`): `Log::warning`
  (`crates/podssh-ssh/src/log.rs:75`) shows a line at INFO, as before, so `-q` and
  `-o LogLevel=ERROR` still hide it, and copies it at 4. It takes a remote forward that the server
  refused (`crates/podssh-ssh/src/remote.rs:94`, and that of `~C` at
  `crates/podssh-ssh/src/escape_run.rs:180`), a channel of agent or X11 forwarding that the server
  opened unasked (`crates/podssh-ssh/src/handler.rs:154`), and the warnings of the settings that
  each command says before it connects (`resolved.warnings`: an agent that is not there, a
  `ServerAliveInterval` that the relay's idle cut passes). Lost: a level WARNING of `-o LogLevel` (no
  OpenSSH setting has it, and each match on the levels would move); the warnings at `info`, as
  before (a unit of `ssh -N -R` whose forward the server refused runs on without it, and a read by
  priority would not show it: the issue's case); "Warning: Permanently added" at 4 (a host key
  recorded as asked is no fault, and each first connection of a unit would be a warning).
- A log in a file (`-E`) sends nothing, and a line that the log hides sends nothing. Lost: a copy of
  each line wherever it went (the journal would get lines that the stream never had, where the user
  named a file for them).
- The binary's remedy after an error (the limit of open files, T-564) goes at the error's priority
  (`crates/podssh-ssh/src/log.rs:238`), as it explains that error in a read by priority too.
- The client's other lines of a failure at `info` (a listener of `-L` that closed, a target that
  refused one connection, a key file that could not be used) keep their level: each is the client's
  choice of level, as OpenSSH's is, and this entry moves no level, only a line's copy. Lost: each of
  them at 4 (a review of the client's levels, which no report asks for).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib journal
cargo test -p podssh-ssh --lib log::
cargo test -p podssh-ssh --lib -- handler::tests remote::tests escape_run::tests
cargo test -p podssh-cli --lib man::
```

A new test: a warning of the SSH client's log reaches the journal's socket with its priority.
In the CLI, against T-640's datagram socket of the test: a warning of `Log` at 4 and an error at 3,
each in stderr's words, and a line of INFO not at all; a log in a file sends nothing. In podssh-ssh,
against a copy of the tests: each level's number, and a warning between an error and INFO; an
error, a warning and a line of INFO at 3, 4 and 6; a log in a file, `-q` and a warning at
`LogLevel=ERROR` copy nothing; a host's prefix on each line of the copy; a hint after its error, at
3. The tests of the lines that became warnings pass as before (their words and their level of
display did not change). Planted: a warning copied at INFO's priority, and the CLI's test fails
(`t674-warning-at-info`); a log in a file that copies, and podssh-ssh's test fails
(`t674-file-log-copied`).

## Done

2026-11-05, merged from its draft (`68687d5`).

- `cargo test -p podssh-cli --lib`: 935 passed, the journal's 13 among them (two new: a warning of
  the client's log reaches the test's journal at 4 and an error at 3, an info line not; a log in a
  file sends nothing).
- `cargo test -p podssh-ssh --lib`: 351 passed, six new in `crates/podssh-ssh/src/log_tests.rs`
  (each level's priority, a warning's between, a log in a file copies nothing, `-q` and a warning
  at `LogLevel=ERROR` copy nothing, a host's prefix on each copy, a hint at its error's priority).
- Planted: `t674-warning-at-info` and `t674-file-log-copied` caught.
- Clippy and rustfmt clean (rustfmt rewrapped one line of the draft's tests).
- Not measured here: a unit of systemd with `journalctl -p warning`; T-640's is not measured either.

# T-692: Two background probes of the relay rank met the relay 439 ms apart on Windows, under a gap of 1.2 s

**Source:** the gate of `0fc03e7` (run 42203919941, the job `windows`), 2026-11-06.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`rank_background::background_probes_come_one_at_a_time_inside_the_session_and_once_a_day` of
`podssh-cli`'s test `relay_rank` failed once on Windows: "439 ms between two probes", where the test
sets a gap of 1,200 ms and allows 200 less. Q89 bounds the background rank to one probe each gap: a
relay that saw two of them closer than that saw more than the ruling allows.

## Premise

- Read: `crates/podssh-cli/src/relay_rank_auto.rs` kept the time of a probe when it started, and the
  next one slept until that time and the gap. The relay's lines of that run: connects at 3,922,
  5,125, 7,108 and 7,547 ms: the third probe's connection reached it about 0.8 s after the probe
  started, and the fourth's at once.

## Approach

Time the gap from the end of a probe, so that a slow dial of one probe never brings the next one
nearer than the gap at the relay; the test as it is.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_rank
```

It passes here; the job `windows` of the gate passes it.

## Done

2026-11-06: `crates/podssh-cli/src/relay_rank_auto.rs` keeps the time when a probe ended (or was
dropped for a race), and the next probe waits the gap from it. `cargo test -p podssh-cli --test
relay_rank`: 6 passed. The job `windows` of the next gate reads it again.

# T-696: A change of a node's shares that waited behind other changes, each of which ended, was refused after 5 s on Windows

**Source:** the gate of `8c7519c0` (run 42290205000, the job `windows`, GitHub #162), 2026-11-06.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`share::tests::two_changes_at_once_both_count_under_the_lock` of `podssh-cli`'s library failed on
Windows: one of its two threads of 40 changes each was refused with "lab.shares.lock: another change
of these shares held its lock for 5 s" (75). No change held the lock for 5 s: each one ended in
milliseconds, and the other thread took the lock again at once each time.

## Premise

- Read: `crates/podssh-cli/src/share/file.rs`, `hold`: the deadline of `WAIT` (5 s) started at the
  first try and never started again. A change that polls each 20 ms, behind another that keeps
  taking the lock again at once, finds it free only by chance; its wait is then of all the other
  changes, and the refusal's words are false.
- Measured here (Linux): a test with one thread of changes of 50 ms each, for 7 s, and one change
  that waits behind them was refused after 7 s, behind 135 changes that each ended.

## Approach

Fail a change only when one holder keeps the lock for `WAIT`: each holder moves the lock file's
length when it takes the lock (one byte longer, back to empty past 64), and a waiter starts its
wait again when the length moves. The test of a lock held past the wait stays as it is.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib share::
```

The new test fails on the code before the change; with it, the tests pass 20 runs in a row here,
and the job `windows` of the gate passes them.

## Done

2026-11-09: `crates/podssh-cli/src/share/file.rs`, `hold`, with `mark`, `taken` and
`held_too_long`: the wait starts again each time that another holder takes the lock, so only one
holder that keeps it for 5 s fails a change (75). The test
`a_change_that_waits_behind_others_that_end_is_not_refused` (`crates/podssh-cli/src/share/tests.rs`):
planted, the code before the change, it fails ("refused after 7.05 s behind 135 changes that each
ended"); with the change, `cargo test -p podssh-cli --lib share::` 7 passed, 20 runs in a row. The job
`windows` of the next gate reads it again.

# T-744: Two tests failed at random in the gate on 2026-11-10: a stand-in's count of DERP logins, and Python's server of the funnel's test on macOS

**Source:** the session of 2026-11-10, the gate's job `gate (libs)` of run 42763603512 (`2f8e0bb0`) and
its job `macos` of run 42794811364 (`ec730ac2`); each commit changed the record alone.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A test that fails at random hides a real failure, and turns the gate red for nothing.
`a_server_that_closes_after_the_client_s_info_sends_the_node_to_the_next` (`-p podssh-relay --test
derp_link`) read `(0, 0)` logins where it wants `(0, 1)`; and on macOS
`a_funnel_serves_python_over_tcp_a_get_in_chunks_and_a_post_with_no_length` (`-p podssh-relay
--features quick --test quick_publish`) said "Python's server did not start" after its 20 s.

## Premise

- Read: `PodUtils/podcrates:crates/pod-derp/tests/derp_link.rs` asserts the two stand-ins' logins; the stand-in
  (`PodUtils/podcrates:crates/pod-derp/src/standin.rs`) counted a login after it had sent its answer, so
  a client that had the answer could read the count first.
- Read: `crates/podssh-relay/tests/quick_publish.rs` started Python with its stderr dropped, so a
  server that ended at once and one that was slow looked alike.

## Approach

Count the login before the answer, as the stand-in registers the client before it, and take it back
when the answer fails. Keep Python's stderr, fail at once with it when Python ends before it is
ready, and wait 60 s for a cold runner; the next failure, if one comes, names its cause.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features derp --test derp_link
cargo test -p podssh-relay --features quick --test quick_publish
```

Planted: the stand-in's count after its answer, with 50 ms between, and the DERP test fails as the
gate's did.

## Correction

The test target `derp_link` of `podssh-relay` moved to `pod-derp` of PodUtils/podcrates when podssh took the crate (its T-031): `cargo test -p pod-derp --all-features --test derp_link` there runs it, with its name.

## Done

Partial, 2026-11-10. The stand-in of DERP counts each login before its answer
(`PodUtils/podcrates:crates/pod-derp/src/standin.rs`); planted, the old order with 50 ms before the
count, `a_server_that_closes_after_the_client_s_info_sends_the_node_to_the_next` failed with
`left: (0, 0)`, the gate's words; put back, `--test derp_link` passed 25 runs in 25. The funnel's
test keeps Python's stderr (`crates/podssh-relay/tests/quick_publish.rs`), fails at once with it
and Python's status when the server ends before it is ready, and waits 60 s; `--test quick_publish`
passed 10 runs in 10 here (Linux). It stays partial for the macOS runner: the next failure there,
if one comes, says why Python did not start.

2026-11-10, the gate at `a083593e` (run 42813698627): two more. `gate (libs)` ran
`cargo test -p podssh-ws --features plain-ws --test plain_loopback`, a target that went to `pod-ws`
with the take of T-684; the step of `scripts/gate.sh` now runs the tests of podssh-ws's glue with
the feature (`cargo test -p podssh-ws --features plain-ws`: 261 passed here). On Windows,
`another_password_is_refused_with_croc_s_words` (`-p podssh-relay --features croc --test croc`, T-694)
read "An existing connection was forcibly closed by the remote host. (os error 10054)" in place of
croc's words: the stand-in relay dropped its stream at once after "bad password", with the client's
next frame unread, and a drop with unread input is a reset on Windows, which discards the bytes
that the bridge had not read yet, the refusal among them. The stand-in now ends each refusal
gracefully, its write half shut and the peer's bytes read to their end within 2 s
(`crates/podssh-relay/tests/croc_stand_in/mod.rs`, `refused`, for "bad password" and "room full");
`--test croc` passed 10 runs in 10 here (Linux). The next gate's job `windows` is its check.

2026-11-10, the gate at `525f8907` (run 42843751348): croc's test failed again on Windows with the
reset, one hop nearer the client: the stand-in's WebSocket bridge dropped the visitor's socket at
once when the relay closed, with the client's next frame unread. The bridge now reads the visitor's
frames until it closes, within 2 s, before it drops the socket (`croc_stand_in/mod.rs`, `visitor`);
`--test croc` passed 5 runs in 5 here (Linux), and the next gate's `windows` is its check. And on
macOS, `openssh_through_podssh_proxy_and_the_role_reaches_openssh_with_equal_digests` (`-p podssh-cli
--test relay_serve`) failed once with no words ("up: "): it had passed on macOS at each commit
before. Its assertion now says ssh's exit status beside its words (`relay_serve.rs`), so the next
failure names its cause; `--test relay_serve`, 28 passed here. It stays partial for those two runs.

2026-11-11, the gate at `d2361ef1` (run 42871529371): each check that this entry waited for passed.
On Windows, `--features croc --test croc` passed (the job failed on bore's stand-in alone, T-745); on
macOS, the job passed whole, `--test relay_serve` and the funnel's `--test quick_publish` among its
tests. Done.


# T-745: The gate at the pause was red on four causes that the record did not know: clippy 1.99, an advisory of SQLite, a test's URL, and bore's stand-in on Windows

**Source:** the session of 2026-11-11, the runs at `d2361ef1` (the hand-off): `build` 42871529371
(jobs `gate (lint)` and `windows`), `deny` 42871529370 and `secrets` 42871529365.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The gate must be green before other work, and each of the three workflows was red at the head of
`main` for a cause that neither `docs/HANDOFF.md` nor an entry named.

## Premise

- Read: `gate (lint)` failed on clippy's `large_enum_variant` (Rust 1.99) at the enum `Said` of
  `PodUtils/podcrates:crates/pod-iroh/src/pkarr.rs`: `Put(Roads)` holds at least 208 bytes, `Failed` none.
- Read: `deny` failed on RUSTSEC-2026-0459 (SQLite before 3.54.0, a crafted `-wal` file), in
  `libsqlite3-sys` 0.38.2 through `rusqlite` 0.40.2, `tor-dirmgr` 0.47.0 and `podssh-tor`. The fixed
  `libsqlite3-sys` 0.39 comes with `rusqlite` 0.41, and each release of `tor-dirmgr` to 0.48.0 asks
  `rusqlite >=0.36.0, <0.41.0` (crates.io's index, read 2026-11-11).
- Read: `secrets` found two URIs of state "unknown": a made-up URL with a user and a password at
  `h.test`, a test value of
  T-565 in `crates/podssh-relay/src/ssh_http/name.rs`, at the draft's commit and at its merge.
- Read: on Windows, `a_server_with_a_secret_takes_its_answer_and_refuses_none_or_another`
  (`-p podssh-relay --test bore_link`, T-569) read "An existing connection was forcibly closed by
  the remote host. (os error 10054)" in place of "invalid secret". The stand-in
  (`crates/podssh-relay/tests/bore_stand_in/mod.rs`) dropped its socket at once after its `Error`,
  with the client's next message unread: the same reset as croc's stand-in of T-744.

## Approach

- clippy: keep the value unboxed, with the lint allowed and its reason beside it; one value lives for
  the life of the task, and a box would cost an allocation at each comparison.
- The advisory: no version of arti takes the fix, so `deny.toml` ignores it with the judgement and
  the date; arti opens only the database of podssh's own cache directory, which its permission check
  refuses when another user can write it. Take the fix when arti accepts `rusqlite` 0.41.
- The URL: an entry for each commit in `.github/secrets-allow.txt`, as for each test value before.
- bore's stand-in: each refusal ends gracefully, its write half shut and the peer's bytes read to
  their end within 2 s, as croc's stand-in does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo +1.99 clippy -p podssh-iroh --all-targets -- -D warnings
cargo +1.99 test -p podssh-relay --features bore --test bore_link
python scripts/check-repo.py
cargo todo check
```

The next gate's `gate (lint)`, `windows`, `deny` and `secrets` are the check on CI.

## Done

2026-11-11. clippy 1.99 as the gate's step lint runs it for iroh (`cargo +1.99 clippy --locked
--all-targets -p podssh-cli -p podssh-iroh --features podssh-cli/iroh-test -- -D warnings -A
clippy::collapsible_if`): exit 0, where the run at `d2361ef1` failed on `Said`. `cargo-deny` 0.20.2
(its release binary, checked against its SHA-256): `check advisories licenses bans sources` says
"advisories ok, bans ok, licenses ok, sources ok", where the same run without the ignore failed on
RUSTSEC-2026-0459. `.github/secrets-allow.txt` names both commits of the URL, and the commit of this entry, whose
Premise first quoted the URL (`secrets` at `ea911a78`, run 42937074059, found it there). bore's stand-in ends
each refusal gracefully; `--features bore --test bore_link` passed 8 runs in 8 here (Linux, in a
network namespace with the loopback alone). The next gate's `windows`, `gate (lint)`, `deny` and
`secrets` are the check on CI.

# T-746: Two tests failed at random in the gate at `6f78a7c7`: a datagram echo of `pipe` on Linux, and OpenTunnel's resume on macOS

**Source:** the session of 2026-11-11, the gate's run 42943481826 at `6f78a7c7`: jobs `gate (iroh)` and
`macos`.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A test that fails at random hides a real failure, and turns the gate red for nothing.
`pipe::datagram::tests::a_program_sends_and_takes_whole_datagrams_and_its_status_comes_back`
(`-p podssh-cli --lib`, in the build image) read the end of the program's output where it wants its
echo; `a_bridge_that_the_service_ends_attaches_again_and_the_session_resumes` (`-p podssh-relay
--features opentunnel --test opentunnel_link`, on macOS) saw `Lost` and `Retry` but no `Resumed`.

## Premise

- Read: in `crates/podssh-cli/src/pipe/datagram.rs`, the loop of `datagrams` ended with `None` when a
  send to the program failed, and dropped the socket with what the program had sent before it closed
  still unread, against its own comment "What it sent before it exited still goes".
- Read: no line of `sh` or `dd` came in the job's log (their stderr is the test's); the program ended
  without its answer reaching the pump, and the log does not say why.
- Read: the OpenTunnel test (crates/podssh-relay/tests/opentunnel_link.rs at `b9c04657`, `echo_mib`) cut the bridges
  after a third of the echo came back, with all 3 MiB written at once: the bytes in flight could finish
  the echo, and then only the CLOSE met the cut, a `Lost` and a `Retry` for it, with no resume.

## Approach

- `datagrams`: a failed send drains what the program sent into the pump before the end, as an exit does.
  The test, when the echo is missing, says the program's verdict, so that its next failure names its
  cause.
- `echo_mib`: with a cut, the writer sends the last two thirds only after the cut, so those bytes need
  the resumed link.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib pipe::datagram
cargo test -p podssh-relay --features opentunnel --test opentunnel_link
```

## Correction

2026-11-15: the test targets opentunnel_link, opentunnel_interop and opentunnel_live of
podssh-relay left with the road, which `pod-opentunnel` of PodUtils/podcrates holds
(PodUtils/podcrates@T-033): its Prove runs there as
`cargo test -p pod-opentunnel --test opentunnel_link`.

## Done

Partial, 2026-11-11. `datagrams` drains the program's datagrams on a failed send; a test that sent to a
program that had answered and closed its socket did not catch the old code (20 runs; 150 more of the gate's
test under load with the old code passed too), so the cause of the gate's failure stays unproven, and the
test now says the program's verdict when the answer is missing. `echo_mib` holds the last two thirds until
the cut. In a namespace with the loopback alone: `pipe::datagram` 10 runs in 10, `--test opentunnel_link`
10 in 10, each asserting the resume. clippy with the feature `opentunnel`, rustfmt: clean. Next: the gate's
`macos` for OpenTunnel, and the datagram test's next failure, if one comes, for its cause.

2026-11-11, the gate at `bc5107b0` (run 42948403145): each job passed; on macOS, `--features opentunnel
--test opentunnel_link` passed with the held thirds. The entry stays partial for the datagram test's
next failure, which now names the program's verdict.

2026-11-14, the next failure came (the gate of `5c177b9`, run 43556423648, `gate (ssh)`) and named its cause:
`the program's output ended with no answer; its verdict: Some((3, []))`: `sh` ran, `dd` ran, and the answer
that `dd` sent before the exit never reached the pump. `drain` asked tokio's `try_recv`, which makes no read
while its reactor has not yet seen the socket readable: when the child's exit won the `select!` before the
reactor saw the answer arrive, the drain found nothing in a queue that held the answer. `drain` now reads the
kernel's queue itself (`recv` with `MSG_DONTWAIT`).

- The new test `a_datagram_that_the_reactor_did_not_see_yet_is_drained` sends a datagram to a socket that
  the reactor never polled, then drains: the old drain reads nothing, the new one the datagram.
- Planted (`scripts/plants/t746-drain-by-readiness.plant`, the old `try_recv` drain): caught.
- `cargo test -p podssh-cli --lib pipe::datagram`: 2 passed. The cause is proven, and the OpenTunnel half of the
  entry passed in each gate since `bc5107b0`.

# T-753: On Windows, an operator over a carrier loses the echo's last bytes at the end of its input

**Source:** the gate at `d71901cb` (run 43136322338, the `windows` job), 2026-11-12.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** partial

## Problem

`node_carrier`'s `an_operator_reaches_the_node_at_the_other_end_of_a_program_s_stdio` failed once on the
Windows job: `podssh operator --carrier exec:'podssh node --carrier stdio box TARGET'` with 1 MiB on stdin
to an echo got 1,048,288 bytes back, 288 short; the node said "the session of KEY ended: the stream under
the channel failed: An existing connection was forcibly closed by the remote host. (os error 10054)", then
"the carrier's client ended the stream". It passed on Linux and on the Windows job of `a834dbed`.

## Premise

- The operator's reverse road (podssh-relay's `reverse/operator.rs` at `75a5031`, lines 249 to 253; since
  podssh took `pod-relay` of PodUtils/podcrates at v0.27.0, that crate's `reverse::operator`) writes a frame's
  bytes to the local side only while not `draining`; `end_of_input` (lines 326 to 336 there) sets `draining`
  once the input ends when `node_ends` is set,
  which each leg of the resumable layer sets (`crates/podssh-cli/src/layered.rs:413`).

## Approach

1. Find whether the layer ends a leg's input (at the operator) before the far end's last bytes came, so that
   the leg drops them as bytes that nobody takes: the layer's own end (`pod-session` of PodUtils/podcrates,
   its glue `crates/podssh-relay/src/session/`) should end only after both ends' streams ended and were
   acknowledged. A fix of a module that podssh took goes to PodUtils/podcrates as an issue (Rule Q3).
2. A test that holds the echo's last bytes back past the end of the input (a slow target), on Linux, that
   fails as the Windows job did.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_carrier
```

The new test of a slow tail passes, and fails with the drop planted; the Windows job passes `node_carrier`.

## Done

Partial, 2026-11-12. A late answer is not it on Linux: `an_answer_that_comes_after_the_input_ended_reaches_the_operator_whole`
(an echo that answers 1.5 s after its input ended, 64 KiB) passes (`cargo test -p podssh-cli --test node_carrier`),
so the layer waits for the far end's last bytes there. The reset (10054) is Windows' own: a socket closed with
bytes unread sends a reset there, not a FIN. Next: which end closes a socket with bytes unread at the end of a
session on Windows (the node's target socket, or the carrier's), from the job's log with `-v` on a run of the
Windows job alone.

The job's log (run 43136322338) narrows it: the node's line says the session ended with "the stream under
the channel failed: ... (os error 10054)", which pod-e2e's carry says of a read or a write of either side;
the stream under it at the node is the layer's, in memory, so the reset is of the node's TCP socket to TARGET,
the test's echo, before its last 288 bytes were read. The test's echo now says what each connection saw (the
bytes back, and whether its read, its write or its shutdown failed) in the failure's message; next, the test
50 times on `windows-2025` (`suite-repeat.yml`, package podssh-cli, test node_carrier).

2026-11-12: `suite-repeat.yml` at `8d31fd3b` (run 43146225199), 50 runs of the test on `windows-2025`: 50 passed. The
failure is rare (once in the gate's runs since `a834dbed`); the test's echo now names what each connection saw,
so the next failure on the gate's windows job says which side reset. Next: that failure's message.


# T-756: `reverse_carrier`'s two sessions of 2 MiB were closed as stalled once, in the whole suite

**Source:** the main session's run of `cargo test --workspace --no-fail-fast` at the take of podcrates v0.35.0,
2026-11-13 (3941 passed, 1 failed).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** partial

## Problem

`two_sessions_of_2_mib_each_way_cross_a_carrier_whole` (`crates/podssh-relay/tests/reverse_carrier.rs`) failed once
in the whole suite: session b ended with `1000 the node's local side does not read`. Alone it passed 20 runs of 20.

## Premise

- pod-relay's node (`reverse/route.rs`, `offer`, at podcrates `v0.35.0`) closes a session whose waiting bytes pass
  its handler's `queue_bytes`, 1 MiB for a handler with no flow control of its own (`reverse/node.rs`,
  `QUEUE_BYTES`), as the relay has no flow control for one session.
- The test's `Echo` handler echoed through a duplex of 256 KiB in a task of its own, so a session of 2 MiB passed
  1 MiB of waiting bytes whenever that task lagged, as on a host busy with the whole suite.

## Approach

Give the test's local side room for each byte of a session, so that the result is the carrier's and not the
scheduler's; then watch the gate for the next failure.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair,quick,derp,serve,piping --test reverse_carrier
```

## Done

Partial, 2026-11-13: the echo's duplex is 4 MiB, more than a session carries. `--test reverse_carrier`: 7 passed;
30 runs of `two_sessions` with a busy loop on each core: 0 failed, and 0 failed with the old duplex too, so the
load of a suite (many test binaries, not busy loops) is not reproduced here; the cause is read from the code above.
The entry stays partial until the gate has run the suite a few times with no recurrence.

# T-769: The gate's onion test failed when it ran on a private Tor network younger than about 9 minutes

**Source:** the main session, 2026-11-13: the gate's job `tor-net` failed on `main` (dispatched run 43362726574,
and the push of cc316b3), as it had twice on 2026-11-12 (02:49 and 10:15 to 11:01 UTC), between runs that passed.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`a_node_s_onion_service_carries_a_mebibyte_each_way_and_hides_from_a_stranger`
(`PodUtils/podcrates:crates/pod-tor/tests/onion_service.rs`) waited its 600 s for the descriptor and failed with "not published
within 600 s (Bootstrapping)"; in the runs that pass it is published in 0 s.

## Premise

- The job starts chutney's network, then runs `private_network`, `tor_private` and `onion_service`
  (`.github/workflows/build.yml:481-489`); the time between the start and the onion test is the build's, shorter
  with a warm cache.
- Arti 0.48 calls a service `Running` only once its descriptor went to both rings of HSDirs, the current time
  period's and the second one (`upload_result_state` in `tor-hsservice` 0.48.0, `src/publish/reactor.rs`); until
  then, and while its uploads are rate-limited, it is `Bootstrapping`. `OnionService::published` waits for
  `is_fully_reachable` (`PodUtils/podcrates:crates/pod-tor/src/onion.rs`).

## Approach

Reproduce it on this host with `scripts/tor-net.sh` and Arti's debug log, find what a young network lacks, and
make the harness wait for it before the onion tests: in CI's job and in the commands of `docs/development.md`.

## Prove

```sh
toml=$(sh scripts/tor-net.sh start .work/tor-net "$(hostname -I | awk '{print $1}')")
sh scripts/tor-net.sh wait-onion .work/tor-net
PODSSH_TEST_TOR_NETWORK=$toml cargo test -p podssh-tor --test onion_service -- --nocapture
sh scripts/tor-net.sh stop .work/tor-net
```

## Correction

2026-11-17. The package podssh-tor is `pod-tor` of PodUtils/podcrates since podssh took `v0.65.0` (T-684): the Prove's tests of `podssh-tor` are podcrates' now (`cargo test -p pod-tor` there); podssh's part of it is the CLI's glue and its tests with `--features tor`.

## Done

2026-11-13. Found on this host, with Arti's debug log (`RUST_LOG=tor_hsservice=debug`, a subscriber added for the
run alone): on a network started at 05:43:02 UTC the restricted service uploaded its descriptor to 8 of 8 HSDirs
for the time period 3738642 (8 minutes long) at once, and for 3738643 at 05:48:58, but each new consensus (every
20 s) rate-limited its next upload, and it never reported both rings in one result: `Bootstrapping` for the whole
600 s, then the failure. The consensus held `shared-rand-current-value` alone at 05:50:51 and both values at 05:52:07
(about 9 minutes, two runs of the protocol at chutney's 20 s votes); run then, the three tests passed in 7.6 s. On
the network of the first failure, 19 minutes old, they passed in 8.1 s. A service started before the second value
does not recover.

- `scripts/tor-net.sh wait-onion DIR [SECONDS]`: waits, 1200 s at most, until an authority's
  `cached-microdesc-consensus` holds both shared random values; exit 0, else 75 (64 for a bound that is no
  number). Tried: on the network above, 0 s and exit 0; on a directory with no network, 20 s and 75; `x`, 64.
- CI's job `tor-net` runs it after `tor_private` and before `onion_service` and `derp_onion`; `docs/development.md`
  gives it in the commands by hand, with the reason.
- The run of the job at the push of this change is the check in CI; the test is unchanged.

# T-770: A push of the record cancelled the gate of a push of code, which then was never built

**Source:** the main session, 2026-11-13: `scripts/gate-base.sh` found that the last whole gate that passed on
`main` was at 02650f1, 45 commits back, though each push since had a run of `build.yml` that passed.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`build.yml` cancels the run of an older push (its `concurrency`), and its plan skips each job that builds when the
push changes only documents and the record, judged from the push's parent (`github.event.before`). A push of code
followed within the gate's time by a push of the record therefore had its gate cancelled, and the next run built
nothing: the take of podcrates v0.36.0 (99b9642) and 44 commits before it reached `main` with only the
repository checks.

## Premise

- `.github/workflows/build.yml:19-24`: a newer push cancels the older one's gate.
- The plan's step "what the push changes" diffs `github.event.before` to `HEAD`.

## Approach

The plan diffs from the commit of the last run of `build.yml` on the branch whose job `gate (...)` passed
(`scripts/gate-base.sh`, through the API with the run's token and `actions: read`), not from the push's parent;
a push of the record after unbuilt code then builds it. No such run found, or a diff that cannot be read: build.

## Prove

```sh
sh scripts/gate-base.sh PodUtils/podssh main
```

It prints the commit of the last whole gate that passed; then a push of the record after a push of code shows
"builds: true" in the plan's log.

## Done

2026-11-13. `scripts/gate-base.sh OWNER/REPO [BRANCH]`: the newest of 30 successful runs of `build.yml` on the branch
whose job `gate (...)` passed (a skipped job is no pass), else nothing; run here, it printed 02650f1 in 11 s. The
plan's step "what the push changes" diffs from it, with `actions: read` and the run's token, and builds when none
is found or the diff cannot be read; a dispatch and a pull request build as before. The run at the push of this
change, whose last whole gate is 02650f1, must show "builds: true"; a later push of the record after a gate passed
shows "builds: false".

# T-772: Two russh session loops over a pipe of 64 KiB stop each other with bytes in flight

**Source:** the main session, 2026-11-13, at the merge of T-108: `serve_exec`'s `stdin_comes_back_whole` (1 MB
through `cat`) stopped after 80 KiB every time, with russh's client and podssh's server joined by
`tokio::io::duplex(1 << 16)`; through a pipe of 4 MiB it passed, and OpenSSH's client moved 5,000,000 bytes each
way through the same server.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The server read 10 messages of 8 KiB, gave each to the child, and read no more; the client's writer stopped, though
the server's window (512 KiB) had room. Each loop seems to flush a batch to the pipe before it reads, so with both
ends russh and a pipe smaller than their batches, each waits for the other's read. podssh's own client is russh, so
a `podssh ssh` to a `podssh serve` over a carrier with a small buffer (`serve NAME` on a node's road, T-107's
Approach item 5) could stop the same way.

## Premise

- `crates/podssh-ssh/tests/serve_exec.rs`: the test's pipe was `tokio::io::duplex(1 << 16)`; at the merge it is
  `1 << 22`, which the test now names as its transport.
- The server's flow (`crates/podssh-ssh/src/server/channel.rs`, `child.rs`) passed OpenSSH's 5,000,000 bytes each
  way (`crates/podssh-cli/tests/serve_openssh.rs`).

## Approach

Reproduce with the pipe of 64 KiB and russh's trace at both ends; find which loop writes without reading (russh's
session loop in `vendor/russh`, whose patches are podssh's), and make it read while a write waits, as podcrates' entry 477 did
for pod-relay's serial form. A test: 4 MiB each way through `cat` over a pipe of 64 KiB, russh at both ends.

## Prove

```sh
cargo test -p podssh-ssh --test serve_exec
```

With the pipe at 64 KiB, `stdin_comes_back_whole` passes.

## Done

Done 2026-11-13. The cause, read in `vendor/russh`: after each step, the server's loop
(`src/server/session.rs`) and the client's (`src/client/mod.rs`) awaited `flush_or_timeout`, the whole write of
the batch, and polled no read meanwhile; with both ends russh and a pipe smaller than both batches, each waited in
its write for the other's read. podssh's patch `vendor/patches/russh/0011-write-beside-read.patch`: the loop writes
what the stream takes at once (`PacketWriter::write_now`), keeps the rest behind an offset, and writes it in its
`select!` beside the read (`write_some`, then the stream's flush); it takes no new application message while 1 MiB
waits, and stops reading too past 16 MiB, so a peer that reads nothing holds bounded memory; the last write before a
shutdown has 10 s. Its row in `vendor/README.md`; eleven patches in AGENTS.md and the root `Cargo.toml`.

- `cargo test -p podssh-ssh --test serve_exec` with the pipe at 64 KiB (`tokio::io::duplex(1 << 16)`): 12 passed,
  `stdin_comes_back_whole` among them, and the new `four_mib_each_way_at_once_over_a_pipe_of_64_kib` (4 MiB each
  way at once through `cat`, russh at both ends).
- The plant `t772-whole-write` (`write_now` waits for the whole write again): caught.
- Clippy as the gate runs it on the workspace: clean; check-repo: pass.
- `cargo test --workspace --no-fail-fast`: 4,107 passed, none failed.


# T-780: m6's session with no fault hung past 600 s in the gate

**Source:** the gate of `f9e12b3` (2026-11-14, run 43549248617, job `gate (m6)`).
**Category:** defect
**Milestone:** M6
**Priority:** P1
**Effort:** M
**Status:** partial

## Problem

`with_no_fault_the_layer_carries_the_session` of `crates/podssh-cli/tests/m6_exit.rs`, 20 MiB up and back
through `podssh ssh node://` with the resumable layer and stand-in proxies with no fault, did not end within
600 s in the gate. The client's `-v` lines end at `authenticated to node://m6 as tester`; the client's proxy
logged one CONNECT, the node's three, and the faults' clock started, so 8 MiB at least were written. The other
six tests of the step passed before it, in one thread.

## Premise

- `crates/podssh-cli/tests/m6_exit.rs:34` says "const LIMIT: Duration = Duration::from_secs(600);": the bound
  that the session passed.

## Approach

1. Keep what a next failure needs: the node's lines after `online` go to `node.log` in the test's directory,
   which the failure prints (done with this entry).
2. At the next failure, read which end stopped moving bytes: the node's lines, the client's, the proxies'.
   Repair what they name, with a test that makes it, where the stand-ins can.

## Prove

```sh
cargo test -p podssh-cli --test m6_exit -- --ignored --test-threads 1
```

The step passes in the gate ten times in a row, or the cause is named and repaired with a test that makes it.

## Done

Partial, 2026-11-14: not made here. `cargo test -p podssh-cli --test m6_exit -- --ignored with_no_fault_the_layer`
passed five runs in five (20 s each), and the whole step with `--test-threads 1` passed (7 tests, 394 s). The
node's later lines are now kept for the failure's text. It waits for the next failure.

Again on 2026-11-14, at `02c0cf3` (the take of podcrates `v0.45.0`, run 43613233641): another test of the step,
`iroh::the_iroh_road_survives_a_new_address`, did not end within 600 s. The client said only its known host;
the node's lines end at "came in, by the door"; and both proxies logged a CONNECT to the stand-in relay again
and again after the faults' clock started, the client's from its new address: each end kept dialing the relay,
and no session's bytes ended. Here it passed five runs in five (29 to 35 s each), with the tag's pod-session.
It passed each gate of the six before this one. It waits for its next failure, as the first did.

The next gate, at `213968e` (run 43621390272, 2026-11-14), passed the step whole, its iroh road after a new address among them.

A third time, on 2026-11-15, at `2ffb7cd` (podcrates `v0.48.0`, run of the gate after 43661427667's push): a
third test of the step, `the_layer_survives_a_stall_of_3_minutes`, did not end within 600 s. The client said "the
link failed: nothing came from the far end for 30 s; resuming the session", then "the session resumed after
190.7 s, 753664 bytes sent again", and nothing after; the node's lines end at "came in, by the door". So three
shapes now, each a session of the layer that stops moving and never ends: with no fault (`f9e12b3`), the iroh road
after a new address (`02c0cf3`), and after the resume that followed a stall (`2ffb7cd`). Next: run this test here
until it fails, with the layer's lines at their most (`-v` and the node's), and read which end holds the bytes after
the resume: the replay of 736 KiB that the client sent again, or the node's acknowledgement of it.

2026-11-15, on this cloud host (no fault planted): the stall test alone passed 5 of 5 runs (197 to 230 s each), and the whole m6 step run as the gate runs it (`cargo test -q -p podssh-cli --features podssh-cli/iroh-test --test m6_exit -- --ignored --test-threads 1`) passed 11 of 11 in 631 s. The hang is not seen here; the entry waits for its next failure in the gate, whose log then gives the fourth shape.

A fourth time, on 2026-11-15, at `8536613` (run 43737282670, job `gate (m6)`): `iroh::the_iroh_road_survives_a_stopped_relay_host`
did not end within 600 s. The client said only its known host; the node's lines end at "the client key ... connected";
after "the open tunnels ended with RST (--stop-after)", the client's proxy logged a CONNECT to the stand-in relay
(`relay-i.test`) again and again, and no session's bytes moved after it. So four shapes now, each a session that
stops moving after a fault and never ends, two of them on the iroh road after its relay's link was cut. The other
ten tests of the step passed (1,307 s). Its rerun passed (attempt 2, #272). Here: the test alone 6 runs in 6 (13 s
each), and the whole step as the gate runs it (`cargo test -q -p podssh-cli --features podssh-cli/iroh-test --test
m6_exit -- --ignored --test-threads 1`) 3 runs in 3 (655 to 693 s). As the client of the iroh road ran with no `-v`, the
failure's text held its known host alone: `Road::carry` of `crates/podssh-cli/tests/m6_exit.rs` now runs `ssh -v`
(`podssh node` has no `-v`; its lines are kept already), so the next failure in the gate says where the session stopped.
Next: read that failure's lines.

A fifth time, on 2026-11-15, at `d00ca78` (podcrates `v0.54.0`, run 43766309151, job `gate (m6)`):
`the_layer_survives_a_new_address` did not end within 600 s. The client said "the link said nothing for 1 s, and a
spare link answered; resuming the session", then "the session resumed after 0.0 s, 688128 bytes sent again", and
nothing after, as after the stall of `2ffb7cd`: no loss of the new link either, in 600 s, so its heartbeat was
answered and no session's byte moved. The client's proxy logged its spare from the new address; the node's lines end
at "came in, by the door"; the other ten tests passed (1,238 s). The two shapes of the layer after a resume each sent
again about 700 KiB, near the window of a link of the pair's road (`PAIR_WINDOW`, 768 KiB, pod-session's
`replay.rs`). A reading of `pump/up.rs`, `pump/down.rs`, `pump/outbox.rs` and `link.rs` at `v0.55.0` found no wait
that holds without an `ACK` due: the up half's `room` is the link's own, the reader never waits for the writer, and a
resume sets the acknowledged offset to the peer's received one. `through_the_layer` of
`crates/podssh-cli/tests/m6_exit.rs` now runs `ssh -v` too, so that the next failure gives the layer's spare and retry
lines.
Here, on podcrates `v0.56.0` with each of the 4 cores held busy by a loop of the shell, `cargo test -p podssh-cli --test
m6_exit -- --ignored --exact the_layer_survives_a_new_address` passed 12 runs in 12 (about 30 s each). It waits for its
next failure in the gate.
A sixth time, on 2026-11-16, at `f5b4f43` (podcrates `v0.60.0`, run 43823925587, job `gate (m6)`):
`the_layer_survives_a_stopped_relay_host` did not end within 600 s. With `-v` the client said: "the link ended with no
word from the far end; resuming the session", "no new link yet (the new link ended before the far end greeted);
trying again in 1.1 s", "the session resumed after 1.2 s, 65536 bytes sent again", and nothing after: no loss of
the new link in 600 s, so its heartbeat was answered, and no session byte moved. The node's lines: its link to the
relay ended with no Close, it connected again at once and was "online again"; no line of the session. The other ten
tests passed (1,269 s). Two findings: the client's replay was 64 KiB, far below the pair's window of 768 KiB, so the
window is not the common factor of the fifth shape; and each of the six is one shape seen from the client, a resume
that it calls done after which the session never moves while the link lives. The code of the resume is
`pod-session`'s (`resume.rs`'s `resume_loop`, `keep.rs`'s `run_resumed` and `take`, the pump), which podcrates owns
(Rule Q3): podssh gives podcrates the six shapes by COORD-091 (#283), and asks for a line of the far end at each resume
(its number, the offsets of both ends, the bytes sent again), so that the next failure says which end holds.
The same day it failed here, for the first time off the gate: `cargo test -p podssh-cli --features
podssh-cli/iroh-test --test m6_exit -- --ignored --exact the_layer_survives_a_stopped_relay_host`, 15 runs one after
another at `f5b4f43`, failed once (run 8, 600 s; each other run 15 s). The client resumed twice in a row, "after 0.0 s,
98304 bytes sent again" and "after 0.0 s, 130126 bytes sent again", then said nothing. After the faults' clock the
client's proxy logged a CONNECT before the RST and one after it; the node's proxy logged one CONNECT after the RST
alone, its link to the relay ("online again"), and none for the session. So the node opened no new connection for the
resumed session, and yet the client heard the far end's greeting and proof: the question for podcrates is which way
carried the node's half of that resume (COORD-091, amended).
A seventh time, on 2026-11-16, at `5340fbb` (podcrates `v0.63.0`, run 43870922795, job `gate (m6)`):
`the_layer_survives_a_stall_of_3_minutes`, now with the far end's line of each resume (podcrates `v0.62.0`, its
T-767). The client: a spare link timed out, "nothing came from the far end for 30 s; resuming the session", five
tries whose TLS handshakes timed out after 20 s, then "the session resumed after 150.0 s, 687745 bytes sent again"
(inside the stall of 180 s), and nothing after for 450 s. The node: "resume 1 on relay session 186f0a64...: the client
has 5040486 bytes of this side, and this side sends 0 bytes again; this side has 7814432 bytes of the client (7814432
in its ACCEPT), 0 of them not yet written to the target; no link carried the session". The test echoes, so the target
had answered more than the 5,040,486 bytes that the node sent; as the node sends 0 again, about 2.77 MB of the answer
never left the target or the node's read of it, and never moved after the resume. So the session holds at the node,
in the half that reads the target and writes to the link, after the resume of a session that no link carried. COORD-091
(#283), amended, gives podcrates the line and asks for a look at that half, or a line of its room and wait.



2026-11-17, podcrates `v0.65.0` taken (COORD-125): its answer to COORD-091 (#283) is the far end's line
`session.stall`, once for each wait of the node's reader of the target that holds 20 s (the replay buffer, the
window, the link's writer, the records sent again, or a target that sent nothing while it took bytes), with the
offsets sent and acknowledged, the bytes kept, the room and the window; and `session.resume` ends with the room and the
window. m6's test keeps the node's lines (`-v`), so the next hang names its wait. Next: at the next failure of `gate
(m6)`, read the node's `session.stall` and write it on #283.

2026-11-17, here at podcrates `v0.69.0`: `cargo test -p podssh-cli --test m6_exit -- --ignored --test-threads 1` passed
8 runs in 8 (2 at `6a1a9eb`, 6 at `5d6efd0`; about 370 s each, 7 passed each). Still waits: the gate's next failure of
`gate (m6)`, whose node's `session.stall` lines name the wait (COORD-091, #283).

2026-11-18, the eighth failure, at `5c254fb` (podcrates `v0.70.0`, run 44287863366, job `gate (m6)`):
`iroh::the_iroh_road_survives_a_new_address`. The node said `the target sent no byte for 23 s, while it took 201
bytes of the client; this side sent 13758313 bytes, the client acknowledged 13247259; the replay buffer keeps 511054
bytes, room 3683250; no window`, and no resume came; the client said nothing after `authenticated`, while its proxy
logged 14 CONNECTs to the iroh relay from the new address. So 511,054 bytes in flight at the change were never
acknowledged and neither end resumed: the wait is in pod-iroh with pod-session, not the node's room. Written on
#283 as its ask 4 (amended).

2026-11-19, podcrates `v0.73.0` (its entries 939 and 945, #283 ask 4): `pod-session` ends a link whose PING waits 30 s
while neither count moves, and the layer resumes on a new link; the client says each wait that holds 20 s (`Note::Stall`,
at `-v`, `layered.rs`), and the iroh road says each change of its relay connection (`say_changes` in
`ssh/iroh/dial.rs`, at `-v`). The next hang names its wait at both ends. Here, `cargo test -p podssh-cli --features podssh-cli/iroh-test
--test m6_exit -- --ignored --exact iroh::the_iroh_road_survives_a_new_address`: 6 runs in 6 passed (about 40 s each).

2026-11-19, the ninth failure, at `9989ae6` (podcrates `v0.74.0`, run 44452674747, job `gate (m6)`):
`iroh::the_iroh_road_survives_a_new_address` again, now with the client's lines: its iroh relay connection ended and
came back in 0.0 s, then "the application took no byte for 21 s, while 288823 bytes wait for it; this side sent
20680508 bytes, the far end acknowledged 20680508; the replay buffer keeps 0 bytes, room 4194304; no window; this side
received 14055738". The node said nothing of a stall. So nothing waits on the link: the client's layer holds 288,823
bytes that the application above it does not take. That application is pod-e2e's channel (`channel::around`), which
writes into the 256 KiB pipe that podssh's SSH reads (`ssh/iroh/dial.rs`). Either SSH stopped reading the pipe, or the
channel holds for a cause of its own. `ssh/iroh/held.rs` now says, at `-v`, a write of the channel to SSH that waits
20 s, with the bytes that went to SSH so far (a unit test with a paused clock); the next hang tells the two apart.
Here: 4 runs in 4 of the case with it.

2026-11-19, the tenth failure, in the gate of Dependabot's pull request at `dcbea2c` (run 44478407399, job `gate (m6)`):
`the_layer_survives_a_stall_of_3_minutes`, the layer's road, not the iroh road. The same sign at the client: "the
application took no byte for 22 s, while 191361 bytes wait for it; this side sent 20680058 bytes, the far end
acknowledged 20680058"; and the node: "the target sent no byte for 24 s, while it took 98505 bytes of the client". So
on both roads the hold is above pod-session, at the client: pod-e2e's channel or podssh's SSH. The watch of the pipe
to SSH (`crates/podssh-cli/src/ssh/held.rs`, moved out of the iroh road) now runs on the `node://` road too
(`ssh/node.rs`). Here: `m6_exit`'s `the_layer_survives_a_new_address`, `the_layer_survives_a_stall_of_3_minutes` and the
iroh new-address case, each passed.

2026-11-19, podcrates `v0.76.0` (its entry 959, #283 ask 5): pod-e2e's channel says each write that waits 20 s, to the
application or to the layer (`e2e.wait`). `channel::around_told` gives a stream of the channel's lines (`Told`), and
the layer's and the exit's roads say each at `-v` (`layered.rs`, `exit/tunnel.rs`). With the layer's `Note::Stall` and
the watch of SSH's pipe, the next hang names its reader at each step. Here: `cargo test --workspace --no-fail-fast`, 383
suites, 0 failed; the m6 cases of the layer's stall and the iroh road's new address passed.

2026-11-19, the eleventh failure, in the gate of Dependabot's pull request at `4b21fcd` (run 44506565889, job `gate
(m6)`): `iroh::the_iroh_road_survives_a_new_address`, with the watch of the pipe: "SSH read nothing for 20 s while the
channel waits to give it bytes; 16089582 bytes went to SSH so far", and the layer: "the application took no byte for
21 s, while 961099 bytes wait for it; this side sent 20680506 bytes, the far end acknowledged 20680506". So the hold is
podssh's SSH, which stopped reading its end of the pipe; the layer and pod-e2e's channel wait on it (pod-e2e carries
both directions at once, `channel/carry.rs` of podcrates `v0.76.0`). podssh's pump reads the channel's messages while
a send waits for the window (`crates/podssh-ssh/src/io.rs`, `send`), so the cause is not plain. A second watch now
says SSH's own write to the channel that waits 20 s ("the channel read nothing of SSH ..."): both lines at the next
hang mean a cycle through the pipe; the first alone means SSH holds by itself (russh's session or podssh's pump). Here:
the iroh new-address case and the layer's new-address case passed; `--test pipe --test proxy` passed. Where SSH can stop
reading: russh's loop (`vendor/russh/src/client/mod.rs`, podssh's patch of T-772) reads beside a pending write only while
the unwritten output stays under `OUTPUT_MOST`, and a read's handler (`reply`) is awaited inline, so a full receiver of
a channel holds the loop. The second watch tells the first (SSH's write waits too) from the second (it does not).

2026-11-19, the twelfth failure, at `c9772a3` (run 44561423514, job `gate (m6)`): `iroh::with_no_fault_the_iroh_road_carries_the_session`,
with no fault at all. "SSH read nothing for 20 s while the channel waits to give it bytes; 18491926 bytes went to SSH so
far", the layer's "the application took no byte for 20 s, while 983777 bytes wait for it", and no line of SSH's own
write. So SSH holds by itself, with no cycle through the pipe and no loss of a link: russh's read loop, or podssh's pump
in a step that does not take the channel's messages. The pump now says, at `-v`, a step that holds it 20 s with the
step's name (`crates/podssh-ssh/src/io/busy.rs`; the send split into `io/send.rs` for `io.rs`'s length): a line of it at
the next hang names the pump's step; none means russh's loop. Here: `-p podssh-ssh --lib io` 66 passed (the watch's
test among them), `-p podssh-ssh` each test passed, both no-fault m6 cases passed.

Loop, 2026-11-19, at `fbf49b2` (the busy watch in): `the_layer_survives_a_stopped_relay_host` and
`iroh::the_iroh_road_survives_a_new_address` 15 times each, then the whole of `m6_exit` 4 times, here: each passed. The
gate at `0661ded` (run 44571876363): `gate (m6)` passed. It waits for its next hang.

2026-11-20, the thirteenth failure, in the gate of Dependabot's pull request #331 at `1a24efd` (run 44649725163, job
`gate (m6)`): `the_layer_survives_a_stopped_relay_host`, the first hang with the pump's busy watch in. The client said
"SSH read nothing for 20 s while the channel waits to give it bytes; 11990334 bytes went to SSH so far" and pod-e2e's
"the application took no byte of the channel for 20 s, while 25224 bytes wait for it"; no line of the busy watch ("held
in ...") and no line of SSH's own write. The client's layer had sent 20,680,531 bytes, all acknowledged, short of the
upload's 20 MiB: SSH wrote nothing either. So the pump waited in its select, ready for the channel's messages, and
russh's loop neither read its stream nor waited in a write: it awaits inside a step of its own. Of its loop's awaits,
podssh's handler answers each at once (`crates/podssh-ssh/src/handler.rs`); the one that can hold is a channel's queue
(`chan.send(...).await` in `vendor/russh/src/client/encrypted.rs`), or a reply's other await. podssh's patch
`vendor/patches/russh/0013-loop-step.patch` keeps the loop's step (`russh::client::Step`: a reply to which message, the
queue of a channel with its data, the handler's data), `Handle::step` gives it, and the pump's busy watch says a step of
the loop that holds 20 s at `-v` ("the SSH session's loop read nothing of its stream for N s, held in ..."). Proven by
`crates/podssh-ssh/tests/loop_step.rs` (a server of the process floods a channel that nobody reads: the step names the
channel's queue; planted, the queue's mark taken out, it named the reply and failed) and the unit test of `io/busy.rs`.
The next hang names the step; a line naming the queue means a channel whose messages nobody takes.

2026-11-20, the fourteenth failure, in the gate of Dependabot's pull request #331 at `cfc07be` (run 44710629383, job
`gate (m6)`, podcrates `v0.79.0`): `iroh::the_iroh_road_survives_a_new_address`, with the step of russh's loop: "the SSH
session's loop read nothing of its stream for 20 s, held in the queue of a channel, with its CHANNEL_DATA", with the
pipe's "SSH read nothing for 20 s ...; 18903706 bytes went to SSH so far" and the layer's "the application took no byte
for 20 s, while 1154073 bytes wait for it", and no line of the pump's busy watch. So russh's loop waits to put a
CHANNEL_DATA into a channel's full queue, while the pump, idle in its select, should drain that queue: either the queue
is another channel's, which nobody reads, or the pump's task is not polled (a branch of its select, or the task that it
shares with the layer, holds the thread). The step now names the channel (`Step::now`'s channel, podssh's patch
`0013-loop-step`), the watch's line names the session's own channel beside it, and the busy watch says an idle pump
whose wait of the channel was not polled for 20 s. Proven: `tests/loop_step.rs` (the step names the channel that nobody
reads; planted, the queue's step with no channel: caught) and `io::busy`'s unit tests (an idle pump not polled for 20 s
is said once; one polled since says nothing); `cargo test -p podssh-ssh` 568 passed, 0 failed; the m6 layer cases of a
new address and of no fault passed here; clippy (the gate's lints) clean.

# T-781: A session through a tunnel of HTTP alone made no progress at localhost.run, as each spare link replayed the same bytes

**Source:** the live job of T-565 in `last-roads-live.yml` (runs 42989086142, 42994885604 and 43560494966).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`a_node_behind_localhost_run_serves_a_client_at_its_tunnel_s_url` passed `greet` and then took none of its 1 MiB
in 120 s, in three runs in a row (it passed on 2026-11-11 at 05:40). The client said "the link said nothing for
13.0 s: a spare link opens beside it" again and again, and the node wrote 192 to 256 KiB into each link, its
writes waiting for 2 to 13 s: localhost.run holds the far end's bytes for longer than a spare waits. Then the
spare took the session, the node replayed the same bytes into the same third party, and nothing came through.

## Premise

- `crates/podssh-cli/src/layered.rs:89` says "let spare_links = !std::env::var(SPARE_LINKS_ENV)": a client
  opens spare links on each road but the iroh road's.

## Approach

1. Where each road of the race is a third party's tunnel of HTTP (Pinggy, Serveo, a tunnel of `ssh -R`,
   srv.us, localtunnel, the Bare hop), the session opens no spare link: a spare goes through the same third
   party. The heartbeat still finds a dead link after 30 s. A race with any other road keeps spare links.
2. Ask podcrates (a COORD issue) for a spare that backs off in `pod-session` after a spare that moved no byte.

## Decision

The rule is in podssh's glue (`road_link::spares`), which podssh owns, as `iroh_settings` holds spares off for
the iroh road; the general back-off belongs to `pod-session`, which podssh took (Rule Q3). Lost: spares off for
localhost.run alone (its kin end HTTPS the same way, and none gains from a spare through itself); a longer wait
for a spare on each road (slower on a client that moved, where a spare earns its 3 s).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib tunnels_of_http
```

Live: the job of T-565 in `last-roads-live.yml` passes.

## Done

Done, 2026-11-14: `road_link::spares` gives the session's settings with no spare link where each road of
the race is a tunnel of HTTP; `ssh::roads` takes it. `cargo test -p podssh-cli --lib tunnels_of_http`:
1 passed (localhost.run with its Bare hop and the other tunnels alone take none; the pair's road or bore.pub
beside them keeps them; `PODSSH_SPARE_LINKS=no` holds). The live job runs after the push (STATUS).

Live, 2026-11-14, `last-roads-live.yml` at `1c4c440` (run 43564876193): no spare link opened (the client's
lines name none), and localhost.run carried 352 KiB of the 1 MiB in 120 s, about 3 KB/s, where on 2026-11-11 its
link carried 1 MiB in 67 s: the pace of its free tunnel, not of podssh. The run through localhost.run (and its Bare
hop) now takes 128 KiB down (`down_for` of `crates/podssh-cli/tests/last_roads_live.rs`), each other road 1 MiB.
The live job runs again after the push (STATUS).

Live, 2026-11-14, `last-roads-live.yml` at `6fdf175` (run 43577144823): localhost.run's job passed (`greet`, then
128 KiB down, whole), as did srv.us, tunnl.gg, Sandhole, localtunnel and bore; the Bare hop failed on
openbare.xyz's own 500, T-740's blocker.

2026-11-14, podcrates `v0.45.0` (COORD-097) answers COORD-065 with its T-579: pod-session's wait for a spare
doubles after each spare that took the session and moved no byte, up to its 30 s, and the first byte that moves
sets it back (`beside.rs`, `SpareWait`). podssh keeps its rule of no spare where each road is a third party's
tunnel of HTTP: there a spare goes through the same holder, and several replays would still be lost before the
wait passed localhost.run's 13 s; the back-off now guards each other road. Lost: spares on again for the
tunnels (a client that moves would resume within seconds, not 30 s, at the cost of those replays), which the
live job of the tunnels would have to measure first.

# T-783: `pipe exec:` beside `udp:node:` lost a program's last answer when a send to it failed after its exit

**Source:** the gate of `1c4c440` (2026-11-14, run 43564870189, job `gate (ssh)`).
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`a_program_sends_and_takes_whole_datagrams_and_its_status_comes_back` failed again after T-746: "the program's
output ended with no answer; its verdict: Some((3, []))". The program echoed the first datagram and exited; the
loop then sent the second one to its closed socket, which failed, and the drain after it found nothing.

## Premise

- Read at `1c4c440`: `crates/podssh-cli/src/pipe/datagram.rs` gave the program one end of one socketpair as both
  its stdin and its stdout ("theirs_out = theirs.try_clone()").
- Linux, `unix_dgram_disconnected`: a send on a datagram socket whose peer is dead purges the sender's own receive
  queue. Measured here with Python: a peer sends `echo` and closes; a send to it is refused (111), then a read
  finds nothing (11); with no send, the read gets `echo`.

## Approach

1. Two socketpairs: the program's stdin on one, on which the loop sends, and its stdout on another, on which
   nothing is sent, so a failed send drops nothing that the program said. The loop reads both, for a program
   that writes on its stdin.
2. A test of the two sockets: an answer on the stdout's pair stays through a failed send on the stdin's.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib pipe::datagram
```

## Done

Done, 2026-11-14: `exec` gives the program two pairs (`Sockets { to, from }`); the loop sends on `to`, reads both,
and drains `from` first after a failed send and at the program's exit. The new test
`an_answer_stays_when_a_send_to_a_program_that_closed_fails`: passed; `--lib pipe::datagram`: 3 passed; the
exec test 300 runs in 300 passed here. The planted run waits for T-251: the loss is a race of the loop against
the program's exit, which the exec test meets only at random.

Correction at the gate of `f599ce4` (2026-11-14): CI's container took the send to the closed end, where this
machine's Linux refused it, so the new test's assertion on the send failed there. The test asserts the answer
alone now, which is what the change keeps on either kernel.

# T-784: On macOS, `pipe_listen`'s stale socket was still served by a child of another test

**Source:** the gate of `6fdf175` (2026-11-14, run 43577129878, job `macos`).
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`a_socket_that_nobody_serves_is_replaced` failed on macOS: podssh found "a program listens on it already" at a
socket that the test had bound and closed. On macOS a listener's close-on-exec is set after its `socket`, so a
child that another test thread forks in between inherits it and serves the socket until it ends.

## Premise

- Read at `6fdf175`: `crates/podssh-cli/tests/pipe_listen.rs` bound a listener and dropped it, then started the
  server at once ("drop(std::os::unix::net::UnixListener::bind(&path).unwrap());").

## Approach

1. The test waits, within its limit, until a connect to the socket is refused: the state that it needs, a
   socket that nobody serves. podssh's probe of a stale socket stays as it is: it is right to refuse one that
   answers.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test pipe_listen
```

The gate's job `macos` passes.

## Done

Done, 2026-11-14: the wait is in the test; `cargo test -p podssh-cli --test pipe_listen`: 8 passed here (Linux);
the job `macos` runs it at the next gate.

The gate of `c009f3b` (run 43594009290, 2026-11-14) passed, its job `macos` among them.

# T-788: On macOS, `node_cut`'s strict stand-in sent no 1003 once

**Source:** the gate of `568f9b2` (2026-11-15, run 43657288233, job `macos`).
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

`a_strict_relay_s_1003_costs_the_other_session_no_backoff` of `crates/podssh-cli/tests/node_cut.rs` failed on macOS:
"the 1003 came", with no line of a 1003 among the node's, though both sessions ended whole. The stand-in sends the
1003 for a frame of the cut session's link that is in flight when it tells the node of the lost link, a second
late (`lateclose:1`); where the cut link had drained before that second, no frame is in flight, and no 1003 comes.

## Premise

- `crates/podssh-cli/tests/node_cut.rs:243` says "assert!(!closed.is_empty()": the check of the 1003.

## Approach

1. At the next failure, read the node's lines and the stand-in's log for the frames of the cut link after the cut.
2. Make the precondition hold: the cut session keeps writing past the cut until the stand-in's close (a source
   that does not end at the cut), so that a frame is in flight each time; never weaken the check of the 1003.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_cut
```

The gate's job `macos` passes it ten times in a row, or the cause is named and repaired with a test that makes it.

## Done

Partial, 2026-11-15: not made here: `cargo test -p podssh-cli --test node_cut a_strict_relay` passed three runs in
three on Linux. It passed each macOS gate before this one. It waits for its next failure.


# T-796: The gate's OpenSSH and Dropbear interop hung past the job's 45 min, and left no line of where

**Source:** the gate of `d13ab01` (2026-11-16, run 43839740067, job `gate (release)`, attempt 1).
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

The step `release` built the static binary in 9 min 53 s, then `interop: OpenSSH and Dropbear` printed nothing for
34 min, until the job's limit of 45 min cut it (GitHub calls that "cancelled"). The same code passed on attempt 2:
636 checks in 12 min 44 s; the two green gates before it took 11 min 8 s and 13 min 49 s. So a check hangs at random,
and the log does not say which.

## Premise

- The gate's `run` writes a step's lines to a file and shows them only when the step ends
  (`scripts/gate.sh:68`), so a step that the job's limit cuts shows none.
- The interop step had no bound of its own under the job's 45 min.

## Approach

1. Give the step its own bound under the job's, so that a hang ends as a failure and `run` shows each line said so
   far: the last check named is the one before the hang.
2. At the next hang, read which check it was, and give that check its own time limit, or repair what it waits for.

## Prove

The gate's `run` in the build image: a step that hangs under the bound ends with its lines shown; planted, the same
step with no bound and cut from outside shows none. Then the next hang of the gate names its check.

## Done

Partial, 2026-11-16. `scripts/gate.sh` runs `scripts/interop.sh` under `timeout 1500`, 25 min, about twice its usual
time and under the job's 45 min with the build before it. In the build image (`rust:1-alpine` at the gate's digest;
busybox's `timeout`), the gate's own `run` function: a step that said two checks and then slept ended at its bound with
`exit=143` and both lines shown; planted, the same step with no bound, cut from outside, showed none. It waits for the
next hang of the step, whose lines then name the check that held.

# T-797: The weekly fuzz run stopped before its first target, two weeks running, on a count of seeds that had moved

**Source:** `fuzz.yml`'s scheduled runs of 2026-11-09 (run 42624714624, at `7e38d5b`) and 2026-11-16 (run 43872863719,
at `5340fbb`).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

`scripts/fuzz.sh` runs `scripts/fuzz-seeds.py` before its targets, and the script's last line counted seeds that it no
longer made: `NameError: name 'answers' is not defined` on 2026-11-09, `name 'hosts' is not defined` on 2026-11-16.
The relay's lists, the DNS answers and the WebSocket frames moved with their code to PodUtils/podcrates (T-684), and
their seeds with them, but the line that counts them stayed. So no target of T-198 ran for two weeks; the record did not
know.

## Premise

- The summary line named `hosts` and `answers`, which nothing in the script defines any more, and the script still wrote
  the seeds of `ws_frame`, a target that `fuzz/Cargo.toml` no longer has.

## Approach

Count only what the script writes; drop the seeds of the gone target; say in its head where the moved seeds are.

## Prove

`python3 -I scripts/fuzz-seeds.py` exits 0 (the code before it exits 1 with the `NameError`), and `fuzz.yml` run by hand
on the commit runs each target.

## Done

Partial, 2026-11-16. `scripts/fuzz-seeds.py` counts the IRC lines and the messages of Cap'n Proto that it writes, and no
longer writes `ws_frame`'s seeds; its head names the targets that moved. `python3 -I scripts/fuzz-seeds.py`: "51 IRC
lines, 23 messages of Cap'n Proto", exit 0; the code before it, run the same way here: exit 1, `NameError: name 'hosts'
is not defined`. `fuzz.yml` by hand at `7c20f2e` (run 43880857817): the seeds were written ("51 IRC lines, 23 messages
of Cap'n Proto") and each of the 16 targets ran its 120 s, 15 of them with no failure. `proxy_url` failed on its first
crash in two weeks of no fuzzing: `http+unix:/s+unix:/`, which `pod-proxy` parses as an HTTP proxy on a Unix socket
(host empty, port 0) and shows as its socket, `unix:/s+unix:/`, while the target held that each proxy shows its host and
port (an empty host and port 0). The parser was right and the target stale, written before `pod-proxy` took proxies on a socket or at a
command: it now wants the host and port of a proxy over TCP alone, and of the others an address that is not one
(`crates/podssh-ws/src/dial.rs` gives `Carrier` beside `Proxy`); the round trip of the URL stays. Checked by the
target's property on `http+unix:/s+unix:/`, `http://user:pw@proxy.example:3128` (shown as `proxy.example:3128`) and
`socks5h+unix:/run/p.sock`, each passed, and `cargo check --manifest-path fuzz/Cargo.toml --bin proxy_url`.
`fuzz.yml` by hand at `a37ea01` (run 43889251706, 2026-11-16): success; each of the 16 targets ran its 121 s
(from 417,747 to 34,533,584 runs) with no crash, `proxy_url` included. Done.


# T-800: `node_cut`'s test of podssh's role failed at random: a relay session's id held the digits 1003

**Source:** the gate at `37f9196` (2026-11-16, run 43912907328), its job `macos`.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

`the_role_drops_the_frames_in_flight_of_a_lost_link` failed: "no 1003 reached the node", while no close reached it.
The node's line of a resume names the relay session's id, random hex, here `d36e0a05f2d3a074100374eea299b8e7`, and the
test looked for "1003" anywhere in a line.

## Premise

- `crates/podssh-cli/tests/node_cut.rs` asserted `!c.node.iter().any(|l| l.contains("1003"))`, and its strict twin
  counted such lines as the close that came.

## Approach

Find 1003 as a word of its own (`names_1003`), in both tests, with a test of the helper on the run's own line.

## Prove

```sh
cargo test -p podssh-cli --test node_cut
```

## Done

Done, 2026-11-16. `names_1003` splits a line at each character that is not a letter or a digit; the test of it holds
the macOS run's line (no 1003) and a close's line (1003). `cargo test -p podssh-cli --test node_cut`: 4 passed. Every other job of that gate passed.

# T-810: `PODSSH_OFFLINE` does not stop `podssh update --check`

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

ENVIRONMENT says `PODSSH_OFFLINE` forbids each network connection. `PODSSH_OFFLINE=1 podssh update --check` exited 0
after 4.2 s and named the newest release "from the releases' feed": it reached GitHub. `ssh`, `relay status`, `ping`
and `doctor` honour the variable.

## Approach

`podssh update` (each form that reads the feed or downloads) checks `PODSSH_OFFLINE` first and ends with its refusal,
as the other commands do, and its exit code (69, nothing reached). A test runs `update --check` with the variable set
and a feed URL that would answer, and asserts no request and the refusal.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test update_offline
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. `podssh update` (each form but `--rollback`, which reads no network) checks `PODSSH_OFFLINE` first and
ends with "PODSSH_OFFLINE is set, so podssh does not connect anywhere" and 69, as `ping` does
(`crates/podssh-cli/src/update/mod.rs`). `cargo test -p podssh-cli --test update_offline`: 1 passed (a listener stands
in for `HTTPS_PROXY` and counts no connection; one line, 69). Planted, the check removed: the run went out through the
proxy, caught.

# T-811: `podssh each` on the layer's road: concurrent sessions of one process fail but one

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

`podssh each ... root@127.0.0.1,127.0.0.1,localhost -- 'echo ok'` through `podssh relay serve` (which offers the layer)
exited 255 in 3 runs of 3 with 1 host of 3 ok; the others said `the resumable layer's handshake failed: the link failed
in the layer's handshake: broken pipe`. With `PODSSH_RELAY_LAYER=no`, 3 of 3 ok; three `podssh ssh` processes at
once, each ok. A host that does not resolve took a good host down with it.

## Approach

Reproduce with a test of `each` over podssh's own relay role and three sessions at once; find what the sessions of one
process share on the layer's road (a process-wide state of the layer's client, its links or its offer) and give each
session its own. The test passes 10 runs in 10, with a fourth host that does not resolve failing alone.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test each_layer
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. The cause: the process's pool of HTTP/2 connections to a relay (`pod_relay::Context`'s, pod-ws's
`h2_road::Pool`) drives each connection on the runtime that opened it, and each session of the layer's road ran on a
thread and a runtime of its own (`relay_layer/ssh.rs`). The sessions of `each` shared one connection; when the first
session ended, its runtime ended the connection, and the others' links broke ("broken pipe", in the layer's handshake
a failure). Reproduced here: `podssh each` of three hosts through `podssh relay serve` lost a link in 2 runs of 3.
Repaired: `crates/podssh-cli/src/relay_layer/one_thread.rs` runs each session of the layer's road on one thread and
runtime for the life of the process (a `LocalSet`, as the opener's future is not `Send`; the thread's stack of 16 MiB as
before). Asked of podcrates, at the root: COORD-113 (#310). `cargo test -p podssh-cli --test each_layer`: 1 passed
(five runs, three good hosts and one name with no answer: 3 gave 0, 1 failed, no link lost); planted, the runtime of
each session back: caught on its first run. `--lib one_thread` 1 passed; `--test relay_serve --test node --test
http_road_layer_cli --test error_lines --test h2_each_cli --test each` and `--lib` (1251) passed.

# T-812: With `PODSSH_RELAY_LAYER` unset, a named relay's offer is never read, so `proxy` never half-closes on a first run

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

ENVIRONMENT says that for a relay host that the user named whose offer is not kept, its `/relays.json` is read once,
1 s at most, before the session. With the variable unset no offer was read or kept (the relay logged no `/relays.json`),
so `podssh proxy` took the contract's road, which has no half-close, and hung on a closed stdin until its timeout.
Only `PODSSH_RELAY_LAYER=yes` wrote the offer; later runs then took the layer.

## Approach

Read the offer as the manual says when the variable is unset and the host was named; a test asserts the one read, the
kept offer, and `proxy`'s end on a closed stdin within a few seconds on a first run.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_offer_read
```

The test fails on the code before the fix and passes after it.

## Correction

2026-11-17. The read is made as the manual says: a fresh cache reads the named host's `/relays.json` once, keeps its
offer, and `proxy` takes the layer and ends at once on a closed stdin (measured here, 0.15 s). What the pass saw was a
kept offer of "no layer": a read that failed (the pass's relay was down after its host restarted) was kept as no
offer for a day, by design, so that a relay that hangs costs its wait once a day; the cache's places include a
directory of the temporary tree that each home of the uid reads (`/tmp/podssh-UID`), so a fresh home took it too.

## Done

2026-11-17. `crates/podssh-cli/src/relay_layer.rs`: `keep_read` keeps an offer that was read, and a read that waited out
its limit as no offer, as before; a read that failed at once (a refused connection, a relay down) is not kept, so the
next run reads again, at no cost. `cargo test -p podssh-cli --test relay_offer_read`: 1 passed (a dead relay keeps no
offer; then a fresh run through podssh's relay role, the variable unset, takes the layer and ends at once on a closed
stdin); `--lib relay_layer` 7 passed; `--test relay_serve --test http_road_layer_cli` passed. Planted, each failed read
kept: caught. The places of the cache (a temporary directory shared by each home of a uid) stay as designed (T-593),
for a sandbox whose home may not be written.

# T-813: `health --preflight` says `direct` of a session that went through the relay

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

`podssh health --relay-host ... --preflight root@127.0.0.1` printed `ok    road           direct: not the relay, so none
of its limits on a session`; the session went through the relay (its log: `upgrade layer`), with no `--direct`.

## Approach

The road line reads the road that carried the session; a test through podssh's relay role asserts the relay's road and
its limits, and `direct` only with `--direct`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test health_road
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. The layer's road gives its stream with no status of the relay's session (`Reached { relay: None, layer:
Some(..) }`), so `health/preflight/mod.rs`'s `Road::of` read it as `direct`. On the relay's road, the layer's carriage now
says that the relay carried it, and the road line says so: "the relay HOST, in the resumable layer: a limit of the relay
ends a link, and the session goes on a new one" (`judge::road`); the contract's road keeps its line of the relay's
limits. The manual's note of `health` says both. `cargo test -p podssh-cli --test health_road`: 1 passed (podssh's
relay role, the layer yes and no); `--lib health` 36 passed. Planted, the layer's road read as no relay: `direct`,
caught.

# T-814: The hint of an idle cut names 180 s where the relay published another limit

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

A relay with `--idle 3`: `podssh proxy` ended with `1001 idle timeout`, then `the relay closes a session after 180 s
with no traffic; set ServerAliveInterval below 180`. The relay's `/relays.json` said `idle_timeout_ms` 3000.

## Approach

The hint takes the limit of the relay's offer when it is known, else says that the relay's limit is unknown; a test
with a role of `--idle 3` asserts "3 s".

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test idle_hint
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. The hint of an idle cut was a fixed text of 180 s (`podssh-ws/src/close.rs`). It is the relay's own limit
now: `podssh_relay::context::tell_idle` gives podssh-ws the idle limit of the relay that the run's sessions use, as
pod-relay keeps it from that relay's `/relays.json` (`Context::in_use`), before each place that says the hint (`ssh`,
`proxy` and `pipe`, the HTTP road); "the relay closes a session after 3 s with no traffic; set ServerAliveInterval
below 3". Where no `/relays.json` of that relay was read, the hint names no number as its own: "after its idle limit
with no traffic (180 s at podssh's default relay)". `cargo test -p podssh-cli --test idle_hint`: 1 passed (podssh's relay
role with `--idle 3`, `proxy` on the contract's road: 69, `1001 idle timeout`, no 180 s as its limit); `podssh-ws --lib
close` 2 passed (3 s where given, the words with no number where not). Planted, the fixed 180 s: caught. Where the
role's own 3 s is named depends on its `/relays.json` being read for a named host, which T-812 repairs.

# T-815: `config import ansible` takes a port that is no number and writes it

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

`printf '[g]\nh1 ansible_port=notnum\n' | podssh config import ansible -` exited 0 and wrote `Port notnum`; the manual
says a bad line ends the run with its number (exit 65).

## Approach

A port of 1 to 65535 alone; another value ends the run with 65 and the line's number. A unit test of the reader, and the
planted case of `notnum`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib config::import
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. `config_import/ansible.rs`: `port_ok` holds `ansible_port` and `ansible_ssh_port` (a host's word, a group's
`:vars` line, and a `host:PORT` pattern) to 1 to 65535; another value ends the run with the line's number and 65.
`cargo test -p podssh-cli --lib config_import`: 15 passed (`a_bad_line_is_refused_with_its_number` takes `notnum`,
70000 and `:0`); `printf '[g]\nh1 ansible_port=notnum\n' | podssh config import ansible -` says `-:2: ansible_port=notnum: a port is a
number from 1 to 65535` and exits 65. Planted, every value taken as a port: caught.

# T-816: `relay serve` does not write the lines that the manual promises: a client's Close, and a refusal's cause

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

The manual says each mint, upgrade and client's Close is a line on stdout, and that a refusal's cause is a line. No
Close line came after many sessions nor after a 1001 idle cut; a 502 for a refused target wrote no line (a 403 did).

## Approach

Write the Close of each session (its code and reason) and the cause of each refusal, as the manual says; a test of the
role reads them from its stdout.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. The role wrote a client's Close only where a Close frame came (`close CODE` in `serve/forward.rs`), and a
session on HTTP/2 or on the layer's road ends its stream with none, so most sessions ended with no line. Each session's
end is a line now, at the end of `forward::pump`, which each road's session goes through: `end client`, `end gone: the
client went with no Close`, or `end close CODE REASON` (the relay's own, as `1001 idle timeout`). A 502 of a target that
cannot be reached is a line of its cause too (`refused 502 cannot reach HOST:PORT: CAUSE`), on the forward road and the
HTTP road; a 403 of its policy was one already. The manual's note of `relay serve` says so. `cargo test -p podssh-relay
--features serve,plain-ws --test relay_serve_h2`: 8 passed (eight sessions on HTTP/2, eight lines of their ends; a
target that refuses, its 502 and its line). Planted, the end's line left out: caught.

# T-817: More causes said twice, beside COORD-112

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

Found by the pass, beside pod-relay's 403 and 502 (COORD-112): the relay down while a layer offer is kept (three lines:
the layer's first link failed and "the session goes on with no resume", a wait, then the connect; the run then fails);
`pipe - tcp:127.0.0.1:2223` says `could not connect to 127.0.0.1:2223:` twice; `ssh node://` with no node says "the
connection closed unexpectedly" before the node's own cause.

## Approach

One cause, one line, each: a test for each case in `crates/podssh-cli/tests/error_lines.rs`; a case in pod-relay or
pod-session goes to podcrates as COORD-112 did.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test error_lines
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. podssh's three cases, each one line now, in one table of `crates/podssh-cli/tests/error_lines.rs` and a test
each for the two that need the relay role:
- `pipe - tcp:HOST:PORT` that cannot connect: the dial's own words name the target, so `pipe/remote.rs`'s
  `tcp_failure` adds no prefix that names it again (`each_failure_with_no_relay_is_one_line_with_its_code`, a table of
  `pipe`, `config import ansible` and `update` under `PODSSH_OFFLINE`; planted, the prefix again: caught).
- `ssh node://` to a node that is not online: `ssh/node.rs` takes the SSH client's lines (`run_outcome`) and leaves out
  its words of the closed connection where the leg says the cause (`layer_told::lines`) (`a_node_that_is_not_online_is_
  one_line`; planted, both lines: caught).
- A relay that the user named, down while its offer is kept: the first link that cannot connect to the one host named
  ends the run with its cause (`relay_layer::dead_alone`), on `ssh` and `proxy`, instead of a line that the session
  goes on, a wait, and the contract's road's same failure (`a_named_relay_that_is_down_is_one_line`, Unix; planted,
  the contract's road tried: three lines, caught).
pod-relay's own doubled lines (a 403 of the policy, a 502) are COORD-112 (#309): fixed on podcrates' `main` (its
entry 869), taken with its next tag. `--lib` 1251 passed; `--test error_lines` 5 and the layer's road's tests passed.

# T-818: The black-box pass's small findings: the manual and the messages

**Source:** the black-box pass of 2026-11-17 (T-809, item 3): an agent with the binary and its documents alone, no source, on this host's loopback with `podssh relay serve` and an OpenSSH sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The documents promise one thing and podssh does another (the black-box pass, below).

## Premise

The pass's nits: `/relays.json`'s `policy.note`, `relay info` and the role's `/llms-full.txt` describe another relay
under `--allow-private`; `agent list` shows no comment of a key; `agent` puts its socket in `/tmp` with a long
`XDG_RUNTIME_DIR` and says nothing; misleading usage lines (`--quota` with `--mint anyone`, a second `--mint`, `play
--speed -1`, `PODSSH_LISTEN=no relay serve`, `ssh --bogus` pointing at `podssh --help`, no `PODSSH_RELAY_TOKEN` named
when a relay mints for none); EXIT STATUS lacks `play`'s 1, `edit`'s 66 and `ping`'s 69 of a refused default target;
`ping` against a dead relay prints an empty field; `sftp -b` does not echo a failing line; `pipe relay:`'s missing
half-close is said in one place and contradicted in another; an unresolvable TARGET of `node` gives one line of 900
characters.

## Approach

Each one repaired, or its documents made true, with a test where the behaviour changes; the manual's sentences stay at
25 words or fewer.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib man::
```

The test fails on the code before the fix and passes after it.

## Done

Partial, 2026-11-17. Done:
- `/relays.json`'s `policy.note` says what the role dials as it was started (`Policy::note`: private addresses too
  with `--allow-private`, the ranges of `--routes`, the ports refused); `podssh-relay --features serve --lib
  serve::policy` 10 passed, among them `the_note_says_what_the_role_dials`.
- The refusals of the command line (`refuse.rs`, `clap_error.rs`): an unknown flag names the verb's own help
  (`podssh ssh --help`); a flag of one value given twice says so (`--mint is given more than once`), never "unknown
  flag '--mint <WHO>'"; a negative number taken for a flag says to give it after `=` (`play --speed -1`). `--lib`
  1251 passed; `--test binary_streams --test flag_table --test scp_args --test tree` passed.
- `PODSSH_LISTEN=no` refuses each verb that listens with the plain line (`pipe/listen.rs` `allowed`); only `pipe`
  adds what needs no listener (`allowed_for_pipe`): `relay serve` said pipe's words before. Both exit 78.
- EXIT STATUS names `play`'s 1 (a recording that cannot be read), `edit`'s 66 (a file not on the host) and `ping`'s 69
  of a refused default target; `--lib man` 114 passed.
- `ping` at a dead relay: no empty field before the cause (`ping/relay.rs` `Leg::line`), with a unit test.
- `sftp -b`: a line that does not parse is echoed first, as each line is (`sftp/mod.rs`), then refused with 64;
  `--test result_file` `sftp_echoes_a_line_that_does_not_parse` (planted, no echo: caught).
- A host or a path that is not UTF-8: "an argument is not UTF-8 text" (`refuse::bad_invocation`), 64; `--lib refuse`
  passed.
Asked of podcrates (COORD-116, #313): a relay that mints for none to name `PODSSH_RELAY_TOKEN` (`pod-relay`'s
`token.rs`), and one line, not 1032 characters, where each resolver of DNS over HTTPS failed alike (`pod-dns`'s
`order.rs`). - The manual on `pipe relay:`: "TCP through the relay on the contract's road, with no half-close", as its later note
  says (it said "as podssh proxy carries it", and `proxy` half-closes on the layer's road).
- `agent list` and `ssh-add -l` show each key's comment: russh's agent kept none (its server decoded the comment and
  dropped it, its client sent none); `vendor/patches/russh/0012-agent-comment.patch` keeps it both ways. `--test
  agent_cli` 7 passed, its listing now with the key's comment; `ssh-add -l` of OpenSSH shows it too.
- `agent` with an `XDG_RUNTIME_DIR` too long for a socket's address says where its socket went and why (`agent/serve.rs`
  `Place::moved`), before its line of where it listens; measured with a directory of 94 characters.
Each finding of the pass in podssh's own code is repaired; the two in crates of podcrates are asked (COORD-116, #313).
`--lib agent` and `--test agent_cli` passed.

# T-819: podvm's lessons checked in podssh: temp files named by a pid, hostile input at the edges

**Source:** PodUtils/podvm#567 (COORD-180 of podvm, 2026-11-17, to all): its lesson 5 (a pid is no unique name where a
process runs in a PID namespace) asked of each project, and its lesson 3 (fail safe at the edges).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A file or directory named by the pid alone can be another process's in another PID namespace with the same `/tmp` or
home; a number that overflows or an argument that is not UTF-8 can panic a parser.

## Premise

- `crates/podssh-cli/src/ssh/x11.rs:125`: `podssh-x11-PID` in the temporary directory, made with `private_dir`, which
  takes a directory that exists, and removed at the end of the run.
- `crates/podssh-cli/src/keygen_cert.rs:140`, `crates/podssh-cli/src/keygen_change.rs:152` and
  `crates/podssh-ssh/src/known_hosts/edit.rs:281`: `.NAME.podssh-new-PID` beside a key or `known_hosts`, made with
  `create_new`.

## Approach

A nonce beside each pid; measure the edges (an argument that is not UTF-8, a number that overflows) and repair a panic.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib
cargo test -p podssh-cli --test keygen --test keygen_cert --test keygen_known_hosts
cargo test -p podssh-ssh --lib known_hosts
```

## Done

2026-11-17. The x11 directory, the new file of `keygen` (a certificate, a changed passphrase) and that of a
`known_hosts` edit take a random nonce beside the pid: two runs never share the x11 directory, which each removes; the
`create_new` of the others failed safe before, and fails no run now. The agent's directory (`agent/serve.rs`) is made
new or refused (`private_dir` of its own), as OpenSSH's is, and kept its name. The edges, measured with the binary:
a verb or a host that is not UTF-8, `-p 99999999999999999999`, `-o ConnectTimeout=` of 23 digits, `cp --timeout` of 20
digits and `relay serve --idle` of 20 digits each end with 64 and one refusal, no panic. `--lib` 1251 passed; the
keygen tests 20 passed; `podssh-ssh --lib known_hosts` 9 passed. A host that is not UTF-8 gets the vague "that command
line cannot be used" (T-818's kind of finding).

# T-821: A target that a proxy took and kept silent: the end's line says so

**Source:** the lane's error rows in `pod-lab`'s network classes (T-809), 2026-11-17: behind `proxy-tls-reterminate`
and `proxy-per-name`, whose proxy answers a CONNECT with 200 for any address or name.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

Where the proxy of the relay's host takes the relay's CONNECT to a target that it cannot reach (an unroutable address,
a name with no answer), then holds it silent for 30 s and closes it, `podssh ssh` says "the SSH handshake has not
finished after 10 s: no byte came from the server" and then the generic "the connection closed unexpectedly", 31 s in
all. The end's line does not say what happened: the target was taken and sent nothing.

## Premise

- `scripts/pod-lab-serve-lane.sh`, rows "an unreachable target" and "a name with no answer": two lines and 31 s behind
  the two classes; one line at once on the host and behind `proxy-only`, whose proxy refuses with 403.
- `crates/podssh-ssh/src/run.rs:466`: `describe` says "the connection closed unexpectedly" of each end of the stream.

## Approach

1. The role: a session whose target sent no byte and ended says so in its Close (a reason such as "the target closed
   with no byte", not 1000), so the client has the relay's words.
2. The client: an end of the stream before any byte of the server, after its note of the wait, says "the target took
   the connection and closed it with no byte after N s", not the generic words; one line.
3. The lane's two rows pass behind each network class.

## Decision

2026-11-17. The client alone says it (item 2): the SSH client knows that no byte of the server came, and how long the
stream lasted, whatever the relay saw. Lost: the role's Close with a reason of its own for a target that sent nothing
(item 1): a relay that is not podssh's role would not give it, and the client's line is true without it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test error_lines
```

With a stand-in target that takes a connection, says nothing and closes: one line that names it, 255. Then the lane
behind `proxy-tls-reterminate` and `proxy-per-name`.

## Done

2026-11-17. `podssh-ssh/src/run.rs`: a handshake that ends with the stream's end and no byte of the server says "the
connection was taken and then closed after N s with no byte of the server", not the generic words (`run_words.rs` holds
`describe` and `closed` now, so that `run.rs` stays within 500 lines); `layer_told` takes it as the client's echo of a
cause that the layer said. Found beside it in the same classes, and repaired: `pairs::connect_refusal` named a way's 403
of the upgrade as the relay's refusal of the pair ("it was stopped, or has expired"); a way's refusal (not the relay's
words, `upgrade_refused`; never a 426, the relay's own of a dialect) is said as the way's now. And the lane ran with
the host's home, so a pair that one run left blocked the next: it takes its own home and caches now, and a pair that is
not made fails it with its words. `cargo test -p podssh-cli --test error_lines`: 6 passed, among them
`a_target_taken_and_closed_with_no_byte_is_said_so` (the layer yes and no; planted, the generic words: caught); `--lib`
1242 passed, among them `a_way_s_refusal_of_the_upgrade_is_not_the_pair_s`. The lane behind `pod-lab`'s classes: all
nine rows pass behind `proxy-only`, `proxy-tls-reterminate`, `proxy-per-name` and `ws-upgrade-refused`; behind
`sni-allowlist` and `no-proxy-no-dns` each row but "a name with no answer", which waits for COORD-112's tag;
`ipv6-only` does not hold on this host.


# T-822: `cp`, `scp` and `sftp` write `relay: null` in `--result-file` for a copy that the relay carried

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

`podssh cp $R ... --result-file r.json lab:/etc/hostname ./h1` exited 0 with `"relay":null`, though `-v` and the role's
log showed the relay's session; `podssh ssh --result-file` fills it. The manual (podssh cp) names relay's host,
close_code, reason and sessions.

## Approach

Fill `relay` for each verb of copies from the relay that carried its sessions; a test of `cp`, `scp` and `sftp`
through podssh's relay role reads the host there.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test result_file
```

The test fails on the code before the fix and passes after it.

## Correction

The cause is not the copies' own record: since the layer (T-811) each session's road runs on a thread of its own,
and the road wrote its relay host to the process's record, not the session's (`relay_layer/ssh.rs`). `ssh` read the
process's record, the copies their own. The test is `tests/result_relay.rs`, through podssh's relay role, where
`result_file`'s tests run `--direct`.

## Done

2026-11-17. `podssh_ssh::outcome::Here::run_in` runs a future with the session's record as its own on any thread;
the layer's road takes the caller's record with it, so its relay host is the session's. `tests/result_relay.rs`:
one table of `sftp`, `cp` and `scp` with `--result-file` through `podssh relay serve` and the layer, each naming
`relay-a.test`. Planted: the road without the caller's record gives `"relay":null` for sftp, and the test fails;
restored, it passes. `cargo test -p podssh-cli --test result_relay`.

# T-823: `transferred.up` of a resumed copy counts the whole file

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

After Ctrl-C and a run again of `cp big.bin lab:...` (120 MiB), `-v` said `continuing ... .part at byte 13317120`, and
`transferred.up` was 125829120 with `1 copied (120.0 MiB)`. The manual: transferred is "the bytes of the files
through this host".

## Approach

Count the bytes that this run moved (the file less its kept part), and say the kept part apart; a test that resumes
a copy and reads both.

## Decision

The kept part is said apart by `-v`'s line `continuing ... at byte N`, which already names it; the result file keeps
its keys (`transferred` up and down), and the manual says that a copy that goes on counts this run's bytes alone. A
key of its own (`kept`) lost: one more key in the one list of six verbs, for a number that `-v` already gives.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test result_file
```

The test fails on the code before the fix and passes after it.

## Correction

The test is `cp_progress`'s interrupted copy (its run that goes on), not `result_file`: that one interrupts nothing.
Its file was 3 MB, under the side file's step of 4 MiB, so the run went on from byte 0; it is now 30 MB at 5 MB/s.

## Done

2026-11-17. `Progress::earlier` holds the bytes that an earlier run left in the temporary file (at load: the offset
and each whole chunk past it; a new start or a change of chunk size lowers it); `Done::kept` takes it when the copy
succeeds, and `transferred` counts `bytes - kept`. The manual (podssh cp, the result file) and `llms-full.txt` say so.
`cargo test -p podssh-cli --test cp_progress`, 7 passed: the interrupted copy's second run, which went on at byte
4439040 of 30000000, reads `transferred.up` 25560960; before the fix it read 30000000 (the planted state, run three
times). `cp_parallel`, `result_file`, `cp_tree`, `cp_delta`, `cp_inplace` and the library's `cp::` tests pass.

# T-824: A refused target says a second, wrong line in `each`, `scp`, `sftp` and `health`

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

The relay's cause first (`the relay could not reach its target: 127.0.0.1:2299: Connection refused`), then
`127.0.0.1:2299: broken pipe` (each, also its `--json` error) or `the connection was taken and then closed after 0.0 s
with no byte of the server` (scp, sftp, health). `ssh` and `proxy` say one line: T-809's rule of `ssh/mod.rs`
(`layer_told`) reaches only that path.

## Approach

The one-line rule at each verb that runs a session on the layer's road: the client's echo of a cause that the road
said is no second line; a table of `error_lines.rs` over each verb.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test error_lines
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. A command that says its own failure claims the road's cause in its session's record
(`podssh_ssh::outcome::claim_road_cause`, per session since T-822); the layer's road then keeps its cause there in
place of saying it, and the command says it once: `ssh` and `each` after the road settled (`layer_told::once`, the
cause in place of the client's closed-connection words), `cp`, `scp`, `sftp` and `health` where the connection failed
(`layer_told::failed`), and a cause kept while a connection came up is said at once (`layer_told::release`). A road
that no command claimed says its cause as before. `tests/error_lines.rs`'s table of `each`, `scp`, `sftp` and
`health` through `podssh relay serve` with the layer to a closed port: one line of the relay's cause, no echo (each's
summary of its hosts aside). Planted: the road says its cause where a command claimed it; this test and `ssh`'s fail
with the cause twice; restored, `cargo test -p podssh-cli --test error_lines` passes, 7 of 7, and `each`, `health`,
`result_file`, `node_copy` and the library's tests pass.

# T-825: Two exit codes that EXIT STATUS does not name: a port in use for `relay serve`, and a route refused

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

`relay serve --listen` on a port in use exits 69 ("the relay or TARGET could not be reached"), where `pipe`'s refused
bind is 77; `operator labnode/nope` with a key that may not use the route exits 70 ("the end-to-end channel failed"),
where a node's refusal of a key is 77.

## Approach

A bind that fails is the code that `pipe` gives (69 in use, 77 refused) with its row in EXIT STATUS; a route refused
is 77, as the node's other refusals; a test of each.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. A route that the key may not use is the node's refusal of the key now (`channel::judged`): 77, as its
allowlist's and its grant's, not 70 (`a_route_refused_is_the_node_s_refusal_of_the_key`). `relay serve` on a port in use
keeps 69, as `pipe`'s bind that fails for a reason other than the host's refusal (77); EXIT STATUS names it in 69's row,
and 77's row names a refused route. `--lib` passed; the manual's tests and `llms-full.txt` written again.

# T-826: At a low `--max-session-mib` the relay's Close is lost as a reset, and the client moves no link first

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

With `relay serve --max-session-mib 1`, `ssh ... 'head -c 3145728 /dev/zero'`: the role logged `end close 1009 session
byte cap` three times; the client saw `the link failed: Connection reset by peer`, resumed, and the bytes came whole.
The manual says the client moves the session to a new link before the relay's limits; it did at 64 MiB, not at 1.

## Approach

The role's Close goes out before its socket closes (its 1009 read by the client); the client's budget of a link takes
the relay's published cap of any size; a test with a role of `--max-session-mib 1`.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve
```

The test fails on the code before the fix and passes after it.

## Correction

The test is `tests/layer_cap.rs`, with bytes each way (`cat`): with bytes down alone, the role's Close was read each
time even before a change. The reset is not the role's. The role's events show `end close 1009 session byte cap` at
each link, and a role that reads on after its Close until the client lets go fails at the same rate. The client loses
the Close: pod-session's pump, on a failed write, drains the read side, but keeps a relay's Close read there
(`End::Lost`) below the write's `broken pipe`. Both halves of the Approach are on the client side, in PodUtils/podcrates
(Rule Q3): that drain (pod-session) and the link budget under a small cap (pod-relay: `forward_layer::Offer` carries
no `max_session_bytes`, and `byte_budget_under` keeps 56 MiB for a cap under 9 MiB).

What is done, 2026-11-17: The role reads on after its own Close until the client lets the connection go, within 2 s
(`serve/forward.rs`, `closing`): a socket closed with the client's bytes unread resets, and RFC 6455 has the closing
handshake. `tests/layer_cap.rs`: 3 MiB each way through a role of `--max-session-mib 1` come whole, over links each
ended by the role's 1009 (4 of 4 runs). The client's half waits for the Blocker.

2026-11-18, podcrates `v0.71.0` (its entry 908, COORD-117 ask 1): the relay's Close read in the drain wins over the
write's error. `tests/layer_cap.rs` now also checks that no link's end is said as a broken pipe or a reset: 10 runs
in 10 passed here. Left: ask 2 (podcrates' entry 909, the cap in the offer and a budget under any cap), then `move_bytes`
from it.

2026-11-19, podcrates `v0.73.0` (its entry 909, ask 2): `paced` in `relay_layer.rs` sets `Settings::move_bytes` from the
kept offer's cap (`Offer::move_bytes`, three quarters of a small cap). With `--max-session-mib 1` the client now says
"the session moved to a new link before the relay's limits, after 768 KiB" at each move. Yet each new link carries the
bytes not yet acknowledged again (up to 1,179,648 here), more than the cap itself, so the role still ends some links with
1009 and the client resumes. Asked of podcrates in COORD-122: a window in flight under the cap, so that what a new link
sends again fits. `tests/layer_cap.rs` passes (the bytes whole, no broken pipe).

2026-11-19, podcrates `v0.74.0` (its entry 953, COORD-122): `paced` takes `Offer::fit`, the move threshold and a window
of a quarter of the cap for the client; `relay serve` with `--max-session-mib` gives its end of the layer
`window_under(cap)` (`relay_serve/resumes.rs`). What a link sends again is now 262,144 bytes at most under a cap of 1 MiB
(before: up to 1,179,648). Yet each run still met the cap: one move, then five links ended by the role's 1009. The cause:
pod-session counts both ways toward `move_bytes` (`pump/watch.rs`), and a move at three quarters of the cap plus a
quarter in flight from each end is five quarters of it; at the loopback's rate the old link passes the cap before the
move ends. Asked of podcrates in COORD-124: a threshold under the cap less both windows (half of it with windows of a
quarter), or smaller windows. Then `layer_cap.rs` checks that no link ends with 1009.

2026-11-19, podcrates `v0.75.0` (its entry 958, COORD-124): while a move is in progress the client holds the old link,
and the window is an eighth of the cap, so the old link ends under seven eighths of it. No change of podssh's code.
`tests/layer_cap.rs` now checks that no link ends with the role's 1009 and that the session moved: 8 runs in 8 passed.
`cargo test --workspace --no-fail-fast`: 383 suites, 0 failed. Done: the client moves each link before a small cap of
the relay, and the relay's Close is never said as a broken pipe (on Linux).

2026-11-19, the gate at `ba19367` (run 44476622620): the job `windows` failed the new check. The first link ended with
the role's 1009: the client said "the session moved to a new link before the relay's limits, after 899 KiB in 0 s
(32768 bytes sent again)", so its move began above seven eighths of the cap (896 KiB), not at three quarters, and the old
link still passed 1 MiB; each later link ended with 1000. On Windows the move starts later after its threshold than on
Linux. The check stays (no link at the cap); asked of podcrates in COORD-126 (amended): a move that begins at its
threshold, or a threshold that leaves room for the lag that Windows showed.

2026-11-19, podcrates `v0.76.0` (its entry 962, COORD-126): the hold of a move starts in the call that passes the
threshold. No change of podssh's code. `tests/layer_cap.rs`, 6 runs in 6 here.

## Done

2026-11-19, the gate at `5975bb0` (run 44504544443), podcrates `v0.76.0`: each job passed, `windows`, `macos` and the
Linux gates' `layer_cap.rs` included: no link ends at the relay's cap, the session moves before it, and no link's end
is said as a broken pipe. Done on each system that the gate runs.

# T-827: `relay serve --key` in a file that others may read starts with no word

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

`relay serve --cert leaf.pem --key lk644` (mode 0644) served with no line; its help says "--key FILE ... in a file that
only its owner reads".

## Approach

Say it on start (a line that names the mode and `chmod 600`), as podssh does of each other key file; or refuse it, as
the help's words ask; a test.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib relay_serve
```

The test fails on the code before the fix and passes after it.

## Done

2026-11-17. `relay serve`'s first line says a key that others may read, with its mode and `chmod 600 KEY`
(`relay_serve/certs.rs`, `open_to_others`; Unix's mode bits, none on Windows, whose ACL is the user's); it still
serves, as a warning, which the help's words allow. `--lib relay_serve` 22 passed, among them
`a_key_that_others_may_read_is_named`; measured with a key of mode 0644.

# T-828: The second black-box pass's smaller findings: the documents and the lines

**Source:** the second black-box pass of 2026-11-17 (T-809): an agent with the debug binary of `37abf31` and its documents alone, on this host's loopback with `podssh relay serve` and OpenSSH's sshd.
**Category:** defect
**Milestone:** M10
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

The documents promise one thing and podssh does another (the second black-box pass, below).

## Premise

Doc gaps: `-f`'s text names ProxyCommand that `ssh` refuses; `session`'s socket under `/tmp` with a long cache path,
unsaid; `node --print-unit --system` with ExecStart under `/tmp` or a home that the unit's hardening hides; no way to
print an operator's own key in the form of `--grant-to` (`keygen -y` refuses `client.key`); `sftp -b missing` exits 66
(not in its row); `node --run-as nosuchuser` exits 69. Lines: a key that may not mint retries the same 403; a failed
TLS check prints one line twice, and a certificate of another name falls to cleartext with no cause said; a relay
killed mid-session gives a docs.rs link and "the far end forgot the session" for a restart; `share add` claims a route
that the command line's route keeps; `remote forward ... could not connect to` twice; `relay trace` names its target
twice; `2 addresses (X, X)`; `-v` calls the relay's layer "a node"; sftp's progress counts across gets; scp and cp do
not expand a remote glob; a missing destination directory names the `.part` file; two copies to one destination share
one `.part`; `ssh -i nofile` says nothing; `ssh root@node://NAME` gives "is not a port"; `node --relay-host` gets the
`-o` reassurance; `~?` does not list `~d`; "the 1 keys", "1 shares".

## Approach

Each one repaired, or its documents made true, with a test where behaviour changes; a case in a crate of podcrates
asked there.

## Decision

`node --run-as` with no such user stays 69, now named in its row. 67 (`EX_NOUSER`) lost: no command of podssh gives it,
and a new code needs a row of its own in EXIT STATUS for one case of one flag.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib
```

The test fails on the code before the fix and passes after it.

## Done

Partly, 2026-11-17 (the rest stays open here):
- `relay serve` says `the one key` and `1 key now`; `share ls` says `1 share`.
- `ssh -v` on the relay's layer says `the relay opened resumable session ID`, not `the far end (a node)`
  (`relay_layer/ssh.rs`).
- A failed direct dial (`ssh --direct`, `via`) names its target once (`pipe::remote::could_not_connect`). So does a
  remote forward's (`podssh-ssh` `remote_join.rs`), and so does the role's 502 and `relay trace` (`egress::cannot_reach`,
  with a unit test).
- `ssh -i nofile` names the file `(no such file)` in its last note.
- `USER@SCHEME://NAME` is refused with the form meant, `SCHEME://USER@NAME` (`ssh/cloud.rs`, a table test).
- An unknown flag of a verb with no `-o` (`node --relay-host`) says `the command did not run`, not the reassurance
  of `-o` (`refuse.rs`, its test).
- The manual says that `~?` lists the escapes that the session offers (`~d` only where the far end keeps shells).

Each was run against the debug binary: a sshd of the scratch lab, `relay serve` with the lab's PKI. `cargo test -p
podssh-cli --lib`, 1245 passed; `-p podssh-ssh --lib`, 423; `-p podssh-relay --features serve,plain-ws`, each passed.
`2 addresses (X, X)` is pod-proxy's line (`race.rs`), asked of podcrates.

Second part, 2026-11-18:
- A copy whose destination's directory is missing names that directory (`no such directory: DIR`), each way and on
  each road (sftp, exec, here), never the `.part` file (`transfer::not_made`; `tests/cp_progress.rs`).
- Each `get` and `put` of `podssh sftp` draws a line of its own, not counted with those before it (`gauge::new_run`).
  In the lab, with `PODSSH_PROGRESS=line`, the second `get` said `1 of 2 files 3.1 MiB` before and its own file after.
- A system unit binds the binary read-only where `ProtectHome` or `PrivateTmp` hides it (a unit test, five paths).
- `keygen -y` and `-l` read podssh's own key file, 64 hex digits of a seed, as the key of its identity (a unit test
  of the same public half), and print the line that `--grant-to` takes.
- The manual: `--detach` names no ProxyCommand, which `ssh` never runs. THE SOCKET of `session` says where a long path
  goes. EXIT STATUS names `sftp -b` with a missing file (66) and `node --run-as` with no such user (69).

Asked of podcrates, 2026-11-18, in COORD-118 (PodUtils/podssh#315): `2 addresses (X, X)` (pod-proxy); a relay
restarted mid-session said as its timeout of 10 min (pod-session's `forgotten`); the cleartext road's line, which
does not say why TLS failed (pod-relay). That road does print its two lines by default, as the manual says.

Third part, 2026-11-18:
- The one relay host that the user named, which refuses this client's key a token (401, 403), ends the run with
  its refusal once, 255: no second mint on the contract's road after a wait (`relay_layer::dead_alone`;
  `tests/error_lines.rs`, its planted defect fails it).
- A node says once that a share of its file has the name of a route of its command line, which serves that name
  (`share/serve.rs`, a unit test of the names of the routes).
- `cp` and `scp` take a remote pattern (`*`, `?` in the last name) as the files that it matches, over SFTP, and one
  that matches nothing exits 66 (`cp/remote_glob.rs`; `tests/cp_progress.rs`; the manual).

Left, 2026-11-18: two copies to one destination share one `.part` (a lock across processes: pod-core's `lock`,
podcrates' entry 877, with its tag); a failed TLS check's line twice, and a docs.rs link when a relay is killed
mid-session, neither met again in the lab (the run of a relay killed and started again gave COORD-118's line).

Fourth part, 2026-11-18, on podcrates `v0.70.0`: two copies to one destination no longer share one `.part`. A copy holds
`pod_core::lock::FileLock` on its side file's `.lock` while it runs (`cp/resume.rs`, `held`); a second copy that finds
it held keeps no side file and writes a `.part` of its own name, and a second load in the same process shares the
first's lock. `cargo test -p podssh-cli --lib cp::resume`: 8 passed, among them
`a_copy_that_another_runs_now_keeps_no_side_file`. Left: COORD-118's three lines (PodUtils/podssh#315), for podcrates.

Fifth part, 2026-11-18, on podcrates `v0.71.0` (COORD-118, #315, its entries 911, 912 and 913): a race dials each address
once and names it once; a far end that lost a session by a restart is said so, not as a timeout; the cleartext road
names why the TLS of each relay failed (`cleartext::over` takes each relay with its cause). `cargo test --workspace
--no-fail-fast`: 383 suites, 0 failed. Each finding of the second pass is fixed here or in podcrates; the third pass
(T-809) reads them again on the candidate.

# T-829: A port that a test lets go is taken by a test beside it: the gate's `ping` offline test counted a dial

**Source:** the gate at `04b7759` (2026-11-17), step `ts`: `tests/ping.rs`, `offline_connects_nowhere_and_exits_69`, `left: 1 right: 0`.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A test that fails at random. Each test of the gate must hold on any run.

## Premise

`tests/ping.rs`: `no_relay_host_that_answers_exits_69` binds a port, lets it go, and pings a relay there. Beside it,
`offline_connects_nowhere_and_exits_69` binds a counting listener on a port of the system's choice, which can be the
same port, and counts that ping as a dial of the offline run. The same pattern, a port bound and let go, stands for a
target or a relay that is not there in several files of tests; three files already hold such a port as a socket
that is bound and never listens.

## Approach

One helper for the class of fault, `tests/held_port/mod.rs`: a port that refuses each dial, held for as long as its
socket lives. Each test of a refused target or relay takes it; the three copies go.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test ping --test each --test error_lines --test relay_offer_read --test serve_forward_openssh --test persist --test roost --test direct_fallback --test bore_road --test derp_road
```

## Correction

2026-11-18, the gate at `6c5a680`: macOS drops a dial to a port that is bound and never listening, which then times
out ("Operation timed out"), where Linux refuses it at once. `held_port::refusing` holds the port on Linux alone and
lets it go elsewhere, as before; `held` keeps the old form, bound everywhere, for the three files that had it
(`persist.rs`, `roost.rs`, `direct_fallback.rs`), which passed on macOS with it.

## Done

2026-11-17. `tests/held_port/mod.rs` (`refusing`): a socket bound to the loopback, never listening, held by the test.
`ping.rs`, `each.rs` (held for the life of the process, as its `server` hands the port to four tests),
`error_lines.rs`, `relay_offer_read.rs`, `serve_forward_openssh.rs` (its refused target; its port for `ssh -L` to
listen on stays free), `bore_road.rs`, `carrier_filehost.rs` and `derp_road.rs` take it; `persist.rs`, `roost.rs` and
`direct_fallback.rs` lose their own copies. The ten tests of the Prove pass (2026-11-17), and clippy, also with
`--features filehost`.

# T-830: `podssh operator` loses the tail of a session's bytes on Windows: a write to stdout left in its thread

**Source:** the gate at `6c5a680` (2026-11-17), job `windows`: `tests/access_relay.rs`, 65518 of 65536 bytes came back, exit 0.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A command that carries a session's bytes to stdout must write each of them before it exits 0.

## Premise

`tokio::io::stdout()` hands each write to a blocking thread, and a write is out only once flushed. `operator.rs` ends
its runtime with `shutdown_background()`, as a read of stdin may still block: a last write still in its thread is
lost. `carrier.rs`, `serve.rs`, `relay_layer.rs` and `pipe/local.rs` join stdout the same way.

## Approach

A writer each of whose writes returns once flushed (`src/flushing.rs`), in place of tokio's stdout at each of these
places; a unit test with a writer whose flush waits, as tokio's does.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib flushing
cargo test -p podssh-cli --test access_relay --test pipe --test proxy
```

## Done

2026-11-18. `crate::flushing::Flushing`, and `flushing::stdout()` at the six places. Its test passes; planted, the
writer with no wrapper leaves the bytes in its buffer, and the test fails (`left: []`). `access_relay`, `pipe`,
`proxy`, `layer_cap` and the others of T-829 pass on Linux; the Windows run of the gate says whether the tail stays.


# T-843: A refusal of the relay's policy no longer says the relay's cause

**Source:** the take of podcrates `v0.70.0` (2026-11-18): pod-relay's answer to PodUtils/podssh#309 (COORD-112) made
a refusal one line, and the line lost the relay's own words.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A relay that refuses a target by its policy says why: `port 25 is refused`, or `this relay dials no address of it`
(`crates/podssh-relay/src/serve/policy.rs:89`). Since `v0.70.0` the client says only `the relay's policy does not
allow HOST:PORT (HTTP 403)`. The line is true, but the user no longer learns which rule refused the target, nor what
to change.

## Premise

`PodUtils/podcrates:crates/pod-relay/src/open_lines.rs:25-26` at `v0.70.0` returns the fixed line for each policy
refusal (`is_policy_refusal`), with no part of the body. The 502 branch beside it keeps the cause
(`unreachable_cause`). podssh's `crates/podssh-cli/tests/relay_serve.rs` checked `port 25 is refused` before the take.

## Approach

1. Ask podcrates (COORD-119): keep the relay's cause after the target, with no part that names the relay or the target
   again, as the 502 line does: `the relay's policy does not allow HOST:25: port 25 is refused (HTTP 403)`.
2. At its tag: put the check of `port 25 is refused` back in `relay_serve.rs`, and the cause of a target outside the
   routes (`dials no address of it`) in the test of the routes.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test relay_serve --test pipe_http
```

## Done

2026-11-18, on podcrates `v0.71.0` (its entry 926, answering COORD-119, #318): the line keeps the relay's cause after the
target, `the relay's policy does not allow 140.82.112.3:25: port 25 is refused (HTTP 403)`. `tests/relay_serve.rs`
checks `port 25 is refused` again, and the role's `this relay dials no address of it` for a target outside the
routes. `cargo test --workspace --no-fail-fast`: 383 suites, 0 failed.

# T-844: `doctor` fails a host when croc's public bridge, a third party's last fallback, does not open

**Source:** the gate at `bf001df` (run 44270996069, 2026-11-18): the job `box` failed, as `doctor` in the box said
`FAIL croc's bridge wss://getcroc.com/ws ... the proxy refused CONNECT getcroc.com:443: 502 Bad Gateway`.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

Since podcrates `v0.70.0` lists croc's public bridge, `doctor` asks it with no variable set, and a bridge that does
not open was a FAIL: the run exits 1 on a host where nothing is wrong, for a volunteer's service that the road takes
only as its last fallback. The lists of public servers (the Piping Servers) already say such a silence as unknown.

## Premise

`crates/podssh-cli/src/doctor/carriers.rs` (`croc_line`) gave `report.fail` for each bridge that did not open,
public or named. `croc::setting` turns the bridge on from `pod-services` (`crates/podssh-relay/src/croc/mod.rs:136`).

## Approach

A public bridge that does not open is `????`, with its cause and why it is no fault of the host; a bridge that the
user named (`PODSSH_CROC=URL`) still fails. One table test of both.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib doctor::carriers
```

## Done

2026-11-18. `bridge_failed` in `doctor/carriers.rs`; `only_a_named_bridge_that_does_not_open_fails` passes (3 of 3 in
`doctor::carriers`). The next gate's `box` is its proof on the box's proxy.

# T-845: Over the HTTP road, `ssh` says `broken pipe` in place of the role's close where it writes before it reads

**Source:** the gate at `054f159` (run 44277828991, 2026-11-18): the job `windows` failed
`a_close_of_the_road_other_than_1000_is_said_by_ssh_as_by_proxy` of `tests/http_road_cli.rs` once (it passed at `bf001df`).
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A role of `--max-session-mib 1` ends a session over the HTTP road with `1009 session byte cap`. `proxy` says it; `ssh`
said `the connection to 127.0.0.1:PORT was lost before the session ended: broken pipe`, with no line of the close.

## Premise

`crates/podssh-cli/src/ssh/cloud/told.rs` said the road's end only when SSH read the end of its stream. The road
records its end, then drops its half of the stream; an SSH that writes first gets a broken pipe and ends with no read.

## Approach

A failed write or flush says the road's end too, once, as a read of the end does. A unit test of a write after the
far half went.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib cloud::told
cargo test -p podssh-cli --test http_road_cli
```

## Done

2026-11-18. `Told`'s `poll_write` and `poll_flush` say the end on an error; `a_failed_write_says_the_end_once` passes
(2 of 2 in `cloud::told`), and `--test http_road_cli`, 9 passed on Linux. The order of a write and a read is the
host's (Windows); the next gates of `windows` are its proof.

# T-846: `serve_pressure`: `yes` on a pty ran on 5 s after its channel closed, once, in the gate

**Source:** the gate at `a6a3a3e` (run 44307961055, 2026-11-18): the job `gate (ssh)` failed
`yes_on_a_pty_with_a_client_that_reads_nothing_holds_the_memory` of `crates/podssh-ssh/tests/serve_pressure.rs`.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

After a client that had stalled closes a channel of `yes` on a pty, `podssh serve` hangs up the child's group
(`crates/podssh-ssh/src/server/child.rs`, `finish`) and `yes` must end. Once, in the gate, it still answered `kill(pid, 0)`
after 5 s.

## Premise

The test passed 5 runs in 5 here (2026-11-18, Linux) and in each gate before. `runs` is `kill(pid, 0)`, which a zombie also
answers; `finish` waits for the child after the hangup, so a reaped child is gone, unless the close reached the server late
behind a full window.

## Approach

1. The failure now says the process's `/proc/PID/stat` and `wchan`: a zombie, or a live `yes` and where it waits.
2. At the next failure, repair the cause that it names (the close's path through the server, or the test's measure).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test serve_pressure
```

## Done

Partial, 2026-11-18: step 1; `cargo test -p podssh-ssh --test serve_pressure`, 5 runs in 5 here. Waits for its next
failure in the gate.

# T-849: `cp::resume`'s test of a copy that another runs: no side file after the lock was freed, once on macOS

**Source:** the gate at `09ab98b` (run 44462713098, 2026-11-19): the job `macos` failed
`cp::resume::tests::a_copy_that_another_runs_now_keeps_no_side_file` (`crates/podssh-cli/src/cp/resume_tests.rs`), which
passed on macOS in each gate before it since T-828.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** partial

## Problem

After the other holder's lock is dropped, the third load of the side file gave offset 0, not the 4 MiB that the first run
saved: either the lock was still refused (no side file kept), or the side file was not read.

## Premise

Each step is synchronous: the save (`cache::store_file_in_first`), `pod_core::lock`'s `flock(2)` and its release at the
drop, and `held` in `crates/podssh-cli/src/cp/resume.rs`. 5 runs in 5 passed here (Linux).

## Approach

1. The assertion now says whether the third load took the lock, and what the side file holds.
2. At the next failure, repair the branch that it names.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --lib cp::resume
```

## Done

Partial, 2026-11-19: step 1; 5 runs in 5 here. Waits for its next failure on macOS.

# T-851: `shadowsocks_cli`: the second `ssserver` of a subscription's test lost its free port to another test

**Source:** the gate of Dependabot's pull request #331 at `1a24efd` (run 44649725163, 2026-11-20, job `gate (ssh)`):
`a_kept_list_whose_servers_changed_is_fetched_again` of `crates/podssh-cli/tests/shadowsocks_cli.rs` failed with 255.
**Category:** defect
**Milestone:** M10
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

The second server of the test answered no salt: "it closed the connection, with no answer to the salt". The run of a
list whose servers changed then failed with 255, where it carries the session.

## Premise

- `crates/podssh-cli/tests/shadowsocks_support/mod.rs:58` takes a free port by a bind that it drops at once, and
  `start_server` called `ssserver` ready once any connect to that port went through, with its output discarded: a port
  that another test of the step took in between leaves `ssserver` to exit on its bind, and the connect reaches the other
  test's listener, which closes a stream it cannot read.

## Approach

1. `start_server` calls the server ready only when the server's own process holds the listening socket (Linux's
   `/proc/net/tcp` and `/proc/PID/fd`; elsewhere a connect, and the process still there after it), and starts it again
   on a new free port, five times at most, where it exited.
2. A test pins the rule: a listener of this process is its own, not another process's, and a closed port is nobody's.

## Prove

```sh
export CARGO_BUILD_JOBS=4
PODSSH_TEST_SSSERVER=/usr/bin/ssserver PODSSH_TEST_SSLOCAL=/usr/bin/sslocal \
  cargo test -p podssh-cli --test shadowsocks_cli
```

## Done

Done, 2026-11-20: steps 1 and 2. Here, with shadowsocks-rust v1.25.0's release binaries (their SHA-256 checked):
`cargo test -p podssh-cli --test shadowsocks_cli`, 10 passed, six runs in six. Planted, the check of the owner taking any
process's listener for the server's: `a_listener_of_another_process_is_not_the_servers` failed ("another process does
not").
