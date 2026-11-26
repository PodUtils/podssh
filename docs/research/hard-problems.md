# The hard and open problems of podssh

A brief for an outside researcher, written on 2026-11-20 from the record at `main`
(`2c7b5942`). It lists each problem of the project that is blocked, partial for a long time,
failing at random, waiting on another party, technically unsolved, or believed out of reach.
It is self-contained: you do not need the repository open, though every claim cites the file
where it is recorded. Where a statement is my own reading and not a recorded measurement, it is
marked **Inferred**. Where the record says "UNVERIFIED" or "not reproduced", this page says so.

## 0. What podssh is, and the facts you need

podssh is one static Rust binary (musl, no dynamic dependencies) that carries SSH, or any TCP
stream, through a WebSocket relay on port 443, for hosts whose only way out is HTTPS, often
through an HTTP CONNECT proxy. Around that core it has: a resumable session layer that keeps an
SSH session alive across a dropped link, a "reverse" road (a `node` behind a NAT reached by an
`operator` through the relay), the relay as a role of podssh itself (`podssh relay serve`), a
mesh of the owner's nodes, dozens of alternative carriers (iroh/QUIC, Tailscale DERP, WARP, Tor,
Piping Server, Wisp, file hosts and others), and `podssh serve` (an SSH server for sandboxes
with no `/dev/ptmx`). `AGENTS.md` is the operating manual of the repository; `docs/design.md`
is the design; `docs/decisions.md` holds the owner's rulings (numbered `Q1`..`Q106`);
`TODO/INDEX.md` lists 805 entries `T-NNN` (39 open, 41 partial, 11 blocked, 714 done);
`TODO/PROGRESS.md` is the work order.

**The layer stack you will meet most.** From the top: OpenSSH-compatible client `russh`
(vendored with twelve patches in `vendor/russh/`, `vendor/patches/russh/`) over a 256 KiB
in-memory pipe, over `pod-e2e`'s end-to-end encrypted channel, over `pod-session`'s resumable
layer (numbered records, a replay buffer, ACKs, a window of 768 KiB on a pair's road, a
heartbeat, "spare links"), over a carrier link (the relay's WebSocket, or an iroh relay
connection). `pod-session`, `pod-e2e`, `pod-relay`, `pod-iroh` and 15 more crates moved on
2026-11-12..17 to a sibling repository, PodUtils/podcrates, which podssh pins by git tag (now
`v0.77.0`). Rule Q3 (`docs/decisions.md`): podssh no longer edits a module that podcrates took;
it asks podcrates by a GitHub issue titled `COORD-NNN: ... (to podcrates)`. That is why many
problems below are "blocked on podcrates".

**Rules that shape every fix** (`AGENTS.md` section 5): one outbound connection (through
`HTTPS_PROXY` if set), no listener unless the user asks and a probe allows it, no `LD_PRELOAD`,
no helper process, nothing assumed of the host (probe at run time), a source file at most 500
lines, a defect repaired in the session that finds it, no weakening of a test to pass.
"Quality first" (the owner, 2026-11-17): every edge fails safe, each failure gives one true line
and a documented exit code.

**How the project tests.** The gate is `.github/workflows/build.yml`, run by `scripts/gate.sh`;
jobs include `gate (m6)` (the resumable-layer faults), `gate (ssh)`, `gate (release)` (static
build plus `scripts/interop.sh`, 636 checks against OpenSSH and Dropbear, about 12 min),
`macos`, `windows`, `gate (iroh)`, `gate (ts)`, `tor-net`. A push cancels the gate of the push
before it. `suite-repeat.yml` repeats one test N times on a chosen runner (used to hunt random
failures). Until the owner calls podssh "stable" (Q88) the checks of T-251 are deferred: planted
defects in the build image, runs over 5 minutes or 100 MiB, the whole release check.

**Build constraints** (`AGENTS.md` section 4): `CARGO_BUILD_JOBS=4`, one build at a time, Rust
1.99, `target/` grows past 28 GB (remove it whole when the disk fills). Do not call `wsl.exe`.
Do not print a relay token or a private key. Do not push to `main`.

## 1. The ranked list

Impact order. P is the record's priority (`TODO/INDEX.md`: P0 data loss or crash, P1 a documented
capability does not work, P2 worth doing, P3 recorded). The record has no open P0.

| # | Problem | Entries | P | Group | Why it ranks here |
| --- | --- | --- | --- | --- | --- |
| 1 | A resumable session stops moving, at random, in the gate (16 failures in 10 days) | T-780 | P1 | A, C | The headline feature (M6) hangs a session; each hang costs a gate rerun; the 16th named a cycle between podssh's pump and russh's loop, repaired in a draft |
| 2 | A relay's byte cap vs the layer's move and window arithmetic | T-826 (COORD-122, 124, 126) | P2 | B, C | The layer still meets the relay's `1009` cap under a small cap; Windows lags the move |
| 3 | Half-close of a Unix-domain socket not reaching the peer, on macOS and Windows | T-465 | P1 | A | One bug has failed on two systems 5 times since 2026-11-02; a platform fact is in doubt |
| 4 | Windows loses the last bytes of an echo at the end of input | T-753 | P2 | A | RST on close with unread data is the likely cause; one failure, 50 runs clean |
| 5 | `pod-relay-serve` and the relay pool: no relay of the public pool runs podssh's role | T-801, COORD-120 | P2 | B | Fixes in podssh's relay role reach users only through the operator or a podcrates crate |
| 6 | A tty with no `/dev/ptmx` and no way to unshare | T-248, T-111, T-113 | P2 | C, B | The M5 exit criterion (vi, less, Ctrl-C in a sealed sandbox) depends on user-space tty routes; one cage still fails |
| 7 | The slow and far link: bulk beside a typed key | T-670, T-666, T-660 | P3 | C, E | Measured gap to a competitor on far links; remaining rows partial since 2026-11-04 |
| 8 | OpenSSH/Dropbear interop hangs with no line of where | T-796 | P1 | A | Gate hung 34 min once; bound added, cause unknown |
| 9 | Cloud-container `--direct` stuck write ends at 240 s instead of 60 s | T-598 | P3 | C | Fixed for one road; the interop proof in the build image is pending |
| 10 | HTTP and HTTP/2 roads never run through a real intercepting proxy | T-319, T-321, T-762 | P2-P3 | C, E | Built against stand-ins only; the live edge offers no extended CONNECT |
| 11 | A node reachable for 90 days with no person | T-710 | P1 | E | A 120-day paused-clock test passes; the calendar proof needs a beta in the field |
| 12 | Single flaky tests: relay role resume, reverse carrier, `node_cut`, `serve_pressure`, `cp::resume`, serve copy | T-627, T-756, T-788, T-846, T-849, T-779 | P1-P2 | A | Each failed once, not reproduced; each waits for its next failure |
| 13 | Blocked on podcrates or the owner: `PODSSH_PUBLIC`, `podssh link`, lease header, Access TCP client, Bare hop, crates.io, TLS tickets | T-711, T-719, T-722, T-729, T-740, T-687, T-672 | P1-P3 | B | Nothing podssh can do alone |
| 14 | Needs the operator's resources: real sandbox, throwaway cloud accounts, a tailnet, FinalShell and Termius exports, a tester's tunnel | T-113, T-376, T-106, T-328, T-755 | P2-P3 | B | No cloud session can reach them |
| 15 | Platform gaps: FIDO keys on macOS, mDNS and DCC where UDP or inbound are refused, Trojan UDP | see D | P3 | D | Judged out of reach, or limited by the platform |

---

## A. Tests that fail at random

All are in `TODO/robustness.md` unless said. They share one rule of the project: do not weaken a
test, do not raise a limit; name the cause. Each failed in the gate, was not reproduced on the
authors' host, and was given diagnostics that print at the next failure.

### A1. T-780 (P1): m6's resumable session hangs past 600 s in the gate

**What fails.** `crates/podssh-cli/tests/m6_exit.rs` (485 lines; `LIMIT = 600 s` at line 34,
`TRIGGER` of 8 MiB at line 32) runs 20 MiB up and 20 MiB back through `podssh ssh node://tester@m6
echo` on the resumable layer, against a stand-in relay (`scripts/fake_reverse.py` over
`scripts/fake_ws.py`) with a stand-in proxy per end (`scripts/fake-proxy.py` with `--move`,
`--pause`, `--stop-after`). The faults start when 8 MiB are written: a stopped relay host, a new
client address, a stall of 3 minutes, or no fault. The same cases run on the iroh road
(`--features podssh-cli/iroh-test`, `PODSSH_IROH_UDP=off`, iroh's relay server on the loopback).
One test of 11 hangs until its limit; its rerun passes. It is a different test each time.

**The sixteen failures** (gate run, podcrates tag, what the lines said). All are on `gate (m6)`.

| # | Date, podssh commit | Test | podcrates | What was seen |
| --- | --- | --- | --- | --- |
| 1 | 2026-11-14 `f9e12b3` | no fault | n/a | client `-v` ends at `authenticated`; 8 MiB at least written |
| 2 | 2026-11-14 `02c0cf3` | iroh new address | v0.45.0 | both ends keep dialing the relay; no session bytes |
| 3 | 2026-11-15 `2ffb7cd` | stall of 3 min | v0.48.0 | "resumed after 190.7 s, 753664 bytes sent again", then silence |
| 4 | 2026-11-15 `8536613` | iroh stopped relay host | n/a | client's proxy logs CONNECTs to the relay again and again |
| 5 | 2026-11-15 `d00ca78` | new address | v0.54.0 | "resumed after 0.0 s, 688128 bytes sent again", silence; heartbeat answered |
| 6 | 2026-11-16 `f5b4f43` | stopped relay host | v0.60.0 | "resumed after 1.2 s, 65536 bytes sent again", silence; also failed 1 run in 15 locally |
| 7 | 2026-11-16 `5340fbb` | stall of 3 min | v0.63.0 | node: "sends 0 bytes again; 0 not yet written to the target; no link carried the session"; ~2.77 MB of the target's answer never left |
| 8 | 2026-11-18 `5c254fb` | iroh new address | v0.70.0 | node: "target sent no byte for 23 s; this side sent 13758313, client acknowledged 13247259; replay buffer 511054" and no resume |
| 9 | 2026-11-19 `9989ae6` | iroh new address | v0.74.0 | client: "application took no byte for 21 s, while 288823 bytes wait for it"; node silent |
| 10 | 2026-11-19 `dcbea2c` | stall of 3 min | v0.75.0 | same sign on the layer's road: "while 191361 bytes wait for it" |
| 11 | 2026-11-19 `4b21fcd` | iroh new address | v0.76.0 | pipe watch: "SSH read nothing for 20 s while the channel waits to give it bytes; 16089582 bytes went to SSH so far" |
| 12 | 2026-11-19 `c9772a3` | iroh, no fault | v0.77.0 | the same, and no line of SSH's own write waiting: no loss of any link at all |
| 13 | 2026-11-20 `1a24efd` (#331) | stopped relay host | v0.78.1 | the pipe watch's line, and no line of the pump's busy watch: the pump waits in its select; russh's loop neither reads nor writes |
| 14 | 2026-11-20 `cfc07be` (#331) | iroh new address | v0.79.0 | russh's loop held in a channel's full queue (`0013-loop-step`), the pump idle |
| 15 | 2026-11-21 `2ae2341` (#338) | iroh stall of 3 min | v0.81.0 | the full queue is the session's own channel (2), and the pump's wait was not polled: the task that runs it holds elsewhere |
| 16 | 2026-11-23 `af95c50` | iroh, no fault | v0.82.0 | the same lines, and none of `ssh/polls.rs`: the task was polled, the pump was out of its select, in the end of the input's unmarked `writer.eof()` |

**How the diagnosis moved** (each step is an added log line, taken from podcrates by COORD issue
#283 "COORD-091"; see `TODO/robustness.md:2490` onward for the dated record):
(1) 1-6: "one shape seen from the client, a resume that it calls done, after which nothing moves while
the link lives." (2) A far-end line at each resume (podcrates T-767, v0.62.0) showed failure 7: the
node's half that reads the target stopped after a resume of a session that no link carried.
(3) `session.stall` (v0.65.0, node) and `Note::Stall` plus iroh `say_changes` (v0.73.0) showed 8:
511,054 bytes in flight at an address change were never acknowledged, and neither end resumed;
pod-session now ends a link whose PING waits 30 s with neither count moving.
(4) From 9 on the client's own line says the layer is not stuck: the application above it takes no
byte. That application is `pod-e2e`'s channel writing into the 256 KiB pipe that podssh's SSH client
reads. (5) Failure 11 added a watch of that pipe (`crates/podssh-cli/src/ssh/held.rs`, 20 s `HOLD`):
**SSH stopped reading its end of the pipe.** (6) Failure 12, with no fault and a second watch for
SSH's own writes, showed no write waiting, so there is no cycle through the pipe. The remaining
holders are russh's read loop and podssh's pump step. A watch of the pump's steps
(`crates/podssh-ssh/src/io/busy.rs`, commit `edefad63`) now says which step holds 20 s; failure 13
(2026-11-20) came with it and it said nothing, so the pump waited in its select, ready: **the hold is
inside russh's own loop**, in a step that awaits beside no read and no write. (7) podssh's patch
`vendor/patches/russh/0013-loop-step.patch` keeps the loop's step (a reply to which message, a
channel's queue, the handler's data); the busy watch says one that holds 20 s
(`crates/podssh-ssh/tests/loop_step.rs` makes the queue's hold). Failures 14 and 15 named it: the queue of the session's own channel, whose pump was not polled. The task that runs the pump joins SSH, the layer and the end-to-end channel (`tokio::join!`); (8) `crates/podssh-cli/src/ssh/polls.rs` names the part whose poll does not return, at the next hang. (9) Failure 16
said nothing of it: the joined task was polled, so the pump, whose wait of the channel was not polled, was out of its
select, in a wait that it did not name. The one such wait that the test reaches is the end of the input: `writer.eof()`,
awaited alone, into russh's queue of 10 from the handle, which the loop takes only while no data waits for the far
end's window; the loop meanwhile puts the echo into the channel's queue of 100 inline, which only the pump drains. Each
waits on the other. The sent count, 20,680,0xx bytes in each failure since the 9th, is the 20 MiB less about ten
packets of 32 KiB: the upload's tail held in russh's queues. The repair (a draft, `TODO/robustness.md`, T-780):
each wait of a pump on the session drains the channel into a bounded backlog beside it
(`crates/podssh-ssh/src/io/beside.rs`), in `io.rs` and in the master's `mux/msession.rs`.

**The code where the hold must be** (cited at the worktree's tree):
- `vendor/russh/src/client/mod.rs:1568-1638`: the client's `select!` loop. It reads the stream only
  `if can_read` with `can_read = packet_writer.unwritten() < OUTPUT_MOST` (16 MiB,
  `vendor/russh/src/lib_inner.rs:538`), writes `if wants_write`, and handles an inbound packet with
  `reply(self, handler, ..).await` **inline** at line ~1541, so a handler that awaits a full bounded
  channel stops all reading. This is podssh's patch 0011 ("write beside read", T-772,
  `vendor/patches/russh/0011-write-beside-read.patch`). `can_receive_outbound` also gates on
  `unwritten() < OUTPUT_ROOM` (1 MiB).
- `crates/podssh-ssh/src/io.rs` and `io/send.rs`: podssh's pump between russh's channel and the
  user's stdio; `send` waits for the channel window and ticks once a second (`WINDOW_STALL` 60 s).
- Other patches that touch windows: `0002-window-target`, `0004-window-low` (typing-aware windows
  T-661/T-670 in `crates/podssh-ssh/src/pace/`), `0009-server-window-on-read`.

**Current hypotheses** (**Inferred** from the lines; the cycle of 1 fits each line of failures 13-16):
1. A circular wait between russh's client loop and podssh's pump: the loop's inline `chan.send().await`
   on the channel's full queue, whose consumer (the pump) awaits room for its EOF in the loop's own
   queue of writes, which the loop takes only after the far end's window adjust that it no longer
   reads. Repaired in a draft (failure 16, above); the gate ten times in a row proves it.
2. A lost wakeup in a wrapper: `tokio::io::duplex` (the 256 KiB pipe), `held.rs`'s watching wrapper,
   or pod-e2e's `channel/carry.rs` that "carries both directions at once". The classic shape is a
   task that does `read` then `write_all` in sequence with both pipes full. Failures 1-8 predate the
   watches, so they could be a different cause from 9-12.
3. A real flow-control deadlock from podssh's own windows: the client advertises a small window and
   tops it up on a quarter used (patch 0004); the far sshd (or the test's server) stops; the echo
   test is full-duplex, so both windows can close with bytes in flight at the fault.
4. The faults leave the layer in a state where `pod-session`'s ACK accounting never frees the
   window, which then shows as the application not being fed. Failure 8 (unacknowledged 511 KiB with
   no resume) is evidence of this class at the iroh road, and was handled by v0.73.0's PING rule.

**What blocks.** Waiting for the next failure with the new lines, and the fact that it reproduces
about 1 in 15 locally, not at all at times (20 of 20, 6 of 6, 8 of 8, 11 of 11 loops passed).

**Research questions for an outside agent.**
- Does russh 0.65.x (upstream, any version) have a known case where the client's read loop stops
  while `wants_write` is false and a channel's mpsc receiver is full (`reply().await` inline)? Read
  `src/client/mod.rs` and `src/channels/` upstream; compare with `vendor/russh`. Look at upstream
  issues about "client hangs when channel data is not consumed" and window adjust handling.
- Is there a known lost-wakeup in `tokio::io::duplex` when `poll_write` is partial and a reader is
  woken only on a full buffer? (tokio 1.x; look at `DuplexStream`, `Pipe::poll_write_internal`,
  `wake_read` / `wake_write` ordering.) Compare with using a real socketpair.
- In `pod-e2e` v0.76+: `crates/pod-e2e/src/channel/carry.rs` of PodUtils/podcrates. Is there any path
  where one direction's `poll_write` or `poll_flush` pending prevents the other direction from being
  polled, so that two full pipes deadlock?
- iroh: when a client's address changes on a relay-only path, are in-flight bytes on the old QUIC
  path lost without the connection noticing (failure 8)? Check noq / quinn path migration with
  `PATH_CHALLENGE` and idle timers; check iroh's home-relay reconnect (`pod_iroh::home_relay`).

**Suggested experiments** (all runnable without a gate):
1. Loop the test and, on a hang, take a task dump: build with `RUSTFLAGS="--cfg tokio_unstable"` and
   tokio's `taskdump` feature (Linux only) and call `Handle::dump()` from a thread after 120 s; or
   attach `gdb`/`eu-stack` for thread stacks. This names the awaiting task directly and skips the
   whole hypothesis tree.
2. Run the loop under CPU contention (`taskset -c 0`, plus `stress-ng`); the hangs were made rarer by
   adding logging, which suggests a timing race. The authors held 4 cores busy once (12 of 12
   passed).
3. Replace the 256 KiB duplex by a Unix socketpair in `crates/podssh-cli/src/ssh/node.rs` and
   `ssh/iroh/dial.rs` as a bisect.
4. Turn the typing-aware windows off and loop (`crates/podssh-ssh/src/pace/` has no environment switch today; a temporary patch that keeps the default window is the bisect).
5. Run russh's own client against russh's own server over a throttled in-memory pipe with 20 MiB of
   full-duplex echo and a mid-transfer pause of the reader, no podssh code, to see if the loop
   deadlocks alone.

**Reproduce.**
```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features podssh-cli/iroh-test --test m6_exit -- --ignored --test-threads 1
# one case, many times:
cargo test -p podssh-cli --features podssh-cli/iroh-test --test m6_exit -- --ignored --exact \
  iroh::the_iroh_road_survives_a_new_address
```
Needs Python 3 and openssl on the host (the test says "skipped" otherwise); the SSH server of the
tests comes from the harness (`crates/podssh-cli/tests/ssh_harness`, `throughput_harness`). About 370-690 s for the whole
file, 15-40 s a case. The failure text prints both ends' `-v` lines and the node's `node.log`.
Gate: `.github/workflows/build.yml` job `gate (m6)`, `sh scripts/gate.sh --list`.
Issue to read: PodUtils/podssh#283 (COORD-091), amended 5 times, the full dated table.

### A2. T-796 (P1): the gate's OpenSSH and Dropbear interop hung 34 minutes, naming no check

`gate (release)` at `d13ab01` (2026-11-16, run 43839740067, attempt 1): the static build finished in
9 min 53 s, then `interop: OpenSSH and Dropbear` printed nothing for 34 min until the job's 45-min
limit. Attempt 2 passed 636 checks in 12 min 44 s. `scripts/gate.sh:68` writes a step's lines to a
file and shows them only when the step ends, so a step cut from outside shows nothing.
**Done so far:** `scripts/gate.sh` now runs `scripts/interop.sh` under `timeout 1500` (25 min);
tested in the build image (`rust:1-alpine`, busybox `timeout`) with a step that said two checks and
slept: it ended `exit=143` with both lines shown; planted, with no bound, a cut showed none.
**Unknown:** which check hangs. It has not hung since (the record's gate runs since then are green).
**Hypotheses (Inferred):** a check with no time limit that waits on a pty driver
(`scripts/interop-pty.py`) or on a stall forwarder (`scripts/stall-forward.py`, used by
`scripts/interop-faults.sh`); sshd/dropbear in the container failing to start so a client waits for
a banner; busybox `timeout` sends TERM to the shell only, so an orphaned grandchild holding the
output pipe could still hold `run`, which the planted test did not cover.
**Questions:** Does busybox `timeout` kill the process group? Which checks of
`scripts/interop*.sh` lack a per-check limit? Can the gate print each `VERDICT ID` line as it comes
(`scripts/interop-lib.sh` writes `VERDICT ID TEXT` lines) instead of at the end?
**Reproduce:** only in CI: `.github/workflows/build.yml` `gate (release)`; locally
`sh scripts/dev.sh check` (the Linux gate in a container) or `sh scripts/interop.sh BINARY` in the
build image.

### A3. T-465 (P1): `podssh pipe` with `unix-connect` loses an end of input on macOS and Windows

`unix_connect_passes_the_end_of_input_and_the_answer_comes_back`
(`crates/podssh-cli/tests/pipe.rs:107`): `podssh pipe stdio unix-connect:PATH` with 1,000,000 bytes
on stdin; the test's server (`crates/podssh-cli/tests/pipe_seen/mod.rs`) answers a digest once its
input ends. Failed once on macOS (2026-11-02), once on Windows (2026-11-04, gate run 41769967226),
and again 5+ times: Windows runs 41783492970 (1 in 50), 41793576380 and 41795259467 (2 in 50 each,
also with no other test beside it), macOS run 42035545363 and 41793580299 (2 in 50), Windows gate
run 42707316166 (2026-11-09).
**The measured facts.** podssh's pump says "A's input ended after 1000000 bytes; the other side's
write half shut down" (`crates/podssh-cli/src/pipe/pump.rs:113`, with `-v`). The server read all
1,000,000 bytes, and its input **never ended** until podssh was killed at the 10 s limit, when the end
arrives at once (macOS run 42035545363: stdin closed at 50 ms, last server read at 50 ms, server
input ended at 10,076 ms, 2 ms after the kill). A standalone probe
(`crates/podssh-cli/tests/af_unix_eof.rs`, Windows, `suite-repeat.yml ignored=yes`) sends 1 MB and
shuts the sending half 100 times with a blocking client and 100 with tokio's: 600 ends in 3 runs, 0
lost (run 41802845998). The failure is not recorded on Linux. The test's server since 2026-11-10
reads with a 250 ms timeout and reads again, and counts timed-out reads; planted (pump's shutdown
skipped, writer leaked) it fails with "nothing is queued: the end never came"; unplanted passes.
**What differs between the probe and the failing test:** the client and the server are different
processes (podssh is the test's child), and the server is the test's own code.
**Hypotheses (Inferred):** (a) a lost wakeup of the server's blocked read: the FIN is queued but the
reader is not woken until the kill wakes it (matches macOS timing); tokio/mio use edge-triggered
kqueue (macOS) and AFD polling (Windows) and a half-closed AF_UNIX stream may deliver an event only
once; (b) on Windows, `afunix.sys` may not deliver `shutdown(SD_SEND)` to a reader that is already
blocked in a different process. The test's added "timed read again" would pass in case (a) and
still fail in case (b).
**Research questions:** Is there a known mio/tokio issue about EOF readiness not delivered on a
half-closed `UnixStream` on macOS or Windows (search mio issues on "AF_UNIX Windows shutdown",
"kqueue EV_EOF unix socket")? Does `afunix.sys` honour `shutdown(SD_SEND)` for a peer in another
process (look at libuv, Python, Go and .NET bug trackers for "AF_UNIX shutdown Windows
half-close")? Does Windows deliver the FIN only when the sending handle is closed, not shut down?
**Experiments:** a two-process probe on `windows-2025` and `macos-15` that mimics the test (server
in a parent, client a child process via `std::process::Command` with stdin piped and an inherited
or duplicated socket handle); run 500 times; if hypothesis (b) holds, the fix is to close the write
half by dropping the whole write handle (not `shutdown`) or to send an in-band end marker.
**Reproduce:** locally on Linux the test passes: `cargo test -p podssh-cli --test pipe`. To hunt:
`gh workflow run suite-repeat.yml -f runner=windows-2025 -f package=podssh-cli -f test=pipe -f
runs=50` (and `runner=macos-15`); the workflow takes the inputs named in `docs/development.md`.

### A4. T-753 (P2): on Windows an operator over a carrier loses 288 bytes at the end of input

`node_carrier`'s `an_operator_reaches_the_node_at_the_other_end_of_a_program_s_stdio` failed once in
the gate's `windows` job (run 43136322338, 2026-11-12): 1 MiB on stdin to an echo came back as
1,048,288 bytes; the node logged "the stream under the channel failed: An existing connection was
forcibly closed by the remote host. (os error 10054)". 50 repeats on `windows-2025` passed (run
43146225199). A late answer (an echo that answers 1.5 s after input ends) passes on Linux
(`an_answer_that_comes_after_the_input_ended_reaches_the_operator_whole`), so the layer waits for the
far end's last bytes there. The reset is the node's TCP socket to the test's echo.
**Hypothesis (Inferred):** on Windows `closesocket` with unread bytes in the receive buffer sends an
RST rather than a FIN (documented Winsock behaviour), so either the echo or the node closes with
bytes unread. The standard remedy is a lingering close: `shutdown(SD_SEND)`, then read until EOF,
then close (RFC 9112 section 9.6). **Question:** which end closes first in the failing run, and does
a lingering close on both the node's target socket and the test's echo remove the failure over 500
runs? The test now prints what each echo connection saw (bytes back, and which of read, write or
shutdown failed).
**Reproduce:** `cargo test -p podssh-cli --test node_carrier`; to hunt, `suite-repeat.yml` with
`runner=windows-2025 test=node_carrier`.

### A5. The single-failure tests (each: failed once, not reproduced, diagnostics now print)

| Entry | Test | What failed | Why, and what waits |
| --- | --- | --- | --- |
| T-627 (P1) | `crates/podssh-relay/tests/relay_serve_once.rs`, `a_resume_takes_the_next_token_that_the_node_gave_and_a_replayed_one_is_refused` | the echo after a cut waited past 20 s, once, in the crate's whole suite | passed 24 alone, 32 at 8 at once, 6 whole-suite runs; the code moved to podcrates' `pod-relay-serve` (T-684), so the repair would be there. The test now panics with the role's events at its limit |
| T-756 (P2) | `crates/podssh-relay/tests/reverse_carrier.rs`, `two_sessions_of_2_mib_each_way_cross_a_carrier_whole` | session b closed `1000 the node's local side does not read` once in the whole suite | cause read in pod-relay's node: it closes a session whose waiting bytes pass its handler's `queue_bytes` (1 MiB); the test's echo task lagged under suite load. Test's echo duplex raised to 4 MiB; not reproduced even with the old duplex under busy loops |
| T-788 (P1) | `crates/podssh-cli/tests/node_cut.rs:243`, `a_strict_relay_s_1003_costs_the_other_session_no_backoff` | on macOS "the 1003 came" with no 1003 line | the stand-in sends 1003 for a frame in flight when it tells the node of the cut link one second late (`lateclose:1`); if the cut link drained, no frame is in flight. Fix is to make the precondition hold (a source that keeps writing past the cut), never to weaken the check |
| T-846 (P1) | `crates/podssh-ssh/tests/serve_pressure.rs`, `yes_on_a_pty_with_a_client_that_reads_nothing_holds_the_memory` | after the channel closed, `yes` still answered `kill(pid, 0)` after 5 s, once, in the gate | `kill(pid,0)` answers for a zombie too; `finish` in `crates/podssh-ssh/src/server/child.rs` hangs up and waits; the close may have arrived late behind a full window. The failure now prints `/proc/PID/stat` and `wchan` |
| T-849 (P1) | `cp::resume::tests::a_copy_that_another_runs_now_keeps_no_side_file` in `crates/podssh-cli/src/cp/resume_tests.rs` | after the other holder's lock was dropped, the third load of the side file gave offset 0, not 4 MiB, once on macOS | steps are synchronous (`cache::store_file_in_first`, `pod_core::lock` flock, `held` in `crates/podssh-cli/src/cp/resume.rs`); either the lock was still refused or the file was not read. **Question:** does `pod-core`'s `lock` use `flock(2)` or `fcntl` locks on macOS, and does a second handle in the same process see the first handle's drop immediately? (`fcntl` locks are per-process and released when any fd to the file closes; `flock` is per open file description.) |
| T-779 (P2) | `scripts/m5-in-sandbox.sh:81`, `cp --timeout 28m` of 200 MiB through `podssh serve NAME` | failed once after 796 s (exit 69) from a cloud container; the directly repeated runs (4 + 1) passed in 40-50 s up | the first run's logs were deleted with the script's directory (now kept). Candidates in the entry: a drop the copy should have outlived (T-136 resumes from an offset, T-137 opens a new session before the relay's 64 MiB cap), the cloud agent proxy that every byte crosses twice, or the node |

Precedents, already repaired, that show the class: T-800 (a relay session's random hex id contained
`1003`, which a test read as a close code), T-783 (Linux `unix_dgram_disconnected` purges the
sender's own receive queue on a send to a dead peer), T-769 (the Tor onion test failed on a private
Tor network younger than ~9 min because Arti reports `Running` only after the descriptor reached
both HSDir rings). When you meet a "random" failure, first look for a test-side assumption of this
sort.

---

## B. Blocked on outside parties

### B1. Asks outstanding with podcrates (the sibling repository)

Each is a GitHub issue of PodUtils/podssh titled `COORD-NNN: ... (to podcrates)`. The podcrates
session answers by a tag; podssh "takes the tag at once".

| Issue | Ask | Entry | Technical core |
| --- | --- | --- | --- |
| #283 COORD-091 | pod-session/pod-iroh/pod-e2e: the hang of A1; asks 1-5, 1 and 5 done, 2-4 partly | T-780 | see A1 |
| #320 COORD-122 | under `--max-session-mib 1` a new link sends again more than the cap (up to 1,179,648 bytes); bound bytes in flight by a quarter of `max_session_bytes` | T-826 | answered in v0.74.0 (`Offer::fit`, windows of a quarter) |
| #325 COORD-124 | move threshold three quarters of the cap plus a quarter in flight from each end is 5/4 of the cap; make `Offer::fit` keep threshold plus both windows under the cap | T-826 | `crates/pod-session/src/pump/watch.rs:19-23` of podcrates counts the link's bytes both ways, as the role's cap does |
| #327 COORD-126 | on Windows the first link met `1009` once: the move began at 899 KiB (above seven eighths of the cap), not at 768 KiB; ask: a move that begins at its threshold however slow the host, or leave room for ~130 KiB of lag | T-826 | scheduler lag; the old link passes the cap before the hold takes it |
| #319 COORD-121 | `pod-core::lock`: a mode for a byte far past the end of a file that others read (Windows locks the whole file, which refuses OpenSSH's reads of `known_hosts`) | T-820 | podssh's `crates/podssh-ssh/src/known_hosts/lock.rs` keeps its own code until then |
| #314, #315 COORD-117, 118 | pod-session's drain after a failed write loses the relay's Close (`End::Lost` below a `broken pipe`); three lines of pod-proxy, pod-session and pod-relay untrue or short | T-826, T-828 | `forward_layer::Offer` carries no `max_session_bytes`; `byte_budget_under` keeps 56 MiB for a cap under 9 MiB |
| #306 COORD-109 | `pod_piping::probe::upgrade` writes no caller header, so a Cloudflare Access gate refuses the node's probe and the node leaves the pair's road | T-718 | podssh skips the probe for hosts that get credentials; the true fix is in podcrates |
| #307 COORD-110 | `pod_relay::pool::members` keeps no `meet`; a member cannot list its net's relay host first as its iroh relay and DERP home | T-720 | needs the role's `meet` read before a session (rule 2 exception 8) |
| #316 COORD-120 | cfb's 22 asks (T-708..T-731, #195) wait for podcrates T-110, T-111, T-112, T-117, ordered after other sessions' CI entries | T-711, T-719, T-722, T-729 | blocked entries below |
| #248 COORD-071 | order of Q101's waves 3 and 4 (the crates still living in podssh) | T-684 | each tag taken at once; `pod-cloudflare` and `pod-ts`, then `pod-relay-serve` remain |

### B2. The blocked entries (11), by who must act

| Entry | P | Who | Technical core and what unblocks |
| --- | --- | --- | --- |
| T-711 | P1 | podcrates T-112 | `PODSSH_PUBLIC=off\|fallback\|default` over each third-party service (forwarders, DERP fleets, Piping, n0 relays, transit, OpenTunnel, WARP); needs `pod-services` to carry each service's party and the effective set as JSON; podssh may not keep a list of other parties' services (Q79) |
| T-719 | P1 | podcrates T-110, T-120 | `podssh link`: a held WebSocket with pings, jittered reconnect, resume by sequence, a replay window, a CONNECT proxy, a private CA, and a Unix socket of frames; the library is `pod-session` |
| T-729 | P1 | podcrates T-117 | the Access TCP client on `cf://`: the browser login and token cache, on Windows, macOS, Linux, replacing `cloudflared access token`; live proof needs a Cloudflare account and the owner ruled 2026-11-09: no test accounts as CI secrets |
| T-722 | P3 | podcrates T-111 | `X-Relay-Lease` header (a short token of one use bound to a target and window) accepted before the upgrade; lives in `pod-relay` |
| T-727 | P3 | owner, Cloudflare account | SSH login with a short-lived Access certificate over `cf://`; the request and answer of Access's certificate service are not in this repository and must be read from `cloudflared`'s source first (T-727 says "do not guess") |
| T-740 | P3 | OpenBare's operator, or a node of another operator | a Bare (TompHTTP v3) server as a last hop; the only node, `openbare.xyz`, answers every upgrade `500 "WebSocket Constructor: The protocol header token is invalid"` because its edge (`nirholas/openbare` at `65a4d8d`, `edge/src/websocket.js`) calls `new WebSocket(url, { headers })` on Cloudflare Workers, whose constructor takes subprotocols as its second argument. The hop is built and tested against TompHTTP's own server (`scripts/bare-hop-server.mjs`); the live job `behind_a_proxy_that_passes_the_bare_node_alone_the_bare_hop_carries_the_session` fails on that 500 |
| T-672 | P3 | rustls maintainers | TLS tickets kept across runs: rustls 0.23.46 gives a client no way to write a ticket (`Tls13ClientSessionValue::new` is `pub(crate)`); rustls/rustls#2907 was merged 2026-02-06 on the 0.24 line and no release carries it. Gain is bytes and a certificate check, not time, in TLS 1.3 with no early data |
| T-687 | P2 | owner | first crates on crates.io: `[patch.crates-io]` carries `vendor/russh` and `vendor/ssh-key`, which a published crate cannot; git dependencies on podcrates cannot be published; the owner rules only after podssh is called stable |
| T-113 | P2 | the operator's agents | M5's exit in a real sealed sandbox: `sh scripts/m5-in-sandbox.sh PODSSH`; passed in the Podman box and a cloud container |
| T-328 | P3 | owner | `podssh config import` from FinalShell and Termius: no published export of a file that those programs wrote (Q41 requires one under a license the repository can hold) |
| T-376 | P3 | owner | live run of the GCP IAP and AWS EICE roads: throwaway cloud accounts with credentials in `.env/` |

### B3. Other outside dependencies

- **The relay pool does not run podssh's role** (COORD-120 / #316; `docs/relay.md`). Each `/health`
  of the 37 hosts of the default relay's `/relays.json` reports `tcp-ssh-relay 2026-10-03-r2`, the
  operator's own deployment on Cloudflare. A fix to `podssh relay serve` (for example T-801's
  "forget a node's socket at once after a reset or failed write") reaches users of the default relay
  only through the relay's operator or through `pod-relay-serve` (podcrates T-036). Its edge also
  chooses HTTP/2 with no `SETTINGS_ENABLE_CONNECT_PROTOCOL` (measured 2026-10-30), so RFC 8441 does
  not work there (`TODO/roads.md`, T-321 Premise).
- **T-106 (P2): the live test of `podssh ts` with two nodes.** The role now serves DERP
  (`podssh relay serve --derp-keys FILE`, `crates/podssh-relay/src/serve/derp.rs`), the harness
  (`scripts/ts-two-nodes.sh`, headscale and tailscaled in Podman) passes, but the run on the
  operator's own tailnet needs its auth key in `.env/`, usable only on the operator's machine.
- **T-755 (P3): Dev Tunnels forward road** (GitHub #215): built on `pod-devtunnel` against a
  stand-in; the live run waits for a tester's tunnel and token.
- **T-738 (P3): file hosts as a last carrier** (`TODO/mesh.md`): live from Actions at 814-858 ms
  piece latency for tmpfiles.org and temp.sh (`filehost-live.yml`); litterbox and 0x0.st are off by
  default (terms refuse automated upload); the run against `mia/0x0` waits for a container.
- **Deferred stealth entries T-757..T-768** (GitHub #224 and #225, `[DEFERRED]` until the author
  lifts it): VLESS first-write coalescing, 0-RTT replay window, conformance vectors for
  Shadowsocks/Trojan/VMess, a browser-shaped HTTP/2 client, a cover site and a delegated handshake.

---

## C. Technically hard or unsolved

### C1. A tty where there is no `/dev/ptmx` and `unshare` is refused (T-248, T-111, T-113, T-775..T-778)

**The problem.** `podssh serve` must give a child a terminal so `vi`, `less`, `top` and Ctrl-C
work, in sealed sandboxes: no `/dev/ptmx`, no `/dev/pts`, no capabilities, `NoNewPrivs`, a seccomp
filter that refuses `unshare`, `mount`, `chroot` and sometimes `ptrace` (`docs/target-environment.md`).
**Measured routes** (`docs/research/serve-tty.md`, driver `docs/research/serve-tty/run.sh`, Linux 6.18
in a `cage.c` that imitates the sandbox): route 1 (a devpts instance of its own through
`unshare(CLONE_NEWUSER|CLONE_NEWNS)` by a single-threaded forked helper; `TIOCGPTPEER`, not
`ptsname`) works unless `unshare` is refused or the process has a second thread (`EINVAL`); route
2a (the child's own stdin is a socket, and podssh answers its tty ioctls through seccomp user
notification; identifies descriptors with `kcmp`, writes answers with `process_vm_writev` or
`/proc/PID/mem`) works in all cages **except** `-n -p -v -P` (ptrace, `process_vm_*` and `/proc` all
refused or hidden: "no way to write the answer; `test -t 0` false"), and refuses when the cage
already has a seccomp listener (`EBUSY`); route 2b (ptrace) fails where `PTRACE_TRACEME` is refused.
Route 3 (the line discipline in user space: `--pty line`) always works but is not a pty.
**State.** Routes 1 (T-775), 2a (T-776), 2b (T-777) and 3 (T-111) are implemented and each measured;
T-107..T-112, T-114, T-117, T-118, T-222 are `partial`, each for its run in the build image (T-251's
checks, deferred by Q88; T-111 and T-248 are partial for their own steps); T-113's real sandbox run is the operator's.
**What is unsolved:** the one cage where nothing but route 3 works; a real pty for programs that
need `/dev/tty` semantics (job control, `tcsetpgrp`) there; ZMODEM and trzsz-style transfers through a
pty that damages bytes (T-831, research, not measured). **Questions:** when seccomp user
notification, `process_vm_*`, `/proc` and ptrace are all unavailable, is there any other
unprivileged way to see and answer a child's tty ioctls, or is route 3 the floor? Does a newer
kernel (`pidfd`, `SECCOMP_IOCTL_NOTIF_ADDFD`) widen route 2a? **Reproduce:** `sh
docs/research/serve-tty/run.sh` (as root on Linux, compiles C probes with `cc`); `cargo test -p
podssh-ssh --test serve_pty --test serve_line`.

### C2. The relay's byte cap against the resumable layer's arithmetic (T-826, COORD-122/124/126)

The live relay ends a link at 64 MiB both directions together (`1009 session byte cap`,
`docs/relay.md:787`); the layer must move to a new link first. With a small cap (`podssh relay serve
--max-session-mib 1`, `crates/podssh-cli/tests/layer_cap.rs`, 3 MiB each way) the move threshold of
three quarters plus a quarter of window in flight from each end is 5/4 of the cap, and on Windows
the move began late by ~130 KiB. The test asserts no link ends with 1009 and no link's end is a
broken pipe or reset. On Linux 8 of 8 pass at v0.75.0; Windows failed once (run 44476622620).
**Question:** a formal bound: with cap C, threshold T, windows W_c and W_n in flight, the old link
must be held from the moment the threshold is crossed until the new link carries; what is the
minimum of T that is safe under scheduler lag L at a given line rate R (T + W_c + W_n + R·L ≤ C)?
Is the right design to hold new writes on the old link from `T` (backpressure) rather than to move
and then drain? This is in podcrates, `pod-session::pump::watch` and `Offer::fit`.

### C3. The slow link: bulk and a typed key (T-660, T-661, T-670, T-666, T-673)

Typing-aware SSH windows (T-661) cut the echo beside a download from seconds to ~0.1-0.5 s, but give
up bulk rate on a far link; T-670 won back most (the slow fake path from 3,009 ms to 162 ms echo at
99% of the old rate), but **two cells remain** (T-670 `## Done`): the download rate while typing on
the **far** link (1.1 MiB/s now, 2.1 before T-661; OpenSSH 5.7 MiB/s; osewa over QUIC 5.6) and the
node's road on the slow link (486 ms before, 761 ms after T-670). Real-netem results
(`feel-netem.yml`, run 41961591548, 2026-11-05) put podssh's `--direct` far-link download beside
typing at 3.1 MiB/s against OpenSSH's 5.7. T-666 (a copy on its own QUIC stream of the same iroh
connection, priority -1 against a terminal's 0) is merged and passes but the "echo beside a copy
through T-660's matrix on the iroh road" and the relay's HTTP/2 connection split are not done.
**Research questions:** the best receive-window policy that keeps echo latency under ~2x idle RTT
while keeping a window at the bandwidth-delay product on a path with a high BDP and loss; what do
mosh, osewa and QUIC's stream priorities do; is a second SSH channel at a lower priority inside one
TCP connection feasible at all (head-of-line blocking says no; the fix is a second connection or
QUIC)? **Reproduce:** `python3 -I scripts/feel-matrix.py PODSSH --runs 3 --roads
openssh,direct,role,node --shapes cellular,slow,far` (needs the repo's fake paths); the netem
version is the workflow `feel-netem.yml` on `ubuntu-24.04`; the unit-level simulation is
`cargo test -p podssh-ssh --lib pace`.

### C4. The HTTP road and the HTTP/2 road have never met a real intercepting proxy (T-319, T-321, T-762)

For a proxy that terminates TLS and refuses `Upgrade` (a Claude Code cloud container's proxy
documents that refusal) podssh has a split HTTP road (`/v1/http/...`, two connections after a probe;
`AGENTS.md` rule 2 exception 3) and a serial form; for many sessions on one TLS connection an RFC
8441 extended-CONNECT road (`PODSSH_H2`). Both pass against the project's own stand-ins and servers
the project wrote (T-319: 4 MiB each way with batches of 64 KiB behind a proxy that refuses bodies
over 100 KiB; T-321: `crates/podssh-cli/tests/h2_each_cli.rs`, 8 sessions on one connection). What is
not done: (1) a real proxy's path; (2) Apache httpd 2.4.58+ with `H2WebSockets on` in the build image
(software podssh did not write) for the HTTP/2 road; (3) T-762: the road behind a proxy that refuses
`Upgrade`, fallback within 1 s; (4) a non-WebSocket `:protocol` (T-499, waiting for IETF's connect-tcp
to become an RFC). Q88 defers these. **Question:** which real-world intercepting proxies (Squid
`ssl_bump`, Zscaler, Blue Coat, mitmproxy, Cloudflare Gateway) buffer chunked responses, merge
batches, or drop long GETs, and which of them speak RFC 8441? An empirical table would settle the
defaults of the batch size, 20 ms/1 MiB answer rule and the 20-25 s long-poll wait
(`TODO/roads.md`, T-319 Decision).

### C5. iroh on a relay-only path after an address change (failure 8 of A1; T-665, T-666)

With `PODSSH_IROH_UDP=off` (a host with no UDP) the iroh relay carries every byte. After the client's
address changes, 511,054 bytes sent before the change were never acknowledged, and neither end
resumed (`TODO/robustness.md`, T-780 eighth failure). pod-session now ends a link whose PING goes
unanswered 30 s with neither count moving (v0.73.0). **Questions:** does noq/quinn on a relay-only
iroh path move in-flight data to the new path, or does it wait on PTO and idle timers (check the
QUIC idle timeout and path validation in `iroh`'s relay transport)? Is a 30 s detection acceptable
for an interactive session, or should the client probe on `Note::Stall` earlier? Related
measurements: T-665 (QUIC tuned on a wide-area path, done), n0's public relays are an allowed live
target (Q38).

### C6. Windows and macOS socket semantics (A3, A4; T-714; T-248 route 1 on macOS)

Besides A3 and A4: T-714's "an upgrade in place that moves a Unix route's session" (does WinSock's
duplicate of an AF_UNIX socket carry across processes? "untried", `TODO/reverse.md`); macOS has no
route to a FIDO device in podssh (`TODO/ssh.md:1849`: macOS gives a FIDO device through IOKit only,
an API of frameworks with a run loop of its own; "IOKit through FFI, with no test, lost for now"),
so a `sk` key works there only through an agent; Windows asks the WebAuthn API of the system.

### C7. T-598 (P3): the stuck write on a cloud host ends on keepalives after 240 s, not 60 s

`podssh ssh --direct` to a peer that stops reading ended on SSH keepalives after 240 s where the
manual says 60 s and "no progress". Measured 2026-11-13: the writes stop at the SSH channel's
window (0) above the socket, so `pod-proxy`'s write limit never arms. Repaired for roads that tell no
silence (`io::Through::window_stall`, `WINDOW_STALL` 60 s in `crates/podssh-ssh/src/io/send.rs`);
the resumable layer's roads excluded because the gate's m6 stall tests ended at the new bound (they
must resume instead). **Left:** the Prove's `INTEROP_ONLY=faults sh scripts/interop.sh BIN` run in
the build image on a cloud host (T-251). **Question:** is excluding the layer's roads from the
60 s bound correct, or can a bound be defined that both ends a dead peer and lets a layer resume a
stall of 3 minutes?

### C8. T-709 and T-710: a node reachable for months

T-709 (done) and T-710 (partial): `crates/podssh-cli/tests/node_months.rs` simulates 120 days on a
paused clock (0.6 s): pair renewals, a move to the next pair, a restart of the role from its file
of pairs, a daily stop-token rotation, the operator's key list, and a member's leg by the node's key.
Plants `t710-next-pair-unrenewed` and `t620-renewal-off-for-good` are caught. **Not done:** a 90-day
proof in a beta in the field, and the real `--install --system` under systemd as PID 1 (the build
containers lack it). **Question:** what clock and real-network behaviours does a paused clock hide
(NAT mapping expiry, DNS TTL, the relay operator's deployments rolling, a laptop's sleep)?

### C9. Open research entries (P3, all `open`, not started)

T-831 (a 7-bit transfer envelope when a multiplexer damages ZMODEM; measure first), T-835 (is a DNS
TXT carrier worth its deployment for a host that reaches a resolver and nothing else), T-834 (a
bearer identity bound to a session and its carrier), T-836 (a gateway role where the user name
chooses the upstream), T-839 (a TPM 2.0 key that signs only while measured boot state matches),
T-499 (IETF connect-tcp). The M5 server extras T-115, T-116, T-119, T-120, T-122..T-124, T-631 and
the mosh-like T-159, T-160 (local echo and prediction), T-161 (screen state and scrollback), T-303,
T-304 (screen frames as QUIC datagrams) wait on `podssh serve` being complete.

---

## D. Believed impossible, deliberately out of reach, or limited by a platform

Each has a source line; none is closed as "won't fix" without the owner (`AGENTS.md`: "never close an
entry as out of scope"), so these stay recorded.

| Item | Why | Source |
| --- | --- | --- |
| IRC DCC file transfer | the receiver connects to the sender and neither side can accept; files go as chunks through the server | `docs/irc.md:142` |
| mDNS and any UDP discovery in the measured sandbox | the sandbox refuses UDP; podssh must probe before it uses UDP | `TODO/reverse.md:1833`, `docs/target-environment.md` |
| A real pty with no devpts, no `unshare`, no ptrace, no `/proc` | route 2a fails in the cage `-n -p -v -P`; only the line discipline remains | `docs/research/serve-tty.md` |
| FIDO security keys on macOS, other than through an agent | IOKit has no usable API for a CLI; no macOS test host | `TODO/ssh.md:1849` |
| HTTP/1.1 for XHTTP's split modes | split modes need a second connection; refused `78` | `docs/STATUS.md`, `TODO/ws.md` (T-759) |
| Trojan's UDP associate | refused by name | T-761 |
| UDP-based roads (MASQUE, Hysteria 2, TUIC, QUIC to the role, iroh direct) where UDP is dropped | each probes UDP first and falls away | STATUS rows, `AGENTS.md` rule 1 |
| TLS session tickets across runs | rustls 0.23 has no encode API for a client's tickets | T-672 |
| Services that need an account of the user's: Deno Deploy, Fly.io, Cloudflare TURN, GitHub Codespaces, Microsoft dev tunnels (except as a tester's), others' MASQUE servers | ruled out by Q77/Q78 | `docs/carriers.md` ("Ruled out") |
| Federation 2's forwarder | lets in only its own web client by its `Origin`; podssh would have to impersonate; stays out pending the owner (Q86) | `docs/carriers.md` |
| `bashupload.com`, domains that look taken over | a name that stops resolving is how a domain gets taken over; never used (Q79) | `docs/carriers.md` |
| VMess's MD5 form | only the AEAD form is built | `docs/carriers.md` |
| Real accounts as CI secrets for Cloudflare Zero Trust | owner's ruling 2026-11-09; tests use stand-ins | T-727, T-729 |
| A published crate with the vendored patches | `[patch.crates-io]` cannot be published | T-687 |
| An interactive session over file hosts | 200 uploads an hour per user at tmpfiles.org is one piece per 18 s; only a large-piece carrier is possible | `docs/carriers.md` ("T-572") |
| A second outbound connection, a listener, a helper process, `LD_PRELOAD` | rule 2 and 3 of `AGENTS.md` (nine documented exceptions) | `AGENTS.md` |
| Anything that needs a host the sessions cannot reach (the operator's real sandbox, tailnet, cloud accounts) | outside every session; see B | T-113, T-106, T-376 |

---

## E. Long-partial work

| Entry | Since | What remains |
| --- | --- | --- |
| T-107..T-114, T-117, T-118, T-222, T-248 (M5 `podssh serve`) | 2026-11-13 | each is merged and works against OpenSSH 9.6's client; each waits for its run in the build image (T-251, deferred by Q88) and for `cargo todo remap`; T-113 for the real sandbox |
| T-319, T-321 (HTTP road, HTTP/2 road) | 2026-10-30 | a real proxy's path, Apache `H2WebSockets` in the build image, live runs (Q88) |
| T-660, T-666, T-670 | 2026-11-04/05 | the far link's download rate, iroh/DERP rows, the node's road on the slow link, osewa's binary on a runner (see C3) |
| T-684 (migration to podcrates) | 2026-11-05 | `pod-cloudflare`, `pod-ts`, `pod-relay-serve`; `v1.1.0` and every beta wait for the end of it |
| T-446 (release of M10) | 2026-11-03 | the next beta waits until podssh is nearly complete and until T-809's black-box pass is clean; `v1.1.0` waits for T-684; nothing goes to crates.io until the owner says stable |
| T-710, T-714, T-718, T-720, T-738, T-755, T-793, T-847 | 2026-11-12..19 | live runs, an upgrade in place of a Unix route, COORD-109, a member's use of `meet`, the first push to ghcr.io at the next tag (an org admin makes the package public once), the installer of a published release with its signature checked |
| T-791 (lane in `pod-lab`'s host profiles) | 2026-11-16 | commands 1-4 pass in nine host profiles and 5-6 behind four network classes; classes with no proxy (`no-proxy-no-dns`, `ipv6-only`) wait for the lab; the candidate run |
| T-809 (what the gate proves) | 2026-11-17 | the third black-box pass on the candidate before any beta; two passes filed 19 entries (T-810..T-828), each done in the record |
| T-820 (copies of shared code) | 2026-11-17 | `pod_core::lock`'s byte mode on Windows (#319), `Interrupts` from `pod-manual` (#312) |

---

## F. Reproduction cookbook

```sh
# Prepare a Linux host or cloud container (Docker, Podman, servers and tools of the tests)
sh scripts/cloud-setup.sh

export CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only \
       CARGO_PROFILE_TEST_DEBUG=line-tables-only      # one build at a time
cargo test --workspace --no-fail-fast                   # about 3,900 tests, 22-30 min; target/ ~28 GB

python3 scripts/check-repo.py                           # cheap repo checks, no build
cargo todo check                                        # the work record agrees (a wrapper of pod-todo)

# no third party (loopback only):
cargo test -q --no-run -p podssh-cli -p podssh-relay -p podssh-ws
unshare -n sh -c 'ip link set lo up && cargo test -q --offline --no-fail-fast -p podssh-cli -p podssh-relay -p podssh-ws'

sh scripts/dev.sh check                                 # the Linux gate in the build image (rust:1-alpine)
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh   # the Podman box like the sandbox
sh scripts/m5-in-sandbox.sh PODSSH                      # M5's exit (serve, vi, less, Ctrl-C, 200 MiB each way)
```

A cloud session's proxy passes HTTPS alone, so raw SSH and other ports go through GitHub Actions
(`docs/HANDOFF.md`, "How to test"). Workflows for hunting: `suite-repeat.yml` (inputs `runner`,
`package`, `test`, `runs`, `ignored`), `feel-netem.yml`, `fuzz.yml`, `relay-live.yml`,
`last-roads-live.yml`, `filehost-live.yml`, `release.yml` by hand with no tag.

## G. Consolidated questions for an outside researcher

1. **russh (upstream 0.65.x):** can the client's read loop stall with no pending write while a
   channel's receiver is full (inline `reply().await`)? Is there an upstream fix?
2. **tokio:** any known lost wakeup in `tokio::io::duplex` under full-duplex partial writes? Is
   there a `Handle::dump()` recipe to capture a hung test on Linux in CI?
3. **mio/tokio on macOS and Windows:** is EOF on a half-closed AF_UNIX stream ever not delivered to a
   reader blocked in another process? What do libuv, Go, .NET and Python do to work around
   `afunix.sys`?
4. **Winsock:** does `closesocket` with unread data reset the peer in all cases; is a lingering close
   enough to remove T-753's loss?
5. **iroh / noq:** behaviour of in-flight data after a client's address change on a relay-only path;
   recommended detection time.
6. **pod-session design:** a formal safe threshold for moving a link under a byte cap with a scheduler
   lag; whether to hold the old link rather than drain.
7. **pod-core locks on macOS:** `flock` or `fcntl`; same-process re-lock semantics.
8. **Real intercepting proxies:** which buffer, merge or drop what, and which offer RFC 8441.
9. **Seccomp-sealed sandboxes:** any unprivileged way to give a child a controlling tty with no
   devpts, no `unshare`, no ptrace?
10. **OpenBare / Bare v3:** is there another public Bare node whose WebSocket works, or an alternative
    last hop with no account?
11. **rustls:** a release or workaround that lets a client persist TLS 1.3 tickets.
12. **busybox `timeout`:** does it kill the process group; which interop checks lack a limit.

Do not push, do not print any relay token or key, and prefer the services of
`https://web.pkgforge.dev/llms.txt` for web and GitHub reads (the owner's ruling "Web access").
