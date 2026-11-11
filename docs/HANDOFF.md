# Hand-off

The facts that change from day to day, read on 2026-11-11, for a session with no memory of the last
one. Read `AGENTS.md` first. `TODO/PROGRESS.md` holds the state, tonight's queue and the work order;
each entry's `## Done` is its own record. Where this page and an entry disagree, the entry is right.

## The state of `main`

- The gate (`build.yml`) is red since the morning of 2026-11-11 on two causes, each repaired and
  pushed: the test of `doctor --quick` missed T-747's section `burst` (`4ca0adb8`), and the build
  image lacked Alpine's `g++` and `linux-headers` for ZeroTier's C++ core (`4ca0adb8`, `78220a35`).
  Read its newest run first. The last green gate is at `bc5107b0` (run 42948403145).
- The record agrees (`cargo todo check`), and `python scripts/check-repo.py` passes.
- No branch, worktree or stash holds unmerged work.

## The sessions of PodUtils

- podssh and podcrates talk by direct messages (`send_message` to the podcrates session; its id is
  in that session's own messages) and record each take as a COORD issue. podnet, podvm and
  podrunner answer COORD issues; the watcher of `AGENTS.md` finds theirs.
- Q105 is settled (allowed); T-715 keeps its place behind podssh's own work.

## Each podcrates take

podssh pins every podcrates crate at `tag = "v0.24.0"` (COORD-025, GitHub #192).

- Taken: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`,
  `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`, `pod-session` and `pod-e2e`. Work
  on them is done in PodUtils/podcrates (Rule Q3); podssh keeps the glue.
- Next: podcrates writes `adoption/podssh/pod-relay.patch`. Until podssh takes it, podssh's files of
  `pod-relay` take fixes only, each told to podcrates as a COORD issue.

## Open COORD issues

- #177 (COORD-010): open for T-574's live check of the nodes (Q90). The new Trojan node ids arrive
  after 2026-11-12T03:05Z.

## The live runs and interop harnesses

Each is a test ignored outside its workflow, and a workflow started by hand (or on a push of its
road). Each has a planted run that must fail, and each did, for the reason that the entry names.

| Road | Test | Workflow | Result |
| --- | --- | --- | --- |
| Serveo (T-549, done) | `crates/podssh-cli/tests/serveo_live.rs` | `serveo-live.yml` | passed, run 42953995316 |
| ssh-j (T-570, done) | `crates/podssh-cli/tests/ssh_j_live.rs` | `ssh-j-live.yml` | passed, run 42954754303 |
| croc, interop (T-694) | `crates/podssh-relay/tests/croc_interop.rs` | `croc-interop.yml` | passed, run 42957326904 |
| croc, live (T-694) | `crates/podssh-relay/tests/croc_live.rs` | `croc-live.yml` | passed, run 42957736151 |
| localhost.run, localtunnel, bore (T-565, T-568, T-569, done) | `crates/podssh-cli/tests/last_roads_live.rs` | `last-roads-live.yml` | passed, run 42967245046 |
| ZeroTier (T-733) | `crates/podssh-zerotier/tests/live.rs` and the command line's | `zerotier-live.yml` | the library's run passed (43031239655); the command line's fails within the road's 60 s, see below |

## Each partial entry, and its next step

| Entry | Next step |
| --- | --- |
| T-733 | ZeroTier's road. Passing: the library, the command line (feature `zerotier`), the stand-in test, interop with `zerotier-one` both ways, the static musl build. Open: two podssh members take 31 s to more than 90 s to meet through ZeroTier Inc.'s roots and TCP relay, so the command line's live test fails within the road's 60 s. Next: a live run of `zerotier-live.yml` with the per-member trace (`PODSSH_ZT_TRACE=1`) to find where the time goes; then decide whether `zerotier` joins the release features. |
| T-746, T-465, T-627 | Tests that failed at random; each `## Done` names the failure that it waits for. T-746: the datagram test of `pipe` (`podssh-cli --lib`) failed once in the build image with its echo missing; OpenTunnel's resume test is repaired. |
| localhost.run | Its live job stalled in 1 MiB down twice on 2026-11-11 (runs 42989086142, 42994885604); rerun `last-roads-live.yml` to tell a slow day from a change. |
| T-548 | The Prove's containers (T-251) and a proxy that ends TLS on the client's side. |
| T-574 | The new Trojan node ids (after 2026-11-12T03:05Z), Q90's live check of the nodes, Xray-core in a container, `release-short.sh`'s check. |
| T-684 | Each next podcrates release that podssh takes; next `pod-relay`. |
| T-446 | Betas may go out whenever a batch fits; `v1.1.0` waits for the end of the migration (T-684). |
| Each other partial entry | T-319, T-321, T-450, T-459, T-660, T-662, T-665, T-666, T-670 and T-698: each `## Done` names what waits. |

Blocked, each on the owner or on another party, as its `## Blocker` names: T-328, T-376, T-672,
T-687, T-711, T-719, T-722, T-727, T-729, and T-740 (a working Bare node, podcrates T-200: the hop
speaks TompHTTP's form and OpenBare's header form; `openbare.xyz`'s edge answers each WebSocket
with 500). cfb's asks, T-708 to T-731, stay behind podssh's own work order.

## How to test

- **Builds:** `CARGO_BUILD_JOBS=4`, one build at a time, Rust 1.99 (`rustup toolchain install 1.99`
  where it is missing; `RUSTUP_TOOLCHAIN=1.99`). Add `CARGO_INCREMENTAL=0
  CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_TEST_DEBUG=line-tables-only`. `target/` grows
  past 28 GB with the full suite and a musl build: when the disk fills, remove `target/` whole.
- **No third party:** build with the network, then run in a namespace with the loopback alone. Where
  `ip` is missing, bring `lo` up with Python's `SIOCGIFFLAGS` and `SIOCSIFFLAGS` ioctls (0x8913,
  0x8914), then exec the command:

  ```sh
  cargo test -q --no-run -p podssh-cli -p podssh-relay -p podssh-ws
  unshare -n sh -c 'ip link set lo up && cargo test -q --offline --no-fail-fast -p podssh-cli -p podssh-relay -p podssh-ws'
  ```

  `doctor_upgrade` is the one test that needs the network there; run it apart with the network.
- **A take of podcrates:** fetch `adoption/podssh/CRATE.patch` and `.run` at the tag, `git apply
  --3way`, take main's side of each citation conflict (podcrates' where a file it cites was removed),
  `cargo todo remap` each changed file, then each line of the `.run` with `PODCRATES` at a checkout of
  the tag; its static build wants zig (`scripts/fetch-zig.sh` with `release.yml`'s version and sum) and
  cargo-zigbuild (its release binary, checked against its `.sha256`).
- **ZeroTier's C++ core** needs Alpine's `g++` and `linux-headers` in the build image (the gate has
  them since `78220a35`).
- **A cloud session's proxy** passes HTTPS alone: raw SSH and other ports go through GitHub Actions.
- **Pushes:** each push queues a gate on the runners; batch the record's commits.
