# Hand-off

The state of podssh at the session of 2026-11-11, for a session with no memory of this one. Read
`AGENTS.md` first. This page adds the facts that change from day to day: where `main` stands, what
each open thread waits for, and the next step of each. `TODO/PROGRESS.md` stays the work order, and
each entry's `## Done` stays its own record. Where this page and an entry disagree, the entry is
right.

## The sessions of PodUtils

- The owner's pause of 2026-11-10 ended on 2026-11-11 (PodUtils/podcrates#53 closed). podssh and
  podcrates talk by direct messages (`send_message` to the podcrates session; its id is in the
  podcrates session's own messages) and record each take as a COORD issue. podnet, podvm and podrunner
  answer COORD issues; the watcher of `AGENTS.md` finds theirs.
- Q105 is settled (allowed, `docs/decisions.md`, 2026-11-11); T-715 keeps its place behind podssh's own
  work.

## The state of `main`

- Each change of the session is pushed; no branch, worktree or stash holds unmerged work.
- The gate was green at `bc5107b0` (run 42948403145: Linux, macOS, Windows, the static release binary),
  and `deny` and `secrets` are green. Later pushes changed tests that are ignored outside their
  workflows, and the record; their gates were queued at the end of the session: read them first.
- The record agrees (`cargo todo check`); `python scripts/check-repo.py` passes.

## Each podcrates take

podssh pins every podcrates crate at `tag = "v0.16.0"` (`fab57923`).

- Taken: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`,
  `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole` (`baa00a06`) and `pod-session`
  (`6f78a7c7`). podcrates recorded the last two (`14982fc`): `code/` and `session/` of podssh-relay are
  glue over the crates, and work on them is done in PodUtils/podcrates (Rule Q3).
- `v0.17.0` changes nothing of podssh's; move the tag with the release that brings podcrates T-171 and
  T-172 (#186: the services localhost-run, localtunnel and bore, and `Rewound::new`).
- ssh-j.com's host key, read live, went to podcrates as a fact for `pod-services`; podssh pins it with
  the tag that brings it (T-570).

## Open COORD issues

- #186 (COORD-019): podcrates T-171 and T-172, next in podcrates' order. Then T-565, T-568 and T-569's
  short live runs, and the private `Replay` of `crates/podssh-relay/src/localtunnel/route.rs` goes.
- #177 (COORD-010): stays open for T-574's live check of the nodes (Q90); `v0.16.0` dropped the four
  dead Trojan nodes.

## The live runs and interop harnesses of this session

Each is a test ignored outside its workflow, and a workflow started by hand (or on a push of its road):

| Road | Test | Workflow | Result |
| --- | --- | --- | --- |
| Serveo (T-549, done) | `crates/podssh-cli/tests/serveo_live.rs` | `serveo-live.yml` | passed, run 42953995316 |
| ssh-j (T-570, done) | `crates/podssh-cli/tests/ssh_j_live.rs` | `ssh-j-live.yml` | passed, run 42954754303 |
| croc, interop (T-694) | `crates/podssh-relay/tests/croc_interop.rs` | `croc-interop.yml` | passed, run 42957326904 |
| croc, live (T-694) | `crates/podssh-relay/tests/croc_live.rs` | `croc-live.yml` | passed, run 42957736151 |

Each has a planted run that must fail, and each did, for the reason that the entry names.

## Each partial entry, and its next step

| Entry | Next step |
| --- | --- |
| T-746 | The datagram test of `pipe` (`podssh-cli --lib`) failed once in the build image with its echo missing; its next failure says the program's verdict. OpenTunnel's resume test is repaired (macOS passed at `bc5107b0`). |
| T-465, T-627 | Each `## Done` names the failure that it waits for. |
| T-694 | `podssh doctor`'s line of croc's bridge (the section `carriers` holds Q65's carriers alone; a probe that carries nothing of the user's), and the node roads of `--derp` and of the Piping Server road. |
| T-548 | The Prove's containers (T-251) and a proxy that ends TLS on the client's side. |
| T-565, T-568, T-569 | Off until `pod-services` names their servers (#186). |
| T-574 | Q90's live check of the nodes, Xray-core in a container, `release-short.sh`'s check. |
| T-684 | Each next podcrates release that podssh takes. |
| T-446 | Betas wait for the end of the migration (T-684). |
| Each other partial entry | T-319, T-321, T-450, T-459, T-660, T-662, T-665, T-666, T-670 and T-698: each `## Done` names what waits. |

Blocked, each on the owner or on another party, as its `## Blocker` names: T-328, T-376, T-672,
T-687, T-711, T-719, T-722, T-727 and T-729. cfb's asks, T-708 to T-731, stay behind podssh's own work
order (the owner's ruling "Priority", 2026-11-09).

## The work order after these

`TODO/PROGRESS.md`, section "Work order": M10's item 4 and its open features: T-733 ZeroTier, T-734 Tox,
T-735 Yggdrasil, T-736 HyperDHT, T-737 MQTT as a meeting point, T-738 file hosts, T-739 VMess, T-740 Bare
servers, T-741 smee.io, T-742 hostc, T-743 Sandhole. Then T-566, T-567, T-571, T-575, T-576 and T-578 to
T-582.

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
- **A cloud session's proxy** passes HTTPS alone: raw SSH and other ports go through GitHub Actions.
- **Pushes:** each push queues a gate on the runners; batch the record's commits.
