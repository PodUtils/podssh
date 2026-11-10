# Hand-off

The state of podssh at the owner's pause of 2026-11-10, for a session with no memory of this one.
Read `AGENTS.md` first. This page adds the facts that change from day to day: where `main` stands,
what each open thread waits for, and the exact next step of each. `TODO/PROGRESS.md` stays the work
order, and each entry's `## Done` stays its own record. Where this page and an entry disagree, the
entry is right.

## The state of `main`

- `main` holds each change of this session, every one pushed. No branch, worktree or stash holds
  unmerged work.
- `draft/draft-f1`, `draft/draft-f3`, `draft/draft-g1` to `draft/draft-g3` and `draft/t465-wait` are on
  GitHub. Each is merged, and each can go. The cloud session's git proxy refused the deletes, so the owner deletes
  them.
- The record agrees (`cargo todo check`), and `python scripts/check-repo.py` passes.
- The tests of `podssh-cli`, `podssh-relay` and `podssh-ws` pass natively. Run them in a network
  namespace with the loopback alone, so that a test that reaches a third party fails (see "How to
  test" below): 3,439 passed at `111e9e50`. The one test that needs the network there is
  `doctor_upgrade`, as `podssh doctor` probes the host's network by design.
- The gate (`build.yml`), at the last commit read (`525f8907`, run 42843751348): each Linux job
  passed, `gate (release)` with the static musl binary among them. Two jobs failed, and both are
  repaired on `main` (T-744):
  - `windows`: croc's stand-in reset a socket.
  - `macos`: an OpenSSH test failed once with no words.

  The next gate's `windows` and `macos` jobs are the check of those repairs.

## Each podcrates take

podssh pins every podcrates crate at `tag = "v0.14.0"`.

- **Taken:**
  - `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`,
    `pod-dns` and `pod-services`.
  - `pod-ws` (`a083593e`, COORD-017).
  - `pod-quic` (`525f8907`, COORD-018).
- **Pending, in podcrates v0.15.0** (being tagged at the pause; its hand-off issue in
  PodUtils/podcrates follows): `pod-wormhole` (podcrates T-022:
  `crates/podssh-relay/src/code/`, its exchange going to `pod-relay`) and `pod-session` (podcrates
  T-020: `crates/podssh-relay/src/session/`).
  - **Both directories are frozen:** they take fixes only, each told to podcrates as a COORD issue
    `(to podcrates)`. A feature that needs a change there keeps it out, or asks it of podcrates, as
    T-568 did.
  - **To take a tag:** follow its hand-off issue in PodUtils/podcrates. Apply
    `adoption/podssh/CRATE.patch` with `git apply --3way`, and run each line of
    `adoption/podssh/CRATE.run` with `cargo +1.99`. Then run the full suite in the namespace, commit,
    push, and write the take as a COORD issue. When podcrates has recorded it, close the issue, with
    the gate's static build on the commit.

## Open COORD issues

- #186 (COORD-019): `pod-services` for localhost.run, localtunnel and bore, and `Rewound::new` in
  `pod-session`. podcrates holds them as its T-171 (the services, each fact read again at its source)
  and T-172 (`Rewound::new`), both for its next session, after the pause. When a tag names a service, its road turns on by default: then make its short live
  run (Q91), and remove the private `Replay` of `crates/podssh-relay/src/localtunnel/route.rs` once
  `pod-session` has `Rewound::new`.
- #177 (COORD-010): the public proxy lists and nodes are in `v0.10.0` and taken. It stays open for
  T-574's live check of the nodes (Q90). Write its result there.
- #174 and #176 (COORD-007, COORD-009): older takes. Close each once podcrates has recorded it.

## Each partial entry, and its next step

The first three are the defects of tests that fail at random. They come first (AGENTS.md, section
6, item 1).

| Entry | What waits, and the next step |
| --- | --- |
| T-744 | Read the next gate's `windows` and `macos` jobs. Close the entry if croc's test passes on Windows and `relay_serve` passes on macOS; if `relay_serve` fails again, its words now name ssh's status. The funnel's Python test on macOS: its next failure says why Python did not start. |
| T-465 | The next failure of `pipe`'s `unix-connect` test on Windows or macOS says, by its count of reads that timed out, whether the platform lost the end or never queued it. |
| T-627 | Its `## Done` names its next run. |
| T-548 Pinggy | The containers of the Prove (T-251) and a proxy that ends TLS on the client's side. It passed live through Pinggy itself (run 42743438927). |
| T-549 Serveo, T-570 ssh-j, T-694 croc | Their servers are in `pod-services` v0.14.0, so each road is on. Next: the short live run of each (Q91), and for croc the run against `croc relay` and `croc-web` on a runner, which is its true interop check. |
| T-565 localhost.run, T-568 localtunnel, T-569 bore | Off until `pod-services` names their servers (#186). Then their short live runs. localtunnel's and bore's tunnel ports are raw TCP: their roads do not help a host with 443 alone, and their entries say so. |
| T-574 | Q90's live check of the nodes before a release, Xray-core in a container, and `release-short.sh`'s check. |
| T-684 | The takes of `pod-wormhole` and `pod-session` (v0.15.0). |
| T-446 | Betas wait for the end of the migration (T-684); no release until then. |
| Each other partial entry | T-319, T-321, T-450, T-459, T-660, T-662, T-665, T-666, T-670 and T-698: each `## Done` names what waits. |

Blocked, each on the owner or on another party, as its `## Blocker` names: T-328, T-376, T-672,
T-687, T-711, T-719, T-722, T-727 and T-729. cfb's asks, T-708 to T-731, stay parked behind
podssh's own work order (the owner's ruling "Priority", 2026-11-09).

## The work order after these

`TODO/PROGRESS.md`, section "Work order": M10's item 4 continues with the open features that the
research filed. Each research entry of item 4 is done (2026-11-10). Its features: T-733 ZeroTier,
T-734 Tox, T-735 Yggdrasil, T-736 HyperDHT, T-737 MQTT as a meeting point, T-738 file hosts, T-739
VMess, T-740 Bare servers, T-741 smee.io, T-742 hostc, T-743 Sandhole (a host of T-565's module).
Then T-566, T-567, T-571, T-575, T-576 and T-578 to T-582.

## How to test

- **Builds:** `CARGO_BUILD_JOBS=4`, one build at a time, `cargo +1.99`. On a small disk, add
  `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  CARGO_PROFILE_TEST_DEBUG=line-tables-only`. When the disk fills, remove `target/`.
- **No third party:** `pod-services` turns several last fallbacks on by default, and a test must
  never reach a third party. Build with the network, then run in a namespace with the loopback
  alone. The loopback must be brought up, or UDP to it fails: `ip link set lo up` where `ip` is
  installed, or a few lines of Python's `SIOCSIFFLAGS` ioctl, then exec the command.

  ```sh
  cargo +1.99 test -q --no-run -p podssh-cli -p podssh-relay -p podssh-ws
  unshare -n sh -c 'ip link set lo up && cargo +1.99 test -q --offline --no-fail-fast -p podssh-cli -p podssh-relay -p podssh-ws'
  ```

- **New roads:** each harness of another road turns each last fallback off (`PODSSH_SERVEO=no`,
  `PODSSH_SSH_J=no`, `PODSSH_CROC=no`, `PODSSH_LOCALHOST_RUN=no`, `PODSSH_LOCALTUNNEL=no`,
  `PODSSH_BORE=no`). A new road adds its own switch to each of them.
- **Merging drafts:** drafts of agents that build nothing are merged one at a time by a session that
  builds (AGENTS.md, "Drafting agents"). Several drafts of one week each made the same shared files:
  merge them into one module (`crates/podssh-cli/src/ssh/road_last.rs` holds every last road), and
  take main's side of each citation conflict before `cargo todo remap`.
