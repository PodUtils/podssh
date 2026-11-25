# Progress

The current state, tonight's queue, the measured baseline, and the only work order. A closed entry
keeps its proof in the entry, and `docs/HANDOFF.md` holds the facts that change from day to day;
this page keeps no history (git does).

## State

Read on 2026-11-24.

1. **The gate.** Green at `dd1f9a9` (2026-11-24, run 45413276289, each job). At `25ac08f` it was red on Windows and
   macOS; T-897 repaired it. Commits after `dd1f9a9`: `1d5070b`, `59778bd`, `96a8897`. Read the gate of the last push
   first: a push cancels the gate of the one before it. Earlier green runs are in `docs/STATUS.md`.
2. **Releases.** The newest beta is `v1.1.0-beta.3` (2026-11-05, at `6d30328`); the newest stable is `v1.0.1`
   (2026-11-03, at `6ece1f9`). The next beta waits until podssh is nearly complete and the black-box pass of T-809 is
   clean (the operator, 2026-11-11), under the rules of `AGENTS.md` ("Releases"); `v1.1.0` waits for the end of the
   migration (T-446, T-684). podssh stays a beta until the owner calls it stable, and nothing goes to crates.io (T-687).
3. **The milestone** is M10 (Q63, `docs/mesh.md`). Its items 0 to 3 are done but for T-106 and T-898 (measurements); of item 4,
   T-738 is partial and T-740 blocked. M5's `podssh serve` is on `main` (Q92): commands, shells, a pty, direct-tcpip,
   SFTP, the options of a key line, `--listen`, kept shells, `--audit-log` and `--totp`.
4. **Partial entries** (each `## Done` names its next step). Tests that failed at random, each waiting for its next
   failure: T-465, T-627, T-753, T-756, T-779, T-780, T-788, T-796, T-846, T-849, T-858. M5's server, each waiting for
   its run in the build image (T-251): T-107 to T-112, T-114, T-117, T-118, T-222, T-248. Serve and sessions: T-123 (step 4, a listener on the node),
   T-831, T-834, T-836, T-837, T-839. The migration and the release: T-684, T-446, T-847 (the push to ghcr.io, the comparison and the
   attestation run at the next release tag). Roads and the mesh: T-106 (the operator's tailnet), T-598, T-660, T-666, T-670 (their rows of the matrix), T-710, T-718, T-720, T-738 (the run against
   `mia/0x0`), T-876 (COORD-139). Chores: T-791, T-793, T-809, T-820.
5. **Blocked entries** (each `## Blocker` names who must act): T-113 (M5's exit in the operator's real sandbox), T-328
   and T-376 (the operator's inputs), T-672 (a release of rustls), T-687 (the owner: stable first), T-899 (a tester's Dev Tunnel, #215), T-740 (a working Bare
   node, podcrates T-200), and cfb's T-711, T-719, T-722, T-727 and T-729.
6. **Issues and the sessions of PodUtils.** An issue from outside the team is changed by the sync only once it has the
   label `confirmed` (the owner's rulings "Strangers" and "Issues"). Each session writes to another by a COORD issue in
   its own repository only, never by a direct message (the owner, 2026-11-12). The open COORD issues and what each waits
   for are in `docs/HANDOFF.md`. cfb's asks, T-708 to T-731 (#195), wait behind podssh's own work order, M10 included
   (the owner's ruling "Priority").
7. **The move to PodUtils/podcrates** (T-684, Q101, Rule Q3). podssh pins each podcrates crate at `v0.82.1`
   (`docs/HANDOFF.md` lists them). Taken, so worked on in PodUtils/podcrates: `pod-todo`, `pod-term`, `pod-identity`,
   `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`, `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`,
   `pod-session`, `pod-e2e`, `pod-relay`, `pod-warp`, `pod-transit`, `pod-acme`, `pod-piping`, `pod-opentunnel`,
   `pod-derp`, `pod-egress`, `pod-tor`, `pod-iroh`, `pod-release` (`podssh update` runs on it) and `pod-cover`. podssh
   keeps glue over them: `resolve.rs`, and `via.rs`, `forwarder.rs`, `wstunnel.rs`, `wisp.rs`, `meek.rs`,
   `webtunnel.rs`, `pt.rs`, `cloudflare.rs`, `vless.rs`, `vmess.rs`, `trojan.rs`, `shadowsocks.rs`, `eice.rs` and
   `iap.rs` of `podssh-ws`; `code/`, `session/`, `src/e2e/`, `transit/mod.rs` and the relay client's modules over
   `context.rs` of `podssh-relay`; `acme/mod.rs` of `podssh-cli`. Nothing is frozen. Next, as podcrates names them:
   `pod-cloudflare` and `pod-ts`; then `pod-relay-serve` last. The plan (Q101, settled 2026-11-05 with podnet's
   session): each crate may link C and declares Rust 1.97 and edition 2024; podssh takes it by a git tag, not from
   crates.io; podssh's pure-Rust TLS provider and the RSA verifier stay behind a feature of `pod-tls`; `pod-relay`
   keeps the `blocking` facade for podvm; neither podssh's session nor podnet's edits podcrates.
8. **Drafts.** None waits (2026-11-25): `d-t877` (T-875 and T-877) is merged. Each `draft/*`, `beta/*` and `release/*`
   branch on GitHub that is already in `main` is deleted by the owner by hand (the git proxy of a cloud session refuses
   deletes).
9. **Lessons that still hold.** Read each failed job's log before calling a red gate the place's. Never commit while
   `scripts/plant-each.sh` runs (a plant is applied in the tree then). When the disk fills, remove `target/` whole,
   never files under it. Never amend a commit that was pushed, not even on a draft branch: the next push would be a
   force-push. A merge in progress waits on a local branch `merge-NNN`, never on `main`. Chain a push on
   `cargo todo check --base HEAD~1`'s own exit code, never a pipe's (`| tail` gives 0): commits went out with stale
   citations twice. Run the gate's `cargo fmt $PKGS --
   --check` and `cargo test --no-fail-fast` (a plain run stops at `job_far`'s known failures) before a push (a test's long line once turned lint red), and never `cargo fmt --all`, which formats
   `vendor/`.

## Tonight

Cloud sessions of 2026-11-24 and 2026-11-25. Done on 2026-11-25: T-839 done (TPM keys; Windows'
TBS case passed in the gate), T-896 done, T-875 and T-877 done (the DNS road; T-900, its form over DoH, waits for podcrates),
podcrates `v0.83.0` taken. Open, in order: the gate of the last push (lint was red at `0c6e9c4` on the format of
`attach_screen.rs` alone); T-161, T-123 and T-831 (partial); podcrates' answers to the COORD issues of
`docs/HANDOFF.md`; T-684's next takes; T-791, T-793 and T-809 before T-446 (**no beta until the black-box pass is
clean**).

## Baseline

Measured on 2026-11-24 in a Claude Code cloud container (Linux x86_64, Rust 1.99.1, `CARGO_BUILD_JOBS=4`):
`cargo test --workspace --no-fail-fast` ran 427 suites, 4272 passed, 3 failed. The 3 are `job_far` at the container's
stand-in of `rm`. `cargo todo check` and `python scripts/check-repo.py`: ok.

## Counts

`TODO/INDEX.md` holds 833 entries: 4 open, 45 partial, 13 blocked, 771 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit, then take the next
one. Each session runs unattended until the goal of `AGENTS.md` (section 2) is reached or the
operator interrupts it.

**The rules of the order**, first to last:

1. A red gate, then a test that fails at random (T-465, T-627, T-753, T-756, T-780, T-796), before any other work.
2. A `partial` entry before a new one, and a draft's merge in the order of "Drafts" (State, item 8). Each partial
   entry's `## Done` says what it waits for (State, item 4).
3. The migration's takes (T-684), as the podcrates session hands each crate over (Rule Q3 of `docs/decisions.md`:
   from the import, podssh changes that code for fixes only; after podssh takes the crate, the work is done in
   PodUtils/podcrates). Where a `## Correction` of 2026-11-05 says that the code of an entry is in a crate that podssh
   has taken, that change is made in PodUtils/podcrates, or asked there as an issue; the part of the entry that uses
   the crate stays podssh's.
4. The testers' defects, then their features (Q84, Q85): the defects first among the `none` entries, P1 before any
   other; their features (those which Q74, Q75, Q77, Q78 and Q82 filed) by priority, beside M10. Between entries: the
   `none` entries, the highest priority first, but for the testers'.
5. The entries that the studies of osewa filed (Q99, `docs/research/osewa.md`) go ahead of the rest of M10: T-660, T-670
   and T-666 (each waits for a run that its `## Done` names), then the open entries of GitHub #127 to #148 by their
   priority, beside M10 (Q85, Q100).
6. podssh's own order by priority beside M10's order below. cfb's asks stay behind podssh's own work order, M10
   included (the owner's ruling "Priority").
7. The holds are released (Q92): the entries of M5's `podssh serve` go by their priority after M10's entries of their
   priority; the work parked behind them ("Parked open work") starts as its condition says. T-328 (a real export of
   FinalShell and of Termius) and T-376 (the operator's throwaway cloud accounts for the live run of the roads of
   `iap://` and `eice://`) wait for inputs that only the operator has. T-672 (TLS tickets kept across runs) waits for a
   release of rustls that lets a client write one.
8. The next beta goes out when podssh is nearly complete (T-446; the operator, 2026-11-11). It waits for T-809 too
   (after podnet's QA round, PodUtils/podnet#649): error-path rows in the lane and a black-box pass with the
   documents alone, before any beta is called ready for testers. The findings of the first black-box pass are each
   fixed before the beta.

**M10**, the mesh and the relay in podssh (Q63 to Q66, `docs/mesh.md`), in this order (what is done is not listed):

0. A test that fails at random comes first.
1. The relay role: done; T-898 (the live runs of the HTTP and HTTP/2 roads: a real proxy's path and Apache's
   `H2WebSockets`, at the release check, Q88).
2. The net: T-106 (the live test of `podssh ts` with two nodes, on the operator's tailnet).
3. Exit, routes, share and funnel: done.
4. The public carriers of Q65 to Q78 and what their research filed: done but for T-738 (file hosts as the last carrier,
   partial), T-740 (Bare servers as a hop, blocked) and T-499 (parked). The DNS carrier (Q107) is done (2026-11-25); its form
   over DoH, T-900, waits for podcrates.
5. T-446: the next beta `v1.1.0-beta.N` when podssh is nearly complete, and `v1.1.0` at the end, once the migration is
   done.

## Parked open work

These entries stay open in the index. The condition in each entry tells when it can start.

| Entry | Start condition |
| --- | --- |
| T-161 | Started on 2026-11-25 from its draft (partial): the measures of steps 1 and 3, step 5, and the seats of `--share` are left |
| T-303 | T-110 is done: `podssh serve` has a pty; and T-161 has a model of the far end's screen |
| T-304 | T-303 is done: frames of the screen exist |
| T-499 | draft-ietf-httpbis-connect-tcp is an RFC, and a server over HTTP/2 or HTTP/1.1 implements it |
| T-875 | Q107 is settled (2026-11-24): it goes by its priority, beside M10 |
| T-877 | Q107 is settled (2026-11-24): it goes after T-875 |

## Questions for the operator

None is open. The rulings are in `docs/decisions.md`. Open entries name three settled questions:

- **Q41** (2026-10-30): T-292 uses export files that their programs wrote and that are published.
- **Q79** (2026-11-02): the repository names only the hosts that podssh uses.
- **Q92** (2026-11-03): the holds end; T-328 and T-376 wait for the operator's inputs alone.

## Operator actions

None blocks a session. What is the operator's:

- Inputs for T-328 (an export of FinalShell and of Termius) and T-376 (throwaway cloud accounts); the real sandbox
  for T-113 (a run of T-004 and T-005 with the brief of `scripts/sandbox-check.sh`); the owner's word that podssh is
  stable (T-687).
- At any time: require the status `all` of the workflow `build` for `main`, if a required check is wanted (T-212);
  `main` requires none today.
- Dependabot's updates reach `main` through a session (`docs/decisions.md`).
- Setting `PODSSH_THROUGHPUT_SSH` and `PODSSH_THROUGHPUT_KEY` adds an optional run on the real path of Q38; the
  netem lab on Actions measures in its place.
- The notes of `docs/relay-operator.md` for the operator of the default relay, at any time, with no entry waiting:
  podssh's own relay role does each since Q63.
