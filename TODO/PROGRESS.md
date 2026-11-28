# Progress

The current state, tonight's queue, the measured baseline, and the only work order. A closed entry
keeps its proof in the entry, and `docs/HANDOFF.md` holds the facts that change from day to day;
this page keeps no history (git does).

## State

Read on 2026-11-27.

1. **The gate.** On `72084ae` (2026-11-27, run 46068660337), 17 of 18 jobs passed (`windows`, `gate (lint)`, `gate (ts)`,
   `gate (release)`, `gate (iroh)`, `gate (ssh)`, and all interop/deny/secrets/issue-sync workflows); only `macos` failed
   on BSD `od -An -tx1` extra spaces in `serve_share_frames.rs`, fixed on `main` at `95c11c4`. Read the gate of this
   session's final push first (and `mqtt-interop.yml`'s new `filehost-0x0` job for T-738). Earlier green runs are in
   `docs/STATUS.md`.
2. **Releases.** The newest beta is `v1.1.0-beta.3` (2026-11-05, at `6d30328`); the newest stable is `v1.0.1`
   (2026-11-03, at `6ece1f9`). The next beta waits until podssh is nearly complete and the black-box pass of T-809 is
   clean (the operator, 2026-11-11), under the rules of `AGENTS.md` ("Releases"); `v1.1.0` waits for the end of the
   migration (T-446, T-684). podssh stays a beta until the owner calls it stable, and nothing goes to crates.io (T-687).
3. **The milestone** is M10 (Q63, `docs/mesh.md`). Its items 0 to 3 are done but for T-106 and T-898 (measurements); of item 4,
   T-738 is partial (harness and plant merged, awaiting `mqtt-interop.yml` on GitHub Actions) and T-740 blocked. M5's `podssh serve`
   is on `main` (Q92): commands, shells, a pty, direct-tcpip, SFTP, the options of a key line, `--listen`, kept shells,
   `--audit-log` and `--totp`. T-303 (screen frames on request, items a to h) and T-720 (relay role iroh/DERP + net discovery)
   are closed `done`.
4. **Partial entries** (31 total; each `## Done` names its next step). Tests that failed at random, each waiting for its next
   failure or clean streak: T-779 (5 more clean runs of `scripts/m5-in-sandbox.sh`), T-796, T-849, T-858. M5's server, each
   waiting for its run in the build image (T-251) or operator real sandbox: T-107 to T-112, T-114, T-117, T-118, T-222, T-248.
   The migration and the release: T-684, T-446, T-847 (the push to ghcr.io, the comparison and the attestation run at the next
   release tag). Roads, pace and the mesh: T-106 (the operator's tailnet), T-598, T-660, T-666, T-670 (far-link ping cap and
   relay forward 16 KiB merged; awaits `feel-netem.yml` re-run and COORD-156 #369 8 KiB chunking in podcrates), T-710, T-718
   (all local work done; only live Cloudflare Access account waits on the operator), T-738 (awaits `mqtt-interop.yml`
   `filehost-0x0` job), T-876 (COORD-139). Chores: T-791, T-793, T-809, T-820 (`node_install/` moved onto `pod-unit` at
   `ccc5a72`; remaining items await podcrates).
5. **Blocked entries** (14 total; each `## Blocker` names who must act): T-113 (M5's exit in the operator's real sandbox), T-328
   and T-376 (the operator's inputs), T-672 (a release of rustls), T-687 (the owner: stable first), T-899 (a tester's Dev Tunnel,
   #215), T-740 (a working Bare node, podcrates T-200), T-967 (operator ruling on former release signer; `Source::former` ready in
   `v0.86.0`), T-1021 (operator ruling on public last fallbacks for user's own relay), and cfb's T-711, T-719, T-722, T-727 and T-729.
6. **Issues and the sessions of PodUtils.** An issue from outside the team is changed by the sync only once it has the
   label `confirmed` (the owner's rulings "Strangers" and "Issues"). Each session writes to another by a COORD issue in
   its own repository only, never by a direct message (the owner, 2026-11-12). The open COORD issues (#349, #357, #358, #363,
   #368, #369) and what each waits for are in `docs/HANDOFF.md`. cfb's asks, T-708 to T-731 (#195), wait behind podssh's own work
   order, M10 included (the owner's ruling "Priority"). Dependabot PRs #364 (`peeroxide 1.8.1`), #365 (`trufflehog 3.100.0`), and
   #366 (`taiki-e/install-action 2.90.8`) remain open for the next session.
7. **The move to PodUtils/podcrates** (T-684, Q101, Rule Q3). podssh pins each podcrates crate at `v0.86.0` (`22d1a75`, taken at
   `72084ae`; `docs/HANDOFF.md` lists them). Taken, so worked on in PodUtils/podcrates: `pod-todo`, `pod-term`, `pod-identity`,
   `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`, `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`,
   `pod-session`, `pod-e2e`, `pod-relay`, `pod-warp`, `pod-transit`, `pod-acme`, `pod-piping`, `pod-opentunnel`,
   `pod-derp`, `pod-egress`, `pod-tor`, `pod-iroh`, `pod-release` (`podssh update` runs on it), `pod-cover`, `pod-h2`
   (the fork of h2 that podssh vendored), `pod-unit` (`node_install/` moved at `ccc5a72`) and `pod-tpm` (the codec of
   `crates/podssh-ssh/src/tpm/`). podssh keeps glue over them: `resolve.rs`, and `via.rs`, `forwarder.rs`, `wstunnel.rs`,
   `wisp.rs`, `meek.rs`, `webtunnel.rs`, `pt.rs`, `cloudflare.rs`, `vless.rs`, `vmess.rs`, `trojan.rs`, `shadowsocks.rs`,
   `eice.rs` and `iap.rs` of `podssh-ws`; `code/`, `session/`, `src/e2e/`, `transit/mod.rs` and the relay client's modules over
   `context.rs` of `podssh-relay`; `acme/mod.rs` and `node_install/` of `podssh-cli`; `tpm/` of `podssh-ssh` (the probe, the
   forms of SSH, the policy key, the agent's and serve's keys, the storage key kept at `0x81000001`, and Windows' TBS with its
   bound and cancel, which `pod-tpm`'s `tbs` lacks). Nothing is frozen. Next, as podcrates names them: `pod-cloudflare` and
   `pod-ts`; then `pod-relay-serve` last. The plan (Q101, settled 2026-11-05 with podnet's session): each crate may link C and
   declares Rust 1.97 and edition 2024; podssh takes it by a git tag, not from crates.io; podssh's pure-Rust TLS provider and the
   RSA verifier stay behind a feature of `pod-tls`; `pod-relay` keeps the `blocking` facade for podvm; neither podssh's session
   nor podnet's edits podcrates.
8. **Drafts and workers** (the ruling "Lead and workers", `docs/hosted-sessions.md`). **None waiting** (2026-11-27): all
   previous `wip/*` branches (`wip/t303-b-shared-frames`, `wip/qa10-t1057-t1064`, `wip/qa10-t1065-t1072`) and all five local
   worker branches (`t820`, `t670-pace`, `t720-iroh-net`, `t303-plant`, `t718-access-exit`, `t738-0x0`) are merged, verified,
   and their local worktrees removed. Each `draft/*`, `wip/*`, `beta/*` and `release/*` branch on GitHub that is already in `main`
   is deleted by the owner by hand (the git proxy of a cloud session refuses deletes).
9. **Lessons that still hold.** Read each failed job's log before calling a red gate the place's. Never commit while
   `scripts/plant-each.sh` runs (a plant is applied in the tree then). When the disk fills, remove `target/` whole,
   never files under it (it reached 46 GB on 2026-11-25). Never amend a commit that was pushed, not even on a draft
   branch. A merge in progress waits on a local branch `merge-NNN`, never on `main`. Push through a guard that runs
   `cargo todo check --base HEAD~1`, `python scripts/check-repo.py` and the gate's `cargo fmt $PKGS -- --check`, each by
   its own exit code (a pipe's `| tail` gives 0: stale citations went out twice); never `cargo fmt --all`, which formats
   `vendor/`. Run a package's tests with `--no-fail-fast`: a plain run stops at `job_far`'s three known failures on hosts with an
   `rm` guard (Antigravity VMs carry real `/usr/bin/rm` and pass all 11 `job_far` tests). A test that dials a closed port dials
   port 1, never a port it freed (T-904).

## Tonight

The session of 2026-11-27 (Antigravity Linux x86_64, Rust 1.99.0), lead with parallel drafting workers. Done and verified on
`main`: T-303 (b) shared-shell frames (`0f336a5`), macOS BSD `od` fix for `serve_share_frames` (`95c11c4`), T-303 (f) Mosh 1.4.0
reference (320.1 ms median of 5), (g) 3 planted defects caught, and (h) OpenSSH control master fallback, **closing T-303**
(`dec781f`); `PodUtils/podcrates#263` COORD-157 `docs/hosted-sessions.md` alignment (`412cad1`); QA10 batches A and B
(T-1057 to T-1072 closed, `cc1ae69` and `0184f95`); `PodUtils/podcrates v0.86.0` take (`72084ae`, closing T-905, T-975, and
COORDs #359–#362 and #367, removing 6 duplicate glue layers); T-820 `node_install/` moved onto `pod-unit` (`ccc5a72`); T-670
`podssh ping` road window cap + 16 KiB relay serve downlink read cap (`c4f5b8f`); T-720 end-to-end net iroh relay discovery test
and QAD Decision, **closing T-720** (`857e7f7`); T-718 Access refusal exit 77 and `RestartPreventExitStatus=64 77 78` via
`pod-unit` (`7cb5678`); T-738 `mia/0x0` interop harness, tests, plant, and `mqtt-interop.yml` job (`e87a8f9`); COORD-156 (#369)
opened `(to podcrates)`.

Next session, in order: (1) check the CI `build` run and `mqtt-interop.yml` `filehost-0x0` job on this push (close T-738 once
`filehost-0x0` is green; repair any red job first); (2) dispatch `feel-netem.yml` (`T-660`/`T-666`/`T-670` `far` typing rate)
and `box.yml` (`T-248`); (3) handle Dependabot PRs #365 (`trufflehog 3.100.0`), #366 (`taiki-e/install-action 2.90.8`), and #364
(`peeroxide 1.8.1`, verify `--features hyperdht`); (4) run T-779's 5 clean `scripts/m5-in-sandbox.sh` runs and T-248's local
Prove; (5) check for any new `PodUtils/podcrates` tag answering #349/#357/#358/#363/#368/#369 and evaluate newly unparked T-304
(`pod-iroh` QUIC datagrams). **No beta until T-684 and T-809's black-box pass are clean.**

## Baseline

Measured on 2026-11-27 on Antigravity Linux x86_64 (2 vCPUs, 7.8 GiB RAM, Rust 1.99.0, `CARGO_BUILD_JOBS=2`, real `/usr/bin/rm`,
Docker, `mosh` 1.4.0, `mosquitto` 2.0.18): targeted test suites, clippy (`-D warnings -A clippy::collapsible_if`), `cargo fmt`,
`cargo todo check` (1003 entries: 3 open, 31 partial, 14 blocked, 955 done), and `python3 scripts/check-repo.py` all green on
`main`. On `72084ae`, CI `build` (`46068660337`) passed 17 of 18 jobs (including `windows` and all Linux gates) plus all interop,
deny, secrets, and issue-sync workflows; the lone `macos` failure (`serve_share_frames.rs` BSD `od` spacing) is fixed at
`95c11c4`.

## Counts

`TODO/INDEX.md` holds 1003 entries: 3 open, 31 partial, 14 blocked, 955 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit, then take the next
one. Each session runs unattended until the goal of `AGENTS.md` (section 2) is reached or the
operator interrupts it.

**The rules of the order**, first to last:

1. A red gate, then a test that fails at random (T-796), before any other work.
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
   partial), T-740 (Bare servers as a hop, blocked) and T-499 (parked). The DNS carrier (Q107) and its form over DNS over HTTPS
   are done (2026-11-25).
5. T-446: the next beta `v1.1.0-beta.N` when podssh is nearly complete, and `v1.1.0` at the end, once the migration is
   done.

## Parked open work

These entries stay open in the index. The condition in each entry tells when it can start.

| Entry | Start condition |
| --- | --- |
| T-304 | Unparked (T-303 closed 2026-11-27); note `pod-iroh` moved to `PodUtils/podcrates` (Rule Q3) |
| T-499 | draft-ietf-httpbis-connect-tcp is an RFC, and a server over HTTP/2 or HTTP/1.1 implements it |

## Questions for the operator

Two are open (2026-11-27):

- **T-967, the former signer of the releases.** `podssh update --version TAG` installs no release made before the
  repository moved: each was signed by the release workflow under the repository's former name, and T-683's ruling
  allows no second signer. Should this build accept that one former identity for the tags through `v1.1.0-beta.3`
  only, with the files still fetched from PodUtils/podssh? Recommendation: yes; `pod-release`'s `Source::former`
  mechanism is already in `v0.86.0` (COORD-153). Until a ruling, `update` gives a true line with the download page
  (T-967 stays blocked on it).

- **T-1021, a node at the user's own relay and the public last fallbacks.** A node whose pair is at the user's own
  relay (`PODSSH_RELAY` or `--relay-host` naming a relay that is not the default deployment) also waits, unasked, at
  the public last fallbacks of Q65, Q77 and Q78 (the transit relay, croc, smee.io). Should such a node keep its
  sessions at the user's relay by default, those fallbacks off unless `PODSSH_LAST_RESORT=yes`? Recommendation: yes;
  the user chose where the bytes go. Until a ruling, the node names each public road it waits on, with its off switch.

The rulings are in `docs/decisions.md`. Open entries name three settled questions:

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
