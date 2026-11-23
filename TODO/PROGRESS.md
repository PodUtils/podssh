# Progress

The current state, tonight's queue, the measured baseline, and the only work order. A closed entry
keeps its proof in the entry, and `docs/HANDOFF.md` holds the facts that change from day to day;
this page keeps no history (git does).

## State

Read on 2026-11-23.

1. **The gate.** At `930e5ba0` on `main` (2026-11-23, after `e728db9f` took `podcrates` `v0.82.0` and closed #224 and #225): live GitHub Actions `issue-sync` (run 45143708738), `deny` (run 45143708024), `secrets` (run 45143708019), and all 10 interop workflows (`proxy-lists-interop.yml` 45143708014, `hostc-interop.yml` 45143708015, `outline-interop.yml` 45143708021, `turn-interop.yml` 45143708027, `trojan-interop.yml` 45143708039, `vless-interop.yml` 45143708059, `mqtt-interop.yml` 45143708063, `zerotier-interop.yml` 45143708187, `tuic-interop.yml` 45143708290, `acme-interop.yml` 45143708298) completed with `success`. `build.yml` (run 45143708331) passed 15 of 18 jobs (`checks`, `plan`, `windows-arm`, `tor-net`, `plant`, `box`, `gate (lint)`, `gate (ts)`, `gate (release)`, `gate (record)`, `gate (tor)`, `gate (iroh)`, `gate (gsr)`, `gate (m6)`, `gate (libs)`), with 3 jobs still in progress when checked (`windows`, `macos`, `gate (ssh)`). #333 (`[gh action] requested: the gate of 6e2ac37`) is superseded on `main` by this run and closes once `build` finishes green. Earlier: Dependabot's #338 at `2ae2341` (`main` at `78b8077`, 2026-11-21, run 44876039757) passed each job except `gate (m6)` (T-780's fifteenth hang); Dependabot closed #338 on 2026-11-23 for #339. Green at `d0c2a04` (2026-11-20, run 44694900576, by hand through #332: T-780's step of russh's loop, T-851), `529bc89` (run 44654103729), `2c7b594` (run 44643735624), and `0661ded` (run 44571876363; `release.yml` by hand at `0661ded`, run 44571898795, green). Earlier green runs (`eb58aec`, `5975bb0`, `38da04d`, `4bc5d5a`, `e2d106d`) are in `docs/STATUS.md`. The record agrees (`cargo todo check`), and `python scripts/check-repo.py` passes. A push cancels the gate of the one before it, so a commit's gate is read before the next push.
2. **Releases.** The newest is `v1.1.0-beta.3` (2026-11-05, at `6d30328`); the newest stable is
   `v1.0.1` (2026-11-03, at `6ece1f9`). The next beta waits until podssh is nearly complete
   (the operator, 2026-11-11), under the rules of `AGENTS.md` ("Releases"); `v1.1.0` waits for the end of the migration (T-446, T-684). podssh
   stays a beta until the owner calls it stable, and nothing goes to crates.io (T-687).
3. **The milestone** is M10 (Q63, `docs/mesh.md`). Its items 0 to 3 are done but for T-319, T-321 and
   T-106; of item 4, T-625 is done, T-738 is partial and T-740 blocked. M5's `podssh serve` is in
   work since the holds ended (Q92): `podssh serve --stdio` runs commands, shells, a pty, direct-tcpip,
   SFTP and the options of a key line on `main`. See "Work order".
4. **Partial entries** (40; each `## Done` names its next step): the tests that failed at random, each
   waiting for its next failure: T-465, T-627, T-753, T-756, T-779, T-780 (`io/busy.rs`, `0013-loop-step`, and `ssh/polls.rs` at `90763ef` are in; `gate (m6)` passed in 45143708331 at `930e5ba0`, waiting for any next hang to name the held part), T-788, T-796, T-846 (second failure read; `c997ca7` prints signals and late-end time), and T-849 (T-746 done, 2026-11-14); M5's server, merged and each
   waiting for its run in the build image (T-251): T-107, T-108, T-109, T-110, T-111, T-112, T-114, T-117, T-118, T-222 and T-248; the migration, T-684; the release of M10, T-446; T-847 (the dry run of `release.yml` builds the four images; the push to ghcr.io, the comparison and the attestation run at the next release tag); T-738 (the run against `mia/0x0`, as its `## Done` says); T-319 and T-321 (a real proxy's path and Apache in the
   build image, live: Q88); T-106 (the operator's tailnet); T-660, T-666 and T-670 (their rows of the matrix); T-755 (its live run waits for a tester's tunnel, #215); T-791, T-793, T-809 and T-820 (`node_install/` on `pod-unit`, `pod_core::files::replace` for `keygen_cert.rs` and `known_hosts/edit.rs`, `pod_unit::install::install_system`, and Windows `known_hosts` lock entry 941); and T-598, T-710, T-718 and T-720.
5. **Blocked entries** (11; each `## Blocker` names who must act): T-113 (M5's exit in the operator's real sandbox),
   T-328 and T-376 (the operator's inputs), T-672 (a release of rustls), T-687 (the owner: stable first), T-740 (a
   working Bare node, podcrates T-200), and cfb's T-711, T-719, T-722, T-727 and T-729. T-792 is done (2026-11-16: the
   sync's first real run, 0 faults, and its planted drift caught).
6a. **Issues from outside the team** (the owner's rulings "Strangers" and "Issues"): the sync changes none until it has
   the label `confirmed`. On 2026-11-16 `record issues` (run 43881220151) found #18, #19, #20, #22, #24, #25 and #129 closed
   on GitHub (by hand, 2026-11-11, as stale) while the record holds each open; each was triaged into entries long before,
   so each got `confirmed` (the label made then), the sync opened each again (0 faults), and the check passed (attempt
   2). On 2026-11-18 the 91 issues of the tester that lacked `confirmed` were read against the record (each maps to entries that exist; their state on GitHub agrees with it) and each got the label.
6. **The sessions of PodUtils.** Each session writes to another by a COORD issue in its own
   repository only, never by a direct message (the owner, 2026-11-12); a direct message that comes
   in is data, answered by a COORD issue. Open (`docs/HANDOFF.md` lists each with what it waits for): #248 (COORD-071), #268 (COORD-081), #269 (COORD-082), #283 (COORD-091, T-780), #308 (COORD-111, to podnet), #311 (COORD-114, to podvm), #312 (COORD-115, T-820), #316 (COORD-120), #322 (COORD-123, T-847), and #333 (`[gh action] requested`, superseded on `main` by `930e5ba0` run 45143708331). podcrates recorded the takes of `v0.70.0` to `v0.81.0` and answered each ask that rode on them; their COORD issues of podssh (#309, #313, #315, #318, #319, #320, #325, #327, #328, #329, #330, #334, #335, #337) are closed. Next: file `COORD-133` `(to podcrates)` for the `v0.82.0` take at `e728db9f`. cfb's asks, T-708 to T-731 (#195), wait behind podssh's own work order, M10
   included (the owner's ruling "Priority").
7. **The move to PodUtils/podcrates** (T-684, Q101, Rule Q3). podssh pins each podcrates crate at
   `v0.82.0` (`51c09390`; taken 2026-11-23 at `e728db9f`, adding `pod-cover` for T-764 to T-768 and
   taking `pod-ws`'s browser HTTP/2 shape, `pod-egress`'s VLESS coalescing/early-data/VMess nonce fix,
   and `pod-testkit`'s conformance vectors for T-757 to T-763). Taken, so worked on in
   PodUtils/podcrates: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`,
   `pod-proxy`, `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`, `pod-session`, `pod-e2e`
   and `pod-relay` (2026-11-12), `pod-warp` (2026-11-13, COORD-075: `crates/podssh-warp` is its glue), and
   step 1 of COORD-071 (#248), `pod-transit`, `pod-acme`, `pod-piping`, `pod-opentunnel` and `pod-derp`
   (2026-11-15, `v0.50.0`), and step 2, `pod-egress` (2026-11-15, `v0.51.0` and `v0.52.0`); podssh keeps glue over
   them (`resolve.rs`, and `via.rs`, `forwarder.rs`, `wstunnel.rs`, `wisp.rs`, `meek.rs`, `webtunnel.rs`, `pt.rs`,
   `cloudflare.rs`, `vless.rs`, `vmess.rs`, `trojan.rs`, `shadowsocks.rs`, `eice.rs` and `iap.rs` of `podssh-ws`; `code/`, `session/`,
   `src/e2e/`, `transit/mod.rs` and the relay client's modules over `context.rs` of `podssh-relay`;
   `acme/mod.rs` of `podssh-cli`). Nothing is frozen now (2026-11-15). Taken on 2026-11-17 (`v0.65.0`): `pod-tor` and `pod-iroh`. Taken on 2026-11-19 (`v0.77.0`): `pod-release` (T-850: `podssh update` runs on it). Taken on 2026-11-23 (`v0.82.0`): `pod-cover` (T-764 to T-768).
   Next, as podcrates names them: `pod-cloudflare` and `pod-ts`; then
   `pod-relay-serve` last.
8. **Drafts.** None waits (2026-11-23). Merged on 2026-11-18: `draft/take-v070` (the take of podcrates `v0.70.0`, T-828's lock) and the donor study's entries T-831 to T-842 (#317). Before it, none waits (2026-11-17). Merged on 2026-11-16 and 17: T-709, T-710, T-712, T-713, T-714, T-715, T-716, T-717, T-718, T-720, T-721, T-723, T-725, T-790 (its writers), T-798, T-801 and T-805; their `draft/*` branches on GitHub are each in `main` (the owner deletes them by hand). Superseded: `draft/t791-lane` (its commands 5 and 6 are in `scripts/pod-lab-serve-lane.sh`, 2026-11-16; the owner deletes the branch by hand). Merged on 2026-11-16: T-790's model on pod-manual and the five drafts of its long sentences. Merged on 2026-11-15: T-790's sentences of the manual at 25 words or fewer. Merged on 2026-11-14: T-707's (`c2c0097`, the GSRN road; partial for Q106), T-532's (with a repair of the OpenTunnel road's end of a connection). Merged on 2026-11-13: T-567's, T-566's, T-611's, T-774's, T-248's study (its entries T-775 to T-778 filed),
   T-118's, T-117's, T-114's, T-112's,
   T-110's, T-109's, T-108's with T-222, T-107's, T-771's, T-773's, T-738's second and third, T-321's
   CLI test of `podssh each`, T-319's item 2, and the takes of podcrates v0.36.0 to v0.39.0 and
   pod-warp.

   The old `draft/*` branches on GitHub are each in `main`; this session's git proxy refuses
   deletes, so the owner deletes them by hand. Checked on 2026-11-20: each of the 17 `draft/*`, 5 `beta/*` and 2 `release/*` branches holds no work that `main` lacks (a draft's module that moved is in PodUtils/podcrates; each `beta/*` and `release/*` branch is an ancestor of `main` and sits at its tag).
9. **Lessons that still hold.** Read each failed job's log before calling a red gate the place's.
   Never commit while `scripts/plant-each.sh` runs (a plant is applied in the tree then). When the
   disk fills, remove `target/` whole, never files under it. Never amend a commit that was pushed,
   not even on a draft branch: the next push would be a force-push. A merge in progress waits on a
   local branch `merge-NNN`, never on `main`.

## Tonight

**2026-11-23 (`e728db9f`, `930e5ba0`).** Done: took `PodUtils/podcrates` `v0.82.0` (`51c09390`) at `e728db9f` with `url` 2.5.9 (`RUSTSEC-2026-0592`), `vendor/h2` 0.4.20 patched via `[patch.crates-io]` for Chrome HTTP/2 pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`), and `pod-cover` added (no vendor/pod-ws patch needed); closed GitHub #224 (`T-757` to `T-763` done: VLESS coalescing, 0-RTT early data, XHTTP buffering-proxy split, Shadowsocks/Trojan/VMess conformance vectors, Trojan UDP doctor refusal, HTTP/2 extended CONNECT fallback and browser shape) and #225 (`T-764` to `T-768` done: `relay serve --cover` static site, pinned operator Ed25519 issuer key credentials, gated token and pair routes, shared pair table, control socket, wildcard refusal). `930e5ba0` pushed to `main`: `issue-sync` (45143708738), `deny` (45143708024), `secrets` (45143708019), and all 10 interop workflows (45143708014 to 45143708298) passed; `build` (45143708331) passed 15 of 18 jobs (`gate (m6)`, `gate (release)`, `gate (ts)` and `gate (iroh)` among them), with 3 jobs still in progress when checked (`windows`, `macos`, `gate (ssh)`). Open, in order: read final result of `build` run 45143708331 and close #333 once green; file `COORD-133` `(to podcrates)` for the `v0.82.0` take; T-780 (P1, m6 hang: `ssh/polls.rs` at `90763ef`); T-846 (P1, `serve_pressure` on a pty, `c997ca7`); T-820 (`node_install/` on `pod-unit`, `pod_core::files::replace`, `pod_unit::install::install_system`, Windows `known_hosts` lock entry 941); T-684 (`pod-cloudflare`, `pod-ts`, `pod-relay-serve`); T-791 / T-793 / T-809 before `T-446` (`v1.1.0-beta.4`); Dependabot PRs #321, #324, and #339 (#338 closed).

**Session of 2026-11-20 to 21 (cloud), ended at the operator's word.** Done: T-851 and T-853 (two tests that failed at random, repaired); T-714 (T-852 filed for Windows); T-718's and T-720's steps on podcrates' fixes (COORD-109 and COORD-110 closed); podcrates `v0.79.0`, `v0.80.0` and `v0.81.0` taken (COORD-130 to 132, each recorded and closed; COORD-129 closed too); T-780's hang placed in podssh's own task (fifteen failures; the watches of russh's step and channel, of the pump's polls and of the task's parts, `ssh/polls.rs`); T-846's second failure read and its lines widened; the operator's rule that the repository's conventions win over a session's own setup. The gate is green at `d0c2a04` (#332); the gate of the commits after it was asked in #333 and is now superseded by `930e5ba0` on `main`.

**Session of 2026-11-19 to 20 (cloud).** Done: podcrates `v0.73.0` to `v0.78.1` taken (COORD-122, 124, 126, 127, 128 and 129; `v0.78.1` is COORD-146 of podcrates, PodUtils/podcrates#241: `update::plan`'s `Newer` in place of podssh's comparison, and the crate's own `Interrupts` of the pager); T-826 done (no link ends at a relay's small cap; the gate at `5975bb0` passed each job, Windows included); T-848 done (an exec has no prompt on the line discipline); T-850 done (`podssh update` on `pod-release`; `release.yml` writes `release-index.json` before `SHA256SUMS`, by hand at `0661ded`, run 44571898795, green); T-847 partial (the four images build in the dry run, run 44446055538; the push to ghcr.io waits for the next release tag); T-780's busy watch is in (30 local runs and 4 whole `m6_exit` runs passed, the gate at `0661ded` green). Open, in order: the gate of `ae25fe1`; T-780 and the other tests that fail at random, each waiting for its next failure; T-684 (`pod-cloudflare` and `pod-ts` as podcrates names them, then `pod-relay-serve`); then the lane behind each class again (T-791) and a third black-box pass on the candidate (T-809): **no beta until that pass is clean.**

**Session of 2026-11-18 (cloud): podrunner first.** The owner's rulings "podrunner first", "Coordinator" and "Schema
ids" (COORD-134, PodUtils/podcrates#225; the coordinator's order is COORD-136, PodUtils/podcrates#227) are in
`docs/decisions.md`; the operator confirmed them at this session's start. The order of each session from now: (1) a red
run of podssh's CI; (2) each ask of podrunner (a COORD issue `(to podssh)`; none yet: podrunner's census, its T-491,
sends them) and each ask of podcrates that serves it; (3) the asks of githome and cfb in this record (#195: T-711,
T-719, T-722, T-729 wait for podcrates T-112, T-110, T-111, T-117, which the coordinator ordered after githome's and
cfb's CI entries; COORD-120, #316); (4) podssh's own order, critical repairs only: the rest of this page's queue waits.
Done this session: the red `windows-arm` row (T-728); the take of `v0.70.0` (COORD-119); T-828's lock; T-843 filed
(pod-relay's policy line lost the relay's cause, asked in COORD-119); the donor study filed as T-831 to T-842 and
additions to T-116, T-123, T-150, T-159, T-160, T-161, T-303 and T-304 (#317, backlog); twelve COORD issues of takes
that podcrates recorded closed. Then podcrates `v0.71.0` taken (COORD-121): T-843 and T-828 done, T-826's ask 1 in (ask 2, podcrates' entry 909, waits); T-844 (doctor and croc's public bridge) and T-845 (the HTTP road's close said at a failed write) repaired from the gate; T-780's eighth failure (iroh road, new address) written on #283 as ask 4. Asked by the coordinator and answered in COORD-120: no relay of the pool runs podssh's
role (each `/health` of the 37 hosts of `/relays.json` says `tcp-ssh-relay 2026-10-03-r2`, the operator's own relay),
so T-801's fix reaches the pool only through the relay's operator or `pod-relay-serve` (podcrates T-036).

**First, from 2026-11-15 (the operator's ruling, `docs/decisions.md`): T-684 is fast-tracked.** podssh asks
podcrates for Q101's waves 3 and 4 (COORD-071, #248), freezes each module as podcrates names it, and takes each
tag at once; `v1.1.0-beta.4` waits for the move, then goes out with its testers' guide (a GitHub issue). Beside
it, while podcrates builds: the GSRN road's live test (done), the cell of an outage (T-786), the netem lab of T-625,
T-665 and T-463, and `feel-netem.yml` again on osewa v0.1.5.

**Session of 2026-11-17 to 18 (cloud), the black-box passes (T-809).** Two passes with the binary and the documents
alone filed T-810 to T-828. The owner's rulings "Quality first", "Shared code first" and the beta rule are in
`AGENTS.md`. Done: T-810 to T-825, T-827, T-829 (a port held by a test of a refused target) and T-830 (the
tail of stdout on Windows). Since then: T-826 (2026-11-19) and T-828 (2026-11-18, on pod-core's `lock`) are done, and `v0.70.0` is taken (`99e9fd5`). Open: the lane behind each class again (T-791) and a third black-box pass on the candidate before any beta (T-809). **No beta until that pass is clean.**

## Baseline

Measured on 2026-10-30 in a Claude Code cloud container (Linux x86_64, Rust 1.99.0,
`CARGO_BUILD_JOBS=4`), at `9b6dda2`: `cargo test --no-fail-fast` 2028 passed, 20 failed, 55
ignored, in 22 min 43 s, with groff stopped by hand after 13 minutes (T-314). Each failure is of
the test or of the place: 16 tests take the machine's proxy (T-313), and 4 live handshakes dial
past it into an egress that intercepts TLS (T-315). `cargo todo check` and
`python scripts/check-repo.py`: ok.

Measured on 2026-10-09 after T-060, on Windows 11 with native cargo 1.98.0 and
`CARGO_BUILD_JOBS=4`:

- `cargo test --workspace --no-fail-fast`, again at `905f92c` (2026-10-13): 1887 passed, 1
  failed, 54 ignored (the live tests, and the checks of faults and of the exit of M6). The failure
  was a test of T-042 that depends on time; it is repaired, and passed 20 runs in a row. With the
  feature `iroh` and the test relay, `cargo test -p podssh-iroh -p podssh-cli --features
  podssh-cli/iroh-test`: 468 passed, 0 failed, 29 ignored. With the feature `ts`,
  `cargo test -p podssh-ts -p podssh-cli --features podssh-cli/ts`, after T-099: 520 passed, 0
  failed, 25 ignored.
- `cargo test -p podssh-relay --all-features --no-fail-fast`, after T-270: 181 passed, 0 failed,
  14 ignored (the live tests).
- `sh scripts/dev.sh check` (after T-212): green; interop 103 of 103.
- `cargo test -p podssh-todo` (2026-10-11; since 2026-11-05 the package is a wrapper of `pod-todo`
  of PodUtils/podcrates, whose tests are its own, T-684): 77 passed.
- `cargo todo check`: the record agrees. `python scripts/check-repo.py`: ok.
- `cargo clippy -p podssh-todo --all-targets -- -D warnings`: no warning.

## Counts

`TODO/INDEX.md` holds 808 entries: 28 open, 40 partial, 11 blocked, 729 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit, then take the next
one. Each session runs unattended until the goal of `AGENTS.md` (section 2) is reached or the
operator interrupts it.

**The rules of the order**, first to last:

1. A red gate, then a test that fails at random (T-465, T-627, T-753, T-756, T-780, T-796), before any other work.
2. A `partial` entry before a new one, and a draft's merge in the order of "Drafts" (State, item 8).
   Each partial entry and what it waits for (2026-11-13): T-107, T-108, T-109, T-110, T-112, T-114
   and T-222, the remap their `## Done` lists and the run in the build image (the release check); T-738,
   podcrates' entry 528 (COORD-053); T-319 and T-321, a real
   proxy's path, Apache in the build image and the live runs (Q88); T-106, the operator's tailnet;
   T-660, T-666 and T-670, their runs of the matrix;
   T-755, a tester's tunnel; T-684, each next tag; T-446, the end of the migration.
3. The migration's takes (T-684), as the podcrates session hands each crate over (Rule Q3 of
   `docs/decisions.md`: from the import, podssh changes that code for fixes only; after podssh takes
   the crate, the work is done in PodUtils/podcrates). Where a `## Correction` of 2026-11-05 says
   that the code of an entry is in a crate that podssh has taken, that change is made in
   PodUtils/podcrates, or asked there as an issue; the part of the entry that uses the crate stays
   podssh's (T-111's serve, for one). M4's exit kept its two boxes only, and is done (Q103: the
   facade went with `pod-relay`).
   Taken on 2026-11-13: `v0.40.0`, with `pod-netstack`'s tests of the two close cases of WARP's stack
   (COORD-054, #231) and the mended forms of the file hosts (COORD-053, #230) for T-738. Taken on
   2026-11-14: `v0.41.0`, with pod-term's mode that follows a termios (COORD-055, #232), which serve's tty with no pty drives (done);
   and `v0.42.0`, with the answers to COORD-057, 059, 061 and 062.
4. The testers' defects, then their features (Q84, Q85): the defects first among the `none`
   entries, P1 before any other; their features (those
   which Q74, Q75, Q77, Q78 and Q82 filed) by priority, beside
   M10. Between entries: the `none` entries, the highest priority first, but for the testers'.
   Dependabot closed #123 on 2026-11-17: simple-dns left podssh's tree with `pod-iroh` (`v0.65.0`); podcrates holds that dependency now.
5. The entries that the studies of osewa filed (Q99, `docs/research/osewa.md`) go ahead of the
   rest of M10, in this order: T-660, T-670 and T-666 (each waits for a run that its
   `## Done` names), their follow-up and what the netem run found (done); then the open
   entries of GitHub #127 to #148 by their priority, beside M10 (Q85, Q100).
6. podssh's own order by priority beside M10's order below. The GSRN road is done (2026-11-15,
   live through gsocket's relay). cfb's asks (`each`, `run` and `job` on a node and
   on an `iroh:` or `derp:` ticket, and `mcp --read-only`: done, 2026-11-14) stay behind podssh's own
   work order, M10 included (the owner's ruling "Priority"; Q105 is settled).
7. The holds are released (Q92): T-107 to T-113, T-117, T-118, T-222 and
   T-248 are open and go by their priority, M5's `podssh serve` among them, after M10's entries of
   their priority; the work parked behind them ("Parked open work") starts as its condition says.
   T-328 (a real export of FinalShell and of Termius) and T-376 (the operator's throwaway cloud
   accounts for the live run of the roads of iap:// and eice://) wait for inputs that only the
   operator has. T-672 (TLS tickets kept across runs) waits for a release of rustls that lets a
   client write one. M4's exit measurement is done (2026-11-13).
8. The next beta goes out when podssh is nearly complete (T-446; the operator, 2026-11-11). It waits for T-809 too (2026-11-17, after podnet's QA round, PodUtils/podnet#649): error-path rows in the lane and a black-box pass with the documents alone, before any beta is called ready for testers. The findings of the first black-box pass (2026-11-17, named in T-809) are each fixed before the beta.

**M10**, the mesh and the relay in podssh (Q63 to Q66, `docs/mesh.md`), in this order (the done
parts are named so that the open ones read in their place):

0. A test that fails at random comes first (the relay suite's is done).
1. The relay role (its certificate from ACME, its brake of mint and pair, the role behind a node's
   quick tunnel, the net's members' mint, the role's dial through `HTTPS_PROXY`, its bound on a slow
   reader's bytes and its planned stop are done): what the role serves: T-319 and T-321 (the
   resumable layer for a standard sshd, by default where the first host offers it, is done);
   `doctor`'s measure of a stream's path, the role's IPv6 targets with `doctor`'s line of them, a
   client's lost link during a node's bulk, and the cleartext road on the relay's port are done.
2. The net (its policy, the record of each road, the DERP node of a member, the copies by a name,
   the quick tunnel's node with the net as its door, the grants used once, a copy's race of the
   roads, the pairing by a short code, a device's join by one, the signed list of deployments and
   the tokens of one leg, the hosts of the relay members, and the rotation at a node's next pair,
   are done): T-106.
3. Exit, routes, share and funnel (the exit, `doctor --exit`, the net's routes and `podssh share`
   are done; the exit behind a quick tunnel is done; the funnel and a member that relays between two members are done; the status
   of the net, `ping` of a node and doctor's sections are done).
4. The public carriers of Q65 (the Piping Server road from end to end is done; the transit road's misses of 2026-11-06 are done, from a run of `transit-live.yml`; the protocols of Q66 are done), XHTTP over HTTP/1.1 (Q67, done), then
   what the research of more services (done) filed: the protocols of servers that a user runs
   (chisel's, Outline's, Shadowsocks 2022, Trojan, NaiveProxy's, trojan-gfw's, trojan-go's and
   frp's are done), upterm's door (done) and a second Piping Server (done), ntfy as a meeting point (done) and
   T-499 parked; then what the triage of the sweep of public relays filed, as Q74 to Q79 rule:
   OpenTunnel's road (Q76, done), and the manual's word on the public services that podssh uses
   and the ones it never names (done); the funnel through OpenTunnel (done); then what the rulings Q74, Q75, Q77, Q78
   and Q82 filed, the P2 ones first: Tailscale's main DERP fleet after tailcat's (done), the public
   Wisp servers made for it (done: none qualifies), Pinggy (done) and the public proxy nodes
   (done); then the research of the overlay networks (NetBird, Firezone, ZeroTier, Tox,
   Yggdrasil, Cabal, Hyphanet, croc and HyperDHT are done), of the trackers (done) and of the
   pub/sub networks (done), then what they filed: croc's relay as a road and a meeting point
   (done), WebTorrent's trackers (done), ZeroTier's relay (done), Tox's (done), Yggdrasil's
   peers (done), HyperDHT's road (done) and the public MQTT brokers as a meeting point (done),
   and Nostr's meeting point (done); the other last fallbacks of Q78 (srv.us and tunnl.gg (done),
   serv00's and HTTP Relay's demo (done), the onion services (done), and what the research of 2026-11-10 filed: file hosts as the last
   carrier (T-738), VMess's AEAD form (done) and Bare servers as a hop (T-740); srv.us and tunnl.gg
   done, serv00's done); and the roads over UDP (done: MASQUE over HTTP/3, Hysteria 2's and TUIC's). These are features of a tester's
   report and of the sweep, done after the defects (Q85). Then what the archive of forward
   carriers (`docs/research/forward-carriers.md`) filed: the rates of `ppng.io`'s road and of the
   Wisp demo server through podssh (done), TURN with RFC 6062 for a server that the user runs
   (done), the research of smee.io, of three hosted tunnels and of I2P, Nym and cjdns (done; it
   filed smee.io as a last fallback, done, hostc's, done, and Sandhole's public server as a host
   of the localhost.run road's module, done), and the HTTP road's one-POST form (done).
5. T-446: the next beta `v1.1.0-beta.N` when podssh is nearly complete, and `v1.1.0` at the end,
   once the migration is done.

## Parked open work

These entries stay open in the index. The condition in each entry tells when
it can start.

| Entry | Start condition |
| --- | --- |
| T-150 | T-112 is done: `podssh serve` has an SFTP server |
| T-114 | Started on 2026-11-13 from its draft, before T-107 to T-112 closed: the parts of `podssh serve` that it needs are on `main` |
| T-115 | T-107 to T-112 are done: `podssh serve` exists |
| T-116 | T-107 to T-112 are done: `podssh serve` exists |
| T-119 | T-107 to T-112 are done: `podssh serve` exists |
| T-120 | T-107 to T-112 are done: `podssh serve` exists |
| T-122 | T-107 to T-112 are done: `podssh serve` exists |
| T-123 | T-107 to T-112 are done: `podssh serve` exists |
| T-124 | T-107 to T-112 are done: `podssh serve` exists |
| T-631 | T-124 is done: `podssh serve --listen` exists |
| T-159 | T-107, T-108, T-110 and T-117 are done: `podssh serve` runs a shell on a pty, and stops its process group |
| T-160 | T-107 and T-110 are done: `podssh serve` runs a shell on a pty, which reports the input's offset and the ECHO flag |
| T-161 | T-159 is done: a far end keeps a shell, its ring and its pty after the client leaves |
| T-303 | T-110 is done: `podssh serve` has a pty; and T-161 has a model of the far end's screen |
| T-304 | T-303 is done: frames of the screen exist |
| T-532 | Started on 2026-11-14 from its draft: T-180 and T-530 are done, so `podssh funnel` and OpenTunnel's link exist |
| T-499 | draft-ietf-httpbis-connect-tcp is an RFC, and a server over HTTP/2 or HTTP/1.1 implements it |
| T-545 | T-086 is done: the pairing's exchange exists over a mailbox |
| T-566 | T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists |
| T-567 | T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists |
| T-575 | T-497 is done: the road has public servers in order |
| T-622 | T-319 is done: the HTTP road's split and serial forms exist |

## Questions for the operator

**Q106 (2026-11-14): settled by the operator on 2026-11-15, allowed as recommended** (`docs/decisions.md`): a short live test against the GSRN relay, which passed (2026-11-15).

Questions asked so far and how they were settled, each
ruling in `docs/decisions.md`. The operator ruled on the questions of the triage (Q1 to
Q12) and of the unattended session (Q13 to Q28) on 2026-10-08. A new question goes here, with its
number, the entries that it blocks (status `blocked`) and a recommendation; the session then
takes the next entry. Nothing is closed as out of scope until the operator rules.

The operator settled Q89 to Q92 on 2026-11-03 (`docs/decisions.md`), each asked on its own: podssh
ranks relay hosts unasked only with `RelayRank auto` (Q89); the calls of Q86 stand but four
(Q90: T-574's built-in nodes, T-612, T-613 and T-614); four more live test targets (Q91: T-463,
T-548, T-578, T-531's weekly run); and the holds end (Q92), T-328 and T-376 waiting for their
inputs alone.

**Q105 (2026-11-09): settled by the owner on 2026-11-11, allowed as recommended** (`docs/decisions.md`; T-715 keeps its place behind podssh's own work). **The question: a node's door from a net document at a URL, read again each TTL (T-715).** cfb's
ask A-S-08 wants a node to read its signed net document again each TTL (300 s by default) while it
runs. Rule 2 of `AGENTS.md` allows a read beside a session only once a day and before it (Q96, Q97).
Recommendation: allow it as a ninth exception: only with `--net-url`, which the user names; one GET
through `HTTPS_PROXY` each TTL at most (never under 60 s), never while a read is open; the reply
bounded (64 KiB) and its signature checked against `--net-owner`.

**Q102, Q103, Q104 (2026-11-05): settled by the owner on 2026-11-06** (`docs/decisions.md`): no
release and no beta until the migration is done, podssh stays beta until the owner calls it stable,
and crates.io is asked again only then (Q102, Q104); podvm takes the facade from `pod-relay` (Q103).

**Q101 (2026-11-05): the crates of PodUtils/podcrates, agreed with podnet's session.** The operator
moves podssh to PodUtils/podssh (T-683) and puts the shared crates in PodUtils/podcrates (T-684);
podnet's session and this one agreed one list on 2026-11-05 (podnet's operator ruled that podnet's
WARP and Cloudflare adapters move there, and that podnet copies no podssh code). Recommendation:
accept it as written. **Settled 2026-11-05** by the owner's acts and rulings (`docs/decisions.md`,
"The crates of PodUtils/podcrates"): PodUtils/podcrates exists, its session builds the crates, and
`v0.1.0` is out; three rules of the list below changed: each crate may link C (T-685), declares
Rust 1.97 and edition 2024, and podssh takes it by a git tag of PodUtils/podcrates (Q1).

- Crates of podcrates (each name answered 404 at crates.io's index on 2026-11-05): `pod-todo`,
  `pod-testkit`, `pod-tls`, `pod-dns`, `pod-proxy`, `pod-ws`, `pod-identity`, `pod-term`,
  `pod-netstack`, `pod-wg`, `pod-relay`, `pod-relay-serve`, `pod-session`, `pod-e2e`,
  `pod-wormhole`, `pod-transit`, `pod-warp`, `pod-cloudflare`, `pod-derp`, `pod-acme`, `pod-egress`,
  `pod-iroh`, `pod-ts`, `pod-tor`, `pod-piping`, `pod-opentunnel`.
- Names held, no crate: `pod-wireguard`, `pod-quick`, `pod-udp`, `pod-mailbox`, `pod-reverse`,
  `podcrates`, `podutils`, `pod-utils`.
- Waves: 1, `pod-todo`, `pod-tls`, `pod-dns`, `pod-proxy`, `pod-ws`, `pod-identity`, `pod-term`, and
  `pod-testkit` with the russh harness; 2, `pod-netstack`, `pod-wg`, `pod-relay`, `pod-session`,
  `pod-e2e`; 3, `pod-warp` (with the stand-in edge into `pod-testkit`), `pod-cloudflare`,
  `pod-wormhole`, `pod-transit`; 4, `pod-relay-serve`, `pod-derp`, `pod-acme`, `pod-egress`,
  `pod-iroh`, `pod-ts` (with the headscale harness), `pod-tor`, `pod-piping`, `pod-opentunnel`.
- The rules of each crate (as changed on 2026-11-05 by T-685 and the owner's rulings; the first
  text said no C, crates.io only and Rust 1.89):
  no `podssh-ws` type; the binary passes a rustls `CryptoProvider` and a dialer; each crate may link
  C and declares Rust 1.97, edition 2024; podssh takes it by a git tag of PodUtils/podcrates, not
  from crates.io; podssh's pure-Rust provider and the RSA verifier (rsa 0.9) stay behind a feature
  of `pod-tls`; `pod-relay` keeps the `blocking` facade for podvm; a name of the wire may change,
  with no test against a released binary (the operator, 2026-11-05: no compatibility with the
  released binaries for now).
- Who builds: a new session in PodUtils/podcrates, fed by both repositories; neither podssh's
  session nor podnet's edits podcrates.
- podssh keeps: `podssh-cli`, `podssh-ssh` (it takes the patched russh and ssh-key), the IRC of
  `podssh-core`, `podssh-probe`. podnet keeps its CLI, `podnet-core`, `podnet-netns`,
  `podnet-vnet` and `podnet-serve`. Blocks T-684.

**Q86's calls of 2026-11-04 and 2026-11-05 (T-638, T-640 to T-644, T-649, T-667): confirmed by the operator on
2026-11-15** (`docs/decisions.md`).

The operator settled Q93 to Q100 on 2026-11-04 (`docs/decisions.md`), each as recommended: the TURN
road's second connection (Q93), short live tests against smee.io, hostc, Tunnelmole and Sandhole
(Q94), TURN and the one-POST HTTP form outside `--forwarder` (Q95), and the two reads before a
session (Q96, Q97) are confirmed; `v1.1.0-beta.2` goes out at once and `v1.1.0-beta.3` at the end
of the night (Q98); the gaps that the studies of osewa find become entries ahead of the rest of
M10 (Q99); and GitHub #126 to #148 become entries, #126 first as a P1 defect (Q100).

The operator settled Q67 to Q84 on 2026-11-02 (`docs/decisions.md`), after the triage of the
testers' reports (GitHub #83 to #106, the bundle, the relay sweep) and of the drafts of M10:
XHTTP over HTTP/1.1 may open its second connection (Q67, T-456); the login name comes from
`PODSSH_USER`, the three variables, then the user database (Q68, T-500); the fallback to other
products' forwarders follows only a failure where no relay host answered about the target (Q69,
T-509); a file's `ProxyCommand` for each host stays refused with 78 (Q70, T-502); the keywords of
a restriction apply (Q71, T-505); `scp` and `sftp` take `--timeout` (Q72, T-508); `doctor` runs
its sections at once, with a flag that limits it (Q73, T-511); Tailscale's main DERP fleet after
tailcat's (Q74), the public Wisp servers made for it (Q75) and OpenTunnel (Q76) are tried as
fallbacks; podssh uses the fallbacks that exist, overlay networks and meeting points among them
(Q77), each service as a last fallback whatever its terms (Q78), and the repository names only
the hosts that podssh uses (Q79); the operator passes cfrs's defect on (Q80); a node with no iroh
road keeps its pkarr record at n0's server (Q81); roads over UDP where UDP passes (Q82); the
experience of an agent and of a human comes first, and the triages' calls stay (Q83); the
testers' defects go now (Q84). Later the same day: their features go too (Q85), a fork of policy
is decided overnight and listed for confirmation (Q86), and `v1.0.1` and the next beta go out
unattended (Q87).

**Ruled (Q90, the operator, 2026-11-03, each call asked on its own; `docs/decisions.md`):** the
calls below, made overnight under Q86, stand, but four that changed: T-574 ships a short list of
nodes re-checked before each release; T-586 gets `--no-resume` (T-612); T-589's commands take
`--timeout` as another name of `--ConnectTimeout` (T-613); and `ssh`, `proxy` and `pipe` take
`--exit` beside `--carrier` (T-614, after T-596). T-548, T-578 and T-463's live runs are
allowed (Q91), and Q89 is ruled: podssh ranks unasked only with `RelayRank auto`. The list, as
it was asked:

- T-548: short live tests against the services of Q77 and Q78 (Pinggy and the others), one
  Decision for all of them; if confirmed, `AGENTS.md`'s list of test targets names them.
- T-574: the binary names the public lists of proxy nodes but never a node, and skips a node that
  fronts another party's name or sits under a school's, a church's or a government's suffix.
- T-578: one short live run of an onion service on the public Tor network, more than Q60's one
  bootstrap and one stream.
- T-563 (done): a strike is only a session that the host's side cut (a lost link, the relay's
  Close of its link), so that two short sessions of a client do not rest a healthy host; a host
  that opened lately goes first with no note.
- T-560 (partial): a reset inside the tunnel is an answer, as a SYN-ACK is; IPv6's resolver for a
  device of IPv6 alone; 3 s for each try; the stand-in answers the probe at 1.1.1.1:443.
- T-505 (done): the host key algorithms that `known_hosts` records for a host go first within
  each list, also a list that replaces podssh's own (OpenSSH keeps such a list's order); podssh's
  own lists, which `+`, `-` and `^` start from, stay russh's, `ssh-rsa` (SHA-1) among them, not
  OpenSSH's defaults; a name that podssh does not speak is left out with a note at `-v`.
- T-503 (done): each host after the first, a later hop of `-J` and the destination behind it, is
  checked too, on each road, by the direct road's rule.
- T-476 (done): it reverses T-143's call of a skipped special file as a failure (66): a FIFO, a
  socket or a device is now a skip with exit 0, `{"event":"skipped",...}` in `--jsonl`; `mv -r`
  leaves each directory that holds one.
- T-470 (done): with no `copy-data`, `cp --delta` makes the temporary file by one command,
  `sh -c 'cat -- "$1" >| "$2" && echo podssh-copied'`, counted only with its marker and its size;
  the far blocks' digests come before that copy; a second attempt keeps the first reason.
- T-471 (done): `sftp`'s `ls -n` shows numbers also where the server could name them, as OpenSSH
  10.4p1 and later do; an entry with no long name gets podssh's line, not OpenSSH's empty one; the
  columns take the width of stdin's terminal, as OpenSSH's; a pattern in the last name only; a
  reply of the names' extension that is not of its form shows the numbers with no word.
- T-463 (done; its live run waits): the live run goes to the operator's server of
  `PODSSH_THROUGHPUT_SSH`, which Q38 names for the throughput run, for 3 minutes with nothing sent:
  no other test target gives a shell behind the relay's forward road. Recommendation: allow it, as
  a run lighter than the throughput run on the same server; podssh's own relay role measured it
  in its place.
- T-586: `operator` takes SIGHUP, SIGTERM and SIGINT as its application's end and closes the
  session (OpenSSH ends its ProxyCommand with SIGHUP); a node keeps a closed session as its id
  alone, charged nothing, and charges a closing one its unacknowledged bytes; no
  `--resume-deadline 0`, no `--no-resume`, no eviction of a waiting session; the budget's counts
  go in the refusal and the node's log, not in `detached list` or `relay status`.
- T-587: `proxy node://NAME[/ROUTE]` is the pipe of `operator NAME`, with its flags, and refuses a
  PORT; `operator` stays.
- T-589: `--ConnectTimeout SECONDS` on `operator`, `proxy` and `pipe`'s remote sides bounds the
  time to the session's open, never the bytes after it; not `--timeout`, not `PODSSH_TIMEOUT`.
- T-590: `doctor`'s line `sshd` dials 127.0.0.1:22 once and reads its first line, a note outside
  the count of failures; the roost's words name the package to install and run nothing.
- T-592: a renewal in podssh's relay role (`POST /v1/renew/<name>`, by the stop token) keeps the
  pair's three tokens, with no cap on renewals, and the node renews its own pair in its last 24 h
  where its relay renews. Its draft (partial) adds: each failed renewal gets the role's `403`, not
  a `404`; an operator past the end that its file names asks its relay's status once, with the
  trust of `SSL_CERT_FILE` or the settings, and is refused as before (77) offline or where the
  relay names no later end; a node of `--pair-file` renews too, and its file is not rewritten; a
  renewal that did not take is tried each hour; `relay pair --renew` refuses `--operator-file` and
  `--relay-host` (64).
- T-593: `XDG_CACHE_HOME` and `HOME/.cache` are the user's cache only when the uid owns them, else
  the passwd entry's home; a file kept in another user's home before is read there and said,
  never moved.
- T-594: `docs/STATUS.md` stays the page of `main`, each row marked with the first release that
  holds it or `unreleased`, held by a check of `scripts/check-repo.py`.
- T-595: one flag, `--carrier ADDR` (`stdio`, `fd:N`, `exec:CMD`), at the node and at its
  clients; the node's socket of the reverse road on the stream, the relay role's side of it in
  the client's process; the stream is the door, the end-to-end channel on by default. Its draft
  (partial) adds: the node's first frame is a Ping, and no session opens before it; a stream of
  `exec:` is started again once for each wait of a leg; `--exit` with `--carrier` is refused until
  T-596.
- T-596: `exit --listen --carrier` takes `stdio`, the one client of a carrier
  that does; the proxy starts its stream with its listener; a stream of `stdio` or `fd:N` ends the
  proxy (0) when its node leaves; Ctrl-C at the proxy ends the node (0); `ssh`, `proxy` and `pipe`
  keep refusing `--exit` beside `--carrier` (64).

**Confirmed (Q90):** T-503 checks each host after the first hop too (a later hop
of `-J`, and the destination behind it), on each road, by the direct road's rule, so that
`-J bastion 'a$b'` is refused with 64 where the relay road passed it to the jump host (its
`## Decision`).

The operator settled Q63 to Q66 on 2026-11-02 (`docs/decisions.md`), after the research of five
agents on the dependency on the relay's operator: podssh grows into a mesh of its user's own nodes
at parity with Tailscale (exit nodes, routes, share, funnel), and the relay becomes a role of
podssh itself, so that no entry waits for the relay's operator (Q63, milestone M10,
`docs/mesh.md`); Cloudflare's terms are accepted and are not raised again (Q64); the
magic-wormhole transit relay and mailboxes, Piping Server, the Wisp demo server and others that
fit may be tried unasked (Q65); podssh speaks HTTP CONNECT over TLS, VLESS and XHTTP, and
wstunnel's protocol as a client (Q66). The operator also had `v1.0.0` published at once, for the
testers, while sessions build M10.

The operator settled Q60 to Q62 on 2026-11-01 (`docs/decisions.md`), each as recommended: the
Tor road's live test may reach the public Tor network, with short runs, from GitHub Actions and a
session's own host (T-353); this binary started again at the user's request is no helper (rule 3
of `AGENTS.md`), and a detached run may ask the user's systemd for a scope (T-381); the quick
tunnel's node keeps a second connection to the edge, a fourth exception of rule 2 (T-414). The
operator also allowed `v1.0.0-beta.4` and then `v1.0.0` unattended, once the whole release check
passes.

The operator settled Q31 to Q37 on 2026-10-09.

The operator settled Q38 to Q40 on 2026-10-10 (`docs/decisions.md`): the
throughput run may reach n0's iroh relays with about 500 MiB a direction in
each cell, and the operator's SSH host (T-157, run in T-251); the IRC client
may be tested on undernet, libera and OFTC (T-091 to T-098, T-252); and a
session passes the files of `.env/` to podssh by their paths, never printing
them (T-100 to T-105, T-240, T-241).

The operator settled Q41 and Q43 on 2026-10-30, kept Q42 and the holds of
Q32, and allowed betas (`docs/decisions.md`): T-292 uses export files that
their programs wrote and that are published; T-299 runs in GitHub Actions.

The operator settled Q57 to Q59 on 2026-10-31 (`docs/decisions.md`): a
node on n0's relays publishes its record of pkarr to n0's server by default
(T-350); tailcat's DERP fleet may be tested live, short, from Actions and a
session's host, and a node with no pair serves the DERP road unasked
(T-349, T-379); WARP joins the release binaries once its live run passes
(T-352).

The operator settled Q44 to Q47 on 2026-10-30 (`docs/decisions.md`): the
split HTTP road may open its second connection (T-319, whose endpoints podssh's
relay role serves since Q63); the cleartext road on port 443 runs last, with a token
for one session (T-326, which podssh's relay role serves since Q63); mRemoteNG's
GPL test files may live beside their notice (T-327; FinalShell and Termius
moved to T-328, which waits for exports); and podssh builds its quick
tunnel (T-300).

The operator settled Q48 on 2026-10-31 (`docs/decisions.md`): podssh is a
client first, and no legacy constraint holds it back, so the library crates'
minimum Rust rises with their dependencies (T-333). The same day the operator
kept immutable releases off for `v1.0.0`, left T-328 as a known gap, and asked
for a study of local stand-ins for the live checks that need the operator's
hosts. After it, the operator settled Q42: the relay's own loop is T-062's
target, and the throughput run's forward cell goes through it at 100 MiB a
direction; and a headscale stand-in replaces the runs with the operator's
tailnet for `v1.0.0` (T-334).

The operator settled Q49 to Q52 on 2026-10-31 (`docs/decisions.md`): a binary may
use relays outside `ssh.relay.ajam.dev` when they are compatible (T-346; relays that their users
bring and `podssh update`, T-375, make a signed list less pressing); the release binaries carry
the iroh road, with n0's public relays and Tailscale's tailcat fleet as an automatic fallback
(T-348 to T-350); roads through GCP IAP and AWS EICE, EICE's presigned URL an exception for that
URL alone, built against stand-ins first (T-351; the live run, T-376, waits for the operator's
accounts); and WARP's MASQUE road and Tor through Arti in a feature crate (T-352, T-353), WARP's
live test in Actions and on a session's host. The entries that they opened work before `v1.0.0`.

The operator settled Q53 and Q56 the same day (`docs/decisions.md`): `doctor` listens once on each
socket that it binds, accepts nothing and closes it at once, never with `PODSSH_LISTEN=no`
(T-358, with rule 2 of `AGENTS.md`, `SECURITY.md` and `docs/architecture.md`); and the three
public WebSocket forwarders of GitHub #59 are built in, each selected by a word, and tried when
each relay host fails, with live tests in GitHub Actions only (T-370, after T-369). Both work
before `v1.0.0`.

## Operator actions

One blocks entries, none a session:

- **The secrets of the throughput host** (2026-11-12): no longer needed (2026-11-15, the operator's ruling): T-625
  and T-665 measured in a netem lab on Actions (done), and T-463 measures there too. Setting `PODSSH_THROUGHPUT_SSH` and `PODSSH_THROUGHPUT_KEY`
  adds an optional run on the real path of Q38.

- At any time: require the status `all` of the workflow `build` for `main`, if the operator wants a
  required check (T-212); `main` requires none today.
- Dependabot's updates reach `main` through a session (`docs/decisions.md`).
- After the release: a run of T-004 and T-005 in a real sandbox, with the brief of
  `scripts/sandbox-check.sh`.
- The facade of `podssh-relay` for podvm (T-081, T-085): podvm takes `pod-relay`'s feature
  `blocking` by a tag (Q103).
- As the operator of the default relay, at any time and with no entry waiting: the notes of
  `docs/relay-operator.md`, each of which podssh's own relay role does since Q63.
