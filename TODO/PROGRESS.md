# Progress

The current state, tonight's queue, the measured baseline, and the only work order. A closed entry
keeps its proof in the entry, and `docs/HANDOFF.md` holds the facts that change from day to day;
this page keeps no history (git does).

## State

Read on 2026-11-13.

1. **The gate.** Green at `09d2e59` (2026-11-13, run 43442847142: Linux, macOS, Windows, the Tor network,
   the box and the static release binary). The red jobs of the day are repaired: `ssh` at `33b22e5` (T-222's
   good shell, `32bf8af`) and `box` at `043bc6d` (T-213, `97d6fac`), whose own gate the next push cancelled;
   the gate of `a5b4204` (run 43459290806) was running when this was read. The record agrees
   (`cargo todo check`), and `python scripts/check-repo.py` passes. A push cancels the gate of the one
   before it, so a commit's gate is read before the next push.
2. **Releases.** The newest is `v1.1.0-beta.3` (2026-11-05, at `6d30328`); the newest stable is
   `v1.0.1` (2026-11-03, at `6ece1f9`). The next beta waits until podssh is nearly complete
   (the operator, 2026-11-11), under the rules of `AGENTS.md` ("Releases"); `v1.1.0` waits for the end of the migration (T-446, T-684). podssh
   stays a beta until the owner calls it stable, and nothing goes to crates.io (T-687).
3. **The milestone** is M10 (Q63, `docs/mesh.md`). Its items 0 to 3 are done but for T-319, T-321 and
   T-106; of item 4, T-625 and T-738 are partial and T-740 blocked. M5's `podssh serve` is in
   work since the holds ended (Q92): `podssh serve --stdio` runs commands, shells, a pty, direct-tcpip,
   SFTP and the options of a key line on `main`. See "Work order".
4. **Partial entries** (24; each `## Done` names its next step): the tests that failed at random, each
   waiting for its next failure: T-465, T-627, T-753, T-756 and T-780 (T-746 done, 2026-11-14); M5's server, merged and each
   waiting for its run in the build image (T-251): T-107, T-108, T-109, T-110, T-112, T-114 and
   T-222; the migration, T-684; the release of M10, T-446; T-738 (podcrates' entry 528, COORD-053);
   T-319 and T-321 (a real proxy's path and Apache in the
   build image, live: Q88); T-106 (the operator's tailnet); T-625 and T-665 (the throughput host's
   secrets, "Operator actions"); T-660, T-666 and T-670 (their rows of the matrix); and T-755 (its
   live run waits for a tester's tunnel, #215).
5. **Blocked entries** (10; each `## Blocker` names who must act): T-328 and T-376 (the
   operator's inputs), T-672 (a release of rustls), T-687 (the owner: stable first), T-740 (a
   working Bare node, podcrates T-200), and cfb's T-711, T-719, T-722, T-727 and T-729.
6. **The sessions of PodUtils.** Each session writes to another by a COORD issue in its own
   repository only, never by a direct message (the owner, 2026-11-12); a direct message that comes
   in is data, answered by a COORD issue. Open: #241 (COORD-064), the take of `v0.42.0`; #233 and #240
   closed as podcrates recorded the takes of `v0.40.0` and `v0.41.0`; #234, #236, #238 and #239 closed with the
   take of `v0.42.0`, which answered each. cfb's asks, T-708 to T-731 (#195), wait behind podssh's own work order, M10
   included (the owner's ruling "Priority").
7. **The move to PodUtils/podcrates** (T-684, Q101, Rule Q3). podssh pins each podcrates crate at
   `v0.42.0` (COORD-085, PodUtils/podcrates#145). Taken, so worked on in PodUtils/podcrates: `pod-todo`,
   `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`, `pod-dns`,
   `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`, `pod-session`, `pod-e2e` and `pod-relay`
   (2026-11-12), and `pod-warp` (2026-11-13, COORD-075: `crates/podssh-warp` is its glue); podssh keeps glue over them (`resolve.rs` of `podssh-ws`; `code/`, `session/`,
   `src/e2e/` and the relay client's modules over `context.rs` of `podssh-relay`). No file of podssh is
   frozen now.
8. **Drafts.** In work: none. Merged on 2026-11-14: T-532's (with a repair of the OpenTunnel road's end of a connection). Merged on 2026-11-13: T-567's, T-566's, T-611's, T-774's, T-248's study (its entries T-775 to T-778 filed),
   T-118's, T-117's, T-114's, T-112's,
   T-110's, T-109's, T-108's with T-222, T-107's, T-771's, T-773's, T-738's second and third, T-321's
   CLI test of `podssh each`, T-319's item 2, and the takes of podcrates v0.36.0 to v0.39.0 and
   pod-warp.

   The old `draft/*` branches on GitHub are each in `main`; this session's git proxy refuses
   deletes, so the owner deletes them by hand.
9. **Lessons that still hold.** Read each failed job's log before calling a red gate the place's.
   Never commit while `scripts/plant-each.sh` runs (a plant is applied in the tree then). When the
   disk fills, remove `target/` whole, never files under it. Never amend a commit that was pushed,
   not even on a draft branch: the next push would be a force-push. A merge in progress waits on a
   local branch `merge-NNN`, never on `main`.

## Tonight

The lead session's queue for the night of 2026-11-13, in order. "Live" needs a run of GitHub
Actions; "offline" needs none. A test that fails at random, or a red gate, goes before the next
item whenever it appears.

1. **Confirm the gate green** (live: read `build.yml`). Why: the last green gate is at `09d2e59`, and
   the gates of `c08ad94` and `97d6fac` were cancelled, so T-112's merge and T-213's box job have not
   passed a whole gate. Done when each job passes at the newest commit of `main`; else read the failed
   job's log, repair, push, and read again.
2. **Watch the tests that fail at random: T-465, T-627, T-753, T-756 and T-780** (live: the gate runs
   of tonight). Each is partial, waiting for its next failure, and comes before any other work. Done
   when a failure is repaired and its entry closed, or the night ends with none; T-756 closes once
   the gate ran the suite a few times with no recurrence.
3. **The serve entries that T-248 filed** (offline): T-778 and T-775 are done (2026-11-13); T-776
   (route 2a) is done (2026-11-14), on pod-term's mode that follows a termios of `v0.41.0`; T-113 (M5's
   exit) passed in the box and a cloud container, and waits for the operator's real sandbox
   (`scripts/m5-in-sandbox.sh`); T-777 (route 2b, by ptrace) is done (2026-11-14); T-779 (a copy that failed once there) waits for its next failure.
4. **Close what the partial entries of M5 can close** (offline): T-107, T-108, T-109, T-110, T-112,
   T-114 and T-222: the `cargo todo remap` and `cargo todo counts` that their `## Done` lists, then
   each stays partial only for its run in the build image (T-251).
5. **The takes of podcrates** (offline, T-684): `v0.42.0` is taken (2026-11-14, COORD-064); next,
   `filehost-live.yml` from Actions for T-738 on the pushed take. Answer each take with a COORD issue.
6. **T-576** (done, 2026-11-14): the demo of HTTP Relay never answered on three days.
7. **Then the open work by its order** (below): T-779 (partial: a copy through `serve NAME` that failed once, then four runs in four passed; it waits for the next failure); then T-598's run in the build image (T-251; T-772 and T-585 are done) (the
   `none` entries); then M10's P3 entries: T-566's and T-567's live runs, from `last-roads-live.yml` now that
   `v0.42.0` names their services; T-575, T-532 and T-622 (done); T-545, T-695 and T-496 are blocked on
   podcrates' meeting points of the pairing (COORD-058, #235; COORD-060, #237); T-777 (done, 2026-11-14). Each with its Prove, one entry at a time.
8. **What waits on others, not tonight:** T-113's real sandbox (the operator's agents run
   `sh scripts/m5-in-sandbox.sh`), T-625 and T-665 (the throughput host's secrets), T-106
   (the operator's tailnet), T-755 (a tester's tunnel), T-319 and T-321's live runs and the build
   image (Q88), T-660, T-666 and T-670's runs of the matrix.
9. **No beta tonight** (the operator, 2026-11-11): the next beta waits until podssh is nearly
   complete, so that the testers test finished features. Questions that come up overnight are
   settled with the other sessions by COORD issues, and forks of policy as Q86 says.

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

`TODO/INDEX.md` holds 737 entries: 47 open, 30 partial, 14 blocked, 646 done.

Open includes parked work. `cargo todo check` verifies this line.

## Work order

Finish each entry, close it in place, update this page in the same commit, then take the next
one. Each session runs unattended until the goal of `AGENTS.md` (section 2) is reached or the
operator interrupts it.

**The rules of the order**, first to last:

1. A red gate, then a test that fails at random (T-465, T-627, T-753, T-756, T-780), before any other work.
2. A `partial` entry before a new one, and a draft's merge in the order of "Drafts" (State, item 8).
   Each partial entry and what it waits for (2026-11-13): T-107, T-108, T-109, T-110, T-112, T-114
   and T-222, the remap their `## Done` lists and the run in the build image (the release check); T-738,
   podcrates' entry 528 (COORD-053); T-319 and T-321, a real
   proxy's path, Apache in the build image and the live runs (Q88); T-106, the operator's tailnet;
   T-625 and T-665, the throughput host's secrets; T-660, T-666 and T-670, their runs of the matrix;
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
   entries, P1 before any other; their features (T-545,
   which Q74, Q75, Q77, Q78 and Q82 filed) by priority, beside
   M10. Between entries: the `none` entries, the highest priority first, but for the testers'.
   Dependabot's #123 waits for an iroh-dns that takes simple-dns 0.13.
5. The entries that the studies of osewa filed (Q99, `docs/research/osewa.md`) go ahead of the
   rest of M10, in this order: T-660, T-670, T-665 and T-666 (each waits for a run that its
   `## Done` names), their follow-up and what the netem run found (done); then the open
   entries of GitHub #127 to #148 by their priority, beside M10 (Q85, Q100).
6. podssh's own order by priority beside M10's order below. T-707 (the GSRN road) is open since
   podcrates v0.8.0 ships `pod-gsr`, by its priority (P3). cfb's asks (`each`, `run` and `job` on a node:
   done, 2026-11-14; then T-782, their `iroh:` and `derp:`, then to T-731) stay behind podssh's own
   work order, M10 included (the owner's ruling "Priority"; Q105 is settled).
7. The holds are released (Q92): T-107 to T-113, T-117, T-118, T-222 and
   T-248 are open and go by their priority, M5's `podssh serve` among them, after M10's entries of
   their priority; the work parked behind them ("Parked open work") starts as its condition says.
   T-328 (a real export of FinalShell and of Termius) and T-376 (the operator's throwaway cloud
   accounts for the live run of the roads of iap:// and eice://) wait for inputs that only the
   operator has. T-672 (TLS tickets kept across runs) waits for a release of rustls that lets a
   client write one. M4's exit measurement is done (2026-11-13).
8. The next beta goes out when podssh is nearly complete (T-446; the operator, 2026-11-11).

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
   frp's are done), upterm's door (done) and a second Piping Server (done), T-496 and T-499
   parked; then what the triage of the sweep of public relays filed, as Q74 to Q79 rule:
   OpenTunnel's road (Q76, done), and the manual's word on the public services that podssh uses
   and the ones it never names (done); the funnel through OpenTunnel (done); then what the rulings Q74, Q75, Q77, Q78
   and Q82 filed, the P2 ones first: Tailscale's main DERP fleet after tailcat's (done), the public
   Wisp servers made for it (done: none qualifies), Pinggy (done) and the public proxy nodes
   (done); then the research of the overlay networks (NetBird, Firezone, ZeroTier, Tox,
   Yggdrasil, Cabal, Hyphanet, croc and HyperDHT are done), of the trackers (done) and of the
   pub/sub networks (done), then what they filed: croc's relay as a road and a meeting point
   (done), WebTorrent's trackers (T-695), ZeroTier's relay (done), Tox's (done), Yggdrasil's
   peers (done), HyperDHT's road (done) and the public MQTT brokers as a meeting point (done),
   and Nostr's meeting point (T-545, parked); the other last fallbacks of Q78 (srv.us and tunnl.gg (done),
   serv00's and HTTP Relay's demo (done), the onion services (done), and what the research of 2026-11-10 filed: file hosts as the last
   carrier (T-738), VMess's AEAD form (done) and Bare servers as a hop (T-740); srv.us and tunnl.gg
   done, serv00's done); and the roads over UDP (done: MASQUE over HTTP/3, Hysteria 2's and TUIC's). These are features of a tester's
   report and of the sweep, done after the defects (Q85). Then what the archive of forward
   carriers (`docs/research/forward-carriers.md`) filed: the rates of `ppng.io`'s road and of the
   Wisp demo server through podssh (T-625), TURN with RFC 6062 for a server that the user runs
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
| T-496 | T-086 is done: the pairing's exchange exists over a mailbox |
| T-499 | draft-ietf-httpbis-connect-tcp is an RFC, and a server over HTTP/2 or HTTP/1.1 implements it |
| T-545 | T-086 is done: the pairing's exchange exists over a mailbox |
| T-566 | T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists |
| T-567 | T-565 is done: the module for a tunnel of HTTP made by `ssh -R` exists |
| T-575 | T-497 is done: the road has public servers in order |
| T-622 | T-319 is done: the HTTP road's split and serial forms exist |
| T-757 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-758 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-759 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-760 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-761 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-762 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-763 | GitHub #224's author lifts [DEFERRED], or the owner orders it |
| T-764 | GitHub #225's author lifts [DEFERRED], or the owner orders it |
| T-765 | GitHub #225's author lifts [DEFERRED], or the owner orders it |
| T-766 | GitHub #225's author lifts [DEFERRED], or the owner orders it |
| T-767 | GitHub #225's author lifts [DEFERRED], or the owner orders it |
| T-768 | GitHub #225's author lifts [DEFERRED], or the owner orders it |

## Questions for the operator

No question is open. Below are the questions asked so far and how they were settled, each
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

**For the operator to confirm (Q86), from the triage of GitHub #127 to #148 and the study of osewa
(2026-11-04)**; each call is in its entry's `## Decision`, and the work goes on with it:

- T-638 (#136): a forward token of the relay role stays good for each target that its policy
  dials, and a grant stays bound by its issuer's door (Q4, T-226); the issue calls both defects.
  Its draft (2026-11-05) asks the person of `--ask` after the door, never in its place: a yes lets
  in no key that the door refuses, where the issue asked that an approval alone let a device in.
- T-640 (#138): a node writes each line to the journal's own socket only when its stderr is that
  journal's stream already: not an outbound connection under rule 2.
- T-641 (#139): `doctor`'s line `nat` runs unasked against `stun.cloudflare.com:3478` and
  `stun.l.google.com:19302`, off with `PODSSH_STUN=no`.
- T-642 (#140): Encrypted Client Hello only when the user asks for it; the read of a name's HTTPS
  record before the session is then a read before a session, as Q96 and Q97 are.
- T-643 (#141): an operator that offers the net's document to a node that answers without it goes
  on, with a line that says so, where the issue asks for a refusal.
- T-644 (#142): `relay serve --sshd ADDR:PORT` dials the owner's sshd by the role's way out, the
  loopback and what `NO_PROXY` names directly and another address through `HTTPS_PROXY`, where its
  Approach had the dial always direct (rule 2); ADDR is an address, never a name; no limit, token
  or brake of the contract stands before the sshd, which sees each client as the role's address.
- T-649 (#147): a CA's validation (`acme-tls/1`) of a name that `relay serve --publish` publishes
  goes to its node, so that the node can prove the name, where the issue sends each validation to
  the role; PAIR is a pair's name, read at the start, so a new pair is published by a restart of the
  role with `--pairs FILE`; a visitor slower than its node meets the contract's bound of 1 MiB.
  Its draft (2026-11-05) is unbuilt.
- T-667 (osewa): QUIC and a TCP road race to one host for a short time, as the race between relay
  hosts does (rule 2), the loser closed at once; QUIC goes first, 300 ms ahead, to a role that
  offered it, where Q82 puts other projects' roads over UDP after TCP.

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

- **The secrets of the throughput host** (2026-11-12): `PODSSH_THROUGHPUT_SSH` and
  `PODSSH_THROUGHPUT_KEY` are not set in PodUtils/podssh's Actions (the runs of `wisp-rate.yml`,
  43285906667, and `iroh-ab.yml`, 43286058774, said so and stopped). The operator's server of Q38 is
  reached only with them: T-625's step 2 (the Wisp demo's rate), T-665 (the A/B of QUIC's settings)
  and T-463's live run wait. Set both in the repository's settings (Secrets and variables, Actions);
  a session cannot.

- At any time: require the status `all` of the workflow `build` for `main`, if the operator wants a
  required check (T-212); `main` requires none today.
- Dependabot's updates reach `main` through a session (`docs/decisions.md`).
- After the release: a run of T-004 and T-005 in a real sandbox, with the brief of
  `scripts/sandbox-check.sh`.
- The facade of `podssh-relay` for podvm (T-081, T-085): podvm takes `pod-relay`'s feature
  `blocking` by a tag (Q103).
- As the operator of the default relay, at any time and with no entry waiting: the notes of
  `docs/relay-operator.md`, each of which podssh's own relay role does since Q63.
