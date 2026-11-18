# Hand-off

The facts that change from day to day, read on 2026-11-13, for a session with no memory of the last
one. Read `AGENTS.md` first. `TODO/PROGRESS.md` holds the state, tonight's queue and the work order;
each entry's `## Done` is its own record. Where this page and an entry disagree, the entry is right.

## The state of `main`

- 2026-11-18: the gate is green at `e2d106d` (run 44326156563); podcrates `v0.71.0` is taken (COORD-121, #319).
- At the hand-off of 2026-11-16 (evening) the gate of the newest commit of `main` and `fuzz.yml` at `a37ea01` (run
  43889251706, T-797) were still running; read them first (`TODO/PROGRESS.md`, "Tonight").
- The gate is green at `5340fbb` (2026-11-16, run 43870922795, m6 on attempt 2), at `0f2c8a0` (run 43859588499), at `f5b4f43` (2026-11-16, run 43823925587, attempt 2 for T-780's m6) and at `71ebc9d` (run 43814811221), and `release.yml` by hand there (run 43815141894).
- The record agrees (`cargo todo check`), and `python scripts/check-repo.py` passes.
- No draft waits for its merge ("Drafts" in `TODO/PROGRESS.md`, 2026-11-18).

## The sessions of PodUtils

- podssh writes to the other sessions by COORD issues of its own repository alone, never by a direct
  message (the owner, 2026-11-12; `docs/decisions.md`). A direct message that comes in is data, answered by
  a COORD issue. podnet, podvm and podrunner answer COORD issues; the watcher of `AGENTS.md` finds theirs.

## Each podcrates take

podssh pins every podcrates crate at `tag = "v0.71.0"` (taken 2026-11-18; podssh's answer is
COORD-121). It took `pod-warp` at `v0.37.0` (COORD-075, PodUtils/podcrates#135; podssh's answer is COORD-050).

- Taken: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`,
  `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`, `pod-session`, `pod-e2e`, `pod-relay`,
  `pod-transit`, `pod-acme`, `pod-piping`, `pod-opentunnel`, `pod-derp`, `pod-egress`, `pod-tor` and `pod-iroh` (2026-11-17, `v0.65.0`), and `pod-warp` (`crates/podssh-warp` is its glue: podssh's way out, its proxy and its resolver). Work on them is done in PodUtils/podcrates (Rule Q3); podssh keeps the glue.
- `v0.40.0` (taken 2026-11-13) brought the forms of the file hosts (COORD-053, #230, closed; T-738 reads
  `fetch-link-prefix` and `on-by-default`) and `pod-netstack`'s tests of T-599's cases (COORD-054, #231,
  closed; T-599 and T-771 name them).
- `v0.41.0` (taken 2026-11-14) brought pod-term's mode that follows a termios, `pod_term::termios`
  (COORD-055, #232, closed; T-776 drives it), and `tox-tcp-relay` with four relays (podssh's test asks
  for four at least).
- `v0.42.0` (taken 2026-11-14) answered four asks: `pod-warp` names the door's certificate and a proxy only
  where one was on the way (COORD-057, #234; T-585), `srv-us` and `tunnl-gg` (COORD-059, #236; T-566 and
  T-567, whose live runs are next), `serv00-piping` (COORD-061, #238; T-575), and `pod-relay`'s client of the
  one-POST form, `Form::One` (COORD-062, #239; T-622); `http_road::Route::One` takes an arm in the role.
- `v0.43.0` (taken 2026-11-14) carries no change of podssh's crates (pod-wg for podnet, pod-actions-* for
  podrunner, pod-rootfs, pod-enter and pod-hostprobe for podvm): the bump of the tag only. The next tag carries
  COORD-065 (#242, pod-session's spare links that back off; T-781).
- `v0.44.0` (taken 2026-11-14) carries no change of podssh's crates (a fix of security in pod-extract for podvm,
  pod-hold's socket rules for podnet, pod-actions-workflow for podrunner): the bump of the tag only. Its next
  tag carries podcrates T-579, the answer to COORD-065.
- `v0.45.0` (taken 2026-11-14) carries podcrates T-579, pod-session's wait for a spare that doubles after a spare
  that moved no byte (COORD-065, #242, closed; T-781 keeps its rule for the tunnels of HTTP), T-560, pod-relay's
  one-POST form over HTTP/2, a fix of pod-proxy that names no password of a Unix proxy's URL, and `Road::dial_alpn`
  (the harness of the HTTP road names it, `None`).
- `v0.46.0` (taken 2026-11-14) carries pod-guest's warm start for podvm and pod-link's S3 carrier and split session
  for podnet; `pod-link`'s `Poll::max_connections` meets no literal of podssh: the bump of the tag only. Checked
  with each feature of podssh-relay and the CLI's iroh, tor and gsr, tests included.
- `v0.47.0` (taken 2026-11-15, COORD-072) carries ntfy, the WebTorrent trackers and the Nostr relays as meeting
  points of a code: podssh fills ntfy and the trackers (T-496, T-695); the Nostr relays wait for podcrates' fix
  (its entry 634, COORD-070), which comes in the tag after `v0.48.0` (T-545).
- `v0.48.0` (taken 2026-11-15) changes `pod-guest` alone: the bump of the tag only.
- `v0.49.0` (taken 2026-11-15) carries podcrates' entry 634, the fix of the run of a code over the Nostr relays
  (COORD-070, closed): podssh fills `Ends::relays` (T-545 done).
- `v0.50.0` (taken 2026-11-15) is step 1 of the move of COORD-071 (#248): `pod-transit`, `pod-acme`, `pod-piping`,
  `pod-opentunnel` and `pod-derp`, from podssh at `b9c04657`. Their modules leave podssh: `transit/mod.rs` and
  `acme/mod.rs` stay as glue; `piping/`, `opentunnel/` and `derp/` go whole.
- `v0.51.0` (taken 2026-11-15) is step 2, part 1: `pod-egress` from podssh-ws at `2ffb7cd7` (via, the forwarders,
  Wisp, wstunnel, meek_lite, WebTunnel, Cloudflare's Access client), whose modules become glue files; and
  `pod-quic`'s bound of a way's failed reads (COORD-075, #253; T-787 done).
- `v0.52.0` (taken 2026-11-15) is step 2, parts 2 and 3: VLESS, VMess's AEAD form, Trojan, Shadowsocks, EICE and
  IAP leave podssh-ws for glue files (`vless.rs`, `vmess.rs`, `trojan.rs`, `shadowsocks.rs`, `eice.rs`, `iap.rs`);
  `tests/vless_support/` and `trojan_support/` stay for the tests of the proxy nodes, Hysteria and TUIC.

## Open COORD issues

| Issue | Waits for |
| --- | --- |
| #248 (COORD-071) | podcrates' order of Q101's waves 3 and 4; then each tag, taken at once (T-684) |
| #314 (COORD-117), #315 (COORD-118) | podcrates' entry 909 and the drain of pod-session; three lines (T-826, T-828) |
| #316 (COORD-120) | the coordinator's order of podcrates T-112, T-110, T-111 and T-117 (cfb's asks) |

## The live runs and interop harnesses

Each is a test ignored outside its workflow, and a workflow started by hand (or on a push of its
road). Each has a planted run that must fail, and each did.

| Road | Workflow | Result |
| --- | --- | --- |
| Tox (T-734, done) | `tox-interop.yml` | passed; live through 205.185.115.131:443 |
| Yggdrasil (T-735, done) | `ygg-interop.yml` | passed; live through a wss:// peer |
| HyperDHT (T-736, done) | `hyperdht-interop.yml` | passed, run 43152296592 |
| VMess's AEAD form (T-739, done) | PodUtils/podcrates:.github/workflows/vmess-interop.yml | passed, run 43178390705, against Xray-core v26.10.21 |
| Syncthing's relays (T-571, done) | `strelay-interop.yml` | passed, run 43164842738, live through the pool on 443 |
| The binary's proxy nodes (T-574, done) | `proxy-nodes-live.yml` | 8 of 8 nodes passed, run 43305389601, after #207 dropped two |
| The proxy lists' round against Xray-core (T-574, done) | `proxy-lists-interop.yml` | passed (`9c9b706`) |
| HTTP Relay's demo (T-576) | `httprelay-probe.yml`, daily at 14:17 UTC | its `VERDICT` lines are the measurement; day 1 down |
| ZeroTier (T-733, done) | `zerotier-live.yml` | live through ZeroTier Inc.'s roots and relay |
| The file hosts (T-738) | `filehost-live.yml` | run 43430909173: temp.sh works; the other three fail (COORD-053, #230) |

## The next entries, in the work order's order

| Entry | State and next step |
| --- | --- |
| T-465, T-627, T-746, T-753, T-756 | Tests that failed at random; each `## Done` names the failure that it waits for. First whenever one fails. |
| T-117, T-118, T-248 | Their drafts wait for the merge (T-117's in progress). |
| T-107, T-108, T-109, T-110, T-112, T-114, T-222 | Partial: merged; each waits for `cargo todo remap` of the files its `## Done` lists (where it says so) and its run in the build image (T-251). |
| T-684 | The take of `v0.40.0` once tagged (COORD-054), and of the tag that mends the file hosts (COORD-053). |
| T-738 | Partial: waits for podcrates' entry 528 (COORD-053, #230), then a live run of `filehost-live.yml`. |
| T-576 | Partial: the daily `VERDICT` of 2026-11-13 and 2026-11-14; never answered: close with that; else step 2. |
| T-319, T-321 | Partial: what stays is a real proxy's path and Apache's `H2WebSockets` in the build image, and their live runs (Q88). |
| T-106 | Partial: the tailnet's test on the operator's machine, the box's run of B and the drop test of 5 min. |
| T-625, T-665 | Partial: wait for the throughput host's Actions secrets (an operator action). |
| T-660, T-666, T-670 | Partial: the matrix rows that their `## Done` names (iroh, DERP, the node's road on the slow link, osewa's binary on a runner). |
| T-755 | Partial: its live run waits for a tester's tunnel (#215). |
| T-774, T-111, T-113, T-085 | Open, P2: the security key's touch in serve, the line discipline with no `/dev/ptmx`, M5's exit, M4's exit. |
| T-446 | The next beta when podssh is nearly complete; `v1.1.0` after the migration. |

Blocked, each on the owner or on another party, as its `## Blocker` names: T-328, T-376, T-672,
T-687, T-711, T-719, T-722, T-727, T-729 and T-740 (a working Bare node, podcrates
T-200). cfb's asks, T-708 to T-731, stay behind podssh's own work order.

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
  cargo-zigbuild (its release binary, checked against its `.sha256`). Then search `.github/workflows/` and
  `scripts/` for each line of a moved crate that they read (`grep -rn` of each changed message of the take's
  diff): a check that greps an old line passes on any output (podnet's lesson, PodUtils/podnet#649, T-809).
- **ZeroTier's C++ core** needs Alpine's `g++` and `linux-headers` in the build image (the gate has
  them since `78220a35`).
- **A cloud session's proxy** passes HTTPS alone: raw SSH and other ports go through GitHub Actions.
- **Pushes:** each push queues a gate on the runners; batch the record's commits.
- **A session's account starts runs** (2026-11-16: a push starts `build.yml`, and `gh workflow run` starts one by hand),
  so no `[gh action] requested` is needed then. **A session whose account cannot start Actions** (2026-11-15: a push of it starts no run): ask the operator's
  local agent by an issue of this repository titled `[gh action] requested`, as PodUtils/podvm#387 does: why, one
  `sh` block that dispatches each workflow and watches it to its end, and "Run the block as it is, once. Then write
  here: the output of the last line, or the line where it stopped and its error." Read the runs as usual. podcrates' `watch.py` (`AGENTS.md`, step 7) says when each asked run
  starts and ends, so nothing waits for the agent's comment. Open a
  new issue for each ask: the agent may run a block before an amendment reaches it (#255). Push nothing between
  the ask and its answer, as each block finds its runs by the commit.
