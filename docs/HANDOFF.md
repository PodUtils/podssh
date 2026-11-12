# Hand-off

The facts that change from day to day, read on 2026-11-12, for a session with no memory of the last
one. Read `AGENTS.md` first. `TODO/PROGRESS.md` holds the state, tonight's queue and the work order;
each entry's `## Done` is its own record. Where this page and an entry disagree, the entry is right.

## The state of `main`

- Read on 2026-11-12. The gate at `adeae2eb` failed on one cause: `no_permissive_verifier` did not
  know strelay's verifier (T-571), which pins a relay's device ID. `38070687` repairs it; read the
  newest run of `build.yml` first. The gate before it, at `0872c2c6` (the take of `pod-relay`), failed
  on pod-relay's words, which `adeae2eb` repaired.
- The record agrees (`cargo todo check`), and `python scripts/check-repo.py` passes.
- No draft waits: `draft/t739-vmess` is merged (T-739, done).

## The sessions of PodUtils

- podssh and podcrates talk by direct messages (`send_message` to the podcrates session; its id is
  in that session's own messages) and record each take as a COORD issue. podnet, podvm and
  podrunner answer COORD issues; the watcher of `AGENTS.md` finds theirs.

## Each podcrates take

podssh pins every podcrates crate at `tag = "v0.30.0"` (COORD-057, PodUtils/podcrates#89; podssh's
report is COORD-038, #212).

- Taken: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`,
  `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`, `pod-session`, `pod-e2e` and `pod-relay`.
  Work on them is done in PodUtils/podcrates (Rule Q3); podssh keeps the glue.
- The next tag: nothing that podssh asked for waits in it.

## Open COORD issues

| Issue | Waits for |
| --- | --- |
| (none) | #209 and #210 are answered by v0.30.0 |

## The live runs and interop harnesses

Each is a test ignored outside its workflow, and a workflow started by hand (or on a push of its
road). Each has a planted run that must fail, and each did.

| Road | Workflow | Result |
| --- | --- | --- |
| Tox (T-734, done) | `tox-interop.yml` | passed; live through 205.185.115.131:443 |
| Yggdrasil (T-735, done) | `ygg-interop.yml` | passed; live through a wss:// peer |
| HyperDHT (T-736, done) | `hyperdht-interop.yml` | passed, run 43152296592 |
| VMess's AEAD form (T-739, done) | `vmess-interop.yml` | passed, run 43178390705, against Xray-core v26.10.21 |
| Syncthing's relays (T-571) | `strelay-interop.yml` | passed, run 43164842738, live through the pool on 443 |
| The binary's proxy nodes (T-574) | `proxy-nodes-live.yml` | 8 of 10 nodes passed, run 43157171177 |
| HTTP Relay's demo (T-576) | `httprelay-probe.yml`, daily at 14:17 UTC | its `VERDICT` lines are the measurement |
| ZeroTier (T-733) | `zerotier-live.yml` | the library passed; the command line misses its 60 s |

## The next entries, in the work order's order

| Entry | State and next step |
| --- | --- |
| T-571 | Partial. The list is read; its live job must run once more with the lab's switch removed (`strelay-interop.yml`, by hand), then close. |
| T-737 | Done (2026-11-12): live through shiftr.io's broker. |
| T-576 | Partial. Read the `VERDICT` of `httprelay-probe.yml` on three days; never answered: close with that; else step 2. A cloud session cannot measure it: its agent proxy fails the demo's certificate. |
| T-578 | Partial. Tested on chutney and live on Tor's own network (329 s). Next: a test of the command line from end to end on chutney, then pkarr's `onion=`. |
| T-738 | Open: file hosts as the last carrier of the resumable layer. |
| T-739 | Done (2026-11-12): against Xray-core v26.10.21 on the loopback; `vmess-interop.yml` passed from Actions (run 43178390705). |
| T-580 | Done (2026-11-12): against Hysteria's own server; `hysteria-interop.yml` from Actions. |
| T-581 | Done (2026-11-12): `--tuic` for ssh, proxy and doctor; `tuic-interop.yml` from Actions. |
| T-582, then the rest | As `TODO/PROGRESS.md`, item 12, orders them. |
| T-753 | Waits for the next failure of the Windows test (50 runs in 50 passed). |
| T-733 | A live run of `zerotier-live.yml` with `PODSSH_ZT_TRACE=1` to find where the members' 31 s to 90 s go. |
| T-746, T-465, T-627 | Tests that failed at random; each `## Done` names the failure that it waits for. |
| T-684, T-446 | Each next podcrates tag; `v1.1.0` waits for the end of the migration. |

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
  cargo-zigbuild (its release binary, checked against its `.sha256`).
- **ZeroTier's C++ core** needs Alpine's `g++` and `linux-headers` in the build image (the gate has
  them since `78220a35`).
- **A cloud session's proxy** passes HTTPS alone: raw SSH and other ports go through GitHub Actions.
- **Pushes:** each push queues a gate on the runners; batch the record's commits.
