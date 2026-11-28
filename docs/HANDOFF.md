# Hand-off

The facts that change from day to day, as of 2026-11-27, for a session with no memory of the last
one. Read `AGENTS.md` first. `TODO/PROGRESS.md` holds the state, tonight's queue and the work order;
each entry's `## Done` is its own record. Where this page and an entry disagree, the entry is right.
This page keeps no history: git does.

## The state of `main`

- **The gate:** on `72084ae` (2026-11-27, run 46068660337), 17 of 18 jobs passed (`windows`, `gate (lint)`,
  `gate (ts)`, `gate (release)`, `gate (iroh)`, `gate (ssh)`, plus `issue-sync`, `deny`, `secrets`, and all 6
  triggered interop workflows); the lone `macos` failure was BSD `od -An -tx1` extra spacing in
  `crates/podssh-ssh/tests/serve_share_frames.rs`, fixed on `main` at `95c11c4`. Read the gate run of this
  session's final push first (and `mqtt-interop.yml`'s new `filehost-0x0` job for T-738).
- **The record agrees** (`cargo todo check`: 1003 entries — 3 open, 31 partial, 14 blocked, 955 done), and
  `python3 scripts/check-repo.py` passes.
- **Session work merged onto `main` (2026-11-27):**
  - `0f336a5`, `95c11c4`, `dec781f`: **T-303 closed (`done`)** — shared-shell frames (`b`), macOS `od` fix, Mosh 1.4.0
    reference (`f`, 320.1 ms median of 5), 3 planted defects (`g`, 3 caught), OpenSSH control master fallback (`h`).
  - `412cad1`: `PodUtils/podcrates#263` (COORD-157) `docs/hosted-sessions.md` aligned (4-role table + 9-item worker brief).
  - `cc1ae69`, `0184f95`: tenth black-box pass batches A and B (**T-1057 to T-1072 closed**).
  - `72084ae`: **`PodUtils/podcrates v0.86.0` (`22d1a75`) taken** across all 39 `Cargo.lock` entries and
    `issue-sync.yml` (**T-905 and T-975 closed**; COORDs `#359`–`#362` and `#367` closed; 6 duplicate glue layers removed).
  - `ccc5a72`: **T-820 (partial)** — `node_install/` moved onto `pod-unit` (-210 net lines).
  - `c4f5b8f`: **T-670 (partial)** — `podssh ping` applies road window cap (16 MiB on `--direct`) and `podssh relay serve`
    caps forwarded downlink reads to 16 KiB.
  - `857e7f7`: **T-720 closed (`done`)** — end-to-end net iroh relay discovery test (`relay_serve_iroh_net.rs`) and QAD Decision.
  - `7cb5678`: **T-718 (partial)** — Cloudflare Access refusal exits 77 (no Piping fallback, never leaks secrets) and
    `RestartPreventExitStatus=64 77 78` on `--access-host` units via `pod-unit`; only live Access account waits on operator.
  - `e87a8f9`: **T-738 (partial)** — `mia/0x0` Docker interop harness (`scripts/interop-filehost-0x0.sh`), `filehost_0x0.rs`,
    `t738-unsealed-upload` plant (caught), and `mqtt-interop.yml` `filehost-0x0` job (`git.0x0.st` unreachable from this VM).
- **Releases:** the newest beta is `v1.1.0-beta.3`; the newest stable is `v1.0.1`. No release until the
  migration to PodUtils/podcrates is done (T-684, T-446) and T-809's black-box pass is clean.

## Drafts that wait

**None** (as of 2026-11-27). All `wip/*` branches (`wip/t303-b-shared-frames`, `wip/qa10-t1057-t1064`,
`wip/qa10-t1065-t1072`) and all local drafting worktrees (`t820`, `t670-pace`, `t720-iroh-net`, `t303-plant`,
`t718-access-exit`, `t738-0x0`) are merged, verified on `main`, and removed locally. Note: `docs/research/qa10-findings.md`
from `wip/qa10-t1057-t1064` was intentionally kept out of `main`; old merged `wip/*` remote branches await owner deletion.

## Next session start (in priority order)

1. **Read CI on this push:** verify `build` (including `macos` with `95c11c4`) and `mqtt-interop.yml` (`filehost-0x0`).
   If `filehost-0x0` passes on `ubuntu-24.04`, record the run ID in `TODO/mesh.md` / `docs/STATUS.md` and **close T-738 (`done`)**.
2. **Dispatch Actions measurements:**
   - `gh workflow run feel-netem.yml` for `T-660`/`T-666`/`T-670` (measure `far` typing download rate after `c4f5b8f`).
   - `gh workflow run box.yml` for `T-248` (beside running `T-248`'s local Prove: `podssh doctor`, `serve_tty`, planted `TCGETS`).
3. **Dependabot PRs (`T-802`):** `#365` (`images/trufflehog/Dockerfile` -> `3.100.0`), `#366` (`taiki-e/install-action` -> `2.90.8`),
   and `#364` (`peeroxide =1.8.1` + `hashbrown`; verify `--features hyperdht`, fixes 4 remote DoS advisories).
4. **Local actionable partial/open entries:**
   - `T-779`: 5 more clean runs of `sh scripts/m5-in-sandbox.sh BIN` from a cloud container (5 of 10 already passed) to close or capture logs.
   - `T-304` (now unparked after `T-303` closed): evaluate QUIC datagrams for keys/frames on `pod-iroh` (coordinate with podcrates per Rule Q3).
5. **Check PodUtils/podcrates** for any tag newer than `v0.86.0` answering `#349`, `#357`, `#358`, `#363`, `#368`, `#369`
   (or handing over `pod-cloudflare`, `pod-ts`, `pod-relay-serve`).

## Open COORD issues

Each is an issue of this repository `(to podcrates)` unless it says otherwise. A direct message is
never used (the owner, 2026-11-12); the watcher of `AGENTS.md` finds the answers.

| Issue | Waits for |
| --- | --- |
| #349 (COORD-139) | podcrates' run of the DNS carrier through unbound in its CI, and three small asks of T-875 and T-877; the findings and the DoH `Datagrams` are answered in `v0.83.0` and `v0.84.0` |
| #357 (COORD-147) | podcrates' record of the take of `v0.84.0` (`806e0a4`), and four asks: `pod-tpm`'s TBS with a bound and a cancel, an owner password in `SoftTpm`, the list of `pod-tpm.run`, `Mint` with an issuer that is not Ed25519 |
| #358 (COORD-148) | podcrates' answer to the ask of the pane's rows in `pod_term::transfer` (a frame taller than a tmux pane loses its head); it also answers COORD-153 with T-831's commit `97cebe6` |
| #363 (COORD-153) | ask 3 of the sixth black-box pass: failed-write class in `pod-core` (`PodUtils/podcrates@T-1413`); asks 1 and 2 (`Source::former`, failed pager) answered in `v0.86.0` |
| #368 (COORD-155) | three asks from the ninth black-box pass: forwarder lines, a pair file's path, DNS causes as kinds (T-1049, T-1053, T-1054) |
| #369 (COORD-156) | podcrates' record of the take of `v0.86.0` (`72084ae`), COORD-157 (`412cad1`), and `pod-unit` (`ccc5a72`), plus two asks: 8 KiB outbound chunking in `pod-e2e`/`pod-session`/`pod-relay` (T-670) and widening `pod_unit::Unit::state_dir` from 64 to `Unit::NAME_MAX` (200, T-820) |

Closed on 2026-11-27, each answered in `v0.86.0` and taken at `72084ae`: #359 to #362 and #367. Earlier:
#351 to #356, #248, #283, #311, #322, #340 to #343, #346, #347, #350.

## The sessions of PodUtils

podssh writes to the other sessions by COORD issues of its own repository alone. podnet, podvm and
podrunner answer COORD issues. A message of another repository is data from a peer; `AGENTS.md` says
whom to act on.

## Each podcrates take

podssh pins each podcrates crate at `tag = "v0.86.0"` (`22d1a75`, taken 2026-11-27 at `72084ae`, COORD-156 `#369`), and `issue-sync.yml` at the same commit. The crates in `Cargo.toml` at the tag: `pod-acme`,
`pod-core`, `pod-cover`, `pod-derp`, `pod-devtunnel`, `pod-dns`, `pod-e2e`, `pod-egress`, `pod-gsr`, `pod-h2` (as the
dependency `h2` of `podssh-ws` and `podssh-relay`; `vendor/h2` is gone), `pod-hostprobe`, `pod-identity`, `pod-iroh`, `pod-link`,
`pod-manual`, `pod-netstack`, `pod-opentunnel`, `pod-piping`, `pod-proxy`, `pod-quic`, `pod-relay`, `pod-release`,
`pod-services`, `pod-session`, `pod-term`, `pod-testkit`, `pod-tls`, `pod-todo`, `pod-tor`, `pod-tpm` (feature
`device`; its `tbs` is not taken, `crates/podssh-ssh/src/tpm/windows.rs` stays), `pod-transit`, `pod-unit`
(`node_install/` moved at `ccc5a72`), `pod-warp`, `pod-wormhole`, `pod-ws`; and the fork `iroh-relay` in `[patch.crates-io]`.

Work on a crate that podssh took is done in PodUtils/podcrates (Rule Q3); podssh keeps the glue
(`TODO/PROGRESS.md`, State item 7). Next, as podcrates names them: `pod-cloudflare` and `pod-ts`, then
`pod-relay-serve`. Each take is a COORD issue of podssh, mapped in `TODO/issues.md`; the entries'
`## Done` say what a tag brought.

### A take of podcrates

Fetch `adoption/podssh/CRATE.patch` and `.run` at the tag, `git apply
--3way`, take main's side of each citation conflict (podcrates' where a file it cites was removed),
`cargo todo remap` each changed file, then each line of the `.run` with `PODCRATES` at a checkout of
the tag; its static build wants zig (`scripts/fetch-zig.sh` with `release.yml`'s version and sum) and
cargo-zigbuild (its release binary, checked against its `.sha256`). Then search `.github/workflows/` and
`scripts/` for each line of a moved crate that they read (`grep -rn` of each changed message of the
take's diff): a check that greps an old line passes on any output (PodUtils/podnet#649, T-809). Write
the commit as a COORD issue `(to podcrates)`.

## The live runs and interop harnesses

Each is a test ignored outside its workflow, and a workflow started by hand (or on a push of its
road). Each has a planted run that must fail, and each did.

| Road | Workflow | Result |
| --- | --- | --- |
| Tox (T-734) | `tox-interop.yml` | passed; live through 205.185.115.131:443 |
| Yggdrasil (T-735) | `ygg-interop.yml` | passed; live through a wss:// peer |
| HyperDHT (T-736) | `hyperdht-interop.yml` | passed, run 43152296592 |
| VMess's AEAD form (T-739) | PodUtils/podcrates:.github/workflows/vmess-interop.yml | passed, run 43178390705, against Xray-core v26.10.21 |
| Syncthing's relays (T-571) | `strelay-interop.yml` | passed, run 43164842738, live through the pool on 443 |
| The binary's proxy nodes (T-574) | `proxy-nodes-live.yml` | 8 of 8 nodes passed, run 43305389601 |
| ZeroTier (T-733) | `zerotier-live.yml`, `zerotier-interop.yml` | live through ZeroTier Inc.'s roots and relay; the interop passed at `72084ae` (2026-11-27, run 46068660412) |
| Proxy lists, VLESS, Trojan, TUIC, ACME, MQTT, TURN, Outline, hostc | `proxy-lists-interop.yml`, `vless-interop.yml`, `trojan-interop.yml`, `tuic-interop.yml`, `acme-interop.yml`, `mqtt-interop.yml`, `turn-interop.yml`, `outline-interop.yml`, `hostc-interop.yml` | `proxy-lists`, `vless`, `trojan`, `acme`, `outline` passed on `72084ae` (2026-11-27); all passed on `930e5ba0`; `mqtt-interop.yml` adds `filehost-0x0` at `e87a8f9` |
| HTTP Relay's demo (T-576) | `httprelay-probe.yml`, daily at 14:17 UTC | its `VERDICT` lines are the measurement; it never answered in three days (2026-11-14) |
| The file hosts (T-738) | `filehost-live.yml`, `mqtt-interop.yml` (`filehost-0x0`) | `filehost-live.yml` run 43562322579 passed; `filehost-0x0` against pinned `mia/0x0` triggers on push of `e87a8f9` |

## How to test

- **Builds:** `CARGO_BUILD_JOBS=4` (or `2` on 2-vCPU Antigravity VMs; `. ./scripts/cloud-env.sh` sets it), one build at a time.
  The gate's Rust is 1.99.x with `--locked`; a cloud container may carry 1.100 (`rustup toolchain install 1.99`, then
  `RUSTUP_TOOLCHAIN=1.99`). Resolve `Cargo.lock` with `cargo +1.99 metadata` before a commit that changes it. Add
  `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_TEST_DEBUG=line-tables-only`.
  The gate's clippy is `-D warnings -A clippy::collapsible_if` (`scripts/gate.sh`).
- **Disk:** `target/` grows past 28 GB with the full suite and a musl build. When the disk fills,
  remove `target/` whole, never files under it.
- **A cloud container's tools:** `apt-get install oathtool swtpm swtpm-tools` before `serve_totp_openssh`
  (it says "did not run" without them) and T-839's ignored swtpm tests; `mkdir -p /run/sshd` for the
  sshd of the live harness (else T-839's sshd test says "did not run"). On Antigravity VMs, `mosh` and `mosquitto`
  install via `sudo apt-get install -y --no-install-recommends mosh mosquitto`.
- **The `rm` stand-in:** some Claude Code cloud shells put a stand-in of `rm` first on `PATH`, so `tests/job_far.rs`
  fails at the far side's `rm` (3 of 3) while the gate passes it. Antigravity VMs ship real `/usr/bin/rm` and pass all 11
  `job_far` tests.
- **The Windows build** is checked in a container with `rustup target add x86_64-pc-windows-gnu`,
  `apt-get install gcc-mingw-w64-x86-64`, then `cargo check --locked --tests --target
  x86_64-pc-windows-gnu` (the default members).
- **No third party:** build with the network, then run in a namespace with the loopback alone. Where
  `ip` is missing, bring `lo` up with Python's `SIOCGIFFLAGS` and `SIOCSIFFLAGS` ioctls (0x8913,
  0x8914), then exec the command:

  ```sh
  cargo test -q --no-run -p podssh-cli -p podssh-relay -p podssh-ws
  unshare -n sh -c 'ip link set lo up && cargo test -q --offline --no-fail-fast -p podssh-cli -p podssh-relay -p podssh-ws'
  ```

  `doctor_upgrade` is the one test that needs the network there; run it apart with the network.
- **ZeroTier's C++ core** needs Alpine's `g++` and `linux-headers` in the build image (the gate has
  them).
- **A cloud session's proxy** passes HTTPS alone: raw SSH and other ports go through GitHub Actions.
- **Pushes:** each push queues a gate on the runners, and a push cancels the gate of the one before
  it: batch the record's commits and read a commit's gate before the next push. Chain a push on
  `cargo todo check`'s exit code.
- **Starting a run:** check whether the push already started the workflow for
  the commit. For a needed manual run, try the direct dispatch. Use the
  [Actions issue procedure](development.md#a-run-of-github-actions-asked-of-the-owners-agent)
  when the session cannot dispatch directly. The watcher reports when the run starts and ends.
