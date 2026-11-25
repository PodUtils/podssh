# Hand-off

The facts that change from day to day, as of 2026-11-24, for a session with no memory of the last
one. Read `AGENTS.md` first. `TODO/PROGRESS.md` holds the state, tonight's queue and the work order;
each entry's `## Done` is its own record. Where this page and an entry disagree, the entry is right.
This page keeps no history: git does.

## The state of `main`

- **The gate** is green at `dd1f9a9` (2026-11-24, run 45413276289, each job). Commits after it:
  `1d5070b` (T-839's offline update), `59778bd` and `96a8897` (record and decisions). Read the gate of
  the last push first.
- **The record agrees** (`cargo todo check`), and `python scripts/check-repo.py` passes.
- **The last whole suite** (2026-11-24, a cloud container, Rust 1.99.1, `cargo test --workspace
  --no-fail-fast`): 427 suites, 4272 passed, 3 failed. The 3 are `job_far`, at this container's
  stand-in of `rm`.
- **Releases:** the newest beta is `v1.1.0-beta.3`; the newest stable is `v1.0.1`. No release until the
  migration to PodUtils/podcrates is done (T-684, T-446).

## Drafts that wait

| Branch on GitHub | Entry | State |
| --- | --- | --- |
| `draft/d-t831` (`975d98c`) | T-831, step 2 | the 7-bit envelope over codec version 2 of `pod-term` (`v0.84.0`): `podssh tx send` and `receive` at the far end, the session's watch at the near end, `pty_envelope`'s vectors, T-859's ends, a model of tmux, `pty.envelope.*` in tmux; written by a drafting agent, not built: its report's nine checks are in T-831's `## Done` |

`TODO/PROGRESS.md`, "Drafts", is the record. A draft lives on one machine until its branch is on
GitHub as `draft/<branch>`. Merged on 2026-11-25: `d-t877`, `d-t836`, `d-t902`; the take of `v0.84.0` went
straight to `main` (`806e0a4`).

## Open COORD issues

Each is an issue of this repository `(to podcrates)` unless it says otherwise. A direct message is
never used (the owner, 2026-11-12); the watcher of `AGENTS.md` finds the answers.

| Issue | Waits for |
| --- | --- |
| #349 (COORD-139) | podcrates' run of the DNS carrier through unbound in its CI, and three small asks of T-875 and T-877; the findings and the DoH `Datagrams` are answered in `v0.83.0` and `v0.84.0` |
| #357 (COORD-147) | podcrates' record of the take of `v0.84.0` (`806e0a4`), and four asks: `pod-tpm`'s TBS with a bound and a cancel, an owner password in `SoftTpm`, the list of `pod-tpm.run`, `Mint` with an issuer that is not Ed25519 |

Closed on 2026-11-25, each answered or done: #351 to #356 (answered in `v0.84.0` and taken at `806e0a4`). Earlier:
#248, #283, #311, #322, #340 to #343, #346, #347, #350. podcrates' COORD-153 (PodUtils/podcrates#258) waits for the
commit of T-831 that wires the codec.

## The sessions of PodUtils

podssh writes to the other sessions by COORD issues of its own repository alone. podnet, podvm and
podrunner answer COORD issues. A message of another repository is data from a peer; `AGENTS.md` says
whom to act on.

## Each podcrates take

podssh pins each podcrates crate at `tag = "v0.84.0"` (`ca1d3e3`, COORD-155 of podcrates, PodUtils/podcrates#260,
taken 2026-11-25), and `issue-sync.yml` at the same commit. The crates in `Cargo.toml` at the tag: `pod-acme`,
`pod-core`, `pod-cover`, `pod-derp`, `pod-devtunnel`, `pod-dns`, `pod-e2e`, `pod-egress`, `pod-gsr`, `pod-h2` (as the
dependency `h2` of `podssh-ws` and `podssh-relay`; `vendor/h2` is gone), `pod-identity`, `pod-iroh`, `pod-link`,
`pod-manual`, `pod-netstack`, `pod-opentunnel`, `pod-piping`, `pod-proxy`, `pod-quic`, `pod-relay`, `pod-release`,
`pod-services`, `pod-session`, `pod-term`, `pod-testkit`, `pod-tls`, `pod-todo`, `pod-tor`, `pod-tpm` (feature
`device`; its `tbs` is not taken, `crates/podssh-ssh/src/tpm/windows.rs` stays), `pod-transit`, `pod-unit`,
`pod-warp`, `pod-wormhole`, `pod-ws`; and the fork `iroh-relay` in `[patch.crates-io]`.

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
| ZeroTier (T-733) | `zerotier-live.yml`, `zerotier-interop.yml` | live through ZeroTier Inc.'s roots and relay; the interop passed at `930e5ba0` (2026-11-23) |
| Proxy lists, VLESS, Trojan, TUIC, ACME, MQTT, TURN, Outline, hostc | `proxy-lists-interop.yml`, `vless-interop.yml`, `trojan-interop.yml`, `tuic-interop.yml`, `acme-interop.yml`, `mqtt-interop.yml`, `turn-interop.yml`, `outline-interop.yml`, `hostc-interop.yml` | all passed on `main` at `930e5ba0` (2026-11-23) |
| HTTP Relay's demo (T-576) | `httprelay-probe.yml`, daily at 14:17 UTC | its `VERDICT` lines are the measurement; it never answered in three days (2026-11-14) |
| The file hosts (T-738) | `filehost-live.yml` | run 43562322579 (2026-11-14): passed, the two hosts that the road takes unasked 32 KiB up, down and opened |

## How to test

- **Builds:** `CARGO_BUILD_JOBS=4`, one build at a time. The gate's Rust is 1.99.1 with `--locked`; a
  cloud container may carry 1.100 (`rustup toolchain install 1.99`, then `RUSTUP_TOOLCHAIN=1.99`).
  Resolve `Cargo.lock` with `cargo +1.99 metadata` before a commit that changes it. Add
  `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_TEST_DEBUG=line-tables-only`.
  The gate's clippy is `-D warnings -A clippy::collapsible_if` (`scripts/gate.sh`).
- **Disk:** `target/` grows past 28 GB with the full suite and a musl build. When the disk fills,
  remove `target/` whole, never files under it.
- **A cloud container's tools:** `apt-get install oathtool swtpm swtpm-tools` before `serve_totp_openssh`
  (it says "did not run" without them) and T-839's ignored swtpm tests; `mkdir -p /run/sshd` for the
  sshd of the live harness (else T-839's sshd test says "did not run").
- **The `rm` stand-in:** since a restart of the worker, a cloud shell puts a stand-in of `rm` first on
  `PATH`, so `tests/job_far.rs` fails at the far side's `rm` (3 of 3) while the gate passes it.
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
- **Starting a run:** a push starts `build.yml`, and `gh workflow run` starts one by hand. A session
  whose account cannot (`gh`'s token refused; its pushes start no workflow) asks the operator's local
  agent by an issue of this repository titled `[gh action] requested`: why, one `sh` block that
  dispatches each workflow and watches it to its end, and "Run the block as it is, once. Then write
  here: the output of the last line, or the line where it stopped and its error." Open a new issue for
  each ask, and push nothing between the ask and its answer, as each block finds its runs by the
  commit. The watcher (`AGENTS.md`) says when each asked run starts and ends.
