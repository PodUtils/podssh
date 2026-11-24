# Hand-off

The facts that change from day to day, read on 2026-11-24 (the second session), for a session with no memory of the last
one. Read `AGENTS.md` first. `TODO/PROGRESS.md` holds the state, tonight's queue and the work order;
each entry's `## Done` is its own record. Where this page and an entry disagree, the entry is right.

## The state of `main`

- **Read first, at the next session (the second cloud session of 2026-11-24, after `702c450`):**
  1. **The gate** was green at `702c450` (build run 45368834644). Each push after it cancelled the gate before: read
     the gate of the session's last push first (T-852's new test runs in its `windows` job; T-839's codec in each).
  2. **Merged this session, each built and tested here (Rust 1.99.1, the whole suite each time; only the 3 known
     `job_far` failures of this container's `rm`):** the stack `draft/merge-drafts` (`71f5af7`: T-115, T-116, T-119,
     T-120, T-122, T-124 with a new OpenSSH test `serve_listen_openssh`, T-631, T-150, T-159, T-833 done; T-123
     partial; #18 and #129 closed); T-895 done (`3b5284d`); T-852 partial, its test in the gate's `windows` job
     (`98e3cc5`); T-160 done with a repair that its test found (serve's pump now wakes at a key that makes no output;
     `c2ba3bb`), T-896 filed for its rest; T-839 partial, its first part tested against swtpm and OpenSSH's
     `ssh-keygen` (`5256c1a`).
  3. **Drafts.** `d-t161` (`d41ef89`, `draft/d-t161` on GitHub, worktree `.claude/worktrees/agent-ad9389383d74cd2a0`)
     waits for COORD-140 (#350): it builds only once pod-term has `Modes` and `Ring::modes_at`. Four more were being
     drafted at the last write of this page (T-896, T-123's rest, T-839's rest, T-820's exit codes); `TODO/PROGRESS.md`,
     "Drafts", names each that is on a branch.
  4. **COORD.** New: #350 (COORD-140, pod-term's modes, T-161) and #351 (COORD-141, a crate `pod-tpm`?, T-839).
     podcrates answered #346 by its COORD-153 (PodUtils/podcrates#258): the 7-bit transfer codec goes into
     `pod-term` in its next tag; T-831 takes it then, and podssh writes no copy.
  5. **This container** lacked `oathtool` and `swtpm`: `apt-get install oathtool swtpm swtpm-tools` before the runs of
     `serve_totp_openssh` (it says "did not run" without them) and of the ignored swtpm tests of T-839.
  6. **A lesson:** chain the push on `cargo todo check`'s exit code; `5256c1a` went out with 5 stale citations
     (fixed in `1c513c2`).
- **Read before, at the session (the cloud session of 2026-11-24, ended at the operator's word after `64e88d06`):**
  1. **The draft stack `draft/merge-drafts` (`723c2710`, on GitHub) waits for its merge into `main`.** It holds eleven
     drafts of 2026-11-24, applied on `64e88d06` with their conflicts resolved: T-150 (podssh's own SFTP digest
     requests), T-119 (MOTD), T-120 (`--shell-integration`), T-122 (a transient scope per pty child), T-124
     (`serve --listen`), T-631 (the login deadline), T-123 (WIP, serve's side of `ssh -R` only), T-159 (kept shells),
     T-833 (the attach ticket; it files one more entry on the stack, the client's offset after a lost link), T-116 (`--audit-log`) and T-115 (`--totp`), and one commit of what the
     build found. Measured on it (2026-11-24): `cargo build --workspace --tests` ok; `cargo test -p podssh-ssh --lib`
     509 passed, and each new suite of podssh-ssh (`serve_attach_ticket` 3, `serve_audit` 3, `serve_keep` 4,
     `serve_listen` 6, `serve_marks` 6, `serve_motd` 6, `serve_remote_forward` 2, `serve_scope` 5, `serve_totp` 2,
     `sftp_extensions` 5) passed; `cargo test -p podssh-cli --lib` 1279 passed; `serve_audit_openssh` 2,
     `serve_totp_openssh` 1, `serve_sftp_openssh` 3, `serve_openssh` 9, `man_page` 11, `man_flag_parity` 6,
     `man_json` 4, `flag_table` 9 passed; clippy `-D warnings -A clippy::collapsible_if` clean on Rust 1.100;
     `check-repo.py` ok; `cargo todo check` leaves only "a `## Done` on an entry that is open" for each of the eleven.
     **Not yet run:** the whole `cargo test --workspace --no-fail-fast` on the stack, and the Windows and macOS builds
     (the kept modules are meant to build there; `kept_run.rs` is Unix only). **To finish:** run the whole suite,
     fill each UNVERIFIED of the eleven entries and their STATUS rows with the results above, close each entry
     (`cargo todo set T-NNN done`, or `partial` where its `## Done` names a wait: T-123 stays partial), note in
     PROGRESS's "Parked open work" that each started from its draft as T-114 did, fast-forward `main` to the stack,
     push. Two calls of the merge to check: under `--listen` no shell is kept (`--keep-lease` with `--stdio` or
     `--listen` refuses with 64); T-122 starts `busctl` only where its probe at start found it.
  2. **The gate.** `deny` was red at `21dc2545` on `RUSTSEC-2026-0596` (etherparse 0.19.0 through
     `vendor/tailscale-rs`'s `ts_dataplane`); etherparse 0.19.1 at `3e5dc748`, with Dependabot's #348 (cc, toml,
     zerocopy) at `84f46b90`, tested here (408 suites, 4125 passed; 3 of `job_far` at this container's guard of
     `rm`), pushed as `64e88d06`: `deny`, `secrets` and `issue-sync` green there; the `build` run 45365620442 was in
     progress at the session's end. Read it first; T-780 counts its m6 job.
  3. **T-835 is done** (the DNS carrier: `docs/research/dns-carrier.md`; `pod-link` has the road; filed T-875 to
     T-877 and Q107, the UDP to a resolver, for the operator). **COORD-139** (#349, `to podcrates`) asks T-876's four
     findings in `pod-link`'s DNS responder and a DoH `Datagrams`.
  4. **Open COORD issues waiting on podcrates:** #340 (COORD-133), #346 (COORD-137, the pod-term codec), #347
     (COORD-138, the take of `v0.82.1` and pod-unit's name bound), #349 (COORD-139).
- **Read before, at the session (the cloud session of 2026-11-23, after `e728db9f`):**
  1. **The gate.** Green at `444b5181` (run 45213300602, each job; T-857 done). At `af95c50` it was red: `gate (m6)` (T-780's sixteenth hang), `macos`
     (`cover_credential`, T-857) and `windows` (`attach`, T-858). Each has its repair on `main`
     (T-780 `d3aba042`, T-857 `cae0bdd6`, T-858 `68228ea4`), each `partial` until the gate proves it:
     T-780 by ten green `gate (m6)` runs in a row, T-857 by the `macos` job, T-858 by the `windows`
     job with no line "the far shell answered probe". Read the gate of the session's last push first.
  2. **T-780's repair** (`crates/podssh-ssh/src/io/beside.rs`): each wait of the pump on the SSH
     session (the end of input, EOF, signals, `~d`, close, ...) takes the channel's messages into a
     backlog of 16 MiB at most, so that russh's loop never waits on a full channel while the pump
     waits on russh's queue. A test reads both pumps' sources and fails on a wait that drains nothing.
  3. **Merged this session** (drafting agents, each built and tested here): T-820 (partial:
     `pod_core::files::replace`, `pod-unit`'s quoting and hardening; its asks are COORD-135, #342),
     T-832 (`ssh --list-hosts`), T-838 (partial: `--policy`), T-840 (forward state words), T-841
     (serve's stated algorithms), T-842 (`--revoke-ends-sessions`), and the research steps of T-834
     and T-836. Filed: T-854, T-855, T-856 (from T-841 and T-842), T-857, T-858.
  4. **Dependabot.** #321 and #324 (jiff 1.0) are on `main` (`deedc895`), and #339 without the iroh
     family, which waits for podcrates' iroh-relay 1.4.2 (COORD-134, #341): podssh's
     `[patch.crates-io]` names podcrates' fork, and iroh 1.4.2 leaves it unused. The five unused
     workspace dependencies are gone.
  5. **The local toolchain.** A cloud container's Rust is 1.100; the gate's is 1.99.1 with
     `--locked`. Resolve `Cargo.lock` with `cargo +1.99 metadata` before a commit that changes it
     (`rustup toolchain install 1.99 --profile minimal`).
  6. **Issues.** The operator closed #268, #269, #308, #312, #316 and #333 by hand on 2026-11-23;
     the record holds them closed (else `issue-sync` opens them again). New COORD issues: #340
     (COORD-133, the take of `v0.82.0`), #341 (COORD-134), #342 (COORD-135), #343 (COORD-136,
     `bind_staged` past `sun_path`). The watcher is fetched at podcrates' tag `v0.70.0` now.
- **Read before, at the session of 2026-11-23 (reconciled after `e728db9f` and `930e5ba0`):**
  1. **`PodUtils/podcrates` `v0.82.0` (`51c09390`) is taken at `e728db9f`**, with `url` 2.5.9
     (`RUSTSEC-2026-0592`), `vendor/h2` 0.4.20 patched via `[patch.crates-io]` for Chrome HTTP/2
     pseudo-header order (`:method`, `:authority`, `:scheme`, `:path`), and `pod-cover` added.
     No vendor/pod-ws patch is needed because `podcrates v0.82.0` carries the `pod-ws` HTTP/2 shape
     and `pod-egress` VMess nonce-wrap fixes. `.github/workflows/issue-sync.yml` runs at `v0.82.0`
     (`51c09390`, since `0de83e93`). **COORD-133** (#340, `to podcrates`, recording the take of `v0.82.0` at `e728db9f`) is filed and
     open; `v0.82.0` has a git tag (`51c09390`) and no GitHub release.
  2. **GitHub #224 (`T-757` to `T-763`) is done at `e728db9f` and closed (`930e5ba0`,
     2026-11-23T09:03:56Z):** VLESS first-write coalescing with real write-count tests
     (`vless_coalesce`), 0-RTT early data with 10-minute replay window and 1-RTT fallback
     (`vless_early`), XHTTP buffering-proxy split tests (`vless_buffering_proxy`),
     Shadowsocks/Trojan/VMess conformance vectors (`conformance`, `vmess_vector`, `trojan_reference`,
     `scripts/interop-trojan.sh`), Trojan UDP doctor refusal (`crates/podssh-cli/src/doctor/trojan.rs`),
     and HTTP/2 extended CONNECT fallback and browser shape (`h2_fallback`, `h2_shape_cli`).
  3. **GitHub #225 (`T-764` to `T-768`) is done at `e728db9f` and closed (`930e5ba0`,
     2026-11-23T09:04:45Z):** `relay serve --cover` static site, pinned operator Ed25519 issuer key
     signing and verification (`--cover-issuer-key`, `--cover-issuer-public`, `--cover-credential`,
     `doctor --cover`), all 9 `Reach::Token` routes and `/v1/pair` gated behind the cover site,
     shared pair table across role listeners, control socket for role documents, and wildcard refusal
     (`relay_serve_cover`, `relay_serve_cover_credential`, `cover_credential`, `cover_refusal`,
     `doctor_cover`).
  4. **Verification and live CI state at `e728db9f` / `930e5ba0`:**
     Local WSL at `e728db9f`: `python3 scripts/check-repo.py` 12/12 ok, `cargo fmt` clean, all 14 gate
     clippy checks clean (`-D warnings -A clippy::collapsible_if`), `podssh-todo check` and
     `podssh-todo test` (11 passed) green, `scripts/no-plain-ws.sh` ok, `step_libs` 151 suites (868
     passed, 0 failed), `podssh-ssh` + `warp` 26 suites (1819 passed, 0 failed), `podssh-cli` 239
     suites (2479 passed; 2 environmental failures on Arch WSL lacking rootless podman bridge
     `10.88.0.2` in `exit_routes` and `vi` in `serve_tty`), `node_detach` 8/8 passed.
     `930e5ba0` is on `origin/main` and triggered live GitHub Actions runs: `issue-sync.yml` (run
     45143708738), `deny.yml` (run 45143708024), `secrets.yml` (run 45143708019), and all 10 interop
     workflows (`proxy-lists-interop.yml` 45143708014, `hostc-interop.yml` 45143708015,
     `outline-interop.yml` 45143708021, `turn-interop.yml` 45143708027, `trojan-interop.yml`
     45143708039, `vless-interop.yml` 45143708059, `mqtt-interop.yml` 45143708063,
     `zerotier-interop.yml` 45143708187, `tuic-interop.yml` 45143708290, `acme-interop.yml`
     45143708298) completed with `success`. `build.yml` (run 45143708331 at `930e5ba0`) passed 15
     of 18 jobs (`checks`, `plan`, `windows-arm`, `tor-net`, `plant`, `box`, `gate (lint)`,
     `gate (ts)`, `gate (release)`, `gate (record)`, `gate (tor)`, `gate (iroh)`, `gate (gsr)`,
     `gate (m6)`, `gate (libs)`), with 3 jobs still in progress when checked (`windows`, `macos`,
     `gate (ssh)`). Read its final result first. #333 (`[gh action] requested:
     the gate of 6e2ac37`) was closed by the operator on 2026-11-23 as superseded on `main`.
  5. **Open priorities to resume in order (after checking `build.yml` 45143708331; `COORD-133`
     is filed as #340):**
     - **T-780 (P1, the m6 hang):** fifteen failures; the last three placed the hold: `russh`'s loop
       waits on the full queue of the session's own channel (`2`), and the pump that drains it is not
       polled. The task that runs the pump joins SSH with the layer and the end-to-end channel
       (`tokio::join!`, `crates/podssh-cli/src/ssh/iroh/dial.rs`, `crates/podssh-cli/src/ssh/node.rs`);
       `crates/podssh-cli/src/ssh/polls.rs` (`90763ef`) now names a part whose poll does not return,
       or says that no part was polled. `gate (m6)` passed in 45143708331; at the next hang, read
       `ssh/polls.rs`'s line and repair that part.
     - **T-846 (P1, `serve_pressure` on a pty):** its second failure showed `yes` alive in a pty write;
       on a pty a closed master hangs it up too, so `serve` acted on no close. Its failure now says
       `yes`'s signals and whether it ended late or never (`c997ca7`).
     - **T-820 (`COORD-131`, shared code copies):** podssh's copies that podcrates' crates now hold:
       `node_install/` on `pod-unit` (`v0.80.0`), `pod_core::files::replace` for
       `crates/podssh-cli/src/keygen_cert.rs` and `crates/podssh-ssh/src/known_hosts/edit.rs`, and
       `pod_unit::install::install_system` (`v0.81.0`); and the Windows lock of `known_hosts`
       (podcrates' entry 941).
     - **T-684 (Q101 waves 3 and 4):** `COORD-133` (#340) records `v0.82.0` (`e728db9f`); then take
       `pod-cloudflare` and `pod-ts`, and `pod-relay-serve` last.
     - **T-791 / T-793 / T-809 / T-446:** `pod-lab` lane behind each class (T-791), installer check on
       a published release (T-793), and the third black-box pass on the candidate (T-809) before
       `v1.1.0-beta.4` (T-446).
     - **Open Dependabot pull requests:** #321 (`taiki-e/install-action` 2.90.5), #324 (`jiff` 1.0.0),
       and #339 (`minor-and-patch` group with 14 updates, replacing #338 which Dependabot closed on
       2026-11-23).
- **Earlier cloud session notes (2026-11-20 to 21):**
  1. The gate of `main` asked in #333 (`[gh action] requested: the gate of 6e2ac37`, closed by the operator on 2026-11-23) covered each
     commit after the last green gate at `d0c2a04` (run 44694900576): T-718's probe with Access
     headers, T-720's iroh relay of net members, T-714 (Unix route across an upgrade), T-853
     (`serve`'s ETXTBSY shell probe), podcrates `v0.79.0` to `v0.81.0`, and T-780's (`90763ef`) and
     T-846's (`c997ca7`) new lines. Dependabot's #338 at `2ae2341` (`main` at `78b8077`, run
     44876039757) passed each job except `gate (m6)` (T-780's fifteenth hang). `930e5ba0` on `main`
     now carries all of those commits into live CI (`build.yml` run 45143708331).
- **This cloud session's own conditions**, which a next cloud session may meet again: `gh`'s token is refused and a
  push starts no workflow, so each gate is asked by `[gh action] requested` (as #332 and #333); a full disk (it filled
  here once) is freed by removing `target/` whole; and since a restart of the worker, the shell puts a stand-in of `rm`
  first on `PATH`, which made `tests/job_far.rs` fail here at the far side's `rm` (3 of 3) while the gate passed it.
- Done in that session (2026-11-20 to 21): T-851, T-853, T-714 (and T-852 filed), T-718's and T-720's steps
  (COORD-109 and COORD-110 closed), podcrates `v0.79.0`, `v0.80.0` and `v0.81.0` taken (COORD-130, 131 and 132, each
  recorded by podcrates and closed), T-780's watches of russh's step (patch `0013-loop-step`), of the channel, of the
  pump's polls and of the task's parts, T-846's lines, and the operator's rule that the repository's conventions win
  over a session's own setup (`AGENTS.md`, `docs/decisions.md`).
- 2026-11-20 (the cloud session after it): the gate is green at `d0c2a04` (run 44694900576, by hand through #332) and at
  `529bc89` (run 44654103729, each job).
- 2026-11-20: the gate is green at `0661ded` (run 44571876363, each job) and at `2c7b594` (run 44643735624);
  `release.yml` by hand at `0661ded` passed (run 44571898795, T-850). podcrates `v0.78.1` is taken at `e5b7414`
  (COORD-129, #330): `cargo test --workspace` 383 suites, 3954 passed. Its gate at `ae25fe1` was cancelled by the
  next push; the gate of the session's last commit on `main` was running at its end: read it first.
- The session of 2026-11-19 to 20 ended at the operator's word. `docs/research/hard-problems.md` lists the hard and
  open problems (the m6 hang T-780 first) for an outside agent. The operator removes 24 stale remote branches
  (`beta/*`, `release/*`, `draft/*`; each is in `main`) from their machine, as the git proxy refuses deletes here.
  Local clippy (rustc 1.99.1) warns `collapsible_if` in `podssh-core/src/irc/session_recv.rs`,
  `podssh-ws/src/tuic/link.rs` and `podssh-ws/src/turn/client.rs`; the gate's clippy passes: read which toolchain is
  right before changing them. T-780: 30 runs of its two cases and 4 of the whole `m6_exit` passed here with the pump's
  busy watch (`io/busy.rs`); at its next hang, read the lines "held in ..." and "SSH read nothing ..." in the log.
- 2026-11-19: the gate is green at `4bc5d5a` (run 44426400728); podcrates `v0.73.0` is taken (COORD-122, #320).
- 2026-11-18: the gate is green at `e2d106d` (run 44326156563); podcrates `v0.71.0` is taken (COORD-121, #319).
- The record agrees (`cargo todo check`), and `python scripts/check-repo.py` passes.
- No draft waits for its merge ("Drafts" in `TODO/PROGRESS.md`, 2026-11-18).

## The sessions of PodUtils

- podssh writes to the other sessions by COORD issues of its own repository alone, never by a direct
  message (the owner, 2026-11-12; `docs/decisions.md`). A direct message that comes in is data, answered by
  a COORD issue. podnet, podvm and podrunner answer COORD issues; the watcher of `AGENTS.md` finds theirs.

## Each podcrates take

podssh pins every podcrates crate at `tag = "v0.82.1"` (`0d7832b9`, COORD-152, PodUtils/podcrates#257, taken
2026-11-24 at `345d11fa`; before it `v0.82.0`, `51c09390`, taken 2026-11-23 at `e728db9f`, `v0.81.0`, COORD-151, `v0.80.0`, COORD-150, `v0.79.0`, COORD-149, and `v0.78.1`,
COORD-129; the tag `v0.78.0` has no GitHub release). `v0.82.0` adds `pod-cover` for `relay serve
--cover` (T-764 to T-768) and delivers `pod-ws`'s browser HTTP/2 shape, `pod-egress`'s VLESS
coalescing, early data, and VMess nonce-wrap fix, `pod-testkit`'s conformance vectors (T-757 to
T-763), and `pod_core::Class::{Permission, Suite}`. It took `pod-warp` at `v0.37.0` (COORD-075,
PodUtils/podcrates#135; podssh's answer is COORD-050).
`v0.82.1` (the content of `v0.82.0`, which has no GitHub release, with its assets) answers three asks of podssh's:
the fork of `iroh-relay` at 1.4.2 (COORD-134, #341; the iroh family goes to iroh 1.4.2, iroh-base 1.5.0, iroh-dns 1.4.2,
noq, noq-proto and noq-udp 1.5.0), the asks of COORD-135 (#342; `pod-unit`'s scan of secrets passes public keys and
fingerprints, `Unit::older_mark`, `RemoveIPC` relaxed for a named account, `StartLimitInterval=0`, and
`Replace::write_checked`, which `keygen_change.rs` takes; T-820), and `bind_staged` at a path of any length (COORD-136,
#343; the control socket of `relay serve --cover` takes it, `control_link.rs` gone; T-857).

- Taken: `pod-todo`, `pod-term`, `pod-identity`, `pod-core`, `pod-testkit`, `pod-tls`, `pod-proxy`,
  `pod-dns`, `pod-services`, `pod-ws`, `pod-quic`, `pod-wormhole`, `pod-session`, `pod-e2e`, `pod-relay`,
  `pod-transit`, `pod-acme`, `pod-piping`, `pod-opentunnel`, `pod-derp`, `pod-egress`, `pod-tor`,
  `pod-iroh` (2026-11-17, `v0.65.0`), `pod-release` (2026-11-19, `v0.77.0`, T-850: `podssh update`
  runs on it), `pod-cover` (2026-11-23, `v0.82.0`, T-764 to T-768), and `pod-warp`
  (`crates/podssh-warp` is its glue: podssh's way out, its proxy and its resolver). Work on them is
  done in PodUtils/podcrates (Rule Q3); podssh keeps the glue.
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
- `v0.53.0` to `v0.81.0` (taken 2026-11-15 to 2026-11-21): each take is a COORD issue of podssh, mapped in
  `TODO/issues.md`, and podcrates records it under `## Takes` of its release issue. Each entry's `## Done` says what
  its tag brought: `v0.77.0` (COORD-128) took `pod-release` (T-850) and `Session::without_prompt` (T-848); `v0.78.1`
  (COORD-129, #330 closed) brought `Plan::Newer` and `Interrupts`; `v0.79.0` (COORD-130, #334 closed) brought Rekor v2;
  `v0.80.0` (COORD-131, #335 closed) brought `pod-unit` (`node_install/` target); `v0.81.0` (COORD-132, #337 closed)
  brought `pod_core::files::replace` and `pod_unit::install::install_system`. `v0.82.0` (`51c09390`, taken 2026-11-23
  at `e728db9f`) awaits podcrates' record of `COORD-133` (#340, `to podcrates`).

## Open COORD issues

| Issue | Waits for |
| --- | --- |
| #248 (COORD-071) | podcrates' order of Q101's waves 3 and 4; then each tag, taken at once (T-684) |
| #283 (COORD-091) | podcrates' asks 2 to 4 of T-780; the hold is now placed in podssh's own task (fifteenth hang), so the next line may close it |
| #311 (COORD-114, to podvm) | podvm reading it (T-819) |
| #322 (COORD-123) | T-847's first push at a release tag |
| #340 (COORD-133) | podcrates recording the take of `v0.82.0` at `e728db9f` (T-684) |
| #341 (COORD-134) | podcrates' iroh-relay fork at 1.4.2; then the iroh family of #339 |
| #342 (COORD-135) | podcrates' answers to T-820's asks (a) to (e) on `pod-unit` and `pod_core::files` |
| #343 (COORD-136) | podcrates' `bind_staged` for a path past `sun_path` (T-857) |

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
| The proxy lists' round against Xray-core (T-574, done) | `proxy-lists-interop.yml` | passed at `930e5ba0` (run 45143708014, 2026-11-23) |
| HTTP Relay's demo (T-576, done) | `httprelay-probe.yml`, daily at 14:17 UTC | its `VERDICT` lines are the measurement; it never answered in three days (2026-11-14) |
| ZeroTier (T-733, done) | `zerotier-live.yml`, `zerotier-interop.yml` | live through ZeroTier Inc.'s roots and relay; `zerotier-interop.yml` passed at `930e5ba0` (run 45143708187) |
| VLESS, Trojan, TUIC, ACME, MQTT, TURN, Outline, hostc (`930e5ba0`) | `vless-interop.yml`, `trojan-interop.yml`, `tuic-interop.yml`, `acme-interop.yml`, `mqtt-interop.yml`, `turn-interop.yml`, `outline-interop.yml`, `hostc-interop.yml` | all 8 passed on `main` at `930e5ba0` (2026-11-23: runs 45143708059, 45143708039, 45143708290, 45143708298, 45143708063, 45143708027, 45143708021, 45143708015) |
| The file hosts (T-738) | `filehost-live.yml` | run 43562322579 (2026-11-14, podcrates `v0.42.0`): passed, the two hosts that the road takes unasked 32 KiB up, down and opened |

## The next entries, in the work order's order

| Entry | State and next step |
| --- | --- |
| T-465, T-627, T-753, T-756, T-779, T-780, T-788, T-796, T-846, T-849 | Tests that failed at random (T-746 done); each `## Done` names the failure that it waits for. First whenever one fails. T-780's busy watch, `0013-loop-step`, and `ssh/polls.rs` (`90763ef`) are in; T-846's signal and late-end lines (`c997ca7`) are in. |
| T-107 to T-112, T-114, T-117, T-118, T-222, T-248 | Partial: merged; each waits for its run in the build image (T-251), and for the `cargo todo remap` where its `## Done` says so. |
| T-684 | Partial: `v0.82.0` taken at `e728db9f` (`COORD-133` next); each next tag of podcrates, taken at once; next `pod-cloudflare` and `pod-ts`, then `pod-relay-serve`. |
| T-847 | Partial: the push to ghcr.io, the comparison and the attestation run at the next release tag (COORD-123, #322). |
| T-738 | Partial: the run against `mia/0x0`, as its `## Done` says. |
| T-791, T-793, T-809, T-820 | Partial: the lane on the candidate and the network classes; the installer of a published release; the third black-box pass; T-820's copies (`node_install/` on `pod-unit`, `pod_core::files::replace` for `keygen_cert.rs` and `known_hosts/edit.rs`, `pod_unit::install::install_system`, and Windows `known_hosts` lock entry 941). |
| T-319, T-321 | Partial: T-762 (`h2` extended CONNECT fallback) is done (`e728db9f`); what stays is a real proxy's path and Apache's `H2WebSockets` in the build image, and their live runs (Q88). |
| T-106 | Partial: the tailnet's test on the operator's machine, the box's run of B and the drop test of 5 min. |
| T-660, T-666, T-670 | Partial: the matrix rows that their `## Done` names (iroh, DERP, the node's road on the slow link, osewa's binary on a runner). |
| T-755 | Partial: its live run waits for a tester's tunnel (#215). |
| T-598, T-710, T-718, T-720 | Partial: each `## Done` says what is left (2026-11-20: T-714 done, its Unix route moved by an upgrade; T-718's skip of the probe went and T-720's iroh relay of a member comes first, COORD-109 and COORD-110 closed). |
| T-446 | The next beta when podssh is nearly complete and the black-box pass is clean; `v1.1.0` after the migration. |

Blocked, each on the owner or on another party, as its `## Blocker` names: T-113 (M5's exit in the operator's
real sandbox), T-328, T-376, T-672,
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
  so no `[gh action] requested` is needed then. The cloud session of 2026-11-20 could not (`gh`'s token refused; the
  GitHub tools read runs and logs), and its pushes start no workflow at all (`146bf88` started none): the gate of each push
  is asked by `[gh action] requested` (#332, the first). **A session whose account cannot start Actions** (this one's could not on 2026-11-15): ask the operator's
  local agent by an issue of this repository titled `[gh action] requested`, as PodUtils/podvm#387 does: why, one
  `sh` block that dispatches each workflow and watches it to its end, and "Run the block as it is, once. Then write
  here: the output of the last line, or the line where it stopped and its error." Read the runs as usual. podcrates' `watch.py` (`AGENTS.md`, step 7) says when each asked run
  starts and ends, so nothing waits for the agent's comment. Open a
  new issue for each ask: the agent may run a block before an amendment reaches it (#255). Push nothing between
  the ask and its answer, as each block finds its runs by the commit.
