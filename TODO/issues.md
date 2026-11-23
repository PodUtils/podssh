# GitHub issues and reports

Where each GitHub issue of `PodUtils/podssh`, and each sandbox report, went
in the record. An issue can close when its entries are done; its closing
comment names them. A request that podssh already meets says so here, with
the evidence.

Triage of 2026-10-08: issues #1 to #36.

## Defects and small requests

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #1 | `podssh man` writes the whole manual | closed | T-014 |
| #2 | Bracketed IPv6 literals refused | closed | T-007 (the commit "IPv6 addresses as targets: podssh sends the bare literal to the relay"); T-253 is M10's, in podssh's own relay role (Q63) |
| #3 | The token cache key is the first host | closed | T-057 (the commit "Relay tokens: one cache entry for each deployment, with the host that minted it") |
| #4 | Blank flag names under groff | closed | T-015 |
| #5 | `-c`, `-m`, `-X`, `-Y`, `-O`: "unknown flag" | closed | T-016 |
| #6 | `cp`, `mv`, `relay` print the `chat` example | closed | T-008 (the commit "A command that is not implemented says so before the --timeout gate") |
| #7 | `PubkeyAuthentication=no` still advises `-i` | closed | T-023 (the commit "A refusal names keys only when keys were tried") |
| #8 | A missing value reads as an unknown flag | closed | T-009 (the commit "A flag with no value names the flag and its value") |
| #9 | `podssh doctor --json` | closed | T-049 (the commit "podssh doctor --json") |
| #10 | A machine-readable flag table | closed | T-050 (the commit "podssh man --json"), and T-010 (`--help --json` drops `--json`; done in the commit "podssh --help and --version drop no word") |
| #11 | `podssh status` | closed | T-051 (the commit "podssh status: one line of JSON about this host") |
| #12 | `PODSSH_TIMEOUT` | closed | T-012 (the commit "PODSSH_TIMEOUT gives the default of --timeout") |
| #13 | `podssh doctor --full` | closed | T-052 (the commit "podssh doctor --full logs in to GitHub with a key made for the check") |
| #14 | `ssh_config`, `-F` and `-G` | closed (2026-10-30, with a comment that names the entries and commits; in `v1.0.0-beta.1`) | T-043, T-044, T-045, T-046 |
| #15 | `keygen` waits for ever on a dead `/dev/tty` | deleted on GitHub by 2026-11-02 (it was closed) | T-005 (repaired in `eacd94e`; measured in the box in the commit "The box has the sandbox's dead /dev/tty; T-005 measured there") |
| #16 | A repeated flag keeps the last value | deleted on GitHub by 2026-11-02 (it was closed) | T-017 |
| #17 | Relay drops (1011): a generic message, no retry | deleted on GitHub by 2026-11-02 (it was closed) | T-024 (the commit "A dropped session names the hop that broke"), T-025 (33c9a31), T-062 (the backpressure close: f93e4a2, b1f75c9); T-336 is M10's, in podssh's own relay role (Q63) |
| #27 | Repository health | closed 2026-11-11 as stale, 13 of 14 done; T-213 stays open in the record | T-205, T-206, T-207, T-208, T-209, T-210, T-211, T-212, T-213, T-214, T-215, T-216, T-217, T-218 |
| #28 | `sandbox-check.sh` exits 0 on failure | deleted on GitHub by 2026-11-02 (it was closed) | T-006 (the commit "sandbox-check.sh: each step has a verdict, and a failed step fails the run") |

## Feature requests with reports (#18 to #26)

Each request lists asks, and its comments hold reports on other projects.
Each ask is below with its entries. The operator ruled on the questions of
scope on 2026-10-08 (`docs/decisions.md`).

**#18, transports and reachability.** The iroh road: T-162, T-163, T-164,
T-165. QUIC with a fallback over TLS and TCP: T-162 and T-164 (the reverse
road is the fallback), T-124 (a server that listens, after a probe). A
self-hosted relay: T-169 (M10, in podssh's own relay role since Q63). SSH on port 443: podssh already carries SSH over port 443
through the relay; for a server that listens, T-124. UDP over TCP:
T-168. A Cloudflare quick tunnel, made by podssh itself: T-170 (the research, done), then T-299
(the measurement), T-300 and T-301. QUIC between peers with a relay
fallback and an allowlist: T-162, T-087. The sandbox limits (no UDP, port 22
refused, only CONNECT): already a decision (probe, never assume;
`docs/decisions.md`, 2026-10-05). Closed on 2026-11-11 as stale, with a comment that names the entries done, and open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done); T-124 stays open in the record.

**#19, the reverse road and sessions that survive.** A receiving mode: T-079,
T-083. Resume by byte offset with a limited replay ring: T-151, T-152,
T-153. Byte replay or screen state: T-152 and T-161. The reconnection policy:
T-153, T-154. A start over a standard sshd: T-167. A lasting terminal through
`tmux`: T-178. A clean server life cycle: T-117. Closed on 2026-11-11 as stale, with a comment that names the entries done, and open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done); T-117 and T-161 stay open in the record.

**#20, `podssh serve` and the pty in the cage.** The server: T-107, T-108,
T-109, T-110, T-111, T-112, T-113. A session that outlives the window: T-159.
Line discipline and copy mode: T-111, T-125 to T-129, T-161. Backpressure:
T-118. A handshake with version and role: T-151. An install with no
privileges: T-121; an agent, a credential helper and hardware keys, inside
podssh: T-034, T-228, T-229. The host key of each hop: T-030.
A limit on each wait: T-110, T-111, T-112, T-133. Transient scopes: T-122. Closed on 2026-11-11 as stale, with a comment that names the entries done, and open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done); the entries of `podssh serve` stay open (T-107 to T-113, T-118, T-122, T-159, T-161) in the record.

**#21, file copy.** Resume with a side file: T-136. Delta, parallel and the
copy options: T-141, T-142, T-143, T-144. A fast road with a fallback: T-164.
Integrity, atomic replacement, `--inplace`, metadata: T-134, T-147, T-146. A
dry run: T-143. Progress, cancellation, remote changes: T-145, T-149. ZMODEM:
T-148. Pipelined SFTP: T-140. Closed on 2026-10-30 with a comment that names
the entries and commits; each is in `v1.0.0-beta.1` but T-164, which needs a
build with the feature `iroh`.

**#22, `ssh_config` and the flags of OpenSSH.** The parser: T-043, T-044. The
settings in effect (`-G`): T-046. `Match`: T-045. `-F` and the port forms of
copy tools: T-043, T-139. Repeated flags: T-017 (done). Values that start with
`-`: T-011. A Mosh transport for each host (SSHub's report): no road runs
`mosh-server` (`docs/decisions.md`); the functions of Mosh: T-171 (the map, done), then T-302,
T-303, T-304, T-305 and T-306. Closed on 2026-11-11 as stale, with a comment that names the entries done, and open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done); T-303 and T-304 stay open in the record.

**#23, output for machines.** JSON on each surface: T-049, T-050, T-051,
T-054. Latency and throughput, and a short preflight: T-053. The health of
the far host: T-189. An exec result with the real exit status: T-054. No
success without an exit status: T-026. The flag table: T-050. The state of
this host: T-051. Closed on 2026-10-30 with a comment that names the entries
and commits, all in `v1.0.0-beta.1`.

**#24, many sessions.** Broadcast, an emergency stop and reviewed macros:
T-185, T-187. A control surface for agents: T-186; over stdio: T-055.
Host groups and per-host settings: T-184, T-043. Session recording: T-033.
Fan-out with an exit rule: T-183. Import and export: T-047, T-292 (PuTTY,
MobaXterm, Remmina), T-327 (mRemoteNG) and T-328 (FinalShell, Termius; it
waits for the operator's exports). Closed on 2026-11-11 as stale, with a comment that names the entries done, and open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done); T-328 stays open, waiting for the operator's exports in the record.

**#25, robustness and releases.** A circuit breaker: T-059; the retry policy:
T-025. Rate limits and quotas: T-169 (in podssh's own relay role, M10, Q63), T-114 (in `serve`),
T-145 (a bandwidth limit). Resource limits: T-201. Connection sharing: T-039.
A scored interop harness: T-199. Fuzzing and a terminal oracle: T-198,
T-200. An audit log: T-116. Live tests kept out of the default run: already
so (the live tests are `#[ignore]`; `docs/STATUS.md`, "Measure again").
Provenance of releases: T-210, T-211. Closed on 2026-11-11 as stale, with a comment that names the entries done, and open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done); T-114 and T-116 stay open in the record.

**#26, streams that are not SSH.** A binary protocol through `-W` or exec:
already works (`docs/STATUS.md`: 262144, 262145 and 5,000,000 bytes with
equal digests over exec, and `-W`). AF_UNIX streams: T-176, T-040. Desktop
streams: T-179. UDP over TCP: T-168. Publish a local HTTP service: T-180 (it waits for the relay's
operator).
Port discovery: T-180. A local-only mode: T-177. USB/IP: T-182 (a tested recipe over `podssh pipe`).
Closed on 2026-10-30 with a comment that names the entries and commits, and
T-180, `podssh funnel` in M10 (Q63).

## Requests of a second review (#29 to #36)

Each request cites the lines that it read in podssh and in another project.
Each became one entry, or two. The entry says which claims it verified, and
corrects a claim that the code does not support.

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #29 | Host certificates are dropped, not verified | deleted on GitHub by 2026-11-02 (it was closed (`a1d32e0`, 2026-10-11)) | T-027 |
| #30 | The relay hosts are tried one at a time | deleted on GitHub by 2026-11-02 (it was closed (`4cfbd5f`, 2026-10-11)) | T-220 |
| #31 | Where the replayed output may begin | deleted on GitHub by 2026-11-02 (it was closed) | T-221 (`61e55d1`); the invariant of T-152 (no byte that is not acknowledged is dropped, `d70f88f`) |
| #32 | `podssh serve` finds a shell with no passwd entry | deleted on GitHub by 2026-11-02 (it was open) | T-222 |
| #33 | `check-repo.py` passes with nothing to check; no scan for a listener | deleted on GitHub by 2026-11-02 (it was closed) | T-223 (the commit "Each repository check has a floor, and fails on an empty tree"), T-224 (the commit "The repository check finds a listener outside its allowance"); the floors of `cargo todo check` are in T-204 (done). Closed on 2026-10-09 with a comment that names them |
| #34 | The expected exit codes, from stock OpenSSH | deleted on GitHub by 2026-11-02 (it was closed) | T-225 (`e8bec97`) |
| #35 | Signed pairing grants that are used once | deleted on GitHub by 2026-11-02 (it was open) | T-226 (M10, in podssh's own relay role since Q63), and T-615 from its draft |
| #36 | `--direct` has no limit on a stuck write | deleted on GitHub by 2026-11-02 (it was closed (`f502fba`, 2026-10-11)) | T-227 |

## Requests after the triage (#51 on)

#37 to #50, #52, #53, #57, #58, #64 to #68, #77, #78 to #82, #119, #120, #122, #123, #149, #150, #197 to #202, #290 to #293, #301, #321, #323, #324, #331, #336, #338 and #339 are pull requests;
Dependabot's #44 to #47, updates of a major version, are T-330, but #47 (aes-gcm 0.11), which is
T-333 (done on 2026-10-31, after the ruling of Q48); Dependabot's #57 and #64
to #68 are T-355, and so is #77 (pageant 0.2.5 in `fuzz/Cargo.lock`, as in the
root lock), made on `main` and closed with a comment; Dependabot's #78 to #82 of 2026-11-01
(the tailscale image, the minor and patch group, rand 0.10, sha2 0.11 and hmac 0.13) are T-386;
Dependabot's #119, #120, #122 and #123 of 2026-11-02 (Python 3.15 for the box's proxy, the build
image's digest, sha2 0.11.1 and simple-dns 0.13) are T-597. Dependabot's #149 and #150 of 2026-11-06
(taiki-e/install-action 2.90.0 and aes 0.9.4) are T-691. Dependabot's #197 to #202 of 2026-11-12
(trufflehog, the actions group, the minor and patch group, Arti's tor-rtcompat and tor-error 0.48,
and num-bigint 0.5) are T-754; Dependabot closed them on 2026-11-12. Dependabot's #290 and #291 of 2026-11-17 (the tailscale and
trufflehog images) and #292 and #293 (the minor and patch group, rsa 0.10) are T-802; Dependabot closed
the four once `main` held them, and opened #301 for webpki-roots 1.0.12 alone, also T-802; Dependabot closed it on 2026-11-17 once `main` took podcrates `v0.68.0` with it. Dependabot's #321 (taiki-e/install-action 2.90.5, the actions group, 2026-11-19) waits behind podrunner's asks (the ruling "podrunner first"), T-802; so do #324 (jiff 1.0.0, a major version) and #331 (the minor and patch group: rand 0.10.4, clap 4.6.8, n0-error 1.0.3; it replaced #323, which Dependabot closed on 2026-11-20). #331's gate (run 44649725163) was red in `gate (m6)` (T-780) and `gate (ssh)` (T-851), neither from its bump; Dependabot closed it on 2026-11-21 for #336, the same group with four updates, #336 the same day for #338, with six, and #338 on 2026-11-23 for #339, with 14 updates.

| Issue | Subject | State | Entries |
| --- | --- | --- | --- |
| #51 | An HTTP/2 road over extended CONNECT (RFC 8441) | open (2026-11-13: commented where it stands, T-321 partial: Apache's `H2WebSockets` and the live run wait until stable, Q88) | T-321 (M10, on podssh's own relay role's listener since Q63; the default relay's edge chose `h2` and did not offer extended CONNECT, measured on 2026-10-30) |
| #54 | `doctor` measures what the proxy does to a stream | closed | T-324 (the three failures of the upgrade, and samples with their loss; the commit "doctor samples each probe of TCP, and names three failures of the upgrade"); T-325 (buffering, a cap on bodies, an idle limit) is M10's, served by podssh's own relay role (Q63) |
| #55 | The split road's wire protocol | open (2026-11-13: commented where it stands, T-319 partial: invariant 5 against a real proxy waits for the live runs, Q88) | T-319 (its Approach holds the protocol; the operator allowed its second connection, Q44, and it is M10's since Q63, served by podssh's own relay role) |
| #56 | A cleartext road on port 443, probed | closed 2026-11-09, T-326 done (`fddabaa3`) | T-326 (the operator allowed it with a token for one session, Q45, and it is M10's since Q63, served by podssh's own relay role) |
| #59 | The forward road without the operator's relay: ways with no account to reach a `host:port` (research) | closed 2026-11-11, each road of its ranking done | T-162, T-169, T-347, T-348, T-351, T-352, T-353, T-369, T-370, T-371, T-372, T-373, T-374 (each road of its ranking, in the paragraph below) |
| #60 | A relay template: a WebSocket forwarder that takes the destination from the URL | closed 2026-11-01, each entry done | T-369 (a forwarder that the user names); T-370 (the public forwarders in the binary, and a fallback to them, by the operator's ruling Q56) |
| #61 | SSH on port 443 as a hop | closed 2026-11-01, each entry done | T-371 (the hop measured, and a `doctor` line for a hop, b666713), T-372 (a hop or a destination whose SSH is wrapped in TLS, `ssh+tls://`, 60c2414) |
| #62 | A Shadowsocks road with a refreshable subscription | closed 2026-11-01, each entry done | T-373 (`--shadowsocks FILE`, tested against shadowsocks-rust's `ssserver` and `sslocal`) |
| #63 | Anonymous exits with no TUN device: WARP over HTTP/2, and Arti | closed 2026-11-01, each entry done | T-352 (Option 1, WARP; its first comment's measurements are in the Premise), T-353 (Option 2, Arti, live on Tor's public network by Q60), T-374 (its second comment: the quick tunnel's edge through WARP) |
| #69 | `doctor` reports a bind as if it had measured a listener | closed | T-357 and T-358 (the commit "T-357 and T-358: done. podssh doctor listens once on each socket that it binds", 12fc719: the lines `listen AF_INET` and `listen AF_UNIX`, by the operator's ruling on Q53). `-L` exits 255 on a refused listener, not 77 as the issue says |
| #70 | The UDP probe measures a local bind, not egress | closed | T-359 (done, 2026-10-31); the quick tunnel's QUIC has its own probe, its handshake (T-301), not this one, so one bind does not decide two roads |
| #71 | The record checks its citations, not its sentences | closed 2026-10-31, each entry done | T-360 (the map of issues against GitHub), T-361 (the targets of a Prove), T-362 (claims of "yet", and a status beside an id). Its five statements: four corrected in place in the commit of the triage (`docs/architecture.md`, `docs/design.md`, `docs/irc.md`), and the fifth, the facts file's comment, is T-342's (its Approach item 5). The reporter withdrew its item on `UNVERIFIED`. #59 to #63, which it found with no row, wait for their triage (T-360, item 5) |
| #72 | The direct road has no automatic selection | closed 2026-11-01, its entry done | T-363 (after the relay hosts fail, in the order of the road table, not before them as the issue asks) |
| #73 | `-R` refuses the socket forms that `-L` and `-D` carry | closed | T-365 (done, 2026-10-31), which takes the remote SOCKS form (`-R [bind_address:]port`) too: #73 reads its refusal as parity, but OpenSSH carries it (measured with OpenSSH 9.6p1's `ssh -G`) |
| #74 | `doctor` never tells a name allowlist from an address allowlist | closed 2026-10-31, its entry done | T-366 |
| #75 | An HTTP CONNECT listener | closed 2026-10-31, its entry done | T-367 |
| #76 | `ws:` and `ws-listen:` as addresses of `pipe` | closed 2026-10-31, each entry done | T-368, with the reader of requests of T-367 |
| #83 | A quiet minute ends the session when a Go server's reply to the keepalive carries data | closed 2026-11-03, each entry done (`b026d58`) | T-460 (russh ends the connection on a failure with data, which Go's x/crypto/ssh sends; OpenSSH reads none) |
| #84 | Exit 0 with stdout cut at the relay's 64 MiB | closed 2026-11-02, its entry done (`5b2468a`) | T-461 (the status came before the output's end; no rotation for a plain sshd, whose far end keeps nothing to go on with) |
| #85 | `-R` refused by a Go server reads as a lost connection | closed 2026-11-03, each entry done (`772275c`) | T-460 (the connection was lost: the failure's data ended it, inferred from the 0.7 s), T-464 (that line names no cause) |
| #86 | A `-J` hop that opens its channel and carries nothing ends in a bare 60 s timeout | closed 2026-11-02, its entry done (`f460dcf`) | T-462 (the hop took the channel, as the handshake's line came; a refused one is named at once, as `crates/podssh-cli/tests/jump_hop.rs:180` tests) |
| #87 | `cp --delta` falls back to a full copy with no word | closed 2026-11-03, its entry done (`9679787`) | T-470 (also: the copy by exec does not read `--delta`, and a server with a command and no `copy-data` gets its delta through that command) |
| #88 | `health` gives the host's 48 CPUs and 188 GiB, not the container's 4 CPUs and 4 GiB | closed 2026-11-03, its entry done (`0ce6745`) | T-480 (the cgroup's limits, v2 and v1, beside the host's facts, and `effective` in the JSON) |
| #89 | `sftp`'s `ls -l` is not OpenSSH's long form | closed 2026-11-03, its entry done (`57fd523`) | T-471 (also: `-f`, `-h`, `-r`, `-S` and `-t` of `ls` do nothing; the words "as OpenSSH's sftp" are the about of `--help`, `crates/podssh-cli/src/flags.rs:426`, not the README's) |
| #90 | A summary line, and progress in a pipe, for `cp` and `run` | closed 2026-11-03, its entry done (`2e3dcec`) | T-472 |
| #91 | `job` and `--persist` with no tmux: the command that installs it, and the dependency in the README | closed 2026-11-03, its entry done (`f093299`) | T-481 (the hint from the far host's package manager, the README's first steps, and `job --no-tmux`, whose runner alone signals its own child, so the PID reuse that T-193 set `nohup` aside for cannot kill another process) |
| #92 | A preflight of the far host: what its server allows, before a long command needs it | closed 2026-11-03, its entry done (`a92c2dd`) | T-482 (`health --preflight`; `doctor --via` is T-439's flag, and `doctor` takes no option of `ssh`); its rows of #83 to #87 are those issues' own entries |
| #93 | `pipe http-listen:` takes `ssh:USER@HOST`, and a worked example of CONNECT | closed 2026-11-03, its entry done (`7417676`) | T-483 |
| #94 | `each --json` and `--result-file`: each host's status and streams in one object | closed (8c2776b, 2026-11-03) | T-484 (a record of each session, in place of the process's, which T-183's Done names) |
| #95 | `cp --no-clobber`, `--update` and `--backup` | closed 2026-11-03, its entry done (`7131713`) | T-473 |
| #96 | `job log --follow` on one connection | closed 2026-11-03, its entry done (`b7080bd`) | T-485 |
| #97 | `--result-file` for `cp`, `mv`, `run` and `sftp`, in one schema | closed (096c2c1, 2026-11-03) | T-486 (the copy's bytes are `transferred`, as `bytes` keeps the meaning of `ssh`'s), with T-484's record of a session for `run` |
| #98 | A warning before the relay's 180 s idle cut | closed 2026-11-02, its entry done (`b39a29d`) | T-463 |
| #99 | `doctor` says once that each TLS handshake was reset | closed 2026-11-03, its entry done (`4cd833e`) | T-487 (the kind of each failure kept, not read from the system's words; a reference handshake with `github.com`; a diagnosis after the counts) |
| #100 | `cp` chooses `--parallel` itself for many small files | closed 2026-11-03, its entry done (`f55c61d`) | T-474 (Q23 sets the default of relay sessions; the files at once are channels of one connection: T-474's Decision) |
| #101 | `podssh mcp` offers `cp`, `job` and `health` as tools | closed 2026-11-03, its entry done (`f8eaeb4`) | T-488 (with `session`, which the issue names too; the copy's local side behind a new `--allow-dir`, the sessions behind `--allow-session`) |
| #102 | `chat --listen --linger`, and a word on the end of stdin | closed 2026-11-03, its entry done (`ea2a70b`) | T-489 (the listener connects out to the relay, so `--linger` adds no listener) |
| #103 | `run` reads a `.podsshignore` by default, and `--dry-run` | closed (535893e, 2026-11-03) | T-475 (its first ask is met already, `crates/podssh-cli/src/run_cmd/mod.rs:161-169`, as its comment found) |
| #104 | A target that ends the connection right after the login reads as a refused session | closed 2026-11-02, its entry done (`772275c`) | T-464 (the words "Disconnected" and "Channel send error" are russh's, not the server's) |
| #105 | `cp -r` says a skip twice, and exits 66 for a skip | closed 2026-11-03, its entry done (`a383ce9`) | T-476 (the line said twice is the first failure of the tree, not the last skip) |
| #106 | The fallback to other products' forwarders should be asked for: 20.8 s against 0.14 s on a dead target, and the target goes to three services | closed 2026-11-03, its entry done (`b32ecef`) | T-509 (the fallback follows the relay's answer about the target too, a 502 or a refusal by policy, which no forwarder mends; the default of off is the operator's to rule, as Q56 set it on) |
| #107 | WARP's road opens on TLS to the edge, and proves no packet through the tunnel | closed 2026-11-03, its entry done | T-560 |
| #108 | WARP's road dials one constant address, not the API's peers | closed 2026-11-03, its entry done (`c5299c2`) | T-561 |
| #109 | WARP's registration has one API name and no second route | closed 2026-11-03, its entry done (`cde307f`) | T-562 (the second name goes in once a live run shows it is the same API) |
| #110 | The relay's record forgets a host that opens, and keys each road's verdict by the host | closed 2026-11-03, its entry done (`7abebd2`) | T-563 |
| #111 | podssh never raises its soft limit of open files | closed 2026-11-03, its entry done (`5b643b1`) | T-564 |
| #112 | A node refuses each new session once its replay budget is full, and names the budget, not its cause | closed | T-586 (inferred, which its Prove measures: OpenSSH ends its ProxyCommand `operator` with SIGHUP, and the node keeps each such session 10 minutes, charged a whole buffer) |
| #113 | `proxy` cannot address `node://NAME` | closed 2026-11-03, its entry done (`6887d97`) | T-587 (`proxy node://NAME` as the pipe of `operator NAME`, a call of Q86; the issue's prefix `podssh ssh:` is not this code's) |
| #114 | `ssh node://` waits the whole ConnectTimeout, where `operator` to the same node reads sshd's line in 3 s | closed | T-588 (not reproduced; no test runs `ssh node://` from Windows) |
| #115 | `operator` and `proxy` take no `--ConnectTimeout` | closed 2026-11-03, its entry done (`801e346`) | T-589 |
| #116 | `node --sshd` with no sshd says `Connection refused`; a line of `doctor` for it | closed 2026-11-03, its entry done (`279a283`) | T-590 |
| #117 | A pair's expiry of 3 days, no renewal, and `relay status` with no expiry | closed 2026-11-03, its entries done (`a4344a7`, `5c14126`) | T-591 (`relay status NAME` names the expiry of a stored pair already; an operator's file cannot be asked), T-592 (a renewal, in podssh's relay role, M10) |
| #118 | The node's key under `HOME/.cache` when `HOME` is another user's | closed | T-593 |
| #121 | `docs/STATUS.md` describes `main`, and the release has no exit node | closed 2026-11-03, its entry done (`c2c4f94`) | T-594 (the exit is in `v1.0.1`'s notes, T-584) |
| #124 | A carrier over stdio or exec for a node and its client | closed 2026-11-03, its entries done | T-595, T-596 (the exit over it), T-614 (`--exit` beside `--carrier` in `ssh`, `proxy` and `pipe`, Q90) |
| #125 | `relay info`: `score_ms` and `rank` are the edge's, so the pool's order changes between calls | deleted on GitHub by 2026-11-04 (it was closed 2026-11-03, T-610 done; its text is the operator's export of 2026-11-04, so no comment goes to it) | T-610; from the export, T-618 (`relay info` names `relay rank` and the order that a run takes, which T-610 left for T-606 and T-607) and T-619 (its remedy on the relay's side, an item of the note to the relay's operator). The rest the record had: the edge's order and the score that did not agree with latency (`docs/relay.md:753-754`, 2026-10-01); the export's figures of upgrades, from the archive's `results/podssh-roads.json`, read with their limits (8 hosts at a time, a delay of the proxy on 8 of 37, `docs/research/relay-measurement.md:172-178`) and measured again through podssh (T-605); a measured order of the pool (T-606, T-607, T-608) |
| #126 | `relay serve`: a policy refusal names the address that a target resolved to | closed 2026-11-04 (`45a3447`), its entry done | T-628 |
| #127 | `relay serve` keeps each capability of its start after the bind | closed 2026-11-04 (`ce411ac`), its entry done | T-629 (dropped by default after the bind, before the runtime; no flag to keep them) |
| #128 | The relay role's 4096 pairs have no share for each key | closed 2026-11-04 (`4ae2284`), its entry done | T-630 (a reserve for each key that a busy key may borrow past, not the issue's ceiling) |
| #129 | `serve --listen`: an absolute deadline from the accept | open 2026-11-15 (closed 2026-11-11 as stale; T-631 stays open, parked until T-124; open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done)) | T-631 (backlog, parked until T-124, whose listener it bounds: no server of `podssh serve` exists yet) |
| #130 | A record of the resumable layer that ends one direction | closed 2026-11-05 (`c3a9b89`, done 2026-11-04), its entry done | T-632 (also the relay role's layer road for a standard sshd, which `proxy` takes unasked by Q96; consent by the layer's own features, not the node's `hello`) |
| #131 | One rule for an absent member that carries a guarantee, and a helper | closed 2026-11-05 (`0289b6d`), its entry done | T-633 (each reader that exists is right; the rule and the helper are new) |
| #132 | Refuse a retired `PODSSH_*` variable by name | closed 2026-11-04 (`91669ae`), its entry done | T-634 (the manual's check of variables runs both ways already, which the issue missed) |
| #133 | `relay serve`: a list of targets between public alone and `--allow-private` | closed 2026-11-04 (`ce411ac`), its entry done | T-635 (`--routes`, as an exit's, ranges and single addresses; a prefix with host bits refused, also for an exit) |
| #134 | `relay serve`: no byte count for a token across sessions or a restart | closed 2026-11-05, its entry done | T-636 (by the key that minted, not by the token, which names no one; a budget for a day) |
| #135 | A gate for each relay origin shared by a process's sessions | closed 2026-11-05, its entry done | T-637 (the longest wait 300 s, not 4 h) |
| #136 | Node admission: one gate for each connection, asked of a person | closed 2026-11-05, its entry done | T-638 (`--ask`; the issue's two defects are not supported: a grant's issuer crosses the door, T-226, and the role's token is the contract's, Q4) |
| #137 | `ws-listen:` answers a request that is no upgrade with a page from a directory | closed 2026-11-04 (`240447e`), its entry done | T-639 (with the reason phrases of 404, 409, 411, 413 and 429, which read "Error") |
| #138 | A service's lines keep their priority in the journal | closed 2026-11-04 (`91669ae`), its entry done | T-640; T-674, the SSH client's own lines, done 2026-11-05 (`bf55c13`) |
| #139 | `doctor`: a `nat` line, one mapping or one for each destination | closed 2026-11-05, its entry done | T-641 (two public STUN servers by default, Q86) |
| #140 | ECH from the name's HTTPS record | closed 2026-11-05, its entry done | T-642 (behind a proxy no resolver runs, so the record is a read before the session; podssh's provider needs HPKE first) |
| #141 | Protocol version negotiation on the reverse road and the channel | closed 2026-11-05, its entry done | T-643 (a net offer answered plainly is T-429's design for an end outside the net or of before: said, not refused) |
| #142 | `relay serve`: an SSH client shares the listener by its first bytes | closed 2026-11-05, its entry done | T-644 (the listener decides by the first byte already, T-326: an SSH client meets the cleartext road, not TLS) |
| #143 | `ws-listen:` answers a keyless upgrade, as WebTunnel's client sends it | closed 2026-11-04 (`240447e`), its entry done | T-645 |
| #144 | `relay serve --mint keys:` from an `https://` URL | closed 2026-11-05, its entry done | T-646 (`--mint net` is the signed way that exists) |
| #145 | A pair halted without its end, its node's socket kept | closed 2026-11-04 (`8caa6f0`), its entry done | T-647 (a planned stop already keeps the node, by `1012`, T-255) |
| #146 | A node socket's data queue is one line for all its sessions | closed 2026-11-04 (`4ae2284`), its entry done | T-648 (the role's own socket in the same change) |
| #147 | `relay serve` routes a published name by its ClientHello, TLS at the node | closed 2026-11-05, its entry done | T-649 (the listener moved to `podssh-relay`; funnel at the edge is T-180) |
| #148 | A pool of sessions opened ahead for each node | closed 2026-11-05, its entry done | T-650 (only for a node that asks, by its own flag) |
| #151 | COORD-001: a test of the fallback channel | closed 2026-11-05, its entry partial | T-684 (the first message of the protocol of PodUtils' sessions, a test that the watcher sees it) |
| #152 | [gh action] requested: the gate on `main` | closed 2026-11-06, the gate passed (run 42179347665, `78e78e4`) | T-684 (Actions start no workflow for this account on 2026-11-06; the owner's agent ran it; T-465's probe, T-451's test and T-691's pins in the gate) |
| #153 | [gh action] requested: the gate on `main` after T-434, T-456 and T-180 | closed 2026-11-06, its run red (42203919941, `0fc03e7`) and repaired (`b20fd8fe`, T-692) | T-684 (Actions start no workflow for this account on 2026-11-06; the owner's agent ran it) |
| #154 | COORD-002: podssh took pod-dns and pod-services of v0.4.0 (to podcrates) | closed 2026-11-09, the take is in podcrates' `SOURCES` (`taken 72fb94d1`) | T-684 (the take at `72fb94d1`, written to the podcrates session as the protocol asks) |
| #155 | [gh action] requested: the gate on `main` after the take of v0.4.0 | closed 2026-11-06: its run red (42214300946, `ea5d4117`) and repaired (`5c91c0b1`); its second run asked in #157 | T-684 (the static binary of the take, which the gate's step `release` built and checked) |
| #156 | COORD-003: podssh moved each podcrates tag to v0.5.0 (to podcrates) | closed 2026-11-09, superseded by the move to v0.6.0 (#161) | T-684 (the move at `486c001b`, written to the podcrates session) |
| #157 | [gh action] requested: the gate on `main` after v0.5.0 and T-491 to T-498 | closed 2026-11-06: run 42248490766 at `8f21bf9a`, each step but `libs` passed; repaired at `db1e6307` | T-684 (the gate of the takes and of the drafts merged since `ea5d4117`) |
| #158 | COORD-004: a second public Piping Server in pod-services, piping.onrender.com (to podcrates) | closed 2026-11-06, delivered in podcrates v0.6.0 | T-497 (done 2026-11-06) |
| #159 | COORD-005: Tailscale's main DERP fleet in pod-services, after tailcat's (to podcrates) | closed 2026-11-06, delivered in podcrates v0.6.0 | T-534 (done 2026-11-06) |
| #160 | [gh action] requested: the gate on `main` after `db1e6307` | closed 2026-11-06: the gate passed each job (run 42254589426, `285b0562`) | T-684 (the gate after the takes of v0.4.0 and v0.5.0, and the drafts of the day) |
| #161 | COORD-006: podssh moved each podcrates tag to v0.6.0 (to podcrates) | closed 2026-11-09, `main` pins v0.6.0 since `28fa1170` | T-684 (the move at `28fa1170`, written to the podcrates session) |
| #162 | [gh action] requested: the gate on `main` at `8c7519c0` | closed 2026-11-09: its run red (42290205000, the job `windows`), repaired by T-696; the gate passed each job at `47e1eba3` (run 42627967826) | T-684 (the gate after the take of v0.6.0, T-497 and T-534), T-696 |
| #163 | [gh action] requested: `PodUtils/podcrates:.github/workflows/live.yml`, the main DERP fleet from GitHub Actions | closed 2026-11-09, the run passed (42290196915, `8c7519c0`) | T-534 (step 1's run from Actions) |
| #164 | The GSRN road: accountless SRP authentication on one TCP connection to port 443 | closed 2026-11-11 as stale; T-707 stays open until the owner takes up `pod-gsr` | T-707 (blocked: the owner deferred `pod-gsr` on 2026-11-09) |
| #165 | Forwarder roads re-derive the half-close discipline per road | closed 2026-11-09 (`cdb46f81`), its entry done | T-699 |
| #166 | `doctor`: one verdict of the host's capabilities that names what each restriction closes | open 2026-11-15 (closed 2026-11-09, its entry done; open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done)) | T-706 (M5, beside T-248) |
| #167 | `sftp` prints no near-cap line before a budget stop, and the reverse node discards the close reason | closed | T-700 (sftp), T-701 (the node) |
| #168 | `serve`: inherit the relay role's capability drop, and bound the accept path before authentication | open 2026-11-15 (closed 2026-11-13 as stale: T-698 done (`565accd`), serve calls the drop (T-107); T-631 stays open, parked until T-124; open again from 2026-11-15, by the owner's ruling "Issues" (an issue is open while one of its entries is not done)) | T-698 (the drop; T-107 depends on it); the bound of the accept path is T-631 (#129) |
| #169 | `relay serve`: the contract's limits are fixed constants; only `--keepalive` is configurable | closed 2026-11-09, its entry done | T-704, T-732 (a defect of the byte cap, found by its test) |
| #170 | `ssh`: the direct road's banner check and the roost's sshd check give opposite verdicts on the same bytes | closed 2026-11-09, its entry done | T-702 |
| #171 | `ssh`: `--relay-host` and `--relay-failover` are dropped in silence for a node destination | closed 2026-11-09 (`cbb31bc0`), its entry done | T-697 |
| #172 | `ssh`: a `cf://` destination with the resumable layer keeps the user's SSH keepalives, with no warning | closed | T-703 |
| #173 | `doctor`: `--full`'s QUIC handshake and stream probes do not run with `--quick` | closed 2026-11-09, its entry done | T-705 |
| #174 | COORD-007: podssh took podcrates v0.7.0; the entries of cfb's asks of COORD-014 (to podcrates) | closed (2026-11-11: podcrates recorded it under its #38) | T-684 (the take at `1fd68cc4`), T-708 to T-731 |
| #175 | COORD-008: public Wisp servers as a pod-services kind (to podcrates) | closed | T-535 (the list of public Wisp servers, asked of podcrates) |
| #176 | COORD-009: podssh took podcrates v0.8.0 (to podcrates) | closed (2026-11-11: podcrates read it; a tag move with no frozen module) | T-684 (the take at `0e3c9eaf`), T-707 (open, as v0.8.0 ships `pod-gsr`) |
| #177 | COORD-010: pod-services: the kinds proxy-list and proxy-node, for podssh T-574 (to podcrates) | closed 2026-11-11, the kinds in `pod-services` and read by podssh (`49cb5c8c`); T-574 stays partial | T-574 (the lists of public proxy nodes, asked of podcrates) |
| #178 | COORD-011: pod-services: Pinggy's endpoint of SSH inside TLS and its host key (to podcrates) | closed | T-548 (the Pinggy road's endpoint and host key, asked of podcrates) |
| #179 | COORD-012: podssh took podcrates v0.9.0 (to podcrates) | closed | T-684 (the take of v0.9.0, `d4b03aa7`) |
| #180 | COORD-013: podssh took podcrates v0.10.0 (to podcrates) | closed | T-684 (the take of v0.10.0, `49cb5c8c`) |
| #181 | COORD-014: podssh took podcrates v0.11.0 (to podcrates) | closed | T-684 (the take of v0.11.0, `dc112ea7`) |
| #182 | COORD-015: pod-services: the services serveo and ssh-j, for podssh T-549 and T-570 (to podcrates) | closed | T-549, T-570 (their servers, asked of podcrates) |
| #183 | COORD-016: pod-services: the service croc, for podssh T-694 (to podcrates) | closed | T-694 (croc's bridge, asked of podcrates) |
| #184 | COORD-017: podssh took podcrates v0.13.0 and pod-ws (to podcrates) | closed | T-684 (the take of pod-ws, `a083593e`) |
| #185 | COORD-018: podssh took podcrates v0.14.0 and pod-quic (to podcrates) | closed | T-684 (the take of pod-quic, `525f8907`) |
| #186 | COORD-019: pod-services: localhost-run, localtunnel and bore; pod-session: Rewound::new (to podcrates) | closed (2026-11-11: taken with podcrates v0.18.0) | T-565, T-568, T-569 (their servers), T-568 (`Rewound::new`) |
| #187 | COORD-020: podssh took podcrates v0.15.0, pod-wormhole and pod-session (to podcrates) | closed (2026-11-11: podcrates `14982fc`; the gate green at `bc5107b0`) | T-684 (the takes at `baa00a06` and `6f78a7c7`) |
| #188 | COORD-021: the proposals of PodUtils/podnet#438 are podssh's entries (to podnet) | closed (2026-11-11: podnet read it; T-748 done at `f143fb73`) | T-747, T-748, T-749, T-750, T-751, and T-319 (the rules added to #55) |
| #189 | COORD-022: podssh took podcrates v0.21.0 (to podcrates) | closed 2026-11-11, the take at `6de121b2` | T-684 |
| #190 | COORD-023: ZeroTier's TCP relay as a service of pod-services (to podcrates) | closed 2026-11-11, written as podcrates T-203, out in `v0.22.0` and read by T-733 | T-733 |
| #191 | COORD-024: podssh took podcrates v0.22.0 with pod-e2e; pod-relay's import takes 75a50318 (to podcrates) | closed 2026-11-11, the take at `75a50318`; pod-relay's take continues in #192 | T-684 |
| #192 | COORD-025: podssh took podcrates v0.24.0; podcrates writes pod-relay's patch (to podcrates) | closed (2026-11-12: podcrates recorded the later takes, to v0.28.0 in COORD-054) | T-684 |
| #193 | COORD-026: podssh took podcrates v0.25.0 at f029594d; the pod-relay cut stays frozen (to podcrates) | closed (2026-11-12: podcrates recorded the later takes, to v0.28.0 in COORD-054) | T-684 |
| #194 | COORD-027: podssh took podcrates v0.26.0 at ff2f7bac; Pinggy's reader reads url-skip (to podcrates) | closed (2026-11-12: podcrates recorded the later takes, to v0.28.0 in COORD-054) | T-684 |
| #195 | cfb asks: tracker for the 22 asks of cfb owned by podssh (from podcrates#35) | open (2026-11-12: each ask an entry already) | T-708, T-709, T-710, T-711, T-712, T-713, T-714, T-715, T-716, T-717, T-718, T-719, T-720, T-721, T-722, T-723, T-724, T-725, T-726, T-727, T-728, T-729, T-730, T-731 |
| #196 | COORD-028: a service of Tox's TCP relays on 443 in pod-services, for podssh's T-734 (to podcrates) | closed 2026-11-12: in pod-services of podcrates v0.28.0, taken | T-734 |
| #203 | COORD-029: a service of Yggdrasil's public wss:// peers on 443 in pod-services, for podssh's T-735 (to podcrates) | closed 2026-11-12: in pod-services of podcrates v0.28.0, taken | T-735 |
| #204 | COORD-030: a service of HyperDHT's public bootstrap nodes in pod-services, for podssh's T-736 (to podcrates) | closed 2026-11-12: in pod-services of podcrates v0.28.0, taken | T-736 |
| #205 | COORD-031: a meeting point of the pairing over public MQTT brokers on 443 in pod-wormhole, for podssh's T-737 (to podcrates) | closed (2026-11-12: `pod_wormhole::mqtt` in v0.29.0; the runs' part is COORD-036, #210) | T-737 |
| #206 | COORD-032: pod-relay taken at v0.27.0 in podssh 0872c2c6 (to podcrates) | closed 2026-11-12: podcrates recorded the take in v0.28.0 | T-684 |
| #207 | COORD-033: Q90's live check of the proxy nodes: drop two of the ten (to podcrates) | closed (2026-11-12: v0.29.0 drops `node-xhttp-78-17-39-129`) | T-574 |
| #208 | COORD-034: podcrates v0.28.0 taken in podssh 12473a10 (to podcrates) | closed 2026-11-12: a report of the take, with adeae2eb | T-684 |
| #209 | COORD-035: a service of Syncthing's public relays on 443 in pod-services, for podssh's T-571 (to podcrates) | closed (2026-11-12: `syncthing-relay` in v0.30.0) | T-571 |
| #210 | COORD-036: pod-relay's runs of a code try the MQTT brokers after the mailboxes, for podssh's T-737 (to podcrates) | closed (2026-11-12: `Ends::brokers` in v0.30.0) | T-737 |
| #211 | COORD-037: podssh took podcrates v0.29.0 at 5b56c4d (to podcrates) | closed (2026-11-12: podcrates recorded it in COORD-057) | T-684 |
| #212 | COORD-038: podssh took podcrates v0.30.0 at ef3666f (to podcrates) | closed (2026-11-12: podcrates recorded it in COORD-058) | T-684 |
| #213 | COORD-039: pod-services: smee.io's server and hostc's server, for podssh's T-741 and T-742 (to podcrates) | closed (2026-11-12: `smee-io` and `hostc` in v0.32.0) | T-741, T-742 |
| #214 | COORD-040: pod-proxy's stun: MESSAGE-INTEGRITY and FINGERPRINT, for podssh's TURN road T-621 (to podcrates) | closed (2026-11-12: `pod_proxy::stun` in v0.32.0; T-621 uses it) | T-621 |
| #215 | relay: add a Dev Tunnels forward road (Nemo-010) | open (2026-11-12: T-755 on `main` at `9fa5523`; a tunnel for its live run asked of the tester) | T-755 |
| #216 | COORD-041: pod-devtunnel, the client side of Microsoft Dev Tunnels' relay, for podssh's T-755 (#215) (to podcrates) | closed 2026-11-12: podcrates v0.33.0 has it, taken at `72d6a3d` | T-755 |
| #217 | COORD-042: podssh took podcrates v0.31.0 at 02650f1 and v0.32.0 at 555fddc (to podcrates) | closed 2026-11-12: recorded in COORD-064 | T-684 |
| #218 | COORD-043: podssh took podcrates v0.33.0 at 72d6a3d (to podcrates) | closed 2026-11-12: recorded in COORD-065 | T-684 |
| #219 | COORD-044: podssh took podcrates v0.34.0 at 287e23b (to podcrates) | closed 2026-11-13: recorded in COORD-069 | T-684 |
| #220 | COORD-045: a pod-services kind file-host, and a retained board in pod_wormhole::mqtt (to podcrates) | closed 2026-11-13 (given in podcrates v0.35.0, COORD-066; used by T-738 in 68e0a07) | T-738 |
| #221 | COORD-046: pod-relay's HTTP road: the invariants 6 to 10 of GitHub #55 (to podcrates) | closed 2026-11-13 (given in podcrates v0.36.0; taken in 99b9642, COORD-049) | T-319 |
| #222 | COORD-047: pod-relay's HTTP road, serial form: an SSH session stalls when the bytes down block the bytes up (to podcrates) | closed 2026-11-13 (repaired in podcrates v0.36.0; the serial form's ssh passes again, 99b9642) | T-319 |
| #223 | COORD-048: podssh took podcrates v0.35.0 at 418e31d (to podcrates) | closed 2026-11-13 (followed by COORD-049) | T-684 |
| #224 | [DEFERRED] Make the WebSocket and HTTP/2 roads indistinguishable from what they claim | closed 2026-11-23 (`e728db9f`, on `PodUtils/podcrates` `v0.82.0`): T-757 to T-763 done | T-757, T-758, T-759, T-760, T-761, T-762, T-763 (the rows of its table, one entry each; a `:protocol` other than `websocket` is T-499's road, CONNECT-3) |
| #225 | [DEFERRED] Serve a cover site and delegate the handshake with a temporary credential | closed 2026-11-23 (`e728db9f`, on `PodUtils/podcrates` `v0.82.0`): T-764 to T-768 done | T-764, T-765, T-766, T-767, T-768 (the rows of its table, one entry each) |
| #226 | COORD-049: podssh took podcrates v0.36.0 at 99b9642 (to podcrates) | closed 2026-11-13 (followed by COORD-050) | T-684 |
| #227 | COORD-050: podssh took podcrates v0.37.0 and pod-warp at 812c61c (to podcrates) | closed 2026-11-13 (followed by COORD-051) | T-684 |
| #228 | COORD-051: podssh took podcrates v0.38.0 at e47d508 (to podcrates) | closed 2026-11-13 (followed by COORD-052) | T-684 |
| #229 | COORD-052: podssh took podcrates v0.39.0 at 5228b65 (to podcrates) | closed (2026-11-13: superseded by the take of `v0.40.0`, COORD-056, #233) | T-684 |
| #230 | COORD-053: pod-services' file hosts: three of four fail live from Actions (to podcrates) | closed (2026-11-13: the forms in podcrates `v0.40.0`, taken at `61658e4`; the road reads them) | T-738 |
| #231 | COORD-054: pod-netstack: tests for the two close cases of podssh's T-599 (to podcrates) | closed (2026-11-13: the tests in podcrates `v0.40.0`, named in T-599 and T-771) | T-771 |
| #232 | COORD-055: pod-term: a line discipline that follows a termios state, for podssh serve's tty with no /dev/ptmx (to podcrates) | closed 2026-11-14: given in podcrates `v0.41.0` (COORD-083), taken by podssh (COORD-063) | T-776 |
| #233 | COORD-056: podssh took podcrates v0.40.0 at 61658e4 (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.40.0` (its #140, closed) | T-684 |
| #234 | COORD-057: pod-warp: name the certificate that the front door showed when its key is not the pinned one (to podcrates) | closed 2026-11-14: given in podcrates `v0.42.0` (COORD-085), taken by podssh (COORD-064) | T-585 |
| #235 | COORD-058: pod-wormhole: Nostr's ephemeral events and WebTorrent's trackers as meeting points of the pairing by a code (to podcrates) | closed 2026-11-18: answered by podcrates' entries 550 and 551; T-545 and T-695 done | T-545, T-695 |
| #236 | COORD-059: pod-services: srv.us and tunnl.gg as services of the kind ssh-tunnel (to podcrates) | closed 2026-11-14: given in podcrates `v0.42.0` (COORD-085), taken by podssh (COORD-064); the live runs are T-566's and T-567's | T-566, T-567 |
| #237 | COORD-060: pod-wormhole: an ntfy topic as a meeting point of the pairing where a proxy refuses the WebSocket upgrade (to podcrates) | closed 2026-11-18: answered; T-496 done | T-496 |
| #238 | COORD-061: pod-services: serv00's public Piping Server as the third of kind piping (to podcrates) | closed 2026-11-14: given in podcrates `v0.42.0` (COORD-085), taken by podssh (COORD-064) | T-575 |
| #239 | COORD-062: pod-relay: the client of the HTTP road's one-POST form (to podcrates) | closed 2026-11-14: given in podcrates `v0.42.0` (COORD-085), taken by podssh (COORD-064) | T-622 |
| #240 | COORD-063: podssh took podcrates v0.41.0 at 6f77eaa (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.41.0` (its #143, closed) | T-684 |
| #241 | COORD-064: podssh took podcrates v0.42.0 at 7e457b4 (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.42.0` | T-684 |
| #242 | COORD-065: pod-session: a spare link that moved no byte should back off before the next (to podcrates) | closed 2026-11-14: given in podcrates `v0.45.0` (T-579), taken by podssh (COORD-068) | T-781 |
| #243 | COORD-066: podssh took podcrates v0.43.0 at b88985f (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.43.0` | T-684 |
| #244 | COORD-067: podssh took podcrates v0.44.0 (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.44.0` | T-684 |
| #245 | COORD-068: podssh took podcrates v0.45.0 at 16d53cb (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.45.0` | T-684 |
| #246 | COORD-069: podssh took podcrates v0.46.0 at 5ac90a3 (to podcrates) | closed 2026-11-14: podcrates recorded the take of `v0.46.0` | T-684 |
| #247 | COORD-070: pod-relay's run of a code fails over Nostr alone, though pod-wormhole's nostr pairs (to podcrates) | closed 2026-11-15: fixed in podcrates `v0.49.0` (its entry 634), taken by podssh | T-545 |
| #248 | COORD-071: fast-track T-684: Q101's waves 3 and 4, the crates that still live in podssh (to podcrates) | open (2026-11-15: podcrates fast-tracked it; step 1 frozen at `b9c04657`, step 2 at `2ffb7cd7`, podssh's answer on its glue in the body) | T-684 |
| #249 | Testers' guide: v1.1.0-beta.4 (in preparation) | open (2026-11-15: posted; updated when the beta is tagged) | T-446 |
| #250 | COORD-072: podssh took podcrates v0.47.0 at 568f9b2 (to podcrates) | closed 2026-11-15: podcrates recorded the take of `v0.47.0` | T-684 |
| #251 | COORD-073: podssh took podcrates v0.48.0 at 3e7c5a2 (to podcrates) | closed 2026-11-15: podcrates recorded the take of `v0.48.0` | T-684 |
| #252 | COORD-074: podssh took podcrates v0.49.0 at a99de1d (to podcrates) | closed 2026-11-15: podcrates recorded the take of `v0.49.0` | T-545, T-684 |
| #253 | COORD-075: pod-quic spins a core on a way whose reads keep failing (to podcrates) | closed 2026-11-15: podcrates `v0.51.0` bounds them (`pod_quic::bounded`), taken at `3f6a9fe` | T-787 |
| #254 | COORD-076: podssh took podcrates v0.50.0 at 13c52be (to podcrates) | closed 2026-11-15: podcrates recorded the take of `v0.50.0` | T-684 |
| #255 | [gh action] requested: the gate on `main` after the take of v0.50.0, and T-665's lab | closed 2026-11-15: the gate passed (run 43687960063, `e7cb4b6`); its first block ran, not the amended one, so the labs are asked again in #256 | T-684, T-665 (Actions start no workflow for this account on 2026-11-15) |
| #256 | [gh action] requested: the netem labs of T-665 and T-625, and T-786's error files | closed 2026-11-15: iroh-ab 43691396393 and wisp-rate 43691399331 passed, T-786's error files read | T-665, T-625, T-786 |
| #257 | [gh action] requested: the gate on `main` after T-665's default | closed 2026-11-15: the gate passed (run 43704942887, `6732178`) | T-665 |
| #258 | [gh action] requested: T-786's outage cell with the role's road | closed 2026-11-15: run 43709370293 read (T-786 done, T-789 filed) | T-786, T-789 |
| #259 | [gh action] requested: T-789's outage cell of the role's road with `-v` | closed 2026-11-15: run 43710388009 read | T-789 |
| #260 | COORD-077: podssh took podcrates v0.51.0 at 3f6a9fe (to podcrates) | closed 2026-11-15: podcrates recorded the take of `v0.51.0` | T-684, T-787 |
| #261 | [gh action] requested: the gate on `main` after the take of v0.51.0 | closed 2026-11-15: the gate passed (run 43711731169, `3f6a9fe`) | T-684 |
| #262 | COORD-078: pod-relay: a spare link of the resumable layer rides the pooled HTTP/2 connection of the silent link it replaces (to podcrates) | closed 2026-11-15: podcrates `v0.53.0` fixed it; the outage cell (run 43770482263) gave the first byte 0.13 and 0.18 s after the return | T-789 |
| #263 | COORD-079: podssh took podcrates v0.52.0 at 94ee6ac (to podcrates) | closed 2026-11-15: podcrates recorded the take of `v0.52.0` | T-684 |
| #264 | [gh action] requested: the gate on `main` after the take of v0.52.0 | closed 2026-11-15: run 43719624106 red in `ssh` (the Shadowsocks CLI test's old proxy wording), repaired; asked again in #265 | T-684 |
| #265 | [gh action] requested: the gate after the repair of the Shadowsocks CLI test | closed 2026-11-15: run 43726773977 red in `ssh`, `cold_connect` at random; asked again in #266 | T-684 |
| #266 | [gh action] requested: the lines of `cold_connect`'s failure in run 43726773977, and a rerun | closed 2026-11-15: the rerun passed; the lines read from the job's log, T-794 repaired the test | T-684, T-794 |
| #271 | [gh action] requested: the gate after T-794 | closed 2026-11-15: run 43737282670 passed `gate (ssh)`, red in `gate (m6)` (T-780) | T-794, T-780 |
| #272 | [gh action] requested: a rerun of the failed jobs of run 43737282670 | closed 2026-11-15: attempt 2 passed | T-780 |
| #273 | [gh action] requested: the gate after m6's iroh client with `-v` | closed 2026-11-15: run 43745453729 passed | T-780 |
| #274 | COORD-084: podssh took podcrates v0.54.0 at d00ca78 (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684 |
| #275 | [gh action] requested | closed 2026-11-15: the gate at `d00ca78` (run 43766309151) red in `gate (m6)` (T-780); the outage cell (run 43770482263) passed T-789 | T-684, T-780, T-789 |
| #276 | [gh action] requested: the gate after the take of v0.56.0, and the dry run of issue-sync | closed 2026-11-16: the runs at `bde7f17`: the gate (run 43804352372) red in `gate (lint)` and `gate (iroh)`, the release (run 43804360577) red in its aarch64 build, the sync's dry run (run 43804356638) green; the three repaired by `71ebc9d` | T-684, T-793 |
| #277 | COORD-085: podssh took podcrates v0.56.0 at 0363272, with the sync of the issues on (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684 |
| #278 | COORD-086: pod-lab: podssh's row of bind-denied asks for commands that its refused TCP connect cannot run (to podcrates) | closed 2026-11-16: `--allow-connect` in podcrates `v0.58.0`; podssh's lane passed in `bind-denied` with the proxy's port | T-791 |
| #279 | COORD-087: podssh took podcrates v0.58.0 at 043f32c, and its lane passes in pod-lab (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684, T-791 |
| #280 | COORD-088: podssh took podcrates v0.59.0 at 763cac5 (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684 |
| #281 | COORD-089: podssh took podcrates v0.60.0 at cbef76d (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684 |
| #282 | COORD-090: pod-lab's network labs: a proxy that reaches a server of the command's own, for podssh's lane (to podcrates) | closed 2026-11-16: podcrates `v0.62.0` gives `podlab run --serve` (its T-759) and sets the other proxy variables (T-760); podssh's lane passed behind five classes with it (`dda86c2`) | T-791 |
| #283 | COORD-091: pod-session: a resume that the client calls done, after which the session never moves (six failures in podssh's gate) (to podcrates) | open 2026-11-16: until podcrates answers | T-780 |
| #284 | COORD-092: podssh took podcrates v0.61.0 at d13ab01, with the installer core of the tag (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684, T-793 |
| #285 | COORD-093: podssh took podcrates v0.62.0 at 9151ebc (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684, T-780, T-791 |
| #286 | COORD-094: podssh took podcrates v0.63.0 at 5340fbb, with the installer core of the tag (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684, T-793 |
| #287 | COORD-095: pod-relay: a link of the resumable layer over the HTTP road (to podcrates) | closed 2026-11-17: podcrates `v0.65.0` gives the client (its entry 801), taken (COORD-097) | T-798 |
| #288 | COORD-096: pod-manual: four things podssh's manual needs before its text, help and JSON move to the crate (to podcrates) | closed 2026-11-17: podcrates `v0.65.0` gives the four forms (its entry 807), taken (COORD-097) | T-790 |
| #289 | COORD-097: podssh took podcrates v0.65.0 at 843e3c5, with pod-tor and pod-iroh (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684 |
| #294 | COORD-098: pod-relay: renew reads the default relay's 400 for an unknown reverse path as an error, not as no renewal (to podcrates) | closed 2026-11-17: podcrates `v0.67.0` reads that 400 as no renewal (its entry 834), taken (COORD-102) | T-713 |
| #295 | COORD-099: pod-relay: a route of a node to a Unix socket, as a target kind of Route (to podcrates) | closed 2026-11-17: podcrates `v0.67.0` gives `Route::unix` (its entry 836); its Windows path is asked in COORD-102 | T-714 |
| #296 | COORD-100: podssh took podcrates v0.66.0 at ae9cf1b (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684 |
| #297 | COORD-101: pod-tls: webpki-roots 1.0.12 with its ROOTS_VERSION, and rsa 0.10 (to podcrates) | closed 2026-11-17: answered by podcrates `v0.68.0` (COORD-129, PodUtils/podcrates#219), taken in `94c01b0` (COORD-106, #303) | T-802 |
| #298 | COORD-102: podssh took podcrates v0.67.0 at a4b1436; a Unix route of pod-relay on Windows (to podcrates) | closed 2026-11-17: answered by podcrates `v0.68.0` (COORD-129, PodUtils/podcrates#219), taken in `94c01b0` (COORD-106, #303) | T-684, T-714 |
| #299 | COORD-103: the two speeds of podssh relay serve: the runtime's placement of tasks, not the role (to podcrates) | closed 2026-11-17: podcrates read it and closed COORD-127 (PodUtils/podcrates#217); T-806 and T-807, its item 2, done | T-803, T-806, T-807 |
| #300 | COORD-104: pod-relay and pod-session: a relay's liveness offer, so a Durable Object relay can hibernate (to podcrates) | closed 2026-11-17: answered by podcrates `v0.68.0` (COORD-129, PodUtils/podcrates#219), taken in `94c01b0` (COORD-106, #303) | T-712 |
| #302 | COORD-105: pod-relay and pod-egress: headers of the caller on each WebSocket road, for Cloudflare Access (to podcrates) | closed 2026-11-17: answered by podcrates `v0.68.0` (COORD-129, PodUtils/podcrates#219), taken in `94c01b0` (COORD-106, #303) | T-718 |
| #303 | COORD-106: podssh took podcrates v0.68.0: the liveness offer, the headers of Access, a Unix route by pod-relay, one rsa (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684, T-712, T-714, T-718, T-802 |
| #304 | COORD-107: the wire document of podssh, for T-120 (to podcrates) | closed 2026-11-18: podcrates' T-120 (the wire documents) is done; T-723 done | T-723 |
| #305 | COORD-108: podssh took podcrates v0.69.0 (to podcrates) | closed 2026-11-18: podcrates recorded the take (its COORD issue closed, 2026-11-18) | T-684, T-808 |
| #306 | COORD-109: pod-piping: the probe of a node's upgrade without the caller's headers (to podcrates) | closed 2026-11-20: podcrates' probe writes the caller's headers (in `v0.78.1`), and podssh's skip of the probe went | T-718 |
| #307 | COORD-110: pod-relay: keep a relay member's `meet` from its `/relays.json` (to podcrates) | closed 2026-11-20: podcrates keeps it (in `v0.78.1`), and podssh's iroh road lists a member's iroh relay first | T-720 |
| #308 | COORD-111: podssh's answer to podnet's QA round: what its gate proves, and what not (to podnet) | closed 2026-11-23: by the operator: podnet closed COORD-102 (PodUtils/podnet#649) on 2026-11-20 after its T-450 to T-455; podssh's QA gate stays T-809 and T-446 | T-809 |
| #309 | COORD-112: pod-relay: OpenError::lines says one cause twice (to podcrates) | closed 2026-11-20: answered by podcrates' entry 869 in `v0.70.0` (PodUtils/podcrates#222), taken at `99e9fd5`; the relay's lost cause is T-843 (done) | T-809 |
| #310 | COORD-113: pod-ws: a shared HTTP/2 connection dies with the runtime that opened it (to podcrates) | closed 2026-11-18: podcrates' fix (its entry 871) taken in `v0.70.0` (COORD-119); T-811 done | T-811 |
| #311 | COORD-114: podssh's answer to podvm's COORD-180: its temp files and edges, and its black-box pass (to podvm) | open 2026-11-17: until podvm reads it | T-819 |
| #312 | COORD-115: podssh's answer to COORD-131: the rulings in AGENTS.md, and its copies of shared code (to podcrates) | closed 2026-11-23: by the operator: podcrates read it (PodUtils/podcrates#221); `Interrupts` public since `v0.78.1`, podssh's copy gone; the copies left are T-820's, and the takes' issues (#335, #337, #340) | T-820 |
| #313 | COORD-116: two messages of pod-dns and pod-relay that podssh's black-box pass found (to podcrates) | closed 2026-11-20: answered by podcrates' entries 903 and 904 in `v0.70.0` (PodUtils/podcrates#222), taken at `99e9fd5`; T-818 done | T-818 |
| #314 | COORD-117: pod-session keeps a write's error over the relay's Close, and the layer's link budget ignores a small cap (to podcrates) | closed 2026-11-19: both asks answered (podcrates entries 908 and 909, then 953 and 958) and taken at `ba19367`; T-826's rest is COORD-126's | T-826 |
| #315 | COORD-118: three lines of pod-proxy, pod-session and pod-relay that podssh's black-box pass found untrue or short (to podcrates) | closed 2026-11-20: answered by podcrates' entries 911, 912 and 913 in `v0.71.0` (PodUtils/podcrates#228), taken at `a6a3a3e`; T-828 done | T-828 |
| #316 | COORD-120: podssh's answer to COORD-134: podrunner first; cfb's asks in podssh wait for podcrates T-110, T-111, T-112 and T-117 (to podcrates) | closed 2026-11-23: by the operator: podcrates closed COORD-134 (PodUtils/podcrates#225) and answered asks 1 and 2 in COORD-136 (PodUtils/podcrates#227); cfb's blocked entries stay in #195 | T-711, T-719, T-722, T-729 |
| #317 | Donor study of 2026-11-18: 24 outside projects, one mechanism each that podssh lacks (tracker) | open 2026-11-18: until each of its entries is done | T-831, T-832, T-833, T-834, T-835, T-836, T-837, T-838, T-839, T-840, T-841, T-842, plus the existing entries that got additions: T-116, T-123, T-150, T-159, T-160, T-161, T-303, T-304 |
| #318 | COORD-119: podssh took podcrates v0.70.0 at 99e9fd5; a policy refusal lost the relay's cause (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#222) and answered T-843's ask by its entry 926 in `v0.71.0` (#228), taken at `a6a3a3e`; T-828 and T-843 done | T-684, T-828, T-843 |
| #319 | COORD-121: podssh took podcrates v0.71.0 at a6a3a3e (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#228) | T-684, T-826 |
| #320 | COORD-122: podssh took podcrates v0.73.0 at bcd2b2f; under a 1 MiB cap a new link sends again more than the cap (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#229, #231) and answered its ask by its entry 953 in `v0.74.0` (#237), taken at `9989ae6` | T-684, T-780, T-826 |
| #322 | COORD-123: podssh's entry for the ruling "ghcr.io": T-847, the job image of release.yml in the form of C789 (to podcrates) | open 2026-11-19: until T-847's first push at a tag | T-847 |
| #325 | COORD-124: podssh took podcrates v0.74.0 at 9989ae6; a move at three quarters of the cap still comes after it (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#237) and answered its ask by its entry 958 in `v0.75.0` (#238), taken at `ba19367` | T-684, T-826 |
| #326 | COORD-125: pod-term: a cooked session with no prompt, for an exec'd command (to podcrates) | closed 2026-11-19: answered in podcrates `v0.77.0` (its entry 960), taken at `b3005e5`; T-848 done | T-848 |
| #327 | COORD-126: podssh took podcrates v0.75.0 at ba19367; on Windows a move began late and met the cap once (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#238) and answered its ask by its entry 962 in `v0.76.0` (#239), taken at `5975bb0`; T-826 done | T-684, T-826 |
| #328 | COORD-127: podssh took podcrates v0.76.0 at 5975bb0 (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#239) | T-684, T-780, T-826 |
| #329 | COORD-128: podssh took podcrates v0.77.0 at b3005e5, and pod-release at c9772a3 (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#240) and answered its ask (podcrates' entry 971, `Plan::Newer`) in `v0.78.1` (#241), taken at `e5b7414`; T-850 done | T-684, T-850 |
| #330 | COORD-129: podssh took podcrates v0.78.1 at e5b7414 (to podcrates) | closed 2026-11-21: podcrates recorded the take (PodUtils/podcrates#241) | T-684 |
| #332 | [gh action] requested: the gate of 146bf88 (T-780's step of russh's loop, T-851) | closed 2026-11-20: the gate at `d0c2a04` (holding `146bf88`), run 44694900576, green; `deny`, `secrets` and `issue-sync` green | T-780, T-851 |
| #333 | [gh action] requested: the gate of 6e2ac37 (T-718, T-720, T-714) | closed 2026-11-23: by the operator: superseded on `main` by `930e5ba0`, `ff670778` and `0de83e93`, whose runs started by the push | T-714, T-718, T-720 |
| #334 | COORD-130: podssh took podcrates v0.79.0 at 4552b86; a leaf's line of pod-release names an empty subject (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#245) and did the ask as its entry 1016, on its `main` for the next tag | T-684 |
| #335 | COORD-131: podssh took podcrates v0.80.0 at 77c63da (to podcrates) | closed 2026-11-20: podcrates recorded the take (PodUtils/podcrates#250) | T-684, T-820 |
| #337 | COORD-132: podssh took podcrates v0.81.0 at 467274b (to podcrates) | closed 2026-11-21: podcrates recorded the take (PodUtils/podcrates#254) | T-684, T-820 |
| #340 | COORD-133: podssh took podcrates v0.82.0 at e728db9 (to podcrates) | open 2026-11-23: until podcrates records the take | T-684 |
| #341 | COORD-134: carry vendor/iroh-relay to 1.4.2, for iroh 1.4.2 (to podcrates) | open 2026-11-23: until a tag of podcrates carries iroh-relay 1.4.2; the iroh family of #339 waits for it | T-684 |
| #342 | COORD-135: what keeps podssh's node_install off pod-unit, and one step of pod_core::files (to podcrates) | open 2026-11-23: until podcrates answers asks (a) to (e) | T-820 |
| #343 | COORD-136: pod_core::files::bind_staged binds at the path past sun_path's room (to podcrates) | open 2026-11-23: until a tag of podcrates binds a long path | T-857 |
| #267 | COORD-080: what podssh's help and manual need of the shared crate (to all) | closed 2026-11-17: T-790 and T-730 done; podnet closed its COORD-090 (PodUtils/podnet#584) | T-730, T-790 |
| #268 | COORD-081: podssh's host classes and lane for pod-lab, and its manual for pod-manual (to podcrates) | closed 2026-11-23: by the operator: podcrates closed COORD-107 and COORD-108 (PodUtils/podcrates#180, #181) on 2026-11-18 and did T-701; T-790 done, T-791 goes on | T-790, T-791 |
| #269 | COORD-082: podssh's map of issues to entries, and its install (to podcrates) | closed 2026-11-23: by the operator: podcrates closed COORD-110 and COORD-109 (PodUtils/podcrates#183, #182) on 2026-11-18; T-792 done, T-793's installer in place | T-792, T-793 |
| #270 | COORD-083: a watcher of each repository's Actions runs, so that no session waits in the dark for a run (to all) | closed 2026-11-15: podcrates took its logic into the one watcher, PodUtils/podcrates:scripts/agent/watch.py (COORD-112, PodUtils/podcrates#186), and podssh dropped its own | T-684 |

**The survey of #59, of 2026-10-31.** It extends #18 and the study of
carriers of the same day (`docs/carriers.md`, whose forward road is T-347,
T-351, T-352 and T-353). Its ranking, road by road: 1, a forwarder that
takes its target from the URL: T-369, and T-370 for the forwarders in the
binary (Q56), both done on 2026-11-01; 2, the same Worker in the user's own Cloudflare account: a
template of T-369 can name it, podssh ships no forwarder (a relay of the user's own
is T-169, podssh's own relay role since Q63, 2026-11-02), and a recipe for it is
part of Q56; 3, SSH on port 443 as a hop: T-371 and T-372 (#61, both done); 4,
Shadowsocks: T-373 (#62, done); 5 and 6, WARP and Arti: T-352 and T-353 (#63,
Q52, settled); 7, n0's iroh relays: a road already (T-162, done), and T-348 for the
release binaries (Q50, settled on 2026-10-31). The comment's corrections of the
study: the three forwarders are T-369 and T-370; the 60 s of EICE's
presigned URL, which the comment found in no document of AWS, the study
cites to AWS's own client, its source F24
(`aws/aws-cli:awscli/customizations/ec2instanceconnect/eicesigner.py`),
which the comment does not name, and T-351 keeps it; Microsoft Dev
Tunnels, which the study left out of the forward road as a tunnel of the
class of `cf://` that needs an account, is fourth on its reverse road, and
`cf://` with a quick tunnel gives that class with no account (T-347); the
rules of `connect()` in a Worker (port 25, and Cloudflare's and private
addresses, refused as targets) hold for the forwarders of T-369. The
classes that gave no road (TURN with TCP allocations, public frp, VPN exits
that need a TUN device, domain fronting) need what a cage does not give
(UDP, a TUN device, a port other than 443, 80 and 8443), or do not exist (a
public front to any target), as #59 says.

**The two options of #63.** Its prerequisite for both, a TCP/IP stack in the
process, holds for T-352 and T-374; Arti gives a stream for each target, so
T-353 needs none (Inferred).
## The reports on other projects (in #18 to #25, and in #29 to #36)

| Report | Entries |
| --- | --- |
| lablup/bssh | T-043, T-046, T-053, T-107, T-018 to T-022, T-140, T-199, T-027, T-028, T-029, T-030, T-039, T-183 |
| VLOD-ZDOV/quic-ssh | T-162, T-164, T-151, T-152, T-153, T-159, T-043, T-160, T-143, T-035, T-038, T-040, T-086, T-087, T-115, T-052, T-198 |
| nikhiljha/rose | T-160, T-161, T-162, T-158, T-167, T-087, T-130, T-201 |
| adonm/zuko | T-162, T-086, T-163, T-177, T-135, T-150, T-052, T-158, T-121, T-087 |
| rustonbsd/iroh-ssh | T-166, T-165, T-163, T-121, T-043, T-090, T-218, T-114, T-225 |
| willykeenan/warren | T-169, T-088, T-089, T-087, T-086, T-180, T-201, T-151, T-157, T-224, T-227 |
| arjun988/GPU-Share | T-086, T-087, T-162, T-052, T-134, T-114, T-169, T-197, T-179, T-090 |
| EpicEric/sandhole | T-123, T-124, T-168, T-169, T-180, T-114, T-157 |
| mirkobozzetto/bunflared | T-170, T-299, T-300, T-301, T-180, T-177, T-055; WebSocket passthrough already holds (`podssh proxy` is a byte pipe) |
| greaber/syq | T-079, T-083, T-136, T-134, T-147, T-054, T-089, T-145, T-146, T-143, T-226 |
| menhera-org/ssh-obi | T-167, T-151, T-152, T-153, T-154, T-158, T-119, T-122 |
| ado11231/slingshot | T-086, T-114, T-079, T-143, T-178, T-189, T-193, T-192, T-220; a menu-bar app: no, podssh is a CLI (`docs/decisions.md`) |
| gold-silver-copper/fux | T-159, T-161, T-118, T-151, T-158, T-186, T-200, T-198, T-117 |
| l0ng-ai/tty7 | T-159, T-153, T-107, T-186, T-120, T-030, T-133, T-036, T-121, T-221, T-224 |
| AlpinDale/parsync | T-136, T-142, T-141, T-164, T-139, T-048, T-144, T-143, T-150, T-134 |
| sleepinginsummer/agent-ssh-cli | T-136, T-134, T-054, T-039, T-114, T-031, T-032, T-043, T-034, T-026 |
| OthmaneBlial/MobaRust | T-149, T-145, T-041, T-038, T-053, T-187, T-185, T-201, T-047, T-179, T-181, T-202, T-227 |
| yituorou/meatshell | T-070, T-047, T-034, T-148, T-134, T-041, T-189, T-179, T-181, T-185 |
| TeddyHuang-00/sshping | T-053, T-157, T-045, T-049 |
| Petyok/SSHub | T-043, T-049, T-054, T-042, T-171, T-302, T-303, T-304, T-305, T-306, T-034, T-033, T-047, T-011 |
| cubic-vm/cubic | T-011, T-139, T-181, T-049, T-050, T-051, T-035, T-013 |
| rssh-org/rssh | T-033, T-041, T-034, T-195, T-190, T-185, T-187, T-222; colored command blocks: no, podssh is a CLI (`docs/decisions.md`) |
| totoshko88/RustConn | T-175, T-043, T-038, T-172, T-153, T-056, T-034, T-189, T-191, T-032, T-047 |
| whme/csshw | T-185, T-184, T-043, T-048, T-187, T-151, T-132, T-210, T-188 |
| ImKKingshuk/USBoverSSH | T-059, T-025, T-039, T-051, T-121, T-145, T-116, T-007, T-009, T-040, T-176, T-182 |

## The sandbox reports of 2026-10-08

| Report | Entries |
| --- | --- |
| Sandbox A (`report-podssh-sandbox-KTM-2026-10-08.txt`) | T-001 (done), T-004, T-005, T-006, T-024, T-025, T-157 |
| Sandbox B (`report-podssh-3a88e1d-20261008.txt`) | T-001 (done), T-004, T-157 |

## The report of the operator's testing agents on `v1.0.0`, 2026-11-02

A black-box test of `podssh-x86_64-unknown-linux-musl` `v1.0.0` (`35a0d19`) on a Debian 13 guest
with a curated environment (no `USER`, no `ssh` config, no key, no `tmux`, egress through one HTTP
CONNECT proxy on ports 80 and 443): eight issues, not on GitHub, a ledger of 40 observations
(L-01 to L-40), its findings and a checker of its claims, which the triage read and did not run.
Each entry says which claims it verified in the code, and corrects the ones that the code does not
support.

| Report | Entries |
| --- | --- |
| Issue 01, "no user name" with `USER`, `LOGNAME` and `USERNAME` unset (`01-no-user-name.md`; L-01) | T-500 (the README of this repository names no `ssh railway.new`; that one-liner is Railway's page) |
| Issue 02, `--su` waits for ever when `SSH_ASKPASS` exits not 0 (`02-su-hang.md`; L-03, L-05, L-11) | T-501 (L-11, `--sudo` under `NOPASSWD`, is by design) |
| Issue 03, `-o ProxyCommand=none` does not beat a file's `ProxyCommand` (`03-proxycommand-in-config.md`; L-07) | T-502 (L-07 is T-043's Decision: `podssh proxy %h %p` names `podssh ssh` itself, and runs nothing) |
| Issue 04, host names by road, and `each`'s blanks (`04-each-whitespace.md`; L-18, L-19) | T-503 (the check of the relay road is podssh's own, not the relay's), T-504 |
| Issue 05, 22 keywords of a restriction accepted with no word (`05-ignored-config-keywords.md`; L-08, L-09, L-39) | T-505 (L-39's two notes come from Debian's `/etc/ssh/ssh_config`, not OpenSSH's defaults) |
| Issue 06, an empty list reads as a broken one (`06-empty-list-output.md`; L-23) | T-506 (`job list` prints no header either) |
| Issue 07, the way back after a downgrade (`07-update-rollback-advice.md`; L-37) | T-507 |
| Issue 08, `--timeout` on two copy verbs of four (`08-timeout-inconsistent.md`; L-12, L-13, L-30) | T-508 (the split is T-139's Decision; the silent server's wait is ConnectTimeout's 60 s, past the report's 30 s; L-30 is met) |
| The ledger's other observations | L-04, L-28 and L-40: T-509, with GitHub #106; L-06: T-481 (GitHub #91); L-15 and L-16: T-510; L-20: T-475; L-26: T-483; L-32: T-511; L-10, L-14, L-17, L-22, L-25, L-27, L-29 and L-36: T-512. Met: L-21 (the row of `--timeout` of `job` names `wait`, and the refusal names `job wait`, `crates/podssh-cli/src/flags/job.rs:14-15`), L-33 (the table of flags for a program is `podssh man --json`, T-050, which holds no such word; `--help` is prose for a person). Not podssh's, as the ledger says: L-02 (Railway refused each login), L-24 (the quick tunnel's road, as its manual says), L-31 and L-35 (the proxy dropped a CONNECT), L-34 (a note on the test), L-38 (both forms of help work) |

The report names GitHub #22 (T-502 and T-505 are on its ground, `ssh_config` and the flags of
OpenSSH) and #60 (T-509 narrows T-370's fallback).
