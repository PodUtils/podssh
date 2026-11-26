The resumable layer of milestone M6, with which a session between two podssh
ends survives a drop: the handshake and the offsets, the replay buffer, the
resume, the heartbeats, the move before the relay's limits, the exit
measurement and the throughput method. Then the session features that build
on the layer, which wait in the backlog.

# T-151: The resumable layer: its handshake and the byte offsets

**Source:** ROADMAP M6 (the resumable stream layer); `docs/design.md:785-856`
(layer 2, decided); GitHub #19 (Nemo-010, 2026-10-08: the quic-ssh, ssh-obi
and fux reports) and GitHub #20 (a handshake with a version and a role).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

A dropped link to the relay ends the session with exit 255, and a new client
address loses it (`docs/design.md:756-768`). The relay keeps nothing across a
new connection (`docs/design.md:770-773`).

## Premise

Read: the design is decided: offsets and acknowledgements in each direction,
a session id and a 256-bit resume secret, under SSH (`docs/design.md:785-856`),
in a `session` module of `podssh-relay` (`docs/design.md:613-622`), a crate
with no C. Measured: `grep -ril resum crates` finds only the IRC client.
Today russh's bytes go through a pipe to the relay session
(`crates/podssh-ssh/src/relay_stream.rs:182-305`). Frame boundaries mean nothing
on the relay (`docs/relay.md:521-524`), and the relay reads each record and can
drop or add frames (`SECURITY.md:33-36`).

## Approach

1. A sans-IO codec (`docs/architecture.md:276-280`) in a new module
   crates/podssh-relay/src/session/, with each file under 500 lines. A record
   is a type byte, a 32-bit length and a body of 64 KiB or less: `GREETING`
   and `ACCEPT` (far end), `OPEN` and `PROOF` (client), `REFUSE`, `DATA` (its
   first offset, then the bytes), `ACK`, `PING`, `PONG`, `CLOSE` (a reason).
2. Offsets are 64-bit, start at 0 in each direction, and never reset. A `DATA`
   record below the expected offset loses its overlap; one above it is a gap:
   drop the link and resume (T-153). Never deliver bytes after a gap.
3. Each first record carries a fresh nonce, and no side waits for the other's.
   On the reverse road the client waits for `GREETING`, because a node with no
   layer sends `SSH-2.0-`; the client then runs with no layer (one `-v`
   note). On the iroh road the ALPN names the layer (T-162).
4. A new session: X25519 keys of both sides, and HKDF-SHA256 over the shared
   value and both nonces, give the secret; `ACCEPT` gives a 128-bit id. A
   resume: `OPEN` names the session, and `PROOF` and `ACCEPT` carry an
   HMAC-SHA256 over both nonces and the sender's received offset.
5. Use `x25519-dalek`, `hkdf`, `hmac`, `sha2` and `zeroize` (`Cargo.toml`), and
   `rand` (`crates/podssh-relay/Cargo.toml:35`). Return an error when the
   system gives no random bytes (T-064). Keep the secret and the proofs out of
   output, logs and argv.
6. `GREETING` names its features (`replay.v1`, `heartbeat.v1`, `move.v1`); a
   side ignores a name that it does not know (ssh-obi's model, read in
   GitHub #19, not verified here).
7. On the client, the layer goes between the pipe and the link, and keeps
   `RelayStatus` (`crates/podssh-ssh/src/relay_stream.rs:69-176`). Docs: the
   records and the threat model in `docs/design.md` section 5,
   `docs/architecture.md`, the map of `AGENTS.md`, and `docs/STATUS.md`.

## Decision

Recommendation: an X25519 exchange gives the secret, and HMAC over fresh
nonces of both ends proves it. No secret and no reusable proof cross the
relay, so a passive reader of its logs cannot take the session; an active
relay can still break it, as today. The alternative, a secret sent in
`ACCEPT`, lost: the relay terminates TLS, so its logs would hold the secret.

Taken (2026-10-09): in this entry only the client of `podssh ssh node://`
runs the layer, and no far end runs it outside the tests. The alternatives
that lost: the node speaks the layer now, which gives each session the
layer's cost and none of its gain until T-152 and T-153, and shows a
`GREETING` to an SSH client with no layer behind `podssh operator` (T-153
decides that with the resume); the client waits for the first byte on the
forward road too, where a standard sshd never greets, so each session would
pay the wait for nothing.

Taken: the client waits 30 s at most for the far end's first byte, more
than the operator leg's 20 s wait for `ready`, after which the node's first
byte comes. 10 s lost: a slow `ready` would make the client choose no layer
before a `GREETING` came. Taken: the `ACCEPT` of a new session carries no
proof, since only an active relay could change the exchange, and it could
make the proof too.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_codec --test session_handshake
sh scripts/dev.sh check
```

The codec test decodes golden vectors written by hand from the table, not
made by the encoder; a planted decoder that delivers bytes after a gap fails
it. The handshake test refuses a wrong secret, a replayed `PROOF` and an
unknown session. The gate builds `podssh-relay` with `CC=/nonexistent`.

## Correction

Step 7 cites the pipe of the forward road
(`crates/podssh-ssh/src/relay_stream.rs:69-176`), whose far end is the
relay itself: it never speaks the layer, so that pipe keeps no layer and its
`RelayStatus` is unchanged. The client's pipe to a node is in
`crates/podssh-cli/src/ssh/node.rs`, between SSH and the operator's leg,
which has no `RelayStatus`; the layer goes there. The far end in
`podssh node` comes with T-153, which keeps a node's sessions across links.
By the operator's decision of 2026-10-09 (`docs/decisions.md`), the gate run
and the planted decoder wait for the checks of the release (T-251).

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test targets
`session_codec`, `session_handshake` moved to `pod-session` with their names; run `cargo test -p
pod-session --test session_codec` `cargo test -p pod-session --test session_handshake` there.

## Done

2026-10-09.

- `crates/podssh-relay/src/session/`: the records and their decoder
  (`record.rs`, `decode.rs`), the offsets (`offset.rs`), the id, the
  nonces, the secret and the proofs (`secret.rs`), the handshakes and the
  sessions that a far end keeps (`handshake.rs`), a link past its handshake
  (`link.rs`), and the two ends over tokio streams (`client.rs`, `far.rs`,
  `pump.rs`); each file under 500 lines, with `sha2`, `hmac`, `hkdf` and
  `x25519-dalek` of the workspace. The table, the derivation and what the
  layer defends against are in `docs/design.md`, section 5.
- `podssh ssh node://` runs the client's end (`crates/podssh-cli/src/ssh/node.rs`):
  it sends nothing until the node's first byte, takes a `GREETING` as the
  layer, and else passes the bytes as they are; `-v` says which (the
  manual's note of `node://`, `docs/cli.md`).
- In passing: x25519-dalek's `zeroize` feature is on in the workspace.
  podssh-ws's TLS key exchange wiped a copy of its X25519 scalar, not the
  scalar inside `StaticSecret`; it now wipes itself, and a function that
  does not compile without the feature guards that. And CI's lint failed at
  `9841fa5` on the form of the manual's scp note, now two paragraphs.
- Prove, native: `cargo test -p podssh-relay --test session_codec --test
  session_handshake --test session_link`: 31 passed (15, 12 and 4). The
  codec decodes 14 vectors written by hand, whole and one byte at a time,
  and refuses 11 bodies that are not their record; a link delivers nothing
  after a gap. The handshake gives the secret `8a41f649…` and the proofs
  `44f2167e…` and `3faedde0…`, computed apart with an X25519 written from
  the pseudo-code of RFC 7748 (checked against its section 6.1), and HKDF
  (checked against RFC 5869, A.1) and HMAC of Python's standard library. It
  refuses a wrong secret, a replayed `PROOF`, an unknown and a removed
  session, a reflected proof and a key of low order. The two ends carried
  1 MiB each way with equal SHA-256.
- Live, once: `cargo test -p podssh-cli --test node_live -- --ignored
  ssh_to_a_node` passed (`exit 3` through a node in front of railway.new,
  with `-v` showing "the far end offers no resumable layer"). Its first run
  failed: railway.new answered with 262 bytes on stdout and another exit
  status, after a login that worked (stderr held only the warning of the
  recorded host key); the next two runs gave 3.
- `cargo test --no-fail-fast`: 963 passed, 0 failed, 20 ignored (the live
  tests). `python scripts/check-repo.py`: ok.
  `cargo todo check`: the record agrees.
- Waits for T-251, by the decision of 2026-10-09: the gate
  (`sh scripts/dev.sh check`, with `CC=/nonexistent` and Rust 1.85), and the
  planted decoder: `Inbound::accept` that returns the bytes of a record past
  a gap must fail `a_gap_delivers_nothing_and_the_offset_stays`,
  `a_link_delivers_nothing_after_a_gap` and
  `a_gap_ends_the_link_and_nothing_after_it_is_delivered`.

# T-152: The replay buffer, limited, with backpressure

**Source:** ROADMAP M6 (a limited replay buffer with backpressure);
`docs/design.md:787-789`; GitHub #19 (Nemo-010, 2026-10-08: quic-ssh's bounded
buffer with a start offset; ssh-obi's duplicate recent bytes); GitHub #31.
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

A resume can send again only the bytes that the sender still holds. A buffer
with no limit fills the memory of a small host when the peer is slow.

## Premise

Read: the sender keeps each byte that is not acknowledged, in 4 to 16 MiB,
"with backpressure when it is full" (`docs/design.md:788-789`). So no byte
that is not acknowledged is dropped, and a resume is byte-exact; the start in
an escape sequence of GitHub #31 needs dropped bytes (T-221). The reverse road
drops a frame and closes with `1011 relay backpressure` above 1 MiB queued
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:185`); the buffer
turns that close into a resume. The SSH window is 512 KiB for each channel
(`crates/podssh-ssh/src/run.rs:30-34`). Do not bring back the backpressure module of
`podssh-transport`, which T-074 removed (`docs/design.md:629-630`).

## Approach

1. In the session module of T-151, keep for each direction the bytes from the
   acknowledged offset to the sent offset, allocated as they arrive.
2. The capacity is 4 MiB, up to 16 MiB by a setting. Invariant: a session
   holds at most the capacity plus one record in each direction.
3. When the buffer is full, the writer returns `Poll::Pending` until an `ACK`
   frees space; russh then waits, and the far end's SSH window stops the
   server. Never drop a byte; never grow past the capacity.
4. The receiver sends `ACK` after each 64 KiB, after 200 ms with bytes not
   acknowledged, and in each `PONG` (T-154).
5. A resume sends again from the peer's received offset. An offset that the
   buffer does not keep gets `REFUSE` with both offsets, and the session ends
   with that reason: never a silent gap.
6. Pitfall: the SSH window limits one channel, so several channels can put
   more than 1 MiB in flight. T-157 tells whether a send window under 1 MiB
   for each link is worth its cost in throughput.
7. With `-v`, print the bytes that each resume sent again. Write the defaults
   in `docs/design.md` section 5, and the bound in T-201.

## Decision

Byte replay or screen state: byte replay is decided (`docs/design.md:785-786`,
the model of Eternal Terminal), and the layer sees only SSH ciphertext. Screen
state matters only when a new client attaches to a kept shell (T-161).

Recommendation: 4 MiB by default. The relay holds at most 1 MiB for a slow
receiver and the SSH window is 512 KiB, so 4 MiB keeps the bytes of a lost
link. A node with 16 sessions (crates/podssh-transport/src/control.rs lines 111-120 at `e8bbd4d`)
then holds 64 MiB at most. The alternative, 16 MiB, lost: four times the
memory in a cage, for no measured gain.

Taken (2026-10-09): the buffer and the `ACK`s run only when both sides
named `replay.v1` in their first records. A peer that never acknowledges
would fill the buffer, and the writer would then wait for ever: the
alternative, a buffer on each session, lost for that reason. Taken: the
writer reads from the application only what the buffer has room for, so the
buffer never holds more than its capacity (the bound of step 2 with no extra
record); a `DATA` record over the room is refused whole, never cut.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_replay
```

The test (crates/podssh-relay/tests/session_replay.rs) writes 32 MiB with no
`ACK`: the writer waits at 4 MiB, and an `ACK` frees space. A resume sends
exactly the missing bytes, also after a lost frame (an equal SHA-256). It
checks the invariant of GitHub #31: no byte that is not acknowledged is
dropped, and a resume at an offset that is not kept gets `REFUSE` with a
named reason, never a silent gap. A planted buffer with no capacity check
fails it, and so does one that drops its oldest bytes when it is full.

## Correction

The bound of the Decision counts 16 sessions on a node, but the node takes
the relay's limit from its `hello`: 64 sessions, measured 2026-10-09
(`docs/reverse.md:33-36`). With each session's 4 MiB kept, a node can hold
256 MiB; T-153, which makes the node a far end that keeps sessions, bounds
the whole node (its step 6). Step 7's `-v` line belongs to the resume loop
of T-153: no resume runs before it, and `Link::resume` gives the count of
the bytes sent again. By the operator's decision of 2026-10-09, the planted
buffers wait for the checks of the release (T-251).

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_replay` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_replay` there.

## Done

2026-10-09.

- `PodUtils/podssh:crates/podssh-relay/src/session/replay.rs`: the bytes from the
  acknowledged offset to the sent offset, taken as they come and given back
  when the buffer empties; 4 MiB by default, up to 16 MiB with
  `PODSSH_REPLAY_BUFFER` (the manual's ENVIRONMENT); bytes past the room
  refused whole; a resume from an offset that it does not keep is `NotKept`,
  whose `REFUSE` (code 3) names the offset asked and the offsets kept.
- `link.rs`: the session's state now outlives a link (offsets, buffer, the
  last `ACK`), and `Link::resume` starts the next link with the bytes to send
  again; an `ACK` or a `PONG` frees the buffer. `pump.rs`: the writer reads
  only what the buffer has room for and waits for an `ACK` when it has none;
  the receiver acknowledges each 64 KiB at once and fewer bytes after 200 ms.
  The two ends turn the buffer on only when both named `replay.v1`
  (`Settings`, `session::FEATURES`); `podssh ssh node://` passes the
  setting. The defaults are in `docs/design.md` (section 5), the bound in
  T-201.
- Prove, native: `cargo test -p podssh-relay --test session_replay`:
  9 passed, three runs in a row with the link test. 32 MiB to a far end that
  does not acknowledge: exactly 4 MiB go out and nothing more for 500 ms; an
  `ACK` of 1 MiB lets exactly 1 MiB more through; then the whole 32 MiB with
  an equal SHA-256. A frame lost after 640 KiB of 2 MiB: the link ends with
  the bytes before the gap, the resume sends exactly the other 1,441,792,
  and the digests are equal. A model of 3 MiB of random sends and
  acknowledgements, old ones among them: the buffer holds exactly the bytes
  not acknowledged after each step. Resumes from below the acknowledged
  offset and past the bytes sent are refused with both offsets. A peer with
  no `replay.v1` gets 6 MiB with no buffer and no `ACK`.
- `cargo test --no-fail-fast`: 972 passed, 0 failed, 20 ignored (the live
  tests). `python scripts/check-repo.py`: ok.
  `cargo todo check`: the record agrees.
- Waits for T-251, by the decision of 2026-10-09: the two planted buffers
  (`Replay::keep` with no check of the room, which must fail
  `the_buffer_never_grows_past_its_capacity` and
  `a_full_buffer_makes_the_writer_wait_until_an_ack`; and one that drops its
  oldest bytes when full, which must fail
  `the_buffer_never_drops_a_byte_that_is_not_acknowledged` and
  `a_resume_sends_exactly_the_missing_bytes_after_a_lost_frame`).

# T-153: Resume through any road and relay host, with a session secret and a capped backoff

**Source:** ROADMAP M6 (reconnection through each relay host);
`docs/design.md:845-847`; GitHub #19 (Nemo-010, 2026-10-08: ssh-obi's policy,
talaria0101's drops); GitHub #17 and #25 (a retry by the close reason).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** L
**Status:** done

## Problem

After a loss, the client must find its session again through any road and
relay host. A retry that ignores the close reason is wrong: one of 180
sessions dropped with `1011`, and some drops repeat on one target, as
GitHub #19 reports. Some closes mean "do not come back".

## Premise

Read: the failover across relay hosts serves the first connection only
(`PodUtils/podssh:crates/podssh-relay/src/open.rs:212-298`). `classify` maps each reverse close
to a retry class (crates/podssh-transport/src/closes.rs lines 154-229 at `e8bbd4d`), with
`relay backpressure` as `Retry::Never`
(crates/podssh-transport/src/closes.rs line 202 at `e8bbd4d`); a received Close lost its code
until T-072 (repaired 2026-10-09). Read, not measured: `/v1/node` and `/v1/connect` are on the
control host only (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:23-24`).
A second node socket for one name gets `409`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:152-153`), and
the node then exits (docs/reverse.md, line 19 at `fb228e9`).

## Approach

1. The client drives the resume. On a loss with no `CLOSE` record, it tries
   the roads of T-164 and each host of the `RelayList`
   (`PodUtils/podssh:crates/podssh-relay/src/relay.rs:115-129`), each within `HOST_DEADLINE`
   (`PodUtils/podssh:crates/podssh-relay/src/open.rs:35-37`), with `open::backoff` between
   rounds (`PodUtils/podssh:crates/podssh-relay/src/open.rs:421-435`). Do not fork it (T-077).
2. A `CLOSE` record never reconnects; each other loss reconnects first
   (ssh-obi's rule, read in GitHub #19, not verified here). Print one stderr
   line for each loss and each resume, and never a secret or a token.
3. Resume after `1011 socket error`, `node disconnected`, `node offline`,
   `relay backpressure`, `1013 node open timeout`, `1009 session byte cap`,
   and a loss with no Close. Stop with the reason on both `1001` rows and on
   the rows of a fault in podssh's own bytes (`1003`, `1008 wait for ready`).
4. The far end keeps a session with no link until the resume deadline, then
   closes the target connection. The client gives up at the same monotonic
   deadline, and exits 255 with the reason and the hop (T-024).
5. Measure first, with a live pair, whether a pool host serves
   `/v1/connect/<name>`. If none does, "each relay host" means each address of
   the control host (pins, resolver, DNS over HTTPS). Write it in
   `docs/relay.md`, with `docs/reverse.md` and the manual's relay section
   (`crates/podssh-cli/src/man/facts.rs:314-468`).
6. A node keeps the replay buffer of each session (T-152): with the relay's
   limit of 64 sessions and 4 MiB each, 256 MiB. Bound the node's whole
   replay memory (a session past the bound gets `REFUSE` busy, code 6), and
   write the bound in T-201.

## Decision

Recommendation: a resume deadline of 10 minutes at both ends: the M6 exit
asks for a stall of 3 minutes, and the backoff adds up to 45 s. The
alternative, no deadline, lost: a node in a cage would keep connections for
clients that never come back.

Recommendation: after a loss, a node retries `409` with the backoff until the
deadline, because the relay can still hold its old socket; a first
registration still exits on `409` (`docs/reverse.md:24`). The alternative, an
exit on each `409`, lost: a new node address would end each session. The
operator confirms this change of `docs/reverse.md`: T-261, to which the
operator agreed on 2026-10-09 (Q31).

Taken (2026-10-09): each session of `podssh node` runs the layer, and the
node has no flag for an operator with no layer. podssh replaces the other
operators of the reverse road, and both of its own (`podssh ssh node://`,
`podssh operator`) speak the layer; a flag would carry no resume, and it
can come when an operator needs it. Taken: the node keeps 64 MiB of replay
buffers at most, a whole buffer for each session that it keeps (16 at the
default of 4 MiB), so the bound of step 6 holds whatever the sessions do; a
new session past it ends at once with the reason. Taken: the line of each
resume gives the bytes sent again, so `-v` is not needed for them (T-152,
step 7).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_resume --test session_policy
```

The resume test cuts a scripted link at random points while 32 MiB go each
way, resumes through a second fake relay host, and compares SHA-256 digests;
after the deadline, `REFUSE` comes and the client exits 255. The policy test
maps each close row to resume or stop; a planted policy that resumes on
`1001 pair expired` fails it.

## Correction

The policy test needs the close table, which is in the feature `pair`: its
command is `cargo test -p podssh-relay --features pair --test
session_resume --test session_policy`. The Premise's `classify` gives
`relay backpressure` no retry, which stays true of a session with no layer;
with the layer, a dropped frame is a gap that a resume repairs, so the
layer's own policy (`podssh_relay::reverse::closes::resumes`) resumes it.
Step 5, measured 2026-10-09: two pool hosts answered an operator's
`/v1/connect/<name>` with `HTTP 503: reverse: unavailable`, and the control
host carried the session; a resume goes through the control host alone, by
each of its addresses (`docs/relay.md`). The `409` of the Decision is T-261.
By the operator's decision of 2026-10-09, the gate run and the planted
policy wait for the checks of the release (T-251).

## Done

2026-10-09.

- The client's session across links (`PodUtils/podssh:crates/podssh-relay/src/session/resume.rs`):
  after a loss, it asks its caller for a new link, proves the secret on it,
  and each side sends again from the other's offset; a `CLOSE`, a `REFUSE`,
  or a close that says not to come back ends it, and else it tries with the
  backoff of the forward opener until 10 minutes after the loss
  (`End::GaveUp` with the reason). The far end's sessions across links
  (`keep.rs`): a session's target and state wait after a loss until the
  deadline; a resume stops the old link when it still runs; the received
  offset of a resume's `ACCEPT` is read from the session's state at that
  moment (`sessions.rs`). One link (`pump.rs`) borrows the application and
  never shuts it on a loss, and the bytes received but not yet written stay
  with the session, so a link that ends in a write loses none.
- `PodUtils/podssh:crates/podssh-relay/src/reverse/layered.rs`: the node's far end, a handler
  over the TCP handler: `ready` at once, the handshake, then TARGET for a new
  session only, and the node's budget of 64 MiB. `reverse::closes::resumes`:
  the policy of step 3 over the table's rows.
- `crates/podssh-cli/src/layered.rs`: the client over the operator's legs,
  for `podssh ssh node://` and `podssh operator`; one line for each loss and
  each resume. `podssh node` runs the far end. The manual's notes of `ssh`,
  `node` and `operator`, `docs/cli.md`, `docs/reverse.md`, `docs/relay.md`
  and `docs/design.md` (section 5) say so.
- Prove, native: `cargo test -p podssh-relay --features pair --test
  session_resume --test session_policy`: 6 passed. Four cuts at random points
  in the middle of records, while 32 MiB go each way: four losses, four
  resumes through two stand-in hosts, and equal SHA-256 digests at both ends.
  A loss with no new link until the far end's deadline passed: the resume
  gets `REFUSE` (an unknown session), and the session ends with that reason;
  with no new link at all, the client stops at its own deadline. Each row of
  the close table resumes or stops as step 3 says. `--test reverse_layered`:
  3 passed: a session cut twice comes back whole with one connection to
  TARGET; an unreachable TARGET and a node past its budget end the session
  with the reason.
- Live, once (`cargo test -p podssh-cli --test node_live -- --ignored`):
  GitHub's banner came through a node with the layer, and `podssh operator`
  carried it with exit 0; `podssh ssh node://` logged in to railway.new
  through the layer (`-v`: "the far end (a podssh node) opened resumable
  session ef6f903b", features `replay.v1`), and railway.new then limited the
  anonymous visitor with its exit 13 in place of `exit 3`; the test now names
  that cause.
- `cargo test --no-fail-fast`: 981 passed, 0 failed, 20 ignored (the live
  tests). `python scripts/check-repo.py`: ok.
  `cargo todo check`: the record agrees.
- Waits for T-251, by the decision of 2026-10-09: the gate, and the planted
  policy that resumes on `1001 pair expired`, which must fail
  `an_expired_pair_and_a_stop_are_never_resumed` and
  `each_row_of_the_table_resumes_or_stops`.

# T-261: A node that lost its socket connects again on `409`, until the resume deadline

**Source:** T-153 (its Decision: "The operator confirms this change of
`docs/reverse.md`"); T-255 (the relay's side drops reverse sockets at
random, with no Close).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay's side drops a node's socket at random (T-255). A node that
connects again can get `409` while the relay still holds the old socket, and
the node then exits: each session that the resumable layer keeps on it ends,
and no client can resume it (T-153).

## Premise

Read, at `fb228e9`: rule 6 of docs/reverse.md (line 19) says "On `409` (a
second socket for the same name), exit. Do not retry." podssh's node does so
(crates/podssh-relay/src/reverse/node.rs, line 148), for a first registration
and after a loss alike. T-153's Decision recommends a retry after a loss and
leaves that change of `docs/reverse.md` to the operator.

## Approach

1. A node that held its socket and lost it takes `409` as a wait: it connects
   again with `open::backoff` until the resume deadline of T-153, then exits
   as now. A first registration still exits on `409`: another node has the
   name.
2. One stderr line for each `409` after a loss, with the time left.
3. Rule 6 of `docs/reverse.md` gives both cases, and the manual's section of
   `node` says so.

## Decision

Recommendation (T-153's): connect again after a loss. The alternative, an
exit on each `409`, lost: a node whose socket the relay dropped would end
each session that the layer keeps. The operator agreed on 2026-10-09 (Q31,
`docs/decisions.md`).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_node -- conflict
```

A stand-in relay answers a node's next connection after a loss with `409`
twice, then accepts it: the node keeps its sessions. A first connection that
gets `409` exits as before. A planted node that exits on each `409` fails the
test.

## Correction

A test of a node that connects needs a stand-in relay over plain `ws://`:
the one of the blocking facade (`PodUtils/podssh:crates/podssh-relay/tests/stand_in/mod.rs`)
and the feature `plain-ws`. The tests are in
`PodUtils/podssh:crates/podssh-relay/tests/blocking_plain.rs`, which the gate's step `libs`
runs: `cargo test -p podssh-relay --features blocking,plain-ws --test
blocking_plain -- conflict`. The node keeps no session across its sockets
itself: the keeper of the resumable layer does, while the node runs, so the
test shows that the node runs on and serves on the new socket.

2026-11-11, the take of `pod-relay` (PodUtils/podcrates): the test target `reverse_node` moved to `pod-relay` with its name; run it there with `cargo test -p pod-relay --all-features --test reverse_node`.

## Done

2026-10-09.

- `crates/podssh-relay/src/reverse/node.rs`: a node notes when it lost a
  socket that it held. A `409` within `Settings::rejoin` of that loss is a
  wait, with the jittered backoff, and a line for the user
  (`NodeConfig::say`) with the time left; a `409` at the first registration,
  or after the limit, ends the node as before (`Exit::NameInUse`).
  `Settings::rejoin` is the layer's resume deadline, 10 minutes.
- `podssh node` prints each such line on stderr, and its last line for
  `Exit::NameInUse` names both causes. Rule 6 of `docs/reverse.md` and the
  manual's note of `node` give both cases.
- Prove, native: `cargo test -p podssh-relay --features blocking,plain-ws
  --test blocking_plain -- conflict`: 3 passed. After a loss with no Close,
  two `409`s, then the node takes the new socket and serves a session on it;
  a `409` at the first registration ends the node at once; with a limit of
  2 s, `409`s after a loss end it, but only after the 2 s. Planted, a node
  that exits on each `409`: both tests after a loss failed, and the one of
  the first registration passed.
- `cargo test --no-fail-fast`: 994 passed, 0 failed, 22 ignored; with `-p podssh-relay --all-features`: 173 passed, 0 failed, 14 ignored.

# T-262: A session cut at random points can end before its bytes come through

**Source:** CI's gate at `7797b2a` (run 37945660729, step `libs`), and local
runs on 2026-10-09.
**Category:** defect
**Milestone:** M6
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

The test of T-153 that cuts a session's links at random points while 32 MiB
go each way, `a_session_survives_links_cut_at_random_points`, sometimes ends
the session before the bytes come through: the application's read fails.
The gate is red until it is repaired, and a user could lose a session that
the layer should carry over.

## Premise

Measured: the test failed in CI's gate at `7797b2a` (step `libs`, the
read at `PodUtils/podssh:crates/podssh-relay/tests/session_resume.rs:117` failed), and
locally in 2 of 3 runs on 2026-10-09; it passed in each run before that
day's last changes. The cause is not known: the resume driver
(`PodUtils/podssh:crates/podssh-relay/src/session/resume.rs`), the far end's keeper
(`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`), the pump
(`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs`), or the test's stand-in relay.

## Approach

1. Run the test until it fails, with the driver's notes printed, and find
   which end gives up and why: a `GaveUp` reason, a `REFUSE`, a link that
   ends the session.
2. Repair the cause, with a test that fails on it alone.
3. The test passes 20 runs in a row, and the gate's step `libs` is green.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test session_resume
```

20 runs in a row pass, and so does CI's gate.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_resume` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_resume` there.

## Done

2026-10-09, with T-154's work and T-155's so far, which the session before
left in the same files. Here, before the repair, the test failed in 6 of 10
runs. A copy of it that printed each end's notes and each link's end found
four causes:

1. A failed write ended a link before its reader read what had come. The far
   end sent its last bytes and its `CLOSE`, and the stand-in relay then
   closed the link; the client's next `ACK` failed with a broken pipe, and the
   client took the link as lost with the `CLOSE` unread. Its resume found the
   session forgotten, and the application's read ended early: the failure of
   CI at `7797b2a`.
2. A stall: each end's reader waited for the link's write lock to send an
   `ACK` while its own writer held the lock, stalled on a full link. With
   both ends sending, no link moved again (a run that waited 120 s).
3. In the move of T-155, the new link's handshake took the offsets while the
   old link still carried acknowledgements: an offset fell below the other
   side's acknowledged one, and the far end refused it as not kept.
4. On the way: the bytes of a resume were written before the new link was
   read, at both ends; the far end left a session with no slot between
   taking it and starting the new link, so a resume that came then failed;
   an older resume could take a session back from a newer one; and a `CLOSE`
   that a lost link took with it was never sent again.

The repair, in `crates/podssh-relay/src/session/`:

- `pump.rs`, with `pump/outbox.rs` and `pump/down.rs`: one writer for each
  link. The reader and the heartbeat leave an `ACK`, a `PONG` or a `PING` in
  an outbox and never wait for the writer; the bytes of a resume go out
  through the writer while the link is read; a link whose writes fail is
  read for 5 s more.
- The end of a session: the peer answers a `CLOSE` with its own. A link that
  ends before the answer ends as `End::Closing`, and the resume sends the
  `CLOSE` again; a far end that forgot the session after this side's
  application ended had the `CLOSE` (`End::LocalEnd`); a resume that the far
  end accepted while the session ended on the old link gets a `CLOSE`.
- `resume.rs`: the move greets a new link while the old one runs, stops the
  old one with `RETIRE`, and only then takes the offsets; no move once this
  side's application ended.
- `keep.rs`: the new link takes the slot in the same lock that empties it,
  and the newest resume takes the session; an older one gives way.
- `docs/design.md` (section 5): a `CLOSE` answered, one writer for each
  link, the end of a session and the order of a move.

Prove, native, Windows, 2026-10-09:

- `cargo test -p podssh-relay --features pair --test session_resume`: the
  test binary, 20 runs in a row, each with its 3 tests passed.
- A test of each cause, which fails on the code before the repair and passes
  after it, 10 runs in a row (20 for the moves): `--test session_end`: a link
  whose writes fail still gives each of 1 MiB and the far end's `CLOSE`
  (before: 98,304 bytes); a `CLOSE` that its link lost goes again on the
  next link, from either side (before: the target waited past the test's
  20 s, and the client ended with a refusal). `--test session_link --
  both_ends_send_at_once_through_a_small_link`: 4 MiB each way through a link
  of 4 KiB (before: nothing moved for 20 s). `--test session_move --
  a_session_moves_while_both_ends_send_at_full_speed`: a move each 256 KiB
  with both ends at full speed, no loss and no failed move (before: the
  session ended with a refusal).
- `cargo test --no-fail-fast`: 991 passed, 0 failed, 21 ignored (the live tests). `cargo test -p podssh-relay
  --all-features --no-fail-fast`: 170 passed, 0 failed, 14 ignored. `cargo clippy -p podssh-relay
  -p podssh-cli --all-targets -- -D warnings`: no warning.
- Live, once: `cargo test -p podssh-cli --test node_live -- --ignored
  node_command_serves_a_tcp_target ssh_to_a_node`: GitHub's banner came
  through a node with the new pump, and `podssh ssh node://` logged in to
  railway.new through it; railway.new then limited the anonymous visitor
  (its exit 13) in place of running `exit 3`, as in the run of T-153.
- CI's gate passed at `a3b81d1`, the commit of this repair: each of its
  steps, `libs` included (run 37963246424).

# T-270: A resume whose far-end task starts late takes the session from a newer one

**Source:** the native run of `cargo test --workspace` on 2026-10-10,
during T-178: the test of moves at full speed lost a link once.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** S
**Status:** done

## Problem

A session that moves twice in a row can lose its newest link: the client
sees the link end with no word from the far end, and resumes on another.
No byte is lost, but the test of T-155 at full speed fails, and a user
would see a loss that should not happen.

## Premise

- Measured: `a_session_moves_while_both_ends_send_at_full_speed`
  (`PodUtils/podssh:crates/podssh-relay/tests/session_move.rs:185-195`) failed once in the
  native run of the workspace on 2026-10-10, with `[Lost { why: "the link
  ended with no word from the far end" }]`. It then passed 30 runs alone,
  60 with four copies at once, 40 with the other test of its file, and 75
  with three copies at once.
- Read: the far end numbered each resume when its task reached
  `run_resumed`, after `far::accept` had sent the `ACCEPT`, and the newest
  number won (`Keeper::run_resumed`, `PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`).
  At full speed the client moves again as soon as the new link carries
  256 KiB, so the far end can answer the handshake of a third link before
  the task of the second reaches `run_resumed`. That task then took a
  greater number, the third link's `take` gave way to it, and the far end
  dropped the third link after its handshake.

## Approach

1. Number a resume in `far::accept`'s handshake, under the sessions' lock,
   before the `ACCEPT` goes out (`Sessions::next_resume`), and carry the
   number in `Accepted`.
2. `run_resumed` takes that number, and only raises the newest: an older
   resume whose task starts late gives way.
3. A test that orders the tasks so: two resumes answered A then B, B's task
   first, then A's.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_newest
cargo test -p podssh-relay --all-features
```

A gives way at once with "a newer link resumed the session", and B still
carries the session. Plant: number by the order of the tasks again; the
test must fail.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_newest` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_newest` there.

## Done

2026-10-10. `Sessions::next_resume` numbers each resume in `far::accept`
before its `ACCEPT` goes out (`PodUtils/podssh:crates/podssh-relay/src/session/sessions.rs`,
`PodUtils/podssh:crates/podssh-relay/src/session/far.rs`); `Accepted` carries the number,
and `Keeper::run_resumed` only raises the newest
(`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`).
- `cargo test -p podssh-relay --test session_newest`: 1 passed. Planted,
  the number by the order of the tasks: the older resume took the session
  from the newer, and the test failed at its limit of 5 s.
- `cargo test -p podssh-relay --all-features`: 181 passed, 0 failed, 14
  ignored; clippy with no warning, also for `podssh-iroh`. The tests of
  moves (`--test session_move`) passed 40 runs in a row after the change.

# T-263: A node in plain mode, for a client with no resumable layer

**Source:** the operator's ruling of 2026-10-09 (Q34, `docs/decisions.md`),
after T-153.
**Category:** feature
**Milestone:** M6
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

Since T-153, each session of `podssh node` greets with the resumable layer.
A client that does not speak the layer (a tool of another project, or a TCP
client through the operator's leg) reads the `GREETING` as the first bytes of
TARGET, and cannot use the node.

## Premise

Read: `podssh node` puts its TCP handler under the layer's far end
(`crates/podssh-cli/src/node.rs`, the handler `Layered`), which sends
`GREETING` before anything else (`PodUtils/podssh:crates/podssh-relay/src/reverse/layered.rs`).

## Approach

1. `podssh node NAME TARGET --plain`: each session dials TARGET at `open`
   and carries its bytes as they are, as before T-153, with no resume. The
   layer stays the default.
2. A row in the flag table of `node` (`crates/podssh-cli/src/flags.rs`), the
   help, the manual's note of `node`, `docs/reverse.md` and `docs/cli.md`.
3. The node's first line on stderr names the mode.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli -- plain
```

The argument test parses `--plain` for `node` and refuses it elsewhere. A
test of the handler shows that a plain node gives TARGET's first bytes with
no `GREETING`, and that the default node greets.

## Done

2026-10-10. `podssh node NAME TARGET --plain` carries each session's bytes
as they are, with no resumable layer: the node's handler is then the TCP
handler alone, which dials TARGET at `open`
(`crates/podssh-cli/src/node.rs`, lines 152-163 at `8e31960`). The node's first line names its
mode (`crates/podssh-cli/src/node.rs:360`). `--plain` with `--iroh` is
refused with 64 (`crates/podssh-cli/src/node_flags.rs:116-118`, moved from `node.rs` by T-531): the iroh road
always runs the layer. The flag's row, the manual's note of `node`,
`docs/reverse.md` and `docs/cli.md`.
- Native: `cargo test -p podssh-cli -- plain`, 3 passed. The argument test:
  `--plain` with `--iroh` exits 64, `--plain` for `operator` and `ssh`
  exits 64, and a node with `--plain` gets to its pair (78, as none is
  stored). Through the stand-in relay's reverse road
  (`crates/podssh-cli/tests/node_plain.rs`), `podssh ssh -v node://` finds
  no layer at a plain node, the layer's features at the default node, and
  logs in and runs `greet` through each. Planted, a `--plain` that changes
  nothing fails the plain check, and the default check still passes.
- CI, the run of `c982d27` (38002695390): each job passed.

# T-154: Heartbeats that also prevent the relay's idle cut

**Source:** ROADMAP M6 (heartbeats); `docs/design.md:848-849`; GitHub #19
(Nemo-010, 2026-10-08: ssh-obi pings each 15 s and wants a pong in 45 s).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay cuts a connection after 180 s with no payload, and its empty
keepalive frames do not count (`docs/relay.md:528-529`, `docs/relay.md:636`). A
reverse socket gets no keepalive at all (`docs/reverse.md:39-49`). SSH's own
keepalives must not end a session that the layer would resume.

## Premise

Read: a read waits 90 s at most (`crates/podssh-ws/src/client.rs:31-33`, set at
`PodUtils/podssh:crates/podssh-relay/src/open.rs:382`), a limit that counts on the relay's
frame each 25 s. The ping watcher acts only after a first Pong
(`PodUtils/podssh:crates/podssh-ws/src/session.rs:296-334`); Pongs and the idle cut on reverse
sockets are not measured (T-061). russh sends a keepalive each 60 s and ends
the session after 3 with no answer (`crates/podssh-ssh/src/options.rs:359-399`).
Measured on `3ee70dc`, offline (`PODSSH_OFFLINE=1`, a `.invalid` host):
`-o ServerAliveInterval=0` prints the warning of
`crates/podssh-cli/src/ssh/resolve.rs:349-359` (the `warnings` of keepalives), and `podssh ssh` exits 255.

## Approach

1. Each end sends a `PING` record when it sent nothing for 10 s, and the peer
   answers `PONG`. A record is payload, so it resets the relay's idle cut on
   each road.
2. Any record counts as life, as for the ping watcher
   (`PodUtils/podssh:crates/podssh-ws/src/session.rs:296-305`). After 3 silent intervals the
   link is dead, and T-153 resumes: 30 to 40 s. Both ends send, so the read
   limit of 90 s also holds on reverse sockets.
3. Carry the `ACK` of T-152 in each `PONG`. The cost is about 20 bytes each
   way each 10 s: under 0.2 MiB in 12 h.
4. On the resumable road, do not print the warning of
   `crates/podssh-cli/src/ssh/resolve.rs:349-359` (the `warnings` of keepalives).
5. In the same commit: "Liveness" and "Idle limit" in the manual
   (`crates/podssh-cli/src/man/facts.rs:394-409`,
   `crates/podssh-cli/src/man/facts.rs:429-438`), the note at
   `crates/podssh-cli/src/man/notes_ssh_more.rs:136`, `docs/relay.md`, `README.md`.

## Decision

Recommendation: on the resumable road, turn russh's keepalives off unless the
user sets `ServerAliveInterval`. The heartbeat finds a dead link in 30 to
40 s, and the resume hides the outage from SSH; with 60 s and 3 missed
answers, russh would end a session in a stall of about 3 minutes (inferred),
the stall that M6 must survive. A keyword that the user sets stays, with one
warning. The alternative, the keepalives as now, lost for that reason.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_heartbeat
cargo test -p podssh-cli --test ssh_args -- resumable
cargo test -p podssh-relay --test live -- --ignored idle_reverse
```

On tokio's paused clock, each end sends a record each 10 s over 200 s of idle
time, and a link silent for 30 s is dead; a planted interval of 200 s fails.
The argument test shows no SSH keepalive and no warning on the resumable road
only. The live test keeps an idle reverse session for 10 minutes, and so
answers T-061.

## Correction

The resumable road is `node://` (T-153): only a podssh node runs the layer,
so the keepalives and the warnings follow the destination. A `ServerAliveInterval`
that the user sets there stays, with one warning that it can end a session
that the layer would carry over; `0` there is no warning, as the layer keeps
the idle cut away. The live test needs a node and the layer's client, which
are in podssh-cli: it is `cargo test -p podssh-cli --test node_live --
--ignored an_idle_session_through_a_node_lives_10_minutes`, with an echo
server on the loopback as the node's TARGET, since an SSH server ends a login
that waits 10 minutes. The paused clock needs tokio's `test-util` in the
dev-dependencies of `podssh-relay`.

2026-11-09 (T-703, GitHub #172): the sentence above, that the resumable road is `node://`, is true of
the road list that `resolve` reads before the connection. T-300 made a `cf://HOST` whose far end
greets with the layer a layered road too; the greeting is known only after the connection. There the
keepalives follow the greeting: no `ServerAliveInterval` named, no SSH keepalives; a named one stays,
with the same warning as on `node://` (printed once, after the connection); `0` has no warning.

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_heartbeat` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_heartbeat` there.

## Done

2026-10-09, with T-262's repair and T-155's work so far, which the session
before left in the same files.

- `PodUtils/podssh:crates/podssh-relay/src/session/pump.rs`: with `heartbeat.v1` named by
  both sides (`session::FEATURES` now names it), each end sends `PING` when it
  sent nothing for 10 s, the far end answers `PONG` with its received offset,
  and a link with nothing from the far end for 30 s ends as a loss, which
  T-153 resumes. The writer notes when it last sent, and the reader when it
  last heard; since T-262, the heartbeat leaves its `PING` for the link's one
  writer, and never waits for it.
- `crates/podssh-cli/src/ssh/resolve.rs`: to `node://`, no SSH keepalive
  unless `ServerAliveInterval` is set, and then one warning; no warning of
  the idle cut there. The manual's "Liveness" and "Idle limit", the note of
  `ssh`, `docs/relay.md`, `docs/design.md` (section 5) and `README.md` say so.
- Prove, native: `cargo test -p podssh-relay --test session_heartbeat`: 3
  passed, on the paused clock, also in 10 runs in a row after the repair of
  T-262. Over 200 s of idle time, no gap of more than
  10 s between records either way, with 18 `PING`s and 18 `PONG`s at least;
  a far end that answers nothing: the link ends after 30 s with "nothing came
  from the far end for 30 s"; a far end that did not name `heartbeat.v1`
  gets no `PING` in 200 s. `cargo test -p podssh-cli --test ssh_args --
  resumable`: passed.
- Live, once, before the repair of T-262: `cargo test -p podssh-cli --test
  node_live -- --ignored an_idle_session_through_a_node_lives_10_minutes`
  passed in 608 s: a session through a node in front of an echo server on
  the loopback, idle for 600 s on the live relay, echoed after the wait; no
  link was lost in that run.
- `cargo test --no-fail-fast`: 991 passed, 0 failed, 21 ignored (the live tests), with T-262.
- Waits for T-251, by the decisions of 2026-10-09: the planted interval of
  200 s, which must fail `an_idle_session_carries_a_record_each_way_each_10_s`,
  and a run of the live test after T-262 (it takes more than 5 minutes).

# T-155: Move a session to a new relay connection before the relay's limits

**Source:** ROADMAP M6 (a new session before the relay's limits);
`docs/design.md:850-851`; the report of sandbox A, 2026-10-08 (the `1009`
close at the volume cap).
**Category:** feature
**Milestone:** M6
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The relay ends a WebSocket session after 64 MiB, both directions together, or
after 12 h (`docs/relay.md:637-638`). A long or large session on the layer
meets these limits, and an end at a limit costs a resume and its delay.

## Premise

Read: the reverse road has the same cap, `1009 session byte cap`, "Open a new
session" (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:183`),
which `classify` maps to `Retry::NewSession`
(crates/podssh-transport/src/closes.rs lines 203-205 at `e8bbd4d`), and a session lives 720
minutes at most (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:233-235`).
Measured in sandbox A (T-001; `docs/STATUS.md`, "In the operator's real
sandboxes, measured"): 67,107,943 bytes, then `1009 session byte cap`. A pair
lives 72 h or less, and the operator gets its `connect_token` only from the
node's side (`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:133-138`).

## Approach

1. Count each byte of a link in both directions, the records of the layer
   included.
2. At 48 MiB or at 11 h, open a second link through the usual roads and relay
   hosts, and run the resume of T-153 on it: no second connect path.
3. Move the writer to the new link at a record boundary. Then send `RETIRE` on
   the old link (a new record of T-151: it ends a link, not the session), and
   close it with 1000.
4. Invariants: at most two links for each session; no byte lost or given
   twice to SSH, because the offsets decide; the move never waits for the old
   link to drain.
5. A failed move is not a fault: at the cap the relay closes with `1009`, and
   T-153 resumes.
6. When the client knows the expiry of the pair (from the node's ticket,
   T-163), it warns 1 h before; at the expiry the session ends with the reason.
7. `-v` prints one line for each move. Docs: `docs/relay.md` ("Limits that
   users see") and the manual (`crates/podssh-cli/src/man/facts.rs:314-468`).

## Decision

Recommendation: move at 48 MiB (75 % of the cap) or at 11 h. The bytes in
flight at a move (a relay queue of 1 MiB, an SSH window of 512 KiB for each
channel) and a second try after a failed move fit in the 16 MiB that remain.
The alternative, a move at 60 MiB, lost: one failed move would leave too
little room for the next.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_move
cargo test -p podssh-relay --test live -- --ignored move_200mib
```

The move test gives a fake link a cap of 1 MiB, as a constructor argument:
8 MiB pass with an equal SHA-256 over more than 8 links, with no `1009`
close. A planted layer that never moves meets `1009` at the first cap, and
the test fails. The live test sends 200 MiB each way with equal digests.

## Correction

The live test needs a node and the layer's client, which are in
podssh-cli: it is `cargo test -p podssh-cli --test node_live -- --ignored
move_200mib`, with an echo server on the loopback as the node's TARGET.
Step 6 needs no ticket of T-163: the operator's part of a pair keeps its
expiry (`expires_ms`, `PodUtils/podssh:crates/podssh-relay/src/pair.rs:343`), and at the
expiry the relay ends each session of the pair with `1001 pair expired`
(`crates/podssh-probe/tests/spec/relay-spec-2026-10-03-r2.txt:171`), which
the policy of T-153 does not resume. The repair of T-262 changed step 3:
the new link greets while the old one carries the session, but its
handshake takes the offsets only after the old one stopped.

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target `session_move`
moved to `pod-session` with its name; run `cargo test -p pod-session --test session_move` there.

## Done

2026-10-09.

- The record `RETIRE` (0x0b, no body: a link ends, the session goes on), in
  the codec, its vectors and `docs/design.md`; `Event::Retired` and
  `End::Retired`. `move.v1` in `session::FEATURES`, used only with
  `replay.v1`; `Settings::move_bytes` (48 MiB) and `move_age` (11 h).
- `pump::Watch`: the stop of a link, whether a stopped link sends `RETIRE`,
  the bytes of the link both ways (records included), and a notice when they
  pass the move's mark. `End::Moving`, which the driver gives its caller
  when it asks for a link to move to.
- The move in `resume::run`: at the mark or the age, a second link is asked
  for, and its far end greets while the old one still carries the session;
  then the old one stops at a record boundary and says `RETIRE`, and the new
  link's handshake takes the offsets, then sends again from the far end's
  offset (`Note::Moved`, `Note::MoveFailed`; the CLI prints them with `-v`,
  and its connect does not wait for a leg that still runs). A session whose
  application ended does not move.
- `podssh ssh node://` and `podssh operator` say, an hour before the pair
  expires, that the relay then ends the session (`EXPIRY_WARNING` and
  `expiry_wait` in `crates/podssh-cli/src/layered.rs`).
- `docs/relay.md` ("Limits that users see"), the manual's "Session limits",
  and `docs/design.md` (section 5) say so.
- Prove, native: `cargo test -p podssh-relay --test session_move`: 2 passed,
  in 20 runs in a row. Links capped at 1 MiB with a move at 768 KiB: 8 MiB
  each way with equal digests over more than 8 links, no cap met and no
  loss; a move each 256 KiB with both ends at full speed: no loss and no
  failed move. `cargo test -p podssh-cli --lib -- layered`: 3 passed (the
  wait before the warning: an hour before, at once with less left, none
  after the expiry). `cargo test -p podssh-cli --no-fail-fast`: 331 passed,
  0 failed, 8 ignored (the live tests). `cargo test --no-fail-fast`: 994
  passed, 0 failed, 22 ignored.
- Waits for T-251: the live test `move_200mib_each_way_through_a_node`
  (400 MiB through the relay: over 100 MiB, Q35), and the planted layer that
  never moves, which must meet the cap and fail the move test.

# T-156: M6 exit: a session survives a stopped relay host, a new address and a stall of 3 minutes

**Source:** ROADMAP M6, exit criteria; `docs/design.md:891-893` (the harness
must grow for layer 2).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

M6 is done when a session survives three faults, on the resumable layer and
on the iroh road: a stopped relay host, a change of the client's address, and
a stall of 3 minutes. Today each of these faults ends the session.

## Premise

Measured in the gate (`docs/STATUS.md`, "Faults between podssh and the relay,
measured"): a relay that stalls is declared dead at 50 s, and a relay host
killed in a session gives exit 255 (`scripts/interop-faults.sh:269-287`).
These checks stay, for the forward road, which has no resumption. Read: the
stand-in relay serves the forward path only (`scripts/fake-relay.py:169-193`),
and its `stall` mode never ends (`scripts/fake-relay.py:339-342`). The
harness cannot change an address or end a stall yet (T-203). The checks need
T-151 to T-155, the iroh road (T-162 to T-165), the reverse runners (T-079,
T-080) and a far end (`podssh serve`, T-107).

## Approach

1. With T-203, give the stand-in relay the reverse path: `/v1/pair`,
   `/v1/node/<name>`, `/v1/connect/<name>`, the text control frames and the
   32-character ids. One process serves two host names, so the reverse state
   survives when one listener stops.
2. Three faults: stop the relay host in use; make the client's link go silent
   with no RST, while new connections succeed from a second loopback address;
   stop each byte in both directions for 180 s, then let them pass again.
3. For each fault on each road (the layer over the reverse road; the iroh road
   with a local iroh relay or n0's relays): a `-tt` session that echoes lines,
   and a transfer of 20 MiB with SHA-256 compared at both ends. The fault
   comes in the middle.
4. Pass: exit 0, equal digests, each echoed line once, one stderr line for the
   loss and one for the resume.
5. A control: the same faults on the forward road end the session with exit
   255, so a check that passes for a wrong reason shows.
6. Then once live, from the Podman box through the live relay
   (`scripts/test_in_box.sh`), with the stall made at the box's proxy
   (`scripts/box/proxy.py`).
7. Record each result in `docs/STATUS.md` with the date and the command, and
   mark the M6 exit in `docs/ROADMAP.md`.

## Decision

2026-10-10, before the work:

- The faults go in the stand-in proxy, where each road meets them alike,
  the relay's protocols unread: `--stop-after SECONDS` (each open tunnel
  ends with RST, SECONDS after the first one, and new tunnels go on: the
  relay host in use stops, and the client and the node come back as through
  another address of the control host), `--move` (T-203) and `--pause
  AFTER:FOR`. Lost: the faults in the stand-in relay, which the iroh road's
  relay, iroh's own server, would then need again.
- The stand-in relay gains the reverse road (item 1) as the live relay
  showed it (`docs/relay.md`, the reverse path): `POST /v1/pair`,
  `/v1/node/<name>`, `/v1/connect/<name>`, `/v1/status/<name>`,
  `/v1/stop/<name>`, each token in `X-Relay-Token`, the text frames `hello`,
  `open`, `ready`, `reject` and `close`, and the 32 characters of each id.
- The iroh road's relay is iroh's relay server under a name that only the
  proxy resolves, with a certificate for that name, so its connections pass
  the faults of the proxy too.
- The same checks run natively in an ignored test, with the tests' SSH
  server for the transfer and the lines; the gate's run, with OpenSSH and a
  `-tt` shell, and the box's live run wait for T-251.

## Prove

```sh
sh scripts/dev.sh check
sh scripts/test_in_box.sh target/x86_64-unknown-linux-musl/release/podssh
```

The fault step of the gate prints `ok` for six new checks (three faults on two
roads) and for the controls on the forward road; the controls show that the
checks fail for a session that does not resume. The run in the box shows a
live session that survives a stall of 3 minutes.

## Correction

The far end that the checks need is the layer's far end, which `podssh node`
is, in front of an SSH server; `podssh serve` (T-107, held by the operator)
is not needed for them.

- The new address and the stall are the client's, as the exit names them:
  the node has a proxy of its own, which makes a fault only when the relay
  host stops. A node whose own link goes silent comes back only when the
  relay lets its old socket go (`409`, T-261), and the stand-in relay, which
  sends nothing on an idle socket, never does.
- The gate runs the same checks in the build image (the step `m6`), with
  the tests' SSH server, and not OpenSSH with a `-tt` shell: the layer is
  below SSH, where a pty's bytes are bytes, and 20 MiB of `echo` checks each
  of them. The live run from the box, with a pty, comes with T-251.

## Done

2026-10-10. The exit of M6 is met on this machine's loopback: a session
survives a stopped relay host, a new address of its client and a stall of
3 minutes, on the resumable layer over the reverse road and on the iroh
road, and the same faults end a session of the forward road with 255
(`docs/STATUS.md`, "Faults between podssh and the relay, measured").
- The stand-ins: the reverse road in the stand-in relay
  (`scripts/fake_reverse.py`, on the WebSocket parts of
  `scripts/fake_ws.py`, which `scripts/fake-relay.py` imports);
  `--stop-after`, `--pause` and `--start-file` in `scripts/fake-proxy.py`;
  iroh's relay server under a name (`spawn_named` in
  `PodUtils/podcrates:crates/pod-iroh/src/test_relay.rs`); and `PODSSH_IROH_UDP=off`, which
  turns the iroh road's UDP off (`PodUtils/podcrates:crates/pod-iroh/src/endpoint.rs`, in
  the manual).
- The checks: 11 ignored tests in `crates/podssh-cli/tests/m6_exit.rs`, and
  the gate's step `m6` (`scripts/gate.sh`), which CI runs at each push.
  Native, Windows: 11 of 11 in 630 s, and the layer's check of a stopped
  relay host 10 times more.
- Found on the way: the stand-in relay gave the operator the node's first
  bytes before its `ready` when the two came in one read, which the live
  relay never does (repaired in the stand-in); and a session of the forward
  road could wait for ever after its relay host stopped (T-269, repaired).
- Waits for T-251: the live run from the box through the live relay, with
  the stall at the box's proxy ("a session that survives a killed relay
  connection").
- CI, the run of `94e3e6a` (38001904475): the gate's step `m6` in the build
  image, 11 of 11 in 692 s; each job passed.

# T-157: Throughput on each road and relay, by a committed method

**Source:** ROADMAP M6 (throughput on each road and relay, in and out of a
sandbox, before a default depends on it); `docs/design.md:1672-1692`; the two
sandbox reports of 2026-10-08; GitHub #18 (warren's method) and GitHub #23
(sshping: throughput up and down).
**Category:** measurement
**Milestone:** M6
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

podssh has no committed method to measure throughput. The figures so far come
from testers' commands, and one target was out of the relay's reach. A
default road (T-164) and the iroh relays (T-165) need figures from one method.

## Premise

Measured by the operator's agents (T-001; `docs/STATUS.md`, "In the
operator's real sandboxes, measured"): 20 MiB down the forward road at 0.5 to
0.7 MB/s through a CONNECT proxy (2 runs), and at 1.8 to 6.9 MiB/s with no
proxy (4 runs). Read in the report, not verified here: the script's target
(thinkbroadband) gave `1011 write failed` and 0 bytes, and the relay's
`/trace` showed that the relay could not reach it.
Read: no iroh figure exists for a relay through a CONNECT proxy
(`docs/design.md:1672-1692`). A session carries 64 MiB at most, both directions
together (`docs/relay.md:638`).

## Approach

1. Write the method as an ignored test,
   crates/podssh-cli/tests/throughput_live.rs, in the form of
   `crates/podssh-cli/tests/proxy_live.rs`: it runs the built binary.
2. The cells: each road (forward, reverse with the layer, iroh through a
   relay, iroh direct where UDP works, direct); each relay (the default host,
   three pool hosts, n0's relays, the operator's iroh relay when it exists);
   two places (outside a sandbox; the Podman box or a real sandbox).
3. In each cell: 5 runs, each on a new connection, near in time to the other
   cells; 20 MiB up and 20 MiB down in separate sessions; 300 s at most each.
4. The targets: a far podssh node that sends and drains bytes. For the
   forward road, two public targets, each checked first with `/trace`, which
   needs a token (`docs/relay.md:709-710`; `docs/relay.md`, lines 296-302 at `24f3e2a`). Skip a
   target that fails the check, with its reason; never count it as 0.
5. A control: the same runs through the stand-in relay on loopback
   (`scripts/fake-relay.py`), which shows podssh's own limit.
6. Report the minimum, p50, p95 and maximum in MiB/s for each direction, and
   keep the line of each run. Write the table in `docs/STATUS.md` with the
   date, the place and the command. Test the statistics offline.

## Decision

Recommendation: an ignored Rust test that runs the binary. It needs no
`curl`, `wc` or shell on the host, and it runs on Windows too. The
alternative, a shell script around `curl`, lost: a sandbox may have no tools
(`docs/decisions.md`, 2026-10-05: never assume a tool).

2026-10-10, the far end and the cells:

- The far end is an SSH server, as a user's session has one: a russh server
  in the test, whose commands send N bytes (`source N`) or drain stdin and
  say the count (`sink`). Each run is `podssh ssh ... source N` or `podssh
  ssh ... sink` with N bytes on stdin, a new process and a new connection
  each time. What podssh carries for a user (SSH, `cp`) is what is measured.
  Lost: raw bytes through `podssh operator`, which has no form for the iroh
  road, and would leave SSH out of the figure.
- The cells that reach no target outside AGENTS.md's list run when nothing
  is set: the loopback (the test's own SSH server, `--direct`), the reverse
  road through the live relay (a pair, `podssh node` in front of the test's
  server, `podssh ssh node://`), and, with the feature `iroh-test`, the iroh
  road through iroh's relay server on the loopback. The others run only
  when a variable names their target: `PODSSH_THROUGHPUT_SSH` (a public SSH
  server, for the forward and the direct road) and
  `PODSSH_THROUGHPUT_IROH_RELAY` (n0's relays, or the operator's). Neither
  kind of target is on AGENTS.md's list of test targets: Q38.
- The control of the forward road, through `scripts/fake-relay.py` on the
  loopback, needs Python and a certificate; the test makes one with
  `openssl` when a probe finds it, and else says that it skipped the cell.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test throughput_live
cargo test -p podssh-cli --test throughput_live -- --ignored --nocapture
```

The first command runs the offline tests of the statistics; a planted p95
that takes the maximum fails them. The second makes the measurement and
prints the table, which goes into `docs/STATUS.md`, section "Throughput,
measured".

## Done

2026-10-10.

- `crates/podssh-cli/tests/throughput_live.rs`: the statistics (min, and
  p50, p95 by nearest rank, and max), tested offline with a planted p95
  that takes the maximum; one small run each way on the loopback, in each
  test run; and two ignored measurements: `throughput_on_the_loopback` (the
  cells that reach no network) and `throughput_on_each_road` (those and the
  live ones). Each cell's table keeps the line of each run, then the
  summary of each direction; a cell that cannot be set up, or a run that
  fails, says why and is never counted as 0.
- `tests/throughput_harness/`: the session (a scratch HOME, the test's SSH
  server, what the cells start, stopped at the end, a pair revoked), one run
  with its clock and its limit of 300 s (the process is killed), and the
  cells: the loopback with `--direct`; the forward road through
  `scripts/fake-relay.py`, with a test CA and certificate that `openssl`
  makes, when a probe finds Python and `openssl`; the reverse road through
  the live relay (a pair, `podssh node`); with `iroh-test`, the iroh road
  through iroh's relay server on the loopback; and, when a variable names
  their target (Q38), a public POSIX server (`PODSSH_THROUGHPUT_SSH`, by the
  live relay and directly, with `head` and `sh -c 'echo R; wc -c'`) and the
  iroh relays of `PODSSH_THROUGHPUT_IROH_RELAY`.
- `tests/ssh_harness/`: the test's SSH server (russh), shared with
  `tests/iroh_road.rs`: `greet`, `source N`, and `sink`, which says `R` as
  it starts to read and the count at the end.
- Prove, native, Windows: `cargo test -p podssh-cli --test throughput_live`:
  3 passed, 2 ignored (the statistics; the planted p95 fails the check; the
  method on the loopback). The loopback measurement, with `iroh-test`, 61 s:
  the table is in `docs/STATUS.md`, "Throughput, measured": `--direct` p50
  165.9 MiB/s up and 106.3 down; the stand-in relay 7.1 and 7.9, its own
  limit (Python's asyncio); the iroh road through iroh's relay server 34.6
  and 25.6. `cargo test --no-fail-fast`: 1006 passed, 0 failed, 24 ignored (the record's own test passed after its remaps). clippy in both builds and
  with `iroh-test`: no warning.
- Waits: the live run of `throughput_on_each_road` (the reverse road through
  the live relay, 200 MiB a cell, is more than 100 MiB) for T-251, and for
  Q38 the cells whose target is not on `AGENTS.md`'s list: a public SSH
  server for the forward and the direct road, and n0's relays. The run in a
  sandbox, or the Podman box, comes with T-251 too.

# T-158: Detach and attach again

**Source:** GitHub #19 (Nemo-010, 2026-10-08: rose's `~d` and `--session`,
ssh-obi's detach and list of sessions, and fux's refusal of a nested attach);
GitHub #18 (zuko: a detached pty with a lease).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A user cannot leave a shell running and come back to it later, from a new
podssh process or from another host. tmux does this on a server that has
tmux; a cage usually has none.

## Premise

Inferred from the design: the layer runs under SSH (`docs/design.md:785-786`),
so the keys and the sequence numbers of the SSH connection live in the client
process. A new process cannot continue that byte stream, so an attach is a
new SSH login to a far end that kept the shell (T-159). Read: podssh knows
the escapes `~.`, `~R`, `~?` and `~~`, and another character after `~` goes
to the server with the `~` (`crates/podssh-ssh/src/escape.rs:1-9`,
`crates/podssh-ssh/src/escape.rs:90-138`). The flag table has 469 lines, near
the limit of 500 (the table of `ssh`: `crates/podssh-cli/src/flags.rs:116-301`).

## Approach

1. Add the escape `~d` (detach), only when the far end offers kept shells (a
   feature name in the `GREETING` of T-151). Elsewhere `~d` goes to the server
   as now.
2. On `~d`, the client asks the far end to keep the shell, prints the name of
   the shell on stderr, and exits 0.
3. `podssh ssh --attach NAME DEST` logs in again and asks the far end to join
   the kept shell, with a channel request of podssh. With no NAME, it lists
   the user's kept shells and exits 0.
4. The far end decides when a shell is busy: one client at a time, unless the
   user asks to take it over (ssh-obi's rule, read in GitHub #19, not
   verified here). Refuse an attach from inside the same shell.
5. Put the new rows of the flag table in a new file, so that `flags.rs` stays
   under 500 lines. Add `~d` to the help of `~?`
   (`crates/podssh-ssh/src/escape.rs:137-145`) and to the manual.
6. Against a standard sshd, use `--persist` with tmux (T-178).

## Decision

Recommendation: the far end keeps the shell, and a new SSH login attaches to
it. This needs no listener on the client (`AGENTS.md`, section 5, rule 2),
survives a restart of the client host, and works from another host with the
same key. The alternative, a client in the background that keeps the SSH
connection and takes attaches over an AF_UNIX socket, lost: it needs a local
listener on the client, and it dies with the client host.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib escape
cargo test -p podssh-cli --test attach
```

The escape tests show `~d` as a detach only when the far end offers it, and
as two bytes otherwise. The attach test (crates/podssh-cli/tests/attach.rs)
runs `podssh serve` and the client: it sets a variable in the shell, detaches,
attaches by name, and reads the variable back. A planted far end that ends
the shell on a detach fails it.

## Correction

2026-10-12, read before the work:

- No far end keeps a shell yet: `podssh serve` (T-107 to T-110) waits for
  the operator (Q32), and the kept shells, their lease and their limits are
  T-159's, which waits on it. So the attach test cannot run `podssh serve`.
  It runs a stand-in of the far end in the test process
  (`crates/podssh-cli/tests/keep_harness/mod.rs`): the layer as `podssh
  serve` speaks it, with `keep.v1`, and a russh server whose shells outlive
  their client, behind a node in plain mode on the stand-in relay, as
  T-156 ran its far end.
- Step 3's channel request of podssh cannot reach a far end on russh: its
  server answers a channel request or a global request of a type that it
  does not know with FAILURE, and calls no handler (russh 0.64.1, the
  version of `Cargo.lock`: `Eugeny/russh:russh/src/server/encrypted.rs`,
  lines 1682-1686 and 1760-1763 at `b03c8d5`). The requests are therefore
  `env` requests of podssh's own names and a subsystem, which the handler
  sees (`crates/podssh-ssh/src/keep.rs`).
- An escape needs a pty and a terminal on stdin
  (`crates/podssh-ssh/src/session.rs:208`), so a test cannot type `~d`
  through a pipe: the attach test types it in a pseudo console on Windows
  (`crates/podssh-cli/tests/conpty_harness/mod.rs`) and in a pty on Linux
  (`crates/podssh-cli/tests/pty_harness/mod.rs`, new).
- The Premise's numbers moved: the escapes are `~.`, `~R`, `~#`, `~?` and
  `~~` since T-041, and the flag table had 464 lines before this entry. Its
  rows are one slice, which a second file cannot extend, so the two new
  rows are constants of a new file that `SSH_FLAGS` names.
- Step 4's refusal of an attach from inside the same shell: the client
  cannot tell which shell it runs in. The far end puts `PODSSH_SHELL_ID` in
  each shell that it starts, the client sends it, and the far end refuses.

## Done

2026-10-12.

- The layer: `keep.v1` (`KEEP`) and `SHELL_FEATURES` in
  `crates/podssh-relay/src/session/mod.rs`. `podssh ssh` names it
  (`layered::ssh_settings`), and the road of `node://NAME`, raced with
  `--iroh-ticket` too, reads the far end's answer before the SSH login
  (`layered::learn`, `layered::carry_keeping`;
  `crates/podssh-cli/src/ssh/node.rs`,
  `crates/podssh-cli/src/ssh/iroh/race.rs`). A node names FEATURES, never
  `keep.v1`.
- The client: `crates/podssh-ssh/src/keep.rs` (the offer, what the user
  asked, the name, the requests `detach@podssh`, `attach@podssh`,
  `take@podssh`, `from@podssh` and the subsystem `shells@podssh`, and the
  answer to `~d`). `~d` in the table of `crates/podssh-ssh/src/escape.rs`,
  an escape and a line of `~?` only with the offer. `session.rs` refuses an
  attach or a list with no offer (255), asks for the attach before `shell`,
  and gives `~d` its name; `io.rs` ends the session with `End::Detached`
  on SUCCESS and goes on after FAILURE, and `--result-file` says
  `detached`. `Termination` moved to
  `crates/podssh-ssh/src/terminal/termination.rs`, so that `io.rs` stays
  under 500 lines.
- The command line: `--attach NAME` and `--take`, in
  `crates/podssh-cli/src/flags/attach.rs`, which `SSH_FLAGS` names; the
  checks and what they ask in `crates/podssh-cli/src/ssh/attach.rs`.
  `--attach DEST` with no other word lists the kept shells. The manual's
  notes of `ssh` (`~d` in the terminal's note, a note of `--attach`,
  `detached` in the result file) and `PODSSH_SHELL_ID` in ENVIRONMENT;
  `docs/terminal.md` ("Detach and attach again"), `docs/cli.md`,
  `docs/design.md` (section 5), `docs/STATUS.md`.
- The calls made where the Approach left a choice. The client names the
  shell: 8 hexadecimal digits at the first detach, the attached name after
  an attach. SSH's SUCCESS carries no data, and only a global request's
  answer does, which russh's server never lets through; the far end
  refuses a name that another shell has. `~d` ends the input there, as
  `~.` does, and a refused detach leaves the session running. A value flag
  of the table needs its value, so `--attach WORD` with no destination
  makes WORD the destination, and lists. `--attach` is for `node://NAME`
  only (64 elsewhere), the one road that reads the offer: the iroh road
  alone (`iroh:TICKET`) carries the layer inside podssh-iroh's `carry`,
  which gives no handshake to read, so `~d` goes as two bytes there and
  `--attach` is refused; it comes with a far end that keeps shells on that
  road (T-159). A refusal of the far end is its words on stderr and its
  exit status, which podssh exits with. `--take` takes the shell, and the
  far end ends the other client's channel (255 there). A control master
  does not carry an attach: the run makes its own connection.
- Prove: `cargo test -p podssh-ssh --lib escape`: 9 passed here (among them
  `tilde_d_detaches_only_when_the_far_end_keeps_shells` and
  `the_help_names_tilde_d_only_where_it_detaches`).
  `cargo test -p podssh-cli --test attach`: 6 passed here, on Windows 11
  with Python and openssl, and in the build image with the pty of Linux
  (6 passed). Its tests:
  `a_shell_left_with_tilde_d_is_attached_again_by_name` (the variable, `~d`
  in a terminal, the list, `--attach NAME` from a new process, the
  variable read back); `a_far_end_that_ends_the_shell_on_a_detach_fails_the_check`
  (the planted far end of the Prove, run here as the control: the read
  fails with exit 1); `a_far_end_that_keeps_no_shells_refuses_attach_and_gets_tilde_d_as_bytes`;
  `the_far_end_refuses_a_nested_attach_and_a_second_client_unless_take`;
  `attach_refuses_what_it_cannot_serve_before_anything_connects`. The
  tests of `~d` run on Windows and Linux only; each test but the last says
  "did not run" with no Python or no openssl. The unit tests of
  `keep.rs` and `ssh/attach.rs`: 13 and 1 passed; the suites of
  `podssh-ssh` and `podssh-relay`, and those of `podssh-cli` that the change
  reaches (`ssh_args`, `node_plain`, the manual's and the flags'), passed,
  and so did a build with the feature `iroh`.
- Waits for T-251: the gate's run in the build image (the pty of Linux),
  and the planted client: an `Escapes` that takes `~d` with no offer must
  fail `tilde_d_detaches_only_when_the_far_end_keeps_shells` and
  `a_far_end_that_keeps_no_shells_refuses_attach_and_gets_tilde_d_as_bytes`.
  A run against `podssh serve`, and live through the relay, waits for
  T-159.

# T-159: Sessions on the far end that outlive the client

**Source:** GitHub #20 (Nemo-010, 2026-10-08: a session that the server owns
and that outlives the window, from fux); GitHub #19 (quic-ssh's registry of
persistent sessions; tty7's sessions after a reboot); GitHub #18 (zuko: a
detached pty kept for 5 minutes).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

When the client is away for longer than the resume deadline, the far end ends
the shell and its programs. A long job that runs in an interactive shell is
lost with the client's laptop or network.

## Premise

Read: no server exists yet; `podssh serve` is M5 (T-107, T-108, T-110). The
registry of the layer keeps a session only until the resume deadline
(T-153). Read in the reports, not verified here: zuko keeps a detached pty for
5 minutes, with no replay; quic-ssh keeps the output of a persistent session
in a bounded buffer with a start offset
(`VLOD-ZDOV/quic-ssh:src/server/persist.rs`); tty7 brings back the layout and
the screen after a reboot. A process does not survive a reboot, so only
metadata can.

## Approach

1. In `podssh serve`, a shell with a pty can outlive its SSH channel: keep the
   pty, the process group of the child, and a ring of its recent output. The
   ring drops its oldest bytes at a boundary of the terminal grammar (T-221),
   and T-161 decides what an attach shows.
2. Keep a shell only on request: the detach of T-158, or a keep request at the
   login. Give each kept shell a lease; it ends when the lease runs out or the
   shell exits.
3. Limits: a maximum count of kept shells for each user and in total, and a
   bounded ring for each. Hold the state in memory only.
4. At the end of a lease, send SIGHUP to the process group, then SIGKILL after
   10 s, with the stop rules of T-117.
5. A restart of `podssh serve` or of the host ends each kept shell. Write the
   names of the kept shells in a state file (mode 0600), so that the user
   learns what was lost. Say so in the manual.
6. Docs: the server side in `docs/terminal.md`, and the section of `serve` in
   the manual.

**The donor study (2026-11-18, PodUtils/podssh#317), report 03.** (trzsz/tsshd at 8ae6c63). A kept shell has one owner at a time, and a new link is a ticket, not a new session. Four rules to settle in step 1, besides the ring: (a) the far end holds a record with one owner slot and a generation that stays after the path dies; a ticket at or below the generation is refused, a newer one swaps the owner and closes the old path (trzsz/tsshd:tsshd/attach.go:371-380, tsshd/proxy_server.go:519-521). (b) A new client takes over from the old one and tells it why before it closes it (trzsz/tsshd:tsshd/server.go:235-248); a read-only second client is not in the donor and is left to T-161's decision. (c) Output that arrives with no client is kept as whole lines, at most `max(1000, 2 * rows)`, and flushed at attach; past the cap, one repaint and one notice (trzsz/tsshd:tsshd/output.go:225-231, tsshd/output.go:254-256). The ring of step 1 already stops at a boundary of the grammar (T-221), so this is its line count, not a second buffer. (d) Eight marker bytes follow an attach and prefix the next input, so the far end drops input that was queued for the old client (trzsz/tsshd:tsshd/session.go:77-79, tsshd/client.go:1249-1250). Limits to avoid: the donor's attach is authorised by the transport alone, so any session id in its table can be named (tsshd/attach.go:371-380); T-833 holds the ticket rule. Whether `pod-session`'s `move.v1` already keeps a generation after a link dies is not read here; the session is `pod-session`'s, so a record needs an ask of podcrates (a COORD issue), not a copy.

**The donor study (2026-11-18, PodUtils/podssh#317), report 22.** (unixshells/latch at its pinned commit). Where step 1 keeps the pty, its ring and its lease, keep them in one object that no transport owns: it holds the pty, the screen of `pod-term`, the ring and the set of attached ends, and names no SSH type (unixshells/latch:internal/mux/render.go:20-66, where the render takes the session and a size, not a client). The SSH handler then only authenticates, resolves the name and attaches; T-158's `--attach` and a later ingress take the same attach call. Write first the test that two in-memory attachments to one object each get the same full frame, one pty write for each input frame, and the pty lives when both close (T-159 and T-161 in one assertion). This does not need a second wire protocol now.

## Decision

Recommendation: keep a shell after the resume deadline only when the client
asked, with a lease that the user gives and a maximum that the server sets.
The alternative, keep each shell after each loss, lost: a cage would collect
programs that nobody comes back to.

2026-11-24, the calls of the draft, each with what lost:

- One object for each kept shell (`crates/podssh-ssh/src/server/kept.rs`), which no channel owns:
  the pty's input and size, the child's group, the ring and the one channel attached now, as report 22
  asks. It is not T-837's `Hub`: the hub's seats and writer lease serve many clients at once, and a
  change of it would move T-837 to T-861 with no run here. Merged with the hub lost for now; T-161,
  which gives the screen to each attach, is the place to make them one.
- The owner of a kept shell is the key that logged in (its fingerprint): serve runs as one user of
  the host, so the limits "for each user" are for each key, and a shell is found by its key and its
  name alone. Any key of the server, as trzsz/tsshd's table lets any session id be named, lost.
- One ring for each shell, fed always, with the offsets of pod-term's `Ring`: an attach gets the
  bytes since the detach, or since its own count later (T-833). A second buffer fed only with no
  client (the donor's rule (c)) lost: two buffers of one stream, and no offset to replay from.
- The lease: `--keep-lease` of serve NAME, 24 h by default, 30 days at most, 0 for none; the client
  asks for less with `env lease@podssh SECONDS` (`podssh ssh -o SetEnv=...`, or OpenSSH's). zuko's
  5 minutes lost (a laptop's night is longer), and no bound lost (a cage would collect programs).
- SIGKILL 10 s after a lease's hangup, as step 4 asks; a shell that its client left unkept keeps
  T-117's rule (a hangup, and a wait), so that no session of today changes.
- Only a login shell on a pty of the kernel is kept, and none with `--share`. A shell on serve's own
  tty (T-111, T-776) has its discipline in the channel's tasks; keeping it too lost for now, and a
  `~d` there is refused with a line, as by a far end that keeps nothing.
- The record (step 5) holds names alone, the key's fingerprint and the name, replaced whole by a
  rename from a name of random bits, and not written during a stop, so that it names the shells
  that the stop ended. A record of each shell's output lost: the step asks for metadata only.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test serve_keep
```

The test (crates/podssh-ssh/tests/serve_keep.rs) starts `sleep 600 &` in a
shell, detaches, and attaches again in the lease: the job still runs. With a
lease of 2 s, the process group is gone after the lease. A planted server that
keeps nothing fails the first check; a planted server with no lease fails the
second.

## Start condition

T-107, T-108, T-110 and T-117 are done: `podssh serve` exists, with a shell on
a real pty and a stop that signals each child's process group. The operator
holds them (Q32, `docs/decisions.md`), so this entry waits as they wait, as
T-114 does. Read at `b03c8d5` (2026-10-12): no source in `crates/` outside
the tests uses `russh::server`, and the verb table of
`crates/podssh-cli/src/flags.rs` has no `serve`. The far end of the resumable
layer keeps a stream to its target until the resume deadline, not a shell
(`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`), so a kept shell has no other
place to live. The parts that need no server (the lease, the limits, the stop
and the state file) wait too, as the TOTP code of T-115 waits: their shape
follows the server's pty and channels, which T-107 to T-110 decide. The
ring of step 1 exists: T-221's `Ring`
(`PodUtils/podssh:crates/podssh-terminal/src/grammar/ring.rs`), which drops its oldest
bytes only up to a boundary of the terminal's grammar.

## Correction

2026-11-05. `podssh-terminal` left this tree: its code is `pod-term` of PodUtils/podcrates, taken by
the git tag `v0.1.0` (T-684; `crates/podssh-cli` depends on it). Each `podssh-terminal` of this
entry reads `pod-term`, and a path under `PodUtils/podssh:crates/podssh-terminal/` is
`PodUtils/podcrates:crates/pod-term/` now, with its own line numbers. The echo discipline,
`Event::Signal`, the passthrough and the ring of T-221 are there. Rule Q3 holds: a change of the
terminal code is done in PodUtils/podcrates (or asked as an issue there), and podssh takes it by the
next tag. The ring of step 1 is `pod-term`'s `grammar/ring.rs`. The far end's sessions and its
handover are in `podssh-relay`'s `session/`, which goes to `pod-session` of PodUtils/podcrates
(Q101, wave 2); Rule Q3 applies to it as above.

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

2026-11-24, read before the draft:

- The Premise's "no server exists yet" no longer holds, and the Start condition's parts are on
  `main`: `podssh serve` runs a login shell on a pty (`crates/podssh-ssh/src/server/pty_child.rs`),
  stops by hanging up each child's group (`crates/podssh-ssh/src/server/stop.rs`), and under NAME
  answers each session of a node in one process with one `Control` (`crates/podssh-cli/src/node_serve.rs`),
  which can hold shells across connections. T-107, T-108, T-110 and T-117 are `partial` for their
  runs in the build image alone, so this entry starts as T-114 did, from the parts on `main`.
- The kept shell is podssh's own (`podssh-ssh`'s server), not `pod-session`'s: an attach is a new SSH
  login above the layer, so the layer's session need not outlive its deadline, and the generation of
  the donor's rule (a) is the shell object's. No ask of podcrates is needed. The ring is pod-term's
  `Ring` (T-221), taken as it is; no crate of podcrates or sibling keeps a pty.
- Step 3's limit for each user: serve runs as one user; the limit is for each key (Decision).
- A job that an interactive shell starts in the background is in a process group of its own (job
  control), so a hangup of the shell's group does not reach it, as under sshd. The Prove's job runs
  after `set +m`, in the shell's own group, which the lease's end must end.
- The requests: T-158's (`detach@podssh`, `attach@podssh`, `take@podssh`, `from@podssh`,
  `shells@podssh`), and two more of podssh's own names, `keep@podssh NAME` (step 2's keep at the
  login) and `lease@podssh SECONDS` (`crates/podssh-ssh/src/keep.rs`).

## Done

Drafted 2026-11-24 (not built here; the main session builds, tests and closes it).

- The server: `crates/podssh-ssh/src/server/kept.rs` (the shell object: its output through `Out` to
  the attached channel and the ring, each channel's input through a gate of its generation, `~d`'s
  detach, a lost channel, a join with `--take`, the catch-up of what came with no client, the lease),
  `kept_ask.rs` (the asks of a channel, the keeper of a start, the id `PODSSH_SHELL_ID`),
  `kept_shelf.rs` (the shells by key and name, 4 for each key and 32 in all, `Control::keep_record`,
  `Control::kept`), `kept_record.rs` (the record, 0600, replaced by a rename), `kept_join.rs` (an
  attach's channel: its spare pty closed, its size to the shell's), `kept_run.rs` (the child's start
  and end; SIGHUP and SIGCONT, then SIGKILL 10 s after a lease). The handler takes the requests in
  `kept_asks.rs`; `handler_gate.rs` holds `admit`, `serving` and `rules`, moved so that `handler.rs`
  stays under 500 lines. `pty_child.rs` starts a login shell that may be kept through `kept_run.rs`,
  `child.rs`'s `Running` gives its parts, `pty_grant.rs` resizes a kept shell, and a stop freezes
  the record (`stop.rs`).
- The command line: `--keep-lease TIME` (`crates/podssh-cli/src/flags/serve.rs`,
  `crates/podssh-cli/src/serve_keep.rs`), 24 h by default under NAME, refused under `--stdio` (64);
  `serve-NAME.kept` beside the host key; serve NAME's layer names `keep.v1` where it keeps shells
  (`node_serve::keeps`); `--print-unit` passes `--keep-lease`. The manual: a note and a FILES row of
  `serve` (`crates/podssh-cli/src/man/notes_serve.rs`). `docs/cli.md`, `docs/terminal.md`,
  `docs/design.md`, `docs/STATUS.md`.
- Prove: `cargo test -p podssh-ssh --test serve_keep`: 4 passed (2026-11-24, on the stack at `a64e47d`, Rust 1.99.1). Its tests:
  `a_kept_shell_keeps_its_job_and_is_joined_again_by_name` (the job runs on, the line that came with
  no client replayed, the list, a second client, an attach from inside and another key's refused,
  `--take`, the status to the client that has the shell);
  `a_lease_that_runs_out_ends_the_process_group` (a lease of 2 s);
  `a_shell_is_kept_only_when_its_client_asked` (no `~d`: hung up as before; `keep@podssh`: kept
  after a lost connection); `a_server_that_keeps_no_shells_refuses_each_request`. The unit tests:
  `cargo test -p podssh-ssh --lib server::kept server::kept_record`: passed (in `cargo test -p podssh-ssh --lib`: 509 passed, 2026-11-24, on the stack at `a64e47d`, Rust 1.99.1);
  `cargo test -p podssh-cli --lib serve_keep`: passed (in `--lib`, 1279 passed); the manual's and the flags' tests of
  `podssh-cli`: `man_page` 11, `man_flag_parity` 6, `man_json` 4, `flag_table` 9 passed.
- Waits: the run of T-158's `crates/podssh-cli/tests/attach.rs` against `podssh serve NAME` in the
  place of its stand-in, and live through the relay; the planted servers of the Prove (one that keeps
  nothing, one with no lease) with the release check (T-251); the remap of the cited files that this
  change moved (`cargo todo remap`).

# T-160: Local echo and prediction for high latency

**Source:** `docs/design.md:888-889`; GitHub #19 and GitHub #18 (Nemo-010,
2026-10-08: quic-ssh's prediction, `VLOD-ZDOV/quic-ssh:src/client/predict.rs`;
rose's prediction, GPL, of which only the specification may be read).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

Through the relay, each typed key shows only after a round trip: at 300 ms,
each key shows 300 ms late. Mosh shows a typed key at once, and corrects it
later.

## Premise

Read: an interactive echo for high latency is a later option on top of layer
2; it needs podssh at both ends, and it cannot use UDP here
(`docs/design.md:888-889`). podssh passes the bytes of a remote pty unchanged
and has no model of the remote screen (`docs/terminal.md:20-25`). A
prediction needs the place of the cursor, and needs to know when the far end
echoed a key. Only a podssh far end can tell when a key reached the pty and
whether the pty echoes. With no echo (a password prompt), a predicted key must
never show.

## Approach

1. A terminal model on the client: a pure-Rust parser of escape sequences and
   a screen grid, enough for the cursor, the line and the alternate screen.
   Accept a crate only with an MIT or Apache license and no C.
2. Predict printable characters, Backspace, and the left and right arrows, on
   the line of the cursor only. Show predictions only after the first
   confirmed key of an epoch (the rule of mosh, read in rose's specification,
   not verified here). Underline a prediction until the echo confirms it.
3. The far end (`podssh serve` with a pty, T-110) reports the input offset
   that reached the pty, and the ECHO flag of the pty. Invariant: no
   prediction shows while ECHO is off, so a password never shows.
4. A difference between a prediction and the screen clears each prediction,
   and starts a new epoch.
5. On only by request (`--predict`), with a pty, to a podssh far end, and
   above a measured round trip of 120 ms.
6. Test the model against the terminal oracle of T-200.

**The donor study (2026-11-18, PodUtils/podssh#317), report 07.** (mobile-shell/mosh at decd9b7). Details of mosh's overlay that step 2 and step 4 do not give, for the design before the code: (a) each predicted cell holds the state number after which it is judged (`local_frame_sent + 1`) and what it replaced, so a prediction is checked against a state, not against a clock (mobile-shell/mosh:src/frontend/terminaloverlay.cc:762, src/frontend/terminaloverlay.h:57-64); (b) the far end tells the client the number of the last input it applied, after 50 ms of batching, and the client gets the echo ack from that number (mobile-shell/mosh:src/statesync/completeterminal.cc:132-136, src/frontend/mosh-server.cc:799-801), which is the "input offset that reached the pty" of step 3; (c) a wrong tentative guess kills its epoch, and a wrong confirmed guess resets the whole engine, which makes right guesses elsewhere flash (mobile-shell/mosh:src/frontend/terminaloverlay.cc:468-482, src/frontend/terminaloverlay.cc:502-507); consider resetting the row only; (d) wide characters and non-printing input are tentative, and a read over 100 bytes is a paste that resets prediction (mobile-shell/mosh:src/frontend/terminaloverlay.cc:712-714, src/frontend/stmclient.cc:331-335); (e) overlays are drawn on a copy of the screen and the copy is diffed to the display, so the model that the far end sends never holds a guess (mobile-shell/mosh:src/frontend/stmclient.cc:281-288). The decision to take before T-160 and T-161 are written separately: mosh's framebuffer holds exactly `height` rows and no history (mobile-shell/mosh:src/terminal/terminalframebuffer.h:396-420), so the object that is numbered and diffed must be larger than the viewport, or the scrollback needs a stream of its own; write the choice in T-161's Decision. T-303 and T-304 then follow: the latest screen is the newest state number, and the datagram is only the carriage.

## Decision

2026-11-24, in the draft (each call with the alternatives that lost).

1. **The far end's word rides the SSH channel.** `podssh ssh --predict` asks with `env
   predict@podssh v1` and a reply, last before the shell or the command, so its answer comes
   after the pty's; `podssh serve` takes it on a channel whose pty it opened, and then sends
   each report as 10 bytes of extended data of the code `0xFE504F44`, in the range that RFC
   4250 leaves for private use (section 4.4.3, read on 2026-11-24 through
   `fetch.web.pkgforge.dev`): the version, ECHO and ICANON, and the count of the client's bytes
   that reached the pty's master 50 ms ago (`crates/podssh-ssh/src/predict/report.rs`). Each
   report goes out of the task that copies the pty's output, after the output read before it
   (`crates/podssh-ssh/src/server/predict.rs`). Lost: a channel request from serve, which
   russh's client answers with FAILURE and passes to no handler
   (`vendor/russh/src/client/encrypted.rs`, the arm of an unknown `CHANNEL_REQUEST`), so it
   needs a patch of russh; a frame of the resumable layer ("on top of layer 2",
   `docs/design.md:925-926`), whose far end is a node that may sit in front of a standard sshd
   and see no pty, and which `--direct` does not have; bytes inside the data stream, which the
   far end's program could write itself and so forge.
2. **The invariant of step 3 reads ICANON with ECHO.** A guess never shows while the pty reads
   a line with no echo (ICANON on, ECHO off). In raw mode a guess shows only in an epoch whose
   first guess the far end echoed, and a change of the flags, a new row of the cursor, Enter
   and each key that is not guessed start a new epoch. Lost: ECHO off alone, which turns local
   echo off under readline, zsh, fish and vim, each of which runs with ECHO off and echoes
   itself; the epoch alone (mosh reads no flag), which shows a guess on a confirmed line until
   the far end's report when a program stops echoing with no other sign.
3. **The model is `vt100`**, at run time in podssh-ssh: the model of the terminal oracle
   (T-200), pure Rust over vte, MIT, in the lock already (podssh-cli's `session capture` runs
   it). Lost: `pod-term`'s grammar, which finds boundaries and keeps no grid; a model of
   another crate, which the oracle would then judge with a second parser.
4. **Guesses are drawn over the terminal and taken off before each byte of the far end**, by
   moves along the cursor's row only (`crates/podssh-ssh/src/predict/draw.rs`). Lost: mosh's
   display, a frame buffer of the client diffed to the terminal, which would make podssh
   redraw the far end's screen itself (the frames of T-303); a move to a place on the screen,
   which the origin mode would shift where the model does not say.
5. **The round trip's line**: guesses show from a smoothed round trip of 120 ms (step 5) and
   stop under 80 ms, so that a link near the line does not make them come and go; the first
   sample is the reply to the ask, the next ones the reports, less the far end's 50 ms. Lost:
   mosh's 30 ms and its 250 ms of a guess that waited (`docs/design.md`, "Local echo"), lower
   than the entry's 120 ms.
6. **A wrong guess resets the row**, which holds each guess (report 07, item c); with it, each
   guess of the epoch goes, and nothing is guessed until the far end has read each key sent.
7. **A line of podssh's own on the terminal stops local echo for the session**: it moves the
   cursor where the model does not know it. Lost: asking the terminal where its cursor is,
   whose answer comes among the keys (as "A notice while the far end is silent" found in
   `docs/terminal.md`).
8. **Shared code first.** The predictor is podssh's: `pod-term` holds the line discipline and
   the grammar of boundaries, and no crate of PodUtils/podcrates at `v0.82.1` holds a screen
   model or a predictor (its `docs/design.md`, the table of crates); no sibling runs an
   interactive client on a link of a long round trip, and the reports are a word between
   podssh's client and `podssh serve`. No ask is filed.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test predict
```

With 300 ms of latency from the fault harness (T-203), typed letters show
before the echo. With ECHO off at the far end, no typed letter shows before
the server writes it. A planted predictor that ignores the ECHO flag fails
the second check.

## Start condition

T-107 and T-110 are done: `podssh serve` exists and runs a shell on a real
pty. The operator holds them (Q32, `docs/decisions.md`), so this entry waits
as they wait, as T-159 does. Step 3 is the far end's: the offset of the input
that reached the pty and its ECHO flag come from `podssh serve`, and the
invariant of step 3 (no prediction while ECHO is off, so that a password never
shows) cannot hold without them; step 5 turns prediction on only to a podssh
far end. A model on the client alone would guess the ECHO flag, which the
invariant forbids. Read at `d56d316` (2026-10-12): the verb table of
`crates/podssh-cli/src/flags.rs` has no `serve`, and no source outside the
tests uses `russh::server`.

## Correction

2026-11-05. Rule 4 of `AGENTS.md` (section 5) changed with T-685: C, zig and the newest stable Rust
may be used in each crate, and the one rule of the build is a statically compiled binary
(`docs/decisions.md`, 2026-11-05). The Approach's "no C" for a crate of the terminal model is gone:
a crate that links C may be taken, with an MIT or Apache license, if the binary stays static. The
grammar of the terminal is `pod-term`'s (PodUtils/podcrates, T-684), and the terminal oracle of
T-200 is `pod-testkit`'s (its feature `screen`), taken by the same tag.

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

2026-11-24 (the draft). The Premise's `docs/design.md:888-889` moved: the text reads at
`docs/design.md:925-926` ("An interactive echo for high latency"). The Start condition's "which
reports the input's offset and the ECHO flag" did not hold at `a64e47d`: serve's pty copied the
master's output and nothing else (`crates/podssh-ssh/src/server/pty_child.rs`); the draft adds
the reports, as step 3 asks. Step 3's invariant, "no prediction shows while ECHO is off", read
alone, turns local echo off under each line editor, which runs with ECHO off and echoes itself
(readline, zsh, fish, vim); it holds as Decision 2 reads it. So the Prove's plant changes: a
predictor that ignores the ECHO flag alone still shows no password, as the epoch and the reset
at a change of the flags each hold it; the plant that fails the second check ignores the flag
and shows guesses of an epoch that no echo confirmed. Step 6's oracle is `vt100`, the model of
`pod-testkit`'s feature `screen`, which the test reads directly.

## Done

2026-11-24, drafted on the branch `d-t160`; merged by the main session on `main` after `98e3cc5`, built and
tested (Rust 1.99.1). It holds:

- The client: `crates/podssh-ssh/src/predict/` (`engine.rs`, the guesses with no I/O, and its
  table of runs; `keys.rs`; `draw.rs`, the drawing and its undo; `report.rs`, the wire; `mod.rs`,
  the model and the glue), wired in `crates/podssh-ssh/src/io.rs` (the keys, the escapes, a
  resize, the output), `crates/podssh-ssh/src/io/msg.rs` (the reports),
  `crates/podssh-ssh/src/session.rs` (the ask) and `crates/podssh-ssh/src/log.rs` (podssh's
  own lines); `--predict` in `crates/podssh-cli/src/flags/predict.rs`, the parser and the
  options; the manual's note `crates/podssh-cli/src/man/notes_predict.rs`; `llms-full.txt` by
  hand.
- The far end: `crates/podssh-ssh/src/server/predict.rs` and
  `crates/podssh-ssh/src/server/predict_ask.rs`; `pump_told` in
  `crates/podssh-ssh/src/server/child.rs`, whose select is now biased (the child's end, the
  output, then a report); the pty's own path in `crates/podssh-ssh/src/server/pty_child.rs`.
- `docs/terminal.md`, "Local echo for high latency (T-160)", and a row of `docs/STATUS.md`.

Results (2026-11-24, Rust 1.99.1):

- `cargo test -p podssh-ssh --test predict` (the Prove: a simulated link of 300 ms between two vt100 models; letters
  show before the echo, and none with ECHO off): 4 passed.
- `cargo test -p podssh-ssh --test serve_predict`: 3 passed, after a repair that its test found. As drafted, serve's
  pump read when the next report fell due only before it waited on the pty, so a key that made no output (a line
  with no echo) woke nothing and its report never came: `a_line_with_no_echo_is_reported_and_shows_no_key` failed
  at its 30 s limit, with the report of offset 0 alone. Now the writer of the keys wakes the pump
  (`Applied::fall_due` on a `Notify`, `server/predict.rs`), and the unit test
  `a_write_while_nothing_is_due_wakes_the_wait` holds it. The failing run is the planted defect of that check.
- `cargo test -p podssh-ssh --lib` (`predict::` and `server::` among them): 521 passed.
- `cargo test -p podssh-cli --lib` 1279 passed; `flag_table` 9, `man_flag_parity` 6, `man_page` 11, `man_json` 4
  passed; `llms.txt` and `llms-full.txt` written again from the manual.
- The whole suite, as the pump of each serve channel changed (its select is biased): `cargo test --workspace
  --no-fail-fast`, 423 suites, 4243 passed, 3 failed (`job_far`, at this container's stand-in of `rm`, as before).
- rustfmt, and the gate's clippy with `-D warnings -A clippy::collapsible_if`: clean. The merge resolved the
  draft's four places beside T-895's counter (`io.rs`, `io/msg.rs`, `session.rs`, `flags.rs`) as both, and moved
  the citations (`cargo todo remap`).

Waits for T-251: the planted predictor of the Correction. Filed as T-896, the rest that the draft names: the run
from end to end through the fault harness's 300 ms (T-203), `podssh ssh --predict` to `podssh serve` in a test of
podssh-cli; reports from a shared shell (T-837) and from a kept shell (T-159), whose guesses never show; and the
Windows console, whose VT mode the drawing needs (`CSI C`, `CSI D`, `CSI X`).

# T-161: Screen state and scrollback when a client attaches

**Source:** GitHub #19 (Nemo-010, 2026-10-08: ssh-obi replays the byte stream
and keeps the local scrollback; rose's State Synchronization Protocol and its
scrollback with stable row indices, GPL, specification only); GitHub #20
(fux: history that wraps again on a resize); GitHub #31 (the modes after a
replay that was cut).
**Category:** research
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** done

## Problem

When a client attaches to a kept shell (T-158, T-159), its terminal is empty
and must show the current screen. A replay of the last bytes can start inside
a full-screen program that set its modes long before. A snapshot of the
screen needs a terminal model on the far end.

## Premise

Read: the resumable layer replays bytes, as decided (`docs/design.md:785-856`).
That serves the same client process, whose terminal still holds the screen
and its modes. A new process starts with an empty terminal. Read in the
reports, not verified here: ssh-obi replays the byte stream and accepts
duplicate recent bytes; rose sends the screen state and scrollback rows with
stable indices.

## Approach

Each step ends with a result in `docs/terminal.md`.

1. Byte replay from a safe point: replay the ring from a boundary (T-221),
   then send a window change to the pty, so that full-screen programs draw
   again (SIGWINCH). Measure with `vi`, `less`, `top` and a shell, through the
   oracle of T-200.
2. Send the terminal modes again after a replay that was cut (the alternate
   screen, application cursor keys, bracketed paste), as tty7 does
   (`l0ng-ai/tty7:crates/tty7-core/src/core/term_modes.rs`, read in the
   report of GitHub #31, not verified here); mind `?1049h` when the mode is
   on already.
3. A snapshot: the far end keeps a terminal model (the parser of T-160) and
   sends the visible screen and N lines of scrollback. Measure its memory for
   each session, wide characters and the alternate screen.
4. Compare the two: the screen after an attach, the local scrollback, the
   memory, and the size of the code.
5. Write the recommendation in `docs/design.md` section 5, for the operator.

**The donor study (2026-11-18, PodUtils/podssh#317), report 14.** (ekzhang/sshx at its pinned commit): a measured alternative to a terminal model for step 3. sshx keeps no emulator: the pty's output is a log with an absolute byte offset that counts what the pty has produced since it started, a bounded tail (2 MiB for each shell, ekzhang/sshx:crates/sshx-server/src/session.rs:26), and a reader attaches with a cursor. The reply starts at `max(cursor, tailStart)`, and a cursor below the tail is marked as resynced so the client knows it missed bytes (ekzhang/sshx:crates/sshx-server/src/session.rs:176); a re-delivery is trimmed by overlap, so it is idempotent (:259); the offset is kept with the tail (ekzhang/sshx:crates/sshx-server/src/session/snapshot.rs:49). The client resends from the server's offset, snapped to a character boundary (ekzhang/sshx:crates/sshx/src/runner.rs:114), which is T-221's rule. Add to the comparison of step 4 a third column: "log with offsets, no model", and measure it on `vi`, `less` and `top` with a cursor that is below the tail. Input stays one queue into the pty with one check of the right at its head (ekzhang/sshx:crates/sshx-server/src/session.rs:349), the same single gate as T-837. The offset of the input is a keystream position in sshx and not a merge key (ekzhang/sshx:crates/sshx-core/proto/sshx.proto:26); do not take it as one. The offset counter belongs to `pod-term`/`pod-session`: ask podcrates by a COORD issue before writing it here.

## Decision

Recommendation, to confirm by the research: byte replay from a boundary, the
modes sent again, then a forced redraw. It needs no terminal model on the far
end, and it keeps the model of the layer. Use a snapshot only if the
measurement shows broken screens. The alternative, a snapshot first, puts a
terminal model into each `podssh serve`.

2026-11-24, the calls of the draft (steps 1 and 2, and the test of the Prove), each with what lost:

- Who gets the modes and the redraw: each attach but one from a count that the ring holds
  (`crates/podssh-ssh/src/server/kept_screen.rs`, `fresh`): no count, a count that the ring cannot serve,
  and a reset asked. A counted attach is served byte for byte, as T-833 serves it
  (`crates/podssh-ssh/tests/serve_attach_ticket.rs` checks that its replay starts at the count). Both on
  each attach lost: the modes on stdout would enter the count of T-895's client, as no reset's line comes
  before them there, and the count's replay would no longer be exact. Neither with no count lost: T-158's
  `--attach` from a new terminal would find an empty screen under a program that sat still. What this
  costs with podssh's own client is in the Correction below (it gives a count on nearly each attach).
- The modes go before the replay, as they stood at its first byte, not after it as they stand at the
  end: `ESC [ ? 1049 h` on a terminal on the alternate screen clears it (xterm's rule; vt100, the oracle,
  does the same), so after the replay it would erase what the replay drew; before it, the redraw that
  follows fills the cleared screen. They are taken under the same lock as the first bytes, at the offset
  where those bytes start (after the bytes that the ring lost), so no cut moves between the two
  (`crates/podssh-ssh/src/server/kept_catch.rs`, `turn`).
- The order on the channel is the modes (stdout), the reset's line (stderr), a dropped part's line, then
  the bytes. T-895's client counts nothing before a reset's line, which sets its count
  (`crates/podssh-ssh/src/keep_count.rs`, `Counter`), so the modes never enter it, with no change of the
  client and no new line. Lost: the modes after the reset's line with their size said on it (a new
  wording that each client must read; a client of T-895 as it is would count the modes as output and
  give a wrong offset at its next attach); the modes on stderr (the client reads serve's lines there, and
  would read the modes into its next line; a `2>` of the user would lose them). The cost: before a
  full-screen program, the reset's line shows on the alternate screen, where the replay and the redraw
  cover it. A reset's line is still sent before the channel has the shell, so that no live output comes
  before it: a turn that owes only the line sends it first.
- The modes at an offset are `pod-term`'s: the ring keeps the modes of the bytes that it drops, and
  `Ring::modes_at` gives them at an offset that it holds; `Modes::restore` writes them
  (PodUtils/podcrates:crates/pod-term/src/modes.rs, `v0.83.0`, asked by COORD-140). A tracker of the
  modes in podssh lost (Shared code first: the grammar of the output and its ring are `pod-term`'s, and
  podvm's server can keep shells too); a second tracker in serve fed with each byte lost too: it knows
  only the modes at the end, which are wrong for a replay that starts before a later change of them. A
  ring that holds no boundary gives no modes (`modes_at` is `None` there); the redraw still comes.
- Each mode is written set or reset, not only the ones that differ from a terminal's defaults: the
  client's terminal may hold the modes of an earlier program (a vi that `~d` left in that window on the
  alternate screen). A full reset first (`ESC c`) lost: some terminals clear their scrollback with it,
  which ssh-obi's design keeps. The alternate screen goes off as `?47l`, which moves no cursor; `?1049l`
  lost: it restores a cursor that a new terminal never saved, and so moves the replay over the top of
  the user's own screen.
- The redraw: the pty one row shorter, 100 ms, then its size again (`REDRAW_PAUSE`). The kernel signals
  the pty's foreground group only when the size changes, so setting the same size does nothing. A
  SIGWINCH sent to the shell's group alone lost (dtach's way): the shell's group is not the group of a
  job that job control runs, and a program that redraws only when its size differs does nothing. A
  Ctrl-L typed into the pty lost: it is input to whatever reads, and a `cat` would get it. A change of
  the columns lost: a line editor at its prompt can wrap its line anew. The pause lets a program read
  the first change before the second comes; two signals in one wait are one. The rows are cut to what
  the kernel holds (65535) before the nudge, so the nudge is a change there too.
- The size that a redraw nudges is the one that serve set last: `Shell::resize` keeps it and sets the pty
  under the shell's lock, and the redraw's return reads and sets it under the same lock, so a window
  change during the pause wins and neither undoes the other. It is read from the pty at the shell's
  start (`crates/podssh-ssh/src/server/kept_run.rs`); the size comes back also when another client took
  the shell meanwhile, so the pty is never left nudged.
- `crates/podssh-ssh/src/server/kept.rs` had 447 lines after T-896: the catch-up moved to
  `crates/podssh-ssh/src/server/kept_catch.rs`, a child module of `kept.rs` beside T-896's
  `crates/podssh-ssh/src/server/kept_flow.rs` (it reads the shell's private state), so that each file
  stays under 500 (`kept.rs` 386, `kept_catch.rs` 149). T-896's wake of the pump at the join
  (`tells.attached`) and its reports go with it unchanged.
- Step 3, a snapshot of a model on the far end, is not built: the Decision above keeps it for a measured
  broken screen, and the comparison of step 4 in `docs/terminal.md` says what it would cost.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test attach_screen
grep -n 'Screen on attach' docs/terminal.md
```

The test attaches to a kept shell that runs `vi`, and compares the client's
screen model with the far end's. A planted replay from a random offset fails
it, and so does a replay that leaves out the modes. The `grep` shows the
recorded result.

## Start condition

T-159 is done: a far end keeps a shell, its ring and its pty after the
client leaves. Each step measures what a client gets when it attaches to
such a shell (the ring replayed from a boundary and a window change sent to
the kept pty; the modes sent again; a snapshot kept by the far end), and no
far end keeps a shell yet: T-159 waits for `podssh serve`, which the
operator holds (Q32). T-158 made the client's side (`~d`, `--attach`,
61796d8), against a stand-in far end that keeps a shell but no screen. The
boundary of the replay is T-221's, done: its ring gives its bytes from a
boundary.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

2026-11-05. The grammar of the terminal and its ring (T-221) are `pod-term` of PodUtils/podcrates
(T-684), and the terminal oracle of T-200 that the Approach names is `pod-testkit`'s (its feature
`screen`), both taken by the git tag `v0.1.0`. A change of that code is done in PodUtils/podcrates
(Rule Q3, `docs/decisions.md`), and podssh takes it by the next tag.

2026-11-24, read before the draft, on `main` with the take of podcrates `v0.83.0` (3001570):

- The Premise holds: the layer's replay (`docs/design.md`, section 5, item 2) sends again what the other
  side did not acknowledge, for the same process, and an attach of T-158 is a new SSH login from a new
  process. A far end that keeps shells exists now: `podssh serve NAME` (T-159, done), with its ring of
  256 KiB, a count that replays from an offset, and a reset that gives the ring from its first boundary
  (T-833, done). The Start condition's "no far end keeps a shell" holds no more.
- `pod-term` at `v0.83.0` has what step 2 needs, asked by COORD-140 (#350, closed): `pod_term::modes::Modes`
  (`new`, `feed`, `restore`) and `Ring::modes_at`, with the modes of the bytes that the ring dropped.
  `restore` also writes focus reports, origin mode, autowrap, the cursor shown and the G0 set.
- T-895 (done) changed what a count means: podssh's client counts each byte of stdout as the shell's
  output and gives a count on each attach where it knows one, from its cache or else from the list's
  offset (`crates/podssh-ssh/src/keep_count.rs`, `Counting::to_give`). So (a) a byte that serve adds to
  stdout would enter that count, unless a reset's line follows it (the order of the Decision); and (b)
  podssh's own client gets the modes and the redraw only with `--reset`, or where it knows no offset: an
  `--attach` from a new terminal with a cached count gets the bytes alone, as the design of this draft
  says. A client of another make that names the shell with `SetEnv` alone gets them on each attach.
  Whether a counted attach should get the redraw too (it adds no byte that is not the shell's output, so
  it moves no count) is left in the Done for the main session.
- T-896 (done) moved the input, the output (`Out`) and local echo's reports to
  `crates/podssh-ssh/src/server/kept_flow.rs`, a child module of `kept.rs`; the catch-up stayed in
  `kept.rs`, with the pump's wake at the join. The earlier draft of T-161 (`d-t161`, `d41ef89`) was
  written before both; this one is written again on them.
- The donor note's "the offset counter belongs to `pod-term`/`pod-session`: ask podcrates" is met:
  T-833's offsets are `pod-term`'s `Ring::end`, and no ask is needed for them.
- Step 3's "the parser of T-160" is the client's; a snapshot on the far end would need a model of the
  screen in `pod-term` (the oracle's `vt100` is in tests only), an ask of its own if a measure ever
  calls for it.
- The test of the Prove runs a stand-in full-screen program in `sh`, which a host with no `vi` has too,
  and `vi` where the host has it (a line says where it does not).

## Done

Drafted 2026-11-24 as a first part on `main` with podcrates `v0.83.0` (branch `d-t161b`); merged by the main session on `main` after T-123, built and tested (2026-11-25, Rust
1.99.1): steps 1 and 2, and the test of the Prove.

- The server: `crates/podssh-ssh/src/server/kept_screen.rs` (who gets the modes and the redraw, the
  modes before an offset, the nudged size, and their unit tests); `crates/podssh-ssh/src/server/kept_catch.rs`
  (the catch-up, moved out of `kept.rs`: the modes before the first bytes and the reset's line, the
  redraw after the join); `kept.rs` (`Joined`'s `fresh`, the size that serve set last, under the lock);
  `kept_run.rs` (the pty's size at the start); `kept_tests.rs` (the join's rule, one table);
  `crates/podssh-ssh/src/server/mod.rs`.
- The manual's note of `serve` (`crates/podssh-cli/src/man/notes_serve.rs`) and `llms-full.txt` (the
  note's paragraph wrapped by hand as the manual wraps it); `docs/terminal.md` ("Screen on attach", with
  the comparison of step 4 read from the designs), `docs/cli.md`, `docs/STATUS.md`. The citations of
  `docs/cli.md`, `docs/terminal.md` and `crates/podssh-ssh/src/server/mod.rs` were moved by a line diff,
  not by `cargo todo remap`.
- Prove: `cargo test -p podssh-ssh --test attach_screen`: passed, three times in a row (its three cases: the stand-in
  joined with no count, the stand-in after a ring that dropped its modes joined with a reset, and `vi`; the merge
  compares `vi`'s screen without its last row, the message that `vi` draws once and its redraw leaves out, on the far
  end too). A plant that turned the redraw off made it fail ("the new client's screen"), so it holds the redraw; `grep -n 'Screen on attach'
  docs/terminal.md`: the section is there. The unit tests: `cargo test -p podssh-ssh --lib
  server::kept_screen server::kept`: passed, in `--lib`'s 551. The catch-up moved, so again: `cargo test -p podssh-ssh
  --test serve_attach_ticket --test serve_keep --test serve_predict_kept`: 3, 4 and 2 passed. They found a defect of the
  draft's order: the modes went on stdout before the reset's line on stderr, and the two go by queues of their own, so
  the client's count after a reset was off by the modes' length (`a_count_older_than_the_ring_or_a_reset_asked_gives_the_last_output`:
  560235, where serve said 560134). Repaired: the reset's line goes first, awaited, and names an offset that makes room
  for the modes after it (`kept_catch.rs`); `cargo test -p podssh-cli --test attach` (T-895's counting client), 7
  passed. The manual's tests:
  `cargo test -p podssh-cli --lib man`: passed, in `--lib`'s 1287; `llms.txt` and `llms-full.txt` written again by
  the binary. `cargo todo check`, `python scripts/check-repo.py`, rustfmt and the gate's clippy: clean. The whole suite
  (with T-123): 430 suites, 4298 passed, 3 failed (`job_far`, at this container's stand-in of `rm`, as before).
- Left, in order: step 1's measure with vi, less, top and a shell through the oracle, and the measured
  row of the comparison in `docs/terminal.md`; step 3's cost of a snapshot (the memory of a model of the
  screen for each shell, wide characters, the alternate screen), only as the comparison's numbers; step
  5, the recommendation in `docs/design.md` section 5; the planted defects of the Prove (a replay from a
  random offset, a replay with no modes) with the release check (T-251). The seats of `--share` (T-837's
  hub) find no screen on their attach either; T-159's Decision names T-161 as the place to make the hub
  and the kept shell one, which this part does not do.

2026-11-24, the main session's call at the merge, by the owner's rule "Decisions" (add the feature, remove none): each
attach gets the redraw, a counted one too; the modes stay with a fresh attach alone. The redraw is the shell's own
output, so it moves no count of T-895's client, where modes on stdout would; it gives a new terminal attached by a
count a screen, and takes nothing from the byte-for-byte replay before it. `kept_catch.rs` redraws after each join;
`kept_screen::fresh` names the modes alone.

2026-11-25, the gate at `3fc930f` failed `gate (ssh)` on `attach_screen`'s case of `vi`: the build image's `vi` is
BusyBox's, whose redraw on a size change pads its lines and draws no `~`, unlike its first draw; the first client
detached before the redraw, so its model is no oracle of a `vi` after one. podssh's bytes were right (the text and the
modes were the far end's). The case of `vi` now compares the file's text and the modes; the stand-in, which draws the
same screen at each change, keeps the comparison row for row, and a plant with no redraw still fails the test. BusyBox's
`vi` also read the quit's `ESC :` as one sequence: the ESC goes apart. Run here (2026-11-25): `cargo test -p podssh-ssh
--test attach_screen`, passed twice with this container's `vi` and three times with BusyBox's (`busybox vi` first on
`PATH`).

2026-11-25, the gate at `0c6e9c4` failed `gate (lint)` alone, on the format of one line of `attach_screen.rs` (the case
of `vi`'s filter); each other job passed, `gate (ssh)` with this test. Formatted by rustfmt; `cargo fmt -p podssh-ssh
-- --check`: clean.

2026-11-25, steps 1, 3, 4 and 5 in the main session. Step 1's measure: `crates/podssh-ssh/tests/attach_measure.rs`
(ignored; run on demand: `CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test attach_measure -- --ignored
--nocapture`): vi, less and top of Ubuntu 24.04 and bash at its prompt, each in a kept shell, joined fresh and with a
reset, the new client's model compared with the first client's after 3 s. vi and less: 23 of 24 rows (all but the
last line's message), top 18 of 23 (the rows its next second changed), the modes the far end's in each; bash at a
still prompt: an empty screen on a fresh attach (0 of 3 rows; bash draws nothing again at a change of size), the whole
screen with a reset. Step 3's cost, as the comparison's numbers: a cell of `vt100` is 32 bytes, 60 KiB a screen of 80
by 24, 2.5 MB for 1,000 lines of scrollback, for each kept shell. Step 4: the table of `docs/terminal.md` ("Screen on
attach") holds the measured column and the table of the run. Step 5: the recommendation in `docs/design.md`, section
5 ("A new client's screen"): no model on the far end; the gap of a shell at a still prompt closes by the ring's last
screenful on a fresh attach outside the alternate screen, filed as T-901 with the seats of `--share`, which find no
screen on their join either. The entry is done; the planted defects of the Prove (a replay from a random offset, a
replay with no modes) wait for the release checks (T-251).


# T-221: Replayed output after dropped bytes starts at a boundary of the terminal grammar (GitHub #31)

**Source:** GitHub #31 (2026-10-08: a rule for where a kept window may start),
with the coordinator's reading of 2026-10-08, checked here against
`docs/design.md:787-847`.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

An escape sequence of a terminal has several bytes. When a ring of output
drops its oldest bytes, the kept window can start inside a sequence or inside
a UTF-8 character. A client that attaches then gets the end of a sequence as
text: a full-screen program draws wrongly, or a part of a title sequence shows
on the command line.

## Premise

Read: the layer keeps each byte that is not acknowledged, "with backpressure
when it is full" (`docs/design.md:788-789`), and a resume sends again from the
other side's offset (`docs/design.md:845-847`). Thus a resume in the buffer
is byte-exact, and it cannot start in the middle of a sequence; T-152 tests
that invariant. Bytes are dropped only where a client attaches after output
that it never received: T-158, T-159 and T-161. The report puts the tracker
in `podssh-transport`; it cannot work there. The layer runs under SSH and
sees only ciphertext (`docs/design.md:785-786`), and the transport crates do
not know the protocol that they carry (`docs/architecture.md:281-283`). The
plaintext of a pty exists only on the far end that keeps the shell. Read in
the report, not verified here: tty7 drops bytes from its ring until a tracker
says that it is at a boundary
(`l0ng-ai/tty7:crates/tty7-core/src/daemon/pane.rs`).

## Approach

1. A sans-IO tracker in `podssh-terminal`, a crate with no C, in a new module
   beside the escape parser (`PodUtils/podssh:crates/podssh-terminal/src/escape.rs`). Bytes
   go in; it says whether the next byte is at a boundary. The caller gives
   the time with each chunk; the module reads no clock.
2. The states: plain, escape, CSI, OSC, DCS, and the other strings (SOS, PM,
   APC); a string ends with ST or, for OSC, with BEL; CAN and SUB end each
   sequence. Track UTF-8 too: a continuation byte is never a boundary.
3. Put the tracker beside the ring of a kept shell (T-159). The ring drops
   its oldest bytes only up to a boundary, so the first byte that it sends
   after dropped bytes is at a boundary.
4. The rule of the report for a long idle time: when the tracker stays in a
   sequence with no byte for 10 s, the grammar is broken. The next start is
   then the next newline or the next full repaint (`ESC [ 2 J`, or a switch to
   the alternate screen).
5. Test with bytes captured from real sessions (`vi`, `less`, `top`, a prompt
   that sets the title with OSC, UTF-8 text), not bytes that the test makes.
   The fixtures are bytes: give them a `-text` line in `.gitattributes`, as
   the IRC fixtures have.
6. Write the rule in `docs/terminal.md`, next to the ring of T-159.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-terminal --test grammar_boundary
```

The test reads the captured sessions from
crates/podssh-terminal/tests/fixtures/, cuts each at a table of offsets, and
asserts that the first byte kept after each cut is at a boundary, and that a
real terminal model (T-200) then shows no part of a sequence as text. A
planted tracker that ignores UTF-8 continuation fails it, and so does one
that ignores OSC strings. A case with a sequence cut by 10 s of silence
starts at the next newline.

## Correction

2026-10-12, read before the work:

- Step 3 puts the tracker beside the ring of a kept shell, and no far end
  keeps a shell: T-159 waits for `podssh serve`, which the operator holds
  (Q32). So the ring is made here, in `podssh-terminal`, with no shell
  around it (`PodUtils/podssh:crates/podssh-terminal/src/grammar/ring.rs`). T-159's step 1
  already puts a ring that drops its oldest bytes at a boundary into each
  kept shell; it takes this one.
- The Prove names the terminal model of T-200 (`vt100`) as the oracle. The
  oracle here is the parser under such a model: anstyle-parse 1.0.0, vte's
  state machine, which `Cargo.lock` has already (through clap's
  `anstream`), a dev-dependency of `podssh-terminal`, pure Rust, with no
  build script. A start is clean when the parser's actions from it are
  those of the whole capture, byte by byte; a model's screen shows only
  the cells that a sequence changed, so a part of a sequence shown as text
  can hide under a later repaint.
- Step 5's captures: this host is Windows, with no pty and no `top`, and
  `less` copies its file unchanged to a stream that is not a terminal. vim
  and bash of Git for Windows write their terminal's bytes to a file too,
  and were captured so; less and top need a pty of Linux
  (`scripts/capture-terminal.py`).

## Done

2026-10-13.

- `PodUtils/podssh:crates/podssh-terminal/src/grammar.rs`: `Tracker`, sans-IO. `feed`
  takes a chunk with the time it came and gives each `Boundary`: its
  offset, and whether it is the first after a broken sequence. The states
  of step 2 and UTF-8; `BROKEN_AFTER`, 10 s, after which the next start is
  the byte after a newline or the `ESC` of a repaint.
  `PodUtils/podssh:crates/podssh-terminal/src/grammar/ring.rs`: `Ring`, at most its
  capacity, which drops its oldest bytes up to a boundary and gives the
  bytes from it (`start`, `kept`).
- The calls made where the Approach left a choice. Where terminals differ,
  the tracker finds no boundary, since one too few costs the ring bytes
  and a wrong one shows garbage: after the byte that cuts a UTF-8
  character short (vte drops that byte), and at 0x9C, which vte takes as
  ST in a DCS and a UTF-8 terminal does not. The head of a DCS is part of
  its string. The repaints are step 4's two, and `ESC [ ? 1047 h`,
  `ESC [ ? 47 h` and the reset `ESC c`, which start a screen as surely. The
  ring keeps a boundary for each 1/256 of its capacity, the first after a
  broken sequence, and the newest, not one for each byte of text: a cut
  drops at most about 1/256 of the ring more than it must. With no
  boundary left it keeps its last bytes and gives none until one comes, so
  it never holds more than its capacity.
- The captures, with a `-text` line in `.gitattributes`:
  `PodUtils/podssh:crates/podssh-terminal/tests/fixtures/vi.bin`, vim 9.2 of MSYS2
  drawing 60 lines of UTF-8 text in 24 rows and 80 columns (10038 bytes:
  the alternate screen, titles by OSC 2, colours, a search, line numbers,
  a split, its exit); `PodUtils/podssh:crates/podssh-terminal/tests/fixtures/prompt.bin`,
  bash run interactive with a prompt that sets the title by OSC 0, then
  `ls --color=always` and UTF-8 text (560 bytes).
  `scripts/capture-terminal.py` captured busybox's less (8230 bytes), top
  (1361) and vi (5355) in a pty of Linux in the build image:
  `PodUtils/podssh:crates/podssh-terminal/tests/fixtures/less.bin`, `top.bin` and
  `vi-pty.bin`. The test reads each capture there is.
- `docs/terminal.md`, "Where kept output may start"; `docs/STATUS.md`, the
  row of `podssh-terminal`.
- Prove: `cargo test -p podssh-terminal --test grammar_boundary`: 5
  passed on Windows 11, and 5 in the build image with no C compiler, over
  the five captures (2026-10-13). Its tests: `each_boundary_in_each_capture_is_clean`;
  `a_ring_cut_at_each_offset_gives_its_bytes_from_a_clean_boundary` (each
  offset of `prompt.bin` and each third of `vi.bin`: the first byte kept is
  a boundary, a terminal that starts there does over 256 bytes what the
  terminal of the whole capture does, and a ring keeps nothing only where
  no boundary follows the cut);
  `the_oracle_finds_a_cut_inside_a_sequence_or_a_character` (the control: a
  cut inside a title, a CSI and a character of each capture fails the
  oracle; these are the cuts that the two planted trackers make);
  `a_capture_cut_by_10_s_of_silence_starts_at_the_next_newline`
  (`prompt.bin`, silent for 10 s inside its second title: the ring keeps
  from the text after the next newline; silent for 5 s: from the byte
  after the title's BEL); and
  `a_capture_cut_by_10_s_of_silence_starts_at_the_next_repaint`
  (`vi.bin`: from its `ESC [ 2 J`). `cargo test -p podssh-terminal --lib
  grammar`: 20 passed (each state, CAN and SUB, chunks cut anywhere, the
  rule of a broken sequence; the ring's capacity, a ring with no boundary
  left, a character cut by the capacity, a repaint after a broken
  sequence). Clippy 1.98 here and 1.99 in the build image: no warning,
  after a list of byte literals became a byte string.
- Planted, each restored: a tracker that takes a UTF-8 continuation byte
  as a boundary failed `each_boundary_in_each_capture_is_clean` and
  `a_ring_cut_at_each_offset_gives_its_bytes_from_a_clean_boundary`; one
  that ends an OSC at its `]` failed those two and
  `a_capture_cut_by_10_s_of_silence_starts_at_the_next_newline`.
- Waits: a ring in a kept shell is T-159's step 1, which waits for
  `podssh serve` (Q32), and T-161 replays it.

# T-302: A notice in the terminal while the far end is silent

**Source:** T-171 (`docs/design.md:915-944`): Mosh shows a line at the top of the screen after
6.5 s with no word from the server.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

When the link goes silent, an interactive session shows nothing until the limit of a dead link:
30 s on the layer, then a line on stderr; 30 to 40 s on the forward road, then the end of the
session. A user cannot tell a slow program from a dead link. And a line on stderr in the middle of
a full-screen program is written into its screen.

## Premise

- Read: the layer's lines, written always: a loss (`crates/podssh-cli/src/layered.rs:414`) and a
  resume (`crates/podssh-cli/src/layered.rs:425`). The heartbeat each 10 s, and a link dead after
  30 s with nothing from the far end (`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:62`,
  `PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:65`). The forward road's checks
  (`docs/design.md:763`).
- Read in Mosh (`docs/design.md:915-944`): the notice comes after 6.5 s with no word from the
  server, or 10 s with no acknowledged state; Mosh draws it over its own model of the screen,
  and removes it when the server answers.
- Read: the client has no model of the screen yet; T-160 (item 1) makes one.
- Inferred: a line written at the cursor of a full-screen program stays in its screen until the
  program draws again.

## Approach

1. The client keeps the time of the last byte from the far end. After 5 s with no byte while keys
   wait for their answer, or after 10 s with no byte at all, the notice shows; it goes when a
   byte comes. This entry sets the times, after a measurement with the `pause` mode of T-203.
2. Where it shows, each after a probe of the terminal: (a) in the window's title, saved first
   with `CSI 22 t` and restored with `CSI 23 t`, where the terminal keeps a stack of titles; (b)
   on the top row, drawn and then repainted from T-160's model, once that model exists; (c) with
   no pty, a line on stderr, as now. Which terminals keep a stack of titles (xterm, VTE, Windows
   Terminal, the Windows console) is not verified: this entry measures them.
3. The text: the seconds since the last word, and the escape that ends the session (`~.`).
4. On a terminal only, never in a pipe; `-q` turns it off. The layer's lines stay when stderr is
   not the terminal.

## Decision

Taken (2026-10-13), the source of the silence: the resumable layer, not
SSH's bytes. The layer hears each byte of the far end, and knows which of
its own records the far end answers at once: `DATA` that it acknowledges
within 200 ms (both named `replay.v1`), a `PING`, and a resume after a loss
(`PodUtils/podssh:crates/podssh-relay/src/session/hearing.rs`). Any byte answers each
question. The alternative, the time since the SSH channel's last bytes,
lost: to a node, SSH sends no keepalive (`docs/design.md`, section 5), so
an idle shell would show the notice, and so would a password's prompt,
which echoes nothing.

Taken: the notice comes when a question has waited 5 s, and counts the
seconds since the far end's last byte. These values were provisional
until the measurement of the Prove, which gave the notice 5.0 s after the
pause began (2026-10-30, through the stand-ins): 5 s is the entry's own
value, a few round trips and the 200 ms of an `ACK`. The entry's "10 s with
no byte at all" lost as a rule of its own: the far end's records come each
10 s in an idle session (the heartbeat, `PING_EVERY`), so a fixed 10 s would
show the notice for a moment in each healthy idle session. The heartbeat's
own `PING`, after 10 s with nothing sent, is a question, so an idle link
that died shows the notice 15 s after the last word at most.

Taken: the title's sequences are XTWINOPS `CSI 22 ; 2 t` and `CSI 23 ; 2 t`
(the window's title alone) and OSC 2 ended by BEL; the text has no control
character and no `;`, at which a model terminal cuts a title. They are
written only where the session's output left the terminal's parser at its
ground state (`crates/podssh-ssh/src/notice/boundary.rs`), and the title
comes back before the far end's next bytes, so that a title that a program
sets then is kept. T-221's tracker of sequences, a draft, may replace that
small parser once it is merged.

Taken: the probe of the stack of titles is what is known of the terminal,
from its environment: xterm (`XTERM_VERSION`) and VTE (`VTE_VERSION`), not
inside tmux or screen, whose bytes go to the multiplexer; and
`PODSSH_TITLE_STACK=yes|no` for another terminal. A query lost: its answer
comes on stdin, which the session's input task reads already, so the
answer would go to the server as keys, or a key would be lost; and xterm
does not answer `CSI 21 t` by default. A title with no stack lost: the
user's title would stay lost. On a terminal not known to keep a stack there
is no notice, and the layer's lines stay as before. Windows Terminal and
the Windows console are not in the list until `scripts/title-stack.py`
measures them (UNVERIFIED); so are xterm and VTE, which the list names from
their documentation.

Taken: while the title shows the notice, the layer's lines of a loss and of
a resume are left out (`layered::folded`): they would be written into the
screen, and the title tells as much. The lines of `-v` stay. With no pty,
the notice is two lines, at its start and when the far end answers again;
a line for each second lost, as it would fill the terminal.

Taken: the roads of the layer: `ssh node://`, its race with
`--iroh-ticket`, `iroh:TICKET` (`podssh_iroh::client::carry_heard`), and
the session after `--upgrade`. `podssh operator` has no terminal of its
own: it is the ProxyCommand of OpenSSH, whose terminal it does not know,
and its lines stay. The forward road lost: there, nothing below SSH
answers a key, and the relay's Pong answers podssh's Ping each 10 s, so a
notice would come 15 s after the last word at the soonest; T-307 is that
road's notice. The top row of item 2 (b) waits for T-160's model of the
screen, which the operator holds behind T-110.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test silent_notice
```

Through the stand-in relay with `pause:AFTER:FOR`, the notice comes after its limit, counts up,
and goes when bytes come back. With the terminal oracle (T-200), the screen after the pause equals
the screen before it, and so does the title. A planted notice written at the cursor fails the
check of the screen.

The run through the stand-ins is ignored, on Linux only, as it needs a pty, Python and openssl
(`cargo test -p podssh-cli --test silent_notice -- --ignored --nocapture`); it uses the stand-in
proxy's `--pause 0:20`, the reverse road's pause, and prints when the notice came and went. The
same checks with no terminal and no stand-in, with a model of the stack of titles beside the
oracle: `cargo test -p podssh-ssh --test silent_notice`. The planted defect: `Facts::place`
that gives `Line` to a terminal in raw mode; in the model, the control
`a_notice_written_at_the_cursor_changes_the_screen` shows the same.

## Correction

The first item of the Premise cites the layer's lines at lines of `next_leg`, which opens a new
leg. The lines are in `line_of`: a loss (`crates/podssh-cli/src/layered.rs:465`) and a resume
(`crates/podssh-cli/src/layered.rs:476`). What the item says of them holds.

## Done

2026-10-13, a draft; merged on 2026-10-30, when the main session built it
and ran each check below.

- `PodUtils/podssh:crates/podssh-relay/src/session/hearing.rs`: the far end's last byte and
  the oldest question that waits, across the links of a session; the pump
  hears each read, and asks with each `PING` and each `DATA` that the peer
  acknowledges; a loss asks too. `Client::with_hearing`, and
  `podssh_iroh::client::carry_heard`.
- `crates/podssh-ssh/src/notice/`: the road's word (`Silence`, in
  `Options`), the place of the notice by the facts of the session, the
  title with its stack and the probe of the stack (`title.rs`), the parser's
  ground state (`boundary.rs`), and the notice itself, which the session's
  pump ticks each second and which takes the title back when it ends.
  `crates/podssh-ssh/src/io.rs` gives it the session's output.
- `crates/podssh-cli/src/layered.rs` (`Shell`, `heard`, `folded`), and the
  roads of `ssh`: `node://`, the race, `iroh:`, `--upgrade`.
- The manual (the note of `ssh`; `PODSSH_TITLE_STACK`, `XTERM_VERSION` and
  `VTE_VERSION` in ENVIRONMENT), `docs/terminal.md` (a section of its own),
  `docs/design.md`, `docs/STATUS.md`; `scripts/title-stack.py`, the
  measurement of a terminal's stack of titles. T-307, the forward road's
  notice, is a new entry.
- Prove: `cargo test -p podssh-ssh --test silent_notice`, 5 passed, and
  `cargo test -p podssh-ssh --lib -- notice`, 5 passed. `podssh-relay`'s
  lib, `hearing` among it, passed in its whole suite. In all, `podssh-ssh`,
  `podssh-relay`, `podssh-cli` and `podssh-iroh` passed 1575 of 1576; the
  one was the note of `ssh`, which wrote `PODSSH_TITLE_STACK=yes`, a word
  that the check of the notes reads as a keyword of `-o`; it says "set to
  yes" now, as the other notes say it, and the lib suite passed, 405.
- The run through the stand-ins on Linux (`cargo test -p podssh-cli --test
  silent_notice -- --ignored --nocapture`) failed as drafted: it pinned
  relay-a.test to the loopback, and since T-318 such a pin goes with no
  proxy, so the client went around the stand-in proxy and its pause, and
  no silence came. It pins no address now, and clears the machine's proxy
  variables, as `crates/podssh-cli/tests/m6_exit.rs` does since T-318.
  Then: the notice came 5.0 s after the pause began ("no word from
  node://lab for 6 s", then "for 7 s"), and the key's answer came after
  20.0 s; it passed. The ignored runs of `attach` and `m6_exit` run in the
  gate's step m6.
- The merge kept `main`'s pump of `crates/podssh-ssh/src/io.rs` (its stop
  of T-185 and its `~C` of T-291) and put the notice's arm into it, and
  `main`'s `Through` (its `command_line` and `expect`) with the field
  `notice`. clippy `-D warnings` on the four crates and rustfmt clean.
- The planted defect, `Facts::place` that gives `Line` to a terminal in
  raw mode: the unit test `a_notice_shows_on_a_terminal_and_nowhere_else`
  failed with it, and passed without it; `--test silent_notice` passed
  with it too, as it drives the model with a place that it chooses.
- The measurement of the terminals: `python3 scripts/title-stack.py` in
  xterm, in VTE, and under WSL in Windows Terminal and in the Windows
  console: UNVERIFIED; it waits for the operator's terminals.
- Waits for T-251: the run in the build image, and clippy at CI's Rust.

# T-303: The latest screen on request: frames that let Ctrl-C show within a round trip

**Source:** T-171 (`docs/design.md:915-944`): Mosh sends the difference of screens at most each
half round trip, so Ctrl-C stops a flood within a round trip (its paper, §2.3).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** partial

## Problem

Under heavy output (a `cat` of a large file, a loop that prints), each byte of the pty crosses the
link in order. Over a slow road, the bytes in buffers and in flight are shown before the output
that follows a Ctrl-C, so the user waits to see the prompt. Mosh sends only the latest screen,
so Ctrl-C shows within a round trip.

## Premise

- Read: the layer and SSH carry each byte in order, and only the end that runs the SSH server
  sees the bytes of the pty in clear (`docs/design.md:906-913`).
- Read: `podssh serve` with a pty is T-110, which the operator holds (Q32); a model of the far
  end's screen is item 3 of T-161, and the client's is item 1 of T-160.
- Read in Mosh's paper (§2, §2.3), as the section of T-171 gives it (`docs/design.md:915-944`):
  a frame at most each half round trip, from 20 to 250 ms, after 8 ms of collection; and frames
  lose the scrollback of the output that they skip (`docs/design.md:948-952`).
- Not measured: how long Ctrl-C takes to show through podssh at 300 ms of latency and a limited
  rate.

## Approach

1. Measure first, with T-203's harness: `-tt` to `podssh serve`, a delay of 300 ms and a rate of
   64 KiB/s, a flood of `yes`, then Ctrl-C: the time until the prompt shows. Write the result;
   build only if it is longer than three round trips.
2. On request only (this entry decides the spelling), with a pty, to `podssh serve`: the server
   keeps a model of the screen (T-161), and sends, in a channel request of podssh's own, the
   difference between the screen that the client last acknowledged and the current one: one
   frame at most each half round trip (20 to 250 ms), after 8 ms of collection.
3. The client applies each frame to its model (T-160), and draws the difference. Keys still go as
   bytes, each one.
4. A frame skips output, which the local scrollback then lacks: the manual says so, and the mode
   is off by default.
5. Mosh as a reference, never a road, where a test host of the operator's has it.

**The donor study (2026-11-18, PodUtils/podssh#317), report 04.** (gedigi/noissh at e0ce50c). Rules for step 2's frames, all from the donor's sender and client loops: (a) a frame carries the number of its state and of its base; the acknowledgement is its own record, not the byte ACK of the layer, which cannot say "I drew state 41". (b) The receiver sets one "ack due" bit when any diff arrives, before it checks the base, so a rejected diff is acknowledged too; it sends at most one ack for each pass of its loop, and none on a timer. (c) A resend is encoded again from the acked state, never replayed from a stored frame; it goes after 1.5 round trips plus 10 ms, not under 30 ms, and frames are gathered for 8 ms first (gedigi/noissh:crates/proto/src/shell.rs and src/server.rs). Faults to design out: the sender keeps a whole screen for each state until an ack, with no cap (gedigi/noissh:crates/proto/src/shell.rs:100-106), so a client that never acks costs memory without bound; keep the acked base and the newest screen, and drop the rest, which makes the next diff a full snapshot. A full snapshot applied regardless of its number (gedigi/noissh:crates/proto/src/shell.rs:184) can move the receiver back to an older state when a datagram passes a delta that took the stream; refuse a snapshot older than the state held. For T-161: noissh's screen mode feeds no scrollback (its CHANGELOG), as T-303 step 4 already says; keep the mode opt-in.

See also the addition of the donor study (report 14) to T-161: the offset log is an alternative to the screen model that this entry sends.

## Decision

2026-11-26, the calls of the draft of step 2 (each with what lost).

1. **The spelling is the flag `--frames` of `podssh ssh`, and nothing else.** As `--predict`: no `-o` keyword
   (`ssh_config` has none, and podssh's `-o` table is OpenSSH's), and no key of the settings file, which holds the
   relay's settings alone (`crates/podssh-cli/src/settings.rs`). Lost: `--screen` and `--latest-screen` (the manual and
   Mosh's paper say frames); a keyword `Frames`, which an `ssh_config` shared with OpenSSH would refuse.
2. **The ask is `env frames@podssh v1` with a reply**, after local echo's ask and before the shell or the command, on a
   channel with a pty; `podssh serve` takes it where it opened the pty, once. Each other server answers FAILURE
   (OpenSSH's sshd for a name outside `AcceptEnv`, an older podssh by its `--accept-env`), and the session carries each
   byte, with one line at the default level, as the user asked for frames by name. A server that takes the name as a
   variable (an sshd with `AcceptEnv *`) answers SUCCESS and sends bytes: the client draws frames only from the
   private code, so those bytes show as they are. Lost: a channel request of a new type (russh's server answers an
   unknown type with FAILURE and gives it to no handler, `vendor/russh/src/server/encrypted.rs`, so serve would need
   a patch of russh, where `env` needs none, and T-160 and T-159 ask the same way); a second channel for the frames (the order of its frames and of
   the first channel's exit status is not defined, and a forward's limit would count it).
3. **A frame rides extended data of the code `0xFE504F46`**, "POF" after 0xFE, in the private range of RFC 4250
   (section 4.4.3, as T-160's Decision read it), beside local echo's `0xFE504F44`. Lost: a channel request from serve,
   the entry's own word: russh's client answers a server's channel request with FAILURE and gives it to no handler
   (T-160's Decision, item 1), so it needs a patch of russh; bytes inside the data stream, which the far end's program
   could write itself, and which a client that did not ask would show.
4. **The acknowledgement is `env frames-ack@podssh NUMBER`, with no reply asked**: its own record (the donor study,
   rule a), the number of the newest state that the client holds, and ` lost` after it when the last frame's base was
   not held. One is due once any frame came, a refused one too, and at most one goes for each pass of the client's loop
   (rule b). Lost: extended data from the client, which serve's reader of a channel gives back to the window unread
   today, and which waits on the channel's window where a request does not; the layer's byte ACK, which cannot say
   which state was drawn, and which `--direct` does not have.
5. **A frame's body is terminal output: what `vt100` writes to turn one screen into another** (`Screen::state_diff`,
   and `state_formatted` for a whole screen), read by a `vt100` model at the client. The header carries the version,
   the flags (whole screen, bell, last), the state's number, the base's number, the rows and columns and the body's
   length (`crates/podssh-ssh/src/frames/wire.rs`). Lost: a codec of cells of podssh's own, as Mosh's: a second
   encoder and decoder to hold to each other, where `vt100`'s difference is its author's and is tested there; and a
   body of text lets a later model change with no change of the wire.
6. **The base is the newest state that the client acknowledged**, as the entry says, though SSH carries each frame in
   order: T-304's datagrams then need no new wire. The far end keeps the base and the last 3 states sent (`HELD`); an
   acknowledgement of a state that is gone moves no base, and a client that lost its base gets the whole screen (the
   donor study's faults: no state for each frame without a cap, and no snapshot applied over a newer state). The
   client keeps its last 8 states. Lost: the difference from the last frame sent, the least code on an ordered stream.
7. **The pace is Mosh's, and a window is added to it**: half the round trip within 20 and 250 ms, 8 ms after the first
   change; the round trip from a frame to its acknowledgement, smoothed by an eighth, and 250 ms before the first
   sample. While 2 frames wait for an acknowledgement (`WINDOW`) no frame goes, until one comes or 2 s pass
   (`PATIENCE`). Lost: the pace alone, as over UDP: on SSH's ordered stream a frame waits behind each one before it,
   so a link slower than the frames would fill as it fills with bytes; the donor's resend after 1.5 round trips, which
   an ordered stream never needs (the patience is what is left of it: a client whose acknowledgements stopped still
   gets the screen).
8. **The last frame is the whole screen, marked, before the exit status**: it shows whatever the client holds, as no
   later frame can repair it. Lost: a difference, which a client with another base would refuse with no second try.
9. **The client draws the difference from what its terminal shows to the newest state, once for the frames of one
   read.** Before the first frame the terminal's lines go up into its scrollback by line feeds. Lost: the alternate
   screen (Mosh's default), which at the end would take the session's last screen away, where a byte session leaves it;
   a plain clear, which erases the user's lines. After a line of podssh's own, the far end's stderr or a new size, the
   next frame draws the whole screen again; lost: asking the terminal for its cursor, whose answer comes among the keys.
   At the end, however the session ended, the modes of the keys go back and the cursor shows.
10. **The far end's model answers the questions that programs wait on**: the device's status and the cursor's place
    (`CSI 5 n`, `CSI 6 n`) and the primary device attributes (`CSI c`), written to the pty. With frames a question never
    reaches the client's terminal. Lost: no answer (fish and each prompt that asks for the cursor wait for their time
    limit); the question passed on to the client, whose answer would come a round trip late, for a cursor that moved.
11. **The window's title and the bell cross; a transfer of ZMODEM and a copy to the clipboard do not**, and the
    manual says so: a frame carries the screen.
12. **Who gets no frames, each said in one line or in the manual**: a shell that is kept (a framed login shell is not
    kept, as with `--share`, and `~d` is refused), `--attach`, a shell shared by name, `--expect`, `--sudo`, `--su`,
    `podssh each` and a control master's client. `--frames` with `--predict` is a usage error (64). Lost for this
    part: frames from a kept shell, whose ring replays bytes, and guesses drawn over frames (Mosh's overlay); both are
    in the Done as what is left.
13. **The model's cost, which the Correction of 2026-11-25 asks to name**: for a channel that asked, and for no
    other, at most 5 screens (the screen now, the base, `HELD` frames), some 60 KiB each at 80 by 24, so about 300 KiB;
    no scrollback is kept. The pty is read at its own pace, so a flood costs serve the processor time of its model
    while it lasts, as it costs mosh-server; a budget of bytes for each frame's time lost, as nothing measured asks.
14. **Shared code first.** Read at the pinned tag `v0.85.0` of PodUtils/podcrates: no crate holds a model of a screen
    or a difference of screens (`pod-term` holds the grammar, the modes and the ring; `pod-testkit`'s `screen` is the
    oracle's `vt100` for tests). The model is the `vt100` crate, podssh-ssh's dependency since T-160. The wire, the
    sender and the receiver do no I/O (`crates/podssh-ssh/src/frames/`), so they can move to podcrates when a sibling
    serves a pty; no ask is filed by this draft, as no second project needs them today.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test frame_rate
```

With a delay of 300 ms and 64 KiB/s, a flood, then Ctrl-C: the prompt shows within three round
trips, and at the end the client's model equals the server's. A planted server that sends each
byte fails the check of the time.

## Start condition

T-110 is done: `podssh serve` has a pty (the operator holds it, Q32); and T-161 has a model of the
far end's screen.

## Correction

2026-11-05. The Start condition's "the operator holds them (Q32)" no longer holds: Q92 (2026-11-03,
`docs/decisions.md`) released the holds, and T-107 to T-112 go by their priority
(`TODO/PROGRESS.md`, "The holds are released"). The Start condition is the list of entries alone.

2026-11-25. T-110 and T-161 are done, and T-161 took no model of the screen on the far end: it would cost 60 KiB a
screen and 2.5 MB for 1,000 lines of scrollback for each kept shell, and the modes, the replay and a redraw gave vi,
less and top their screen (`docs/terminal.md`, "Screen on attach"; `docs/design.md`, section 5). Frames need that
model, so this entry starts when a user asks for frames of the screen (a slow link where the bytes of a flood are too
many), with the model's cost then named in its Decision.

2026-11-26, read before the draft of step 2, on `main` at `0f1f64b`:

- Step 2's "in a channel request of podssh's own" holds for the ask and the acknowledgement, which are `env` requests
  of podssh's own names; the frames ride extended data of a private code, as a request from serve reaches no handler of
  russh's client (the Decision, item 3).
- Step 2's "a model of the screen (T-161)" and step 3's "its model (T-160)": T-161 built no model on the far end (the
  Correction above), and T-160's model is local echo's own. The draft makes one for each end from `vt100`
  (`crates/podssh-ssh/src/frames/screen.rs`), with its cost in the Decision, item 13.
- The Start condition's two parts hold: `podssh serve` has a pty (T-110, done), and the far end's model is this
  entry's own. The Correction above waits for a user who asks for frames: the main session started step 2 on
  2026-11-26 all the same, after step 1 measured 21 round trips against the bar of three.
- The Prove's planted server "that sends each byte" is measured by the control of `frames_e2e` (the same session with
  no `--frames`, which must take longer than three round trips); the plant itself waits for T-251.

## Done

Drafted 2026-11-26: step 1's measure `scripts/feel_interrupt.py`, on the bench of `scripts/feel-matrix.py` (its
throwaway keys, its sshd on a free loopback port) with `scripts/fake-proxy.py --shape link:150:65536:1500000:0:1` in
front of both far ends: `podssh ssh -tt` to `podssh serve --listen 127.0.0.1:PORT --shell /bin/sh`, and OpenSSH's ssh
to its sshd as the reference, each in a local pty, the far end `/bin/sh -i` with a known prompt; `yes` for 3 s, then
0x03, and the time until the prompt shows, 5 runs, in ms and in round trips of 300 ms (JSON on stdout, one line on
stderr). Its `--self-test` checks the link, the figures, the prompt's matcher and the pty driver on this host's
`/bin/sh`, and passed. Run 2026-11-26 on this cloud host, a debug build of `58a21c1`, `python3 scripts/feel_interrupt.py --podssh
target/debug/podssh --runs 3` (fake_shape's `link:150:65536:1500000:0:1`, a flood of `yes` for 3 s, then 0x03): podssh
(`ssh --direct -tt` to `podssh serve --listen`) 6,316 ms median (21.05 round trips; 6,092 to 6,457 ms), with about
360 KB drawn after the Ctrl-C; OpenSSH's `ssh -tt` to its sshd through the same link 18,035 ms (60.12 round trips;
18,034 to 18,406 ms). Each is far over the bar of three round trips (900 ms): step 2 is worth building. The bytes
drawn after the Ctrl-C are those already in the link's queue and the buffers on the way, which only frames of the
screen can skip. Step 2 waits for its parts: the far end's model of the screen (T-161) and `podssh serve`'s pty (T-110).

Drafted 2026-11-26 by a worker, on `main` at `0f1f64b` and rebased onto `9574133` (T-989) with no conflict, not built
and not run: steps 2, 3 and 4. Each result below is
Built and run by the main session (below).

- The frames, with no I/O: `crates/podssh-ssh/src/frames/wire.rs` (the records and the acknowledgement),
  `crates/podssh-ssh/src/frames/screen.rs` (the model, the difference, what a terminal is drawn with, the answers),
  `crates/podssh-ssh/src/frames/sender.rs` (the pace, the bases, the window), `crates/podssh-ssh/src/frames/receiver.rs`
  (the client's states, one draw for each read, the acknowledgement), and their tests beside them, each on one table.
- The far end: `crates/podssh-ssh/src/server/frames.rs` (the pump's sink, the task that sends, the last frame before
  the status), `crates/podssh-ssh/src/server/frames_ask.rs` (the ask and the acknowledgements), and the hooks in
  `crates/podssh-ssh/src/server/handler.rs`, `crates/podssh-ssh/src/server/pty_child.rs` (a framed shell is not kept),
  `crates/podssh-ssh/src/server/pty_grant.rs` (a new size), `crates/podssh-ssh/src/server/channel.rs`,
  `crates/podssh-ssh/src/server/child.rs` and `crates/podssh-ssh/src/server/predict_ask.rs` (no reports beside frames).
- The client: `crates/podssh-ssh/src/frames/mod.rs` (the ask, the answer, the end), `crates/podssh-ssh/src/session.rs`,
  `crates/podssh-ssh/src/io.rs` (the acknowledgement once for each pass, a new size; its waits moved to
  `crates/podssh-ssh/src/io/wait.rs`, as the file stood at 496 lines), `crates/podssh-ssh/src/io/msg.rs` (a frame
  drawn, the far end's stderr), `crates/podssh-ssh/src/options.rs`, `crates/podssh-ssh/src/predict/mod.rs` (the count
  of podssh's own writes, read).
- The command line and the manual: `crates/podssh-cli/src/flags/frames.rs`, `crates/podssh-cli/src/flags.rs`,
  `crates/podssh-cli/src/ssh/args.rs`, `crates/podssh-cli/src/ssh/resolve.rs` (the refusal beside `--predict`, in the
  table of `crates/podssh-cli/src/refuse.rs`), `crates/podssh-cli/src/man/notes_frames.rs`; a row of
  `crates/podssh-cli/tests/words.rs`.
- The documents: `docs/terminal.md` ("The latest screen: frames"), `docs/cli.md`, `docs/design.md`,
  `docs/development.md`, a row of `docs/STATUS.md`; `scripts/feel_interrupt.py` has `--frames` (its `--self-test`
  passed here, as it needs no podssh).

What the main session runs, in this order:

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --lib frames::
cargo test -p podssh-ssh --lib server::frames
cargo test -p podssh-ssh --test frame_rate
cargo test -p podssh-ssh --test serve_predict --test serve_pty --test serve_keep --test serve_share
cargo test -p podssh-cli --lib man
cargo test -p podssh-cli --test words --test flag_table --test man_flag_parity
cargo test -p podssh-cli --test frames_e2e --test predict_e2e
python3 scripts/feel_interrupt.py --frames --runs 3
```

Then `podssh man --llms index > llms.txt; podssh man --llms full > llms-full.txt` (the manual has a new flag and a new
note), `cargo todo remap` of each file that the draft changed (`docs/terminal.md`, `docs/cli.md`, `docs/design.md`,
`docs/development.md`, `docs/STATUS.md`, and the sources named above), rustfmt and the gate's clippy. A test of the
draft that fails may have found a defect that the worker could not see, as nothing here was compiled.

Left, in order: (a) measured (below); (b) frames from a kept shell and from a shell shared by name, each of which sends bytes today
(T-159, T-837); (c) local echo's guesses drawn over frames, as Mosh's overlay, in place of the usage error; (d) the
scrollback: a frame's lines that left the top of the screen could go to the terminal before the frame, which no part
of this draft does; (e) `podssh session capture` and `--record` of a framed session record what was drawn, not the
far end's bytes; (f) step 5, Mosh as a reference on a host of the operator's that has it; (g) the plant of the Prove,
with T-251; (h) a control master's client and `podssh each`, which carry each byte.

Merged 2026-11-26 and built: `cargo test --locked -p podssh-ssh -p podssh-cli --no-fail-fast` 313 binaries passed,
`frame_rate` and `frames_e2e` among them, once the tables of `frames::screen`'s tests kept the window's title of a
base whose next screen set none (a terminal has no sequence that takes a title away; one stream never goes from a title
to none, which two screens of the table can); clippy clean, also for `x86_64-pc-windows-gnu`; `llms-full.txt` made
again. Measured the same day on this cloud host, `python3 scripts/feel_interrupt.py --frames --podssh
target/debug/podssh --runs 3` (300 ms, 64 KiB/s, a flood of `yes`, then Ctrl-C): with `--frames` the prompt shows after
533 ms median (1.78 round trips; 436 to 789 ms), 11.6 times sooner than podssh's byte stream (6,181 ms, 20.6) and
under the bar of three round trips; OpenSSH 18,494 ms (61.65); `--frames` to OpenSSH's sshd is refused and keeps the
bytes (6,290 ms, one run). The window of 2 and the patience of 2 s stand. Left: (b) to (h) above.


# T-304: Keys and screen frames as QUIC datagrams on the iroh road

**Source:** T-171 (`docs/design.md:915-944`): each datagram of Mosh is an idempotent difference
from a numbered state, so a lost one costs only itself (its paper, §2.2).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** L
**Status:** open

## Problem

On the iroh road with UDP, a session is one QUIC stream: a lost packet holds each later byte of
the stream until it comes again. With frames of the screen (T-303), a lost frame need not come
again: the next frame replaces it.

## Premise

- Read: a session on the iroh road is a bidirectional QUIC stream, after a UDP probe
  (`docs/design.md`, section 7; T-162).
- Not verified: whether iroh 1.3 lets its user send QUIC datagrams (RFC 9221).
- Read: the fault harness shapes the TCP stream of the stand-in relay (T-203), where a loss is
  only a delay; no stand-in drops datagrams.
- Read in Mosh's paper (§4), as the section of T-171 gives it (`docs/design.md:960-967`): with 29 %
  loss each way, a mean response of 0.329 s for Mosh and 16.8 s for SSH over TCP. QUIC recovers a
  loss in another way than TCP; not measured.

## Approach

1. A stand-in UDP forwarder on the loopback that drops a seeded share of datagrams (2 %, 10 % and
   29 %), between two iroh endpoints with direct UDP.
2. Measure first: `-tt` with the frames of T-303 over the QUIC stream, and the time from each key
   to its echo. Build only if the p95 at 2 % loss is longer than three round trips.
3. Each frame as one datagram: the numbers of its source and target screens, then the
   difference; the keys as the input since the last acknowledged key; an acknowledgement in each
   datagram. A lost or repeated datagram changes nothing.
4. A frame larger than a datagram goes on the stream, as each other byte of SSH does.
5. The datagrams are inside the iroh connection, whose keys both ends proved (T-163); whether they
   also go through the Noise channel of T-088, or carry a MAC of their own, this entry decides.
6. Only when both ends name it in the layer's features, after the UDP probe.

**The donor study (2026-11-18, PodUtils/podssh#317), report 20.** (hashicorp/yamux at its pinned commit). Each session is its own QUIC stream with a lane by priority (`docs/design.md:1643-1651`), so no multiplexer of podssh's own owns a per-lane window, and yamux's credit rule (hashicorp/yamux:stream.go, the update at a half window) is not needed. If this entry puts screen frames and keys beside the session's bytes on one stream, three rules of yamux are the checks: a frame longer than what was advertised ends the session, with its own reason code (not a reset of one lane); the end of a lane is ordered behind its queued bytes; and a keepalive reply is written on a path that does not queue behind data, with the miss reported as a write stall (the 60 s bound of T-598) and not as a dead peer. Datagrams, as this entry plans them, need none of these. Revisit if a second ask for several lanes in one stream comes: it is an ask of podcrates (`pod-session`), not code of podssh.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-iroh --features test-relay --test datagram_frames
```

Through the lossy forwarder at 10 %, each key echoes, the last screens are equal, and the p95 of a
key's echo is below the stream's. A planted receiver that applies a difference to the wrong source
screen fails it.

## Start condition

T-303 is done: frames of the screen exist.

## Correction

2026-11-05. The code of this entry (`podssh-iroh`) goes to `pod-iroh` of PodUtils/podcrates (T-684;
the waves are in Q101 of `docs/decisions.md`, and the module map is
`PodUtils/podcrates:docs/design.md`). Rule Q3 (`docs/decisions.md`, "The crates of
PodUtils/podcrates") applies: from the import podssh makes fixes only, and once podssh takes the
crate the work is done in PodUtils/podcrates, which podssh takes by the next tag; a test of the
moved code then runs there.

# T-305: Roam at once: a new link beside a silent one

**Source:** T-171 (`docs/design.md:915-944`): Mosh's server follows the newest authentic datagram,
and its client takes a new source port after 10 s with no round trip.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

When the client's address changes, its TCP link through the proxy and the relay often goes silent
with no error. The layer finds the link dead after 30 s with nothing from the far end, and only
then resumes over a new one. For those 30 s, an interactive session shows nothing.

## Premise

- Read: a link with nothing from the far end for 30 s is dead
  (`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:65`; `docs/design.md:1059-1067`).
- Read: a resume can come while the far end still runs the old link; the old link stops, and the
  new one goes on (`docs/design.md:1073-1075`). The far end lets the newest resume take a session
  (`docs/design.md:1149-1151`).
- Measured (T-156): a session on the layer and on the iroh road survives a new address of its
  client (`crates/podssh-cli/tests/m6_exit.rs:272`); the time that the resume took is not in the
  record.
- Read in Mosh (`docs/design.md:915-944`): its client tries a new source port after 10 s with no
  round trip, and its server follows each newer authentic datagram at once.

## Approach

1. Measure first: with the `--move` of the stand-in proxy, the time from the move to "the session
   resumed", on the layer over the reverse road and on the iroh road, 5 runs each.
2. A spare link: when a link has had nothing from the far end for 3 s while bytes wait for their
   acknowledgement, or for two heartbeats, the client opens a new link beside it. When the old
   link's bytes come first, the new link closes before its handshake ends; else the new link's
   resume takes the session, as now. One spare link at a time, and one each 10 s at most.
3. `-v` says each spare link, and which link went on.

## Decision

Taken (2026-10-13), what makes a link silent: the client's hearing of
T-302 (`PodUtils/podssh:crates/podssh-relay/src/session/hearing.rs`), across the session's
links. A question of the client, `DATA` that the far end acknowledges
within 200 ms or a `PING`, that waited 3 s with nothing from the far end;
or, where both ends run the heartbeat, nothing at all for 20 s, two of its
intervals. A link with no heartbeat that is idle stays as it is: its quiet
says nothing. The values (3 s, 20 s, one spare each 10 s) are the entry's;
the measurement of item 1 (`crates/podssh-cli/tests/roam_at_once.rs`, the
tests that measure) found a resume 3.0 to 3.2 s after a new address with
them, and they stand.

Taken: a spare link is a link beside the old one, as a move's is
(`PodUtils/podssh:crates/podssh-relay/src/session/beside.rs`): the caller gets
`End::Moving`, so it opens a new link with no wait for the old one's end;
the client reads the new link's `GREETING` and sends nothing. When the old
link's bytes come first, the new link closes, and its far end, which waits
for `OPEN`, dials no target. When the new link greets first, the old link
stops with no `RETIRE`, as it carries nothing, and the new link's resume
takes the offsets, as after a loss; the far end lets the newest resume win
(T-270). One watch beside each link serves the move and the spare, so one
new link at a time; a move that fails is not tried again on that link, but
the spare goes on, where the move's watch ended before.

Taken: a spare that takes the session says one line for the loss and one
for the resume, as a resume after a loss does ("the link said nothing for
N s, and a spare link answered; resuming the session"), so a user, and the
check of M6's exit, still see one of each for each loss. `-v` says each
spare link, and each that closes, with why. The alternative, a line of its
own for a spare that takes the session, lost: a loss would then say two
things by the road it took.

Taken: spare links are off in the library's default `Settings`, and on in
podssh's commands; `PODSSH_SPARE_LINKS=no` turns them off, for a link that
the user pays by the byte, for the measurement before the change, and for
the Prove's planted client. On in the library lost: the tests of the layer
count the links that they give, and a host under load can hold an `ACK`
3 s in a transfer of 32 MiB, which would open a spare and take a link of
theirs.

Taken, a limit: the caller of `podssh ssh node://` keeps the operator's leg
of the newest link, and a spare that closes leaves its own leg there, as a
move that fails does. At the next loss, the old leg's close is then not
read; a stopped or expired pair is found by the refusal of the next leg
(401 to 410), and the session still ends with its reason.

Taken at the merge (2026-10-30): the old link's reads wake the watch of a
spare at once (`Hearing::spoke_after`, a count of the reads and a `Notify`),
during the spare's connect too, and when both came the old link goes on.
The draft's look each 250 ms at the instant of the far end's last bytes
lost: a spare that greeted between two looks took a link that had spoken,
and on a paused clock two reads at one instant looked like none.

Taken at the merge, after item 1's measurement: no spare link on the iroh
road (`iroh_settings` of `crates/podssh-cli/src/layered.rs`, for `ssh`,
`pipe` and `chat` over iroh). With no spare link, its QUIC carried the
session across the move with no resume of the layer in 5 runs of 5; with
spare links, 3 runs of 5 resumed the layer, 15.8 to 20.2 s after the move,
as a spare there is a stream of the same connection and comes no sooner
than the old one. Spare links on each road lost: a resume that buys nothing
costs its handshake and the bytes sent again. The race of the two roads
(T-164) keeps them, as its spare races both roads again and the pair's road
can answer where the iroh road is silent; that is not measured.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test roam_at_once -- --ignored
```

After a `--move`, the session resumes within 10 s, where item 1 measured the time before the
change; and a link that stalls for 5 s and recovers keeps the session with no resume. A planted
client with no spare link takes 30 s, and fails.

The planted client is the test run with `PODSSH_SPARE_LINKS=no` in its environment. The same
checks in the library, on a paused clock, with the control of no spare link:
`cargo test -p podssh-relay --test session_spare`. Item 1's measurement:
`cargo test -p podssh-cli --test roam_at_once -- --ignored --test-threads 1 --nocapture measure`;
with `--features iroh-test`, the iroh road's check that a new address opens no spare link.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_spare` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_spare` there.

## Done

2026-10-13, a draft; merged on 2026-10-30, when the main session built it
and ran each check below.

- `PodUtils/podssh:crates/podssh-relay/src/session/beside.rs`: the watch beside a link,
  for a move and a spare; `resume.rs` runs it, says its steps as they come
  (`Note::Spare`, `Note::SpareClosed`), stops the old link of a spare with
  no `RETIRE`, and resumes on the spare. `Settings::spare_links`; the
  hearing's `quiet` and `heard_at`, and the mark of its reads with the wait
  for the next ones (`words`, `spoke_after`).
- `crates/podssh-cli/src/layered.rs`: spare links on, but with
  `PODSSH_SPARE_LINKS=no`, and off on the iroh road (`iroh_settings`, the
  Decision); the lines of `-v`. The manual (the note of
  `ssh`, ENVIRONMENT), `docs/design.md` (section 5, with the measurement),
  `docs/cli.md`, `docs/STATUS.md`.
- `crates/podssh-cli/tests/stand_harness/`: the stand-ins of `m6_exit.rs`
  as a harness, with the time of each line after the fault, which
  `tests/silent_notice.rs` of T-302 uses too.
- The merge repaired four things. The draft's spare looked each 250 ms
  whether the old link had spoken, by the instant of the far end's last
  bytes: `session_spare`'s test of a link that speaks again failed, as the
  session ended between two looks, and a spare that greeted between two
  looks would take a link that had spoken. Each read now wakes the wait, by
  a count of the reads that two reads at one instant of a paused clock
  still tell apart, while the spare connects too, and when both came the
  old link goes on (the Decision). The harness pinned relay-a.test to the
  loopback, a pin that since T-318 goes around the proxy and its fault: it
  pins nothing now, and clears the machine's proxy variables, as
  `m6_exit.rs` does. And T-302's run on the harness typed its key at once
  after the start file, which the stand-in proxy reads each 50 ms: once in
  its first two runs the key passed before the pause, and the notice timed
  a later heartbeat (it came at 16 s); `Stand::start_faults` now waits for
  each proxy's word that the clock of its faults runs. And a spare that
  greeted, then failed in its handshake after the old link had stopped,
  said the loss twice, and "the link goes on" of a link that had stopped:
  the next link is now tried at once, with no second loss (`after_stop` of
  `resume.rs`), which a fourth test of `session_spare` holds.
- Prove: `cargo test -p podssh-relay --test session_spare`, 4 passed on a
  paused clock, with the control of no spare link. `cargo test -p
  podssh-cli --test roam_at_once -- --ignored --test-threads 1`, 3 passed:
  the session resumed 3.1 s after the move, and the stall of 5 s kept it
  with no resume. The planted client, `PODSSH_SPARE_LINKS=no` in the run's
  environment: the first check failed, the session resumed 35.1 s after the
  move.
- Item 1, the time from the move to "the session resumed", 5 runs each: on
  the pair's road, with no spare link 35.1, 35.0, 35.1, 35.1 and 35.0 s,
  with one 3.2, 3.2, 3.2, 3.2 and 3.0 s. On the iroh road, with no spare
  link, no resume of the layer in 5 runs of 5, as QUIC carried the session
  across the move; with spare links, 20.2 s, 15.8 s, none, 20.2 s and
  none. So the iroh road opens no spare link (the Decision), and its test
  checks that: `cargo test -p podssh-cli --features iroh-test --test
  roam_at_once -- --ignored on_the_iroh_road`, 3 runs, passed, with no
  resume of the layer; planted, an iroh road with spare links failed it at
  its first run.
- The tests that the change touches: `podssh-relay`'s whole suite, 186
  passed, 0 failed, 2 ignored (`session_move`, `session_resume`,
  `session_end` and `session_newest` among them, and the lib's two of the
  hearing). `podssh-cli`'s whole suite, 990 passed, 0 failed, 39 ignored,
  once the note of `ssh` said "set to no": it wrote
  `PODSSH_SPARE_LINKS=no`, which the check of the notes reads as a keyword
  of `-o`, as at T-302. `cargo test -p podssh-cli --test m6_exit --
  --ignored --test-threads 1`: 7 passed, a new address in 19 s, a stall of
  3 minutes in 198 s and a stopped relay host in 21 s, each with exit 0,
  and the three controls of the forward road with 255. T-302's run on the
  harness, `--test silent_notice -- --ignored`, 3 of 3 passed: the notice
  came 5.9 s after the pause began, and the key's answer at 20.0 s. clippy
  `-D warnings` on `podssh-relay` and `podssh-cli`, and rustfmt, clean.
- Planted: a hearing whose reads wake no wait (`heard` with no
  `notify_waiters`) failed the lib's
  `a_wait_for_the_next_bytes_ends_when_they_come_at_the_same_instant`, and
  passed without it; the draft's look each 250 ms failed
  `a_link_that_speaks_again_first_keeps_the_session_and_the_spare_closes`;
  the draft's steps after a spare's failed handshake failed
  `a_spare_that_greets_and_fails_its_handshake_gives_way_and_the_loss_is_said_once`
  with two losses, and it passed without them.
- Waits for T-251: the run in the build image, and clippy at CI's Rust.

# T-306: A resume deadline that the user sets, for a host that sleeps

**Source:** T-171 (`docs/design.md:915-944`): Mosh's server keeps a session until its client comes
back, with no limit by default (`MOSH_SERVER_NETWORK_TMOUT`).
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A laptop that sleeps for a night loses each of its sessions on the layer: the far end forgets a
session 10 minutes after its link was lost. A session of Mosh waits.

## Premise

- Read: the deadline is 10 minutes at both ends (`PodUtils/podssh:crates/podssh-relay/src/session/resume.rs:44`;
  `docs/design.md:1068-1078`). T-153's Decision kept a deadline, as a node in a cage would keep
  connections for clients that never come back.
- Read: a node keeps 64 MiB of replay buffers at most, a whole buffer for each session that it
  keeps (`docs/design.md:1259-1262`); a pair expires after 72 h at most
  (`docs/design.md:1180-1182`).
- Read: the client measures the deadline with `Instant`
  (`PodUtils/podssh:crates/podssh-relay/src/session/resume.rs:332`). Not verified: whether `Instant` counts the
  time that the host slept, on Linux, macOS and Windows. If it does not, a client that wakes
  counts too little, and tries to resume a session that the far end forgot; it then gets
  `REFUSE` with the code 1.
- Read: the features of the layer are names only (`docs/design.md:983`, the section of T-151), so a
  limit needs a new feature or a new record.

## Approach

1. The far end's limit: a flag of `podssh node` (this entry decides the spelling), 10 minutes by
   default, the pair's expiry at most. The far end tells the client its limit, in a way that this
   entry decides; a side that does not know the way keeps 10 minutes.
2. The client asks for no more than the far end's limit; a flag of its own can only shorten it.
3. The node's bound on memory stays: a session kept longer keeps its buffer longer, and a session
   past the bound is refused, as now (`REFUSE` with the code 6).
4. After a `REFUSE` with the code 1, the client says that the far end forgot the session, and how
   long the client was away by the wall clock.

## Decision

Taken (2026-10-13), the way the far end tells its limit: one more feature
name in its `GREETING`, `deadline.SECONDS`, which only a far end gives. A
side ignores each name that it does not know, so an older client keeps 10
minutes, and an older far end names none, so a new client keeps 10 minutes
too. The alternatives lost: a new record after `ACCEPT`, which an older
client refuses at its type byte
(`PodUtils/podssh:crates/podssh-relay/src/session/decode.rs:85`), and which so needs a
feature to gate it as well; a field after the body of `ACCEPT`, which an
older decoder refuses as bytes after the end of a body
(`PodUtils/podssh:crates/podssh-relay/src/session/decode.rs:235-241`). A name for each value
is not a feature that both sides name, so `deadline::of` reads the far
end's own names, not the common ones.

Taken: the spelling `--resume-deadline TIME`, on `podssh node` for the far
end, and on `podssh ssh` and `podssh operator` for the client's own, which
only shortens the far end's. TIME is a whole number, then `s`, `m`, `h` or
`d` (none is seconds), from 1 minute (a silent link is found dead after
30 s) to 72 h, the longest life of a pair, at whose expiry the relay ends
each of its sessions; the iroh road, with no pair, has the same bound, for
the node's memory. `--keep-for` and `--linger` lost: they do not say what
is kept, nor that the client's flag is the same time. An `-o` keyword lost:
OpenSSH has none, and a node has no `-o`. A variable alone lost: the entry
asks for a flag. `--plain` and `--temporary` refuse it (64): a plain node
keeps no session, and the temporary node keeps the defaults of `ssh
--upgrade`.

Taken: the two deadlines are set for the process (`layered::settings`), as
the pins of `--relay-addr` and the rate of `cp --limit` are, since one
process runs one command. Passing them through each function that carries a
session lost: five signatures on two roads, each touched for one value.

Taken: the client counts its wait on the monotonic clock, as before, and
the wall clock only says how long it was away. Rust's `Instant` does not say
whether a sleep counts (`rust-lang/rust:library/std/src/time.rs`, lines
56-57 at the toolchain 1.98); it reads `CLOCK_MONOTONIC` on Linux and
`CLOCK_UPTIME_RAW` on macOS, which do not count a sleep, and
`QueryPerformanceCounter` on Windows (lines 114-119 there). The alternative,
to give up by the wall clock, lost: a wall clock set forward by NTP would
end a session that the far end still keeps; a resume after a sleep costs
one link, and its refusal now says why. Each far end names its deadline, 10
minutes too, so `-v` says it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_deadline
```

On a paused clock: with a limit of 3 h, a session resumes after 2 h, and is refused after 4 h with
the line of item 4. A planted far end that ignores its limit fails the first check.

The planted defects: `Keeper::idle` that keeps a lost session
`RESUME_DEADLINE` in place of its own deadline fails the first check (the
far end forgets the session at 10 minutes, and the resume after 2 h gets
`REFUSE`); `deadline::of` that reads no name fails it too (the client waits
10 minutes); a client that gives the far end's refusal alone, with no words
of item 4, fails the second.

## Correction

Item 3 of the Approach says that a session past the node's bound is refused
with `REFUSE` (6). Read: the far end accepts the handshake, then ends the
session with a `CLOSE` that gives the reason ("this node keeps as many
resumable sessions as its budget allows",
`PodUtils/podssh:crates/podssh-relay/src/session/far.rs:269-279`, whose words since T-586 name what holds the
budget); code 6 is not sent. The bound and its words stay as they are.

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_deadline` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_deadline` there.

## Done

2026-10-13, a draft; merged on 2026-10-30, when the main session built it
and ran each check below.

- `PodUtils/podssh:crates/podssh-relay/src/session/deadline.rs`: the name
  `deadline.SECONDS`, its reading (72 h at most; a name that is not a number
  is ignored), the far end's names, the client's wait, and the words of item
  4. `Settings` has `client_deadline` and `wall_clock`; `Established` has
  `peer_deadline`; the far end's `GREETING` names its deadline; the client
  waits `client_wait`, and after `REFUSE` (1) says that the far end forgot
  the session, how long the far end keeps one, and how long this side was
  away by the wall clock. `Keeper::expire_at`, for a far end whose clock ran
  on.
- `podssh node --resume-deadline TIME`, and the client's own on `ssh` and
  `operator` (`crates/podssh-cli/src/node_flags.rs`, with the key flags
  moved there from `node.rs`, which had 500 lines; `layered.rs`). At the
  merge, `main` held the arguments of `node` in
  `crates/podssh-cli/src/node_args.rs` (T-121), so the field
  `resume_deadline` went there, read in `NodeArgs::from_matches`; and the
  check of the client's own deadline went before the snippets of `podssh
  ssh` (T-187). The
  node's first line says the time; `-v` of a client says the far end's.
- The manual (`notes_pair.rs`, `notes_ssh.rs`, the flag rows),
  `docs/cli.md`, `docs/design.md` (section 5), `docs/reverse.md`,
  `docs/STATUS.md`.
- Prove: `cargo test -p podssh-relay --test session_deadline`: 4 passed
  (3 on a paused clock). The tests that the change touches passed in whole
  suites: `podssh-relay` 181 passed, 0 failed, 2 ignored (`session_resume`,
  `session_move`, `session_handshake` and `session_heartbeat` among them),
  and `podssh-cli` 988 passed, 0 failed, 35 ignored (`node`, `node_plain`,
  `roost` and the lib's `layered` among them). clippy `-D warnings` and
  rustfmt clean.
- The planted defects, each run: `Keeper::idle` with `RESUME_DEADLINE` in
  place of its own failed `a_far_end_that_keeps_3_h_lets_its_client_resume_after_2_h`;
  `deadline::of` that reads no name failed it, and the three others; the
  refusal alone, with no words of item 4, failed
  `a_client_whose_clock_stood_still_is_refused_and_says_how_long_it_was_away`.
  Each passed again without its plant.
- Waits for T-251: the run in the build image, clippy at CI's Rust, and a
  node with `8h` on the live relay through a client whose host sleeps.

# T-307: A notice of silence on the forward road

**Source:** T-302's Decision: the notice of a silent far end runs on the roads of the resumable
layer only.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

On the forward road (`podssh ssh HOST` through the relay, or `--direct`), a link that goes silent
shows nothing until the WebSocket's checks find it dead, 30 to 40 s later, and the session ends.
A user cannot tell a slow program from a dead link there either, and the notice of T-302 does not
show on that road.

## Premise

- Read: the relay's session pings each 10 s, and a link with no frame for three intervals is dead
  (`crates/podssh-ws/src/client.rs:38-43`); the relay stream of the SSH client runs that check
  (`crates/podssh-ssh/src/relay_stream.rs:243`).
- Read: on that road nothing below SSH answers a key: the relay copies the bytes to the target's
  TCP connection. A Ping of podssh's, which the relay answers with a Pong, is the one question
  that the road asks.
- Read: the notice takes any road's word on the far end's silence (`Silence::attach`,
  `crates/podssh-ssh/src/notice/mod.rs`), and shows it in the window's title (T-302).
- Not measured: how soon the relay's Pong comes, and how often the relay's own keepalive comes
  (25 s, read in the relay's document).

## Approach

1. Measure first, with the stand-in relay's `pause:AFTER:FOR` on the forward road: the time from
   a pause to the WebSocket's end, with and without `ServerAliveInterval`.
2. The relay stream tells the silence: the time of the last frame from the relay, and a Ping of
   podssh's that waits for its Pong, as a question; with `ServerAliveInterval`, SSH's keepalive,
   which asks for a reply, as a question too. `--direct` has SSH's keepalive alone.
3. The forward road attaches it to the session's `Options::silence`; the notice and its places
   are T-302's.

## Decision

2026-10-30. The question on the forward road through the relay is a
WebSocket Ping of podssh's, sent after SSH's bytes up while no question
waits, so at most one waits at a time, each answered within a round trip;
any frame of the relay answers it, a Pong or the target's bytes, as the
layer counts any byte of the far end (T-302). The alternatives that lost:
SSH's bytes alone as the question, which a program that echoes nothing (a
password's prompt) leaves unanswered, and which the plant below shows as a
false notice; and the relay stream's own pings each 10 s, after which a key
could wait 10 s before its question is asked, past the notice's 5 s. The
`--direct` part of the Approach's item 2 goes to a new entry, T-332: there
the one question below SSH is SSH's own keepalive, which russh asks inside
the encrypted stream, and russh's `Handle::send_ping` (a keepalive that
waits for its reply) makes that one a change of podssh-ssh's session loop,
not of a road.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test silent_notice -- --ignored
```

Through the stand-in relay's forward road with `pause:0:20`, the notice comes, counts up and
goes before the key's answer, and the screen and the title are the ones before the pause. A
planted relay stream that tells no silence fails it.

## Correction

2026-10-30. The stand-in relay's `pause:AFTER:FOR` starts its clock at the
upgrade, before the session is ready, so a key cannot be sure to wait in
it. The test holds the bytes in the client's stand-in proxy instead
(`fake-proxy.py --pause 0:20`), whose clock starts when the test says so
(`--start-file`), as T-302's test does: the same stall that ends, both
ways, on the same link.

## Done

2026-10-30.

- `crates/podssh-ws/src/session.rs`: the session keeps when its last frame
  of any kind came (`last_heard`), beside the count of frames.
- `crates/podssh-ssh/src/relay_stream.rs`: the status asks with a Ping
  (`ASK`) after SSH's bytes up while no question waits, and tells the
  silence (`RelayStatus::silent`): once a question waited the wait, the
  time since the relay's last frame; any frame answers it.
- `crates/podssh-cli/src/ssh/transport.rs`: the forward road attaches it to
  the session's `Options::silence`, with the layer's wait of 5 s
  (`SILENCE_WAIT`); the notice and its places are T-302's.
- `cargo test -p podssh-ssh --lib relay_stream`: 5 passed, of them the
  relay's silence: a key and its Ping, no second Ping while one waits, the
  silence once the question waited 300 ms, counted from the last frame, a
  Pong that answers it, and the target's bytes that answer the next; and
  the burst of 1 MiB, its bytes in order with one Ping. Planted, no Ping:
  both failed; a question that no frame answers: the silence's test
  failed; each passed again without its plant.
- `cargo test -p podssh-cli --test silent_notice -- --ignored`, through the
  stand-in relay and a proxy that holds each byte both ways: on the
  forward road with a pause of 20 s, the notice came 6.0 s after the pause
  began, counted up, and went before the key's answer at 20.0 s, the
  screen and the title as before the pause (T-302's test, which shares its
  body, came at 5.9 s); with `sink`, which echoes nothing, a key each
  second for 12 s gave no notice; and the measure of item 1: a pause of
  90 s ended a forward session 40.0 s after it began (nothing from the
  relay for 30 s, the pings unanswered), and 12.0 s after with
  `ServerAliveInterval=4` and `ServerAliveCountMax=2` ("the server stopped
  answering keepalives"). Planted, a relay stream that tells no silence:
  the forward notice failed; no Ping with the keys: the test of `sink`
  failed with a notice; each passed again without its plant.
- `docs/terminal.md` ("A notice while the far end is silent"), the manual's
  note of the notice (`podssh man ssh`), `docs/STATUS.md`.
- The four ignored tests together: 4 passed (the notice 6.0 s after the
  pause on each road). `cargo test -p podssh-ws -p podssh-ssh`: 511 passed,
  0 failed, in 42 binaries; the manual's tests 28, and its lib tests 35;
  clippy `-D warnings` on podssh-ws, podssh-ssh and podssh-cli: clean.

# T-332: A notice of silence with `--direct`

**Source:** T-307's Decision (2026-10-30): the forward road's notice runs
through the relay only.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

With `--direct`, a link that goes silent shows nothing until SSH's
keepalives give up (3 times `ServerAliveInterval`, 180 s by default), or the
kernel's TCP gives up. The notice of T-302 and T-307 does not show there.

## Premise

- Read: on the direct road, nothing below SSH answers a key; the bytes are
  SSH's own, end to end, so the only question that the road can ask is one
  of SSH's.
- Read: russh's `Handle::send_ping` sends `keepalive@openssh.com` with a
  reply asked for, and waits for the reply (vendor/russh/src/client/mod.rs,
  "Send a keepalive/ping package to the remote peer, and wait for the
  reply/pong"); a server that does not know the request answers with a
  failure, which is a reply too (RFC 4254, section 4).
- Read: the notice takes any road's word on the far end's silence
  (`Silence::attach`, `crates/podssh-ssh/src/notice/mod.rs`).

## Approach

1. In podssh-ssh's session, with a key from the terminal while no question
   waits, a task calls `send_ping` and marks the question; its reply, or
   any byte of a channel, answers it. The silence counts from the server's
   last packet.
2. Attach it on the direct road, where no road below SSH tells the silence;
   through a `-J` hop, on the target's own session (the Decision).

## Decision

2026-10-30.

- **The question goes on the target's own session, through a `-J` hop.**
  The notice names the target, and the keys go to it: a hop that answers
  while the target is silent is still silence for the keys. The question
  on the first hop's connection lost: it would miss a silent target behind
  a live hop, and the target's keepalive goes through the hop anyway.
- **The question is in the session's own loop, not a task.** The pump
  holds `send_ping`'s future beside the channel's messages, so the question
  ends with the session; a task would need a handle of its own, and could
  outlive the session that it asks for.
- **A slot of the session's own, beside the road's** (`Silence::attach_own`).
  A road that tells the silence (the relay, the layer) keeps its word, and
  the session then asks nothing, as the road's question already goes with
  each key. One slot for both lost: the session's question would replace
  the road's word, which also hears the road's own frames.
- **Any reply answers.** A server that knows no `keepalive@openssh.com`
  answers with a failure, which russh resolves as it does a success; the
  server is there. Keys that nothing echoes are then no silence.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test silent_notice -- --ignored
```

With `--direct` through the stand-in proxy's `--pause 0:20`, the notice
comes, counts up and goes before the key's answer; with `sink`, keys that
nothing echoes give no notice. Planted, a key with no `send_ping`: the test
of `sink` fails.

## Done

2026-10-30.

- `crates/podssh-ssh/src/notice/asked.rs`: the server's last word and the
  question that waits (`Asked`): a key asks while none waits, a reply or a
  channel's message answers, and once a question waited 5 s (`WAIT`, the
  layer's and the relay's), the silence counts from the last word.
- `crates/podssh-ssh/src/notice/mod.rs`: the session's own slot
  (`attach_own`) beside the road's (`told_by_road`); the road's word comes
  first.
- `crates/podssh-ssh/src/io.rs` and `io/msg.rs` (the channel's messages,
  moved out to keep the file under 500 lines): with a key, while no
  question waits, `Handle::send_ping`; its reply, or any channel message,
  answers it. `crates/podssh-ssh/src/session.rs` attaches the question
  where no road told the silence.
- `cargo test -p podssh-ssh`: 298 passed, the new test of `Asked` among
  them (its wait, a second key while one waits, the silence from the last
  word, an answer and the next question).
- `cargo test -p podssh-cli --test silent_notice -- --ignored`: 6 passed.
  With `--direct` through a proxy that holds each byte both ways for 20 s
  (`fake-proxy.py --pause 0:20`, the harness's `direct()` to `target.test`),
  the notice came 6.0 s after the pause began ("no word from target.test
  for 8 s", then 9 s) and went before the key's answer at 20.1 s; with
  `sink`, a key each second for 12 s gave no notice. Planted, a key with
  no `send_ping`: the test of `sink` failed with a notice; a session that
  attaches no question of its own: the pause's test failed with none; each
  passed again without its plant.
- Against software that podssh did not write, on this host: OpenSSH 9.6p1
  and Dropbear 2022.83, each on 127.0.0.1 with a throwaway user and key,
  `podssh ssh --direct -t` in a pty. Keys to `stty -echo; cat >/dev/null`,
  one each second for 12 s: no notice from either. Through the stand-in
  proxy's pause of 20 s: the notice came 6.0 s into the pause and went
  before the echo, at 20.1 s (OpenSSH) and 20.0 s (Dropbear). The user,
  the keys and the servers were removed after.
- clippy `-D warnings` on podssh-ssh and podssh-cli, all targets: clean.
- `docs/terminal.md` ("A notice while the far end is silent"), the
  manual's note of the notice (`podssh man ssh`), `docs/STATUS.md`.
- A repair after the close, found in review (2026-10-30): a keepalive
  that still waited for its reply kept the next key from asking, so a
  link that died after the far end's bytes answered one question, and
  before the keepalive's reply, showed no notice again. Each key now marks
  its question, and a keepalive goes only when none waits; the waiting one
  asks the new question too (`Asked::key`). `cargo test -p podssh-ssh --lib
  notice::asked`: 2 passed; planted, the old order of the test, so that a
  waiting keepalive marks no question: the new test failed, and passed
  again without it. The two `--direct` tests of `silent_notice` passed
  again: the notice came 5.9 s into the pause and went before the key's
  answer at 20.1 s; keys that nothing echoes gave none.

# T-335: The iroh cells of the throughput run may not cross a relay

**Source:** the study of stand-ins for the live checks (2026-10-31): the
throughput harness never turns the iroh road's UDP off.
**Category:** defect
**Milestone:** M9
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

The cells of the iroh road "through iroh's relay server" may measure a
direct path: with both ends on one host and UDP on, iroh can leave the
relay for a direct path, and the figure in `docs/STATUS.md` is then no
relay's figure.

## Premise

- Read: the iroh road turns UDP off with `PODSSH_IROH_UDP`
  (`PodUtils/podcrates:crates/pod-iroh/src/endpoint.rs`), and its probe only binds a
  socket (`PodUtils/podcrates:crates/pod-iroh/src/probe.rs`).
- Read: no file of `crates/podssh-cli/tests/throughput_harness/` sets
  `PODSSH_IROH_UDP`.
- Inferred: iroh moves a connection to a direct path when one works.

## Approach

1. The relay cells set `PODSSH_IROH_UDP=off` on both ends.
2. Each cell records the path that iroh used, and a relay cell that went
   direct fails.
3. Run the cells again, and correct the rows of `docs/STATUS.md` that the
   old figures hold.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features iroh-test --test throughput_live -- --ignored --nocapture
```

Each relay cell reports the relay as its path. Planted: UDP on again in a
relay cell; that cell fails.

## Done

2026-10-31. The iroh cells of the throughput run measure the relay, and
say so:

- The iroh client watches the paths of each connection (iroh's
  `paths_stream`), and notes when a direct path is the one that carries the
  data (`PodUtils/podcrates:crates/pod-iroh/src/client.rs`); `Dialer::path` gives "the
  relay carried each byte of the session" or "a direct path carried the
  session", and nothing before a connection. `podssh ssh iroh:TICKET`, and
  the race of a pair's label with the iroh road, say it at the end of the
  session with `-v` (`crates/podssh-cli/src/ssh/iroh/dial.rs`,
  `crates/podssh-cli/src/ssh/iroh/race.rs`); the manual's entry of
  `PODSSH_IROH_UDP` says so too.
- The harness: a cell holds the variables of its runs and a line that each
  run must say (`crates/podssh-cli/tests/throughput_harness/cells.rs`,
  `mod.rs`). The iroh cells set `PODSSH_IROH_UDP=off` at the node and at
  each run, run with `-v`, and a run that does not say that the relay
  carried each byte gives no figure: the table gives the reason.
- Here, a Claude Code cloud container (Linux, the debug build): the
  loopback cells at 20 MiB a run (`cargo test -p podssh-cli --features
  iroh-test --test throughput_live -- --ignored --nocapture
  throughput_on_the_loopback`, 110 s): the iroh cell 4.2 MiB/s up and
  2.8 MiB/s down at the p50, each run said that the relay carried each
  byte; the table of `docs/STATUS.md` is replaced, and its old iroh row
  (34.6 MiB/s up) is named as most likely a direct path's. Planted: UDP on
  (`probe`) at both ends of the cell: its first run said "a direct path
  carried the session", and the cell gave no figure.
- Through n0's relay `use1-1` (`PODSSH_THROUGHPUT_IROH_RELAY=https://use1-1.relay.n0.iroh.link.`,
  the same command with `throughput_on_each_road`, 442 s with the other
  cells): 1.08 MiB/s up and 1.10 MiB/s down, alike in each run, and each
  run said that the relay carried each byte. Inferred: the flat figure is
  n0's limit for each connection (Read:
  <https://docs.iroh.computer/relays/rate-limiting>). The same run gave the
  reverse road through the live relay, with the layer, 2.37 MiB/s up and
  1.37 MiB/s down at the p50; both rows are in `docs/STATUS.md`.

# T-354: A session that closes while it moves can say a loss that was none

**Source:** CI's macOS job at `08275ee`, 2026-10-31 (run 41158346607):
`a_session_moves_while_both_ends_send_at_full_speed`
(`PodUtils/podssh:crates/podssh-relay/tests/session_move.rs:188-195`) failed once.
**Category:** defect
**Milestone:** backlog
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A session whose application ends while the layer moves it at full speed can
say a loss ("the link ended before the far end answered this side's CLOSE"),
then open a new link only to learn that the far end had ended the session.
The session ends well, but `-v` shows a loss that was none, the exit waits
for a new link, and the test that asks for no loss fails at random.

## Premise

- Measured: in the macOS job of CI at `08275ee` (run 41158346607), the
  test's notes held one loss, `Lost { why: "the link ended before the far end
  answered this side's CLOSE" }`, and no `Resumed`; the outcome and both
  digests held (`PodUtils/podssh:crates/podssh-relay/tests/session_move.rs:168-170`), and the
  assertion that failed is `:193`. The commit changed only `TODO/issues.md`.
- Not reproduced here: 40 runs of the test alone, and 80 runs eight at a
  time, passed (a Claude Code cloud container, 2026-10-31).
- Read: `End::Closing` comes from the pump's wait for the answer to its
  `CLOSE` (`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:366-373`): a reader that
  ended with anything but the peer's `CLOSE`, the 10 s of `LINGER` (not
  reached in a run of 2.9 s), or a stop. A loss with no `Resumed` after it is
  a resume that found the session forgotten while this side's application
  had ended (`PodUtils/podssh:crates/podssh-relay/src/session/resume.rs:362`): the far end
  had the `CLOSE` and ended the session, and this side's reader ended before
  its answer.
- Inferred: both ends closed at once (the test's target ends as the
  client's application does), and the far end's answer met a reader that
  had already ended, or the stop of a move.

## Approach

1. Reproduce: the test in a loop with the far end's answer delayed, or on
   paused time, to find which branch ends the wait.
2. Repair that branch: a reader that ended with the peer's own `CLOSE`
   before this side's (both closing at once) is the session's end, not a
   loss; a move does not cut a `CLOSE` in flight.
3. A test that closes both ends at once, with a move beside, many times.

## Decision

1. **A far end's last record on a link waits for the client**: `last_word`
   (`PodUtils/podssh:crates/podssh-relay/src/session/far.rs:203-220`) writes the record, then
   keeps the link, reading and dropping what the client sends, until the
   client ends it or 10 s pass (the wait of a `CLOSE` for its answer). It
   ends the four places: the `REFUSE` of the handshake, the `CLOSE` of a
   session that cannot start, the `CLOSE` of a resumed link whose session
   ended, and the `REFUSE` of an offset no longer kept. No shut of the write
   side first: a stand-in that ends at the first end of either way would
   then end before the client's next write, and the cut comes back. Lost:
   a shorter wait (1 s), which a slow path to the client could outlast; a
   wait in the relay's own close, which podssh cannot change.
2. **A loss after this side's `CLOSE` is said only when the resume goes
   on** (`PodUtils/podssh:crates/podssh-relay/src/session/resume.rs:274-280`, `:310-414`): the
   line "the link ended before the far end answered this side's CLOSE;
   resuming the session" waits, and comes before the next step said (a
   retry, the resume, the end that the resume gave up at), or once the
   resume takes longer than 3 s (`LOSS_GRACE`, the wait of a spare link). A
   far end that forgot the session had the `CLOSE`: nothing is said, and the
   session ends `LocalEnd`. Lost: saying it at once, as before, which is a
   line on each end whose answer a relay drops; never saying it, which hides
   a resume that waits.
3. **A handshake whose write fails reads what came before**
   (`PodUtils/podssh:crates/podssh-relay/src/session/client.rs:293-321`), 2 s at most, as the
   pump reads a link whose writes fail: a `REFUSE` there is the answer, else
   the write's failure is. Redundant with item 1 at podssh's own far end,
   and the answer from a far end or a relay that closes right after its
   last record.
4. Not done: the client's own `REFUSE` of a resume whose offset it no
   longer keeps (`resume.rs`, `resend`) is still sent and dropped; it ends a
   session that cannot go on, the far end's pump reads it after a failed
   write as each record, and the far end's deadline ends the rest.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_move
```

200 runs of `a_session_moves_while_both_ends_send_at_full_speed` with no loss
said; a planted race fails the new test.

## Correction

The reproduction found the cause on the far end's side, in three places of
one kind, and the client's word for it in a fourth. Debug lines in the close
paths, 40 runs of the test on one CPU (a Claude Code cloud container,
2026-10-31): in one run the far end accepted a resume on a move's new link,
then found the session ended on the old link (`NotTaken::Ended`,
`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs` at `cbaa806`, lines 277-280), wrote its `CLOSE` there and
dropped the link at once. The client's pump wrote on that link (the `DATA`
of a resume, its own `CLOSE`), and the stand-in relay, which ends both ways
when one way ends or fails as the relay ends a session, failed that write and
dropped the far end's `CLOSE` still on its way. The client then saw a link
end with no answer (`End::Closing`), said a loss, and learned on one more
link that the far end had ended the session. A new test of both ends closing
at once while the session moves each 16 KiB, 50 sessions a run, failed once
in 10 runs on one CPU on the code before, by the same kind of cut in the
handshake: the far end refused a resume at its `OPEN` and dropped the link
(`PodUtils/podssh:crates/podssh-relay/src/session/far.rs:182-186`) while the client wrote its
`PROOF`, so the client got a broken pipe in place of the refusal, said a
move's failure and a loss, and tried again. The same pattern is in
`Accepted::close`, whose reason the client would lose for "the far end did
not resume the session" (`PodUtils/podssh:crates/podssh-relay/src/session/far.rs:322-330`).
Approach item 2 is done as the Decision says.

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target `session_move`
moved to `pod-session` with its name; run `cargo test -p pod-session --test session_move` there.

## Done

2026-10-31. A session whose ends close at once while it moves says no loss:

- The far end's last record on a link waits for the client (Decision 1);
  the client says a loss after its `CLOSE` only when the resume goes on or
  waits (Decision 2); a handshake whose write fails reads the `REFUSE` before
  it (Decision 3). `docs/design.md` (the end of a session) says so.
- Tests, each against a stand-in relay that ends both ways when one fails:
  `PodUtils/podssh:crates/podssh-relay/tests/session_end.rs`,
  `a_close_whose_answer_its_link_lost_ends_with_no_loss_said` (the far end
  had the `CLOSE` and forgot the session; no note); the new
  `PodUtils/podssh:crates/podssh-relay/tests/session_last_word.rs`, 4 tests: a resumed
  link's `CLOSE` slower than the client's next write, the handshake's
  `REFUSE` at the `OPEN` while the `PROOF` is on its way, a `REFUSE` before a
  failed write read, and a new session's reason "no target here" while the
  client's application writes; `PodUtils/podssh:crates/podssh-relay/tests/session_move.rs`,
  `both_ends_close_at_once_while_the_session_moves` (50 sessions, both ends
  closing at once, a move each 16 KiB, no note but moves). `cargo test -p
  podssh-relay --test session_end --test session_last_word --test
  session_move`: 11 passed.
- Planted, each failed its test in 3 runs of 3: the loss said at once; the
  handshake's `REFUSE` sent and dropped; no read after a failed write; a new
  session's reason sent and dropped; a resumed link's `CLOSE` sent and
  dropped.
- The Prove: 200 runs of `a_session_moves_while_both_ends_send_at_full_speed`
  (100 on one CPU with `taskset -c 0`, 100 on four), none failed; 30 runs of
  the new test on one CPU, 1500 sessions, none failed, where the code before
  failed 1 run in 10. `cargo test -p podssh-relay`: 220 passed; with
  `--all-features`: 340 passed.

# T-387: A bulk session through a node loses its link each 35 s, and never moves

**Source:** T-251's live runs of 2026-11-01: `move_200mib_each_way_through_a_node` (T-155), here
and from GitHub's network (`relay-live.yml`, run 41282827634).
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

200 MiB each way through a node in front of an echo server came back whole, but slowly: in 720 s
here and 1256 s from GitHub's network, where the client met each link's end about 35 s after it
began ("the link ended with no word from the far end"), resumed, and sent its whole replay buffer,
4 MiB, again. No link lived to the 48 MiB at which the client moves, so the test's 6 moves were 0.
A session that carries bytes both ways at once at full speed (a copy into a shell, an echo, a
tunnel of a busy protocol) crawls, and each resume costs 4 MiB again.

## Premise

- Measured: the same in both places, so not this host's egress (`TODO/release.md`, T-251's Done).
- Read: the reader of the link awaits the write of each delivered record to the application before
  it reads the next (`PodUtils/podssh:crates/podssh-relay/src/session/pump/down.rs`, before this entry). While the
  application is slow, nothing on the link is read: not the far end's `ACK` and `PONG`, which free
  this side's replay buffer, and not its data, which a relay then holds for a slow receiver. The
  node's application, an echo, waits for the node's own sends, which wait for the client's `ACK`.
- Read: `ACK` and `PONG` carry the received offset (`PodUtils/podssh:crates/podssh-relay/src/session/link.rs`);
  the far end may send a replay window past it.
- Inferred, not yet shown: the link ends from the relay's side or the node's watchdog (30 s with
  nothing heard), within the 35 s seen.

## Approach

1. The reader reads the link while it writes to the application: both in one `select!`, the
   application's write first, so bytes wait only while it is slow; a `CLOSE` or a broken record
   still reaches the application after each byte before it.
2. An acknowledgement covers the bytes written to the application, not those received: the far
   end then sends at most its window past what this side wrote, which bounds what this side holds
   (twice the largest window, once more after a resume). The pump says the bytes it holds to the
   link's state under the lock of the record, so that no `ACK` in between covers them.
3. A test of an echo through a far end, 32 MiB with small pipes, no link lost; the live test of
   T-155 here and from GitHub's network, with its 6 moves.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair
cargo test -p podssh-relay --features pair --test session_echo
cargo test -p podssh-cli --test node_live -- --ignored --exact move_200mib_each_way_through_a_node
```

The live test makes 6 moves or more and loses no link; the relay's tests pass.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target `session_echo`
moved to `pod-session` with its name; run `cargo test -p pod-session --test session_echo` there.

## Done

2026-11-01, done with T-388: a session through a node carried 200 MiB each way on the live relay in
156 s with 7 moves and no link lost, where it took 720 s and lost a link each 35 s before; first
partial, then closed with T-388's repair, which the move needed.

- The reader (`PodUtils/podssh:crates/podssh-relay/src/session/pump/down.rs`) writes to the application and reads
  the link in one `select!`, the application first; a `CLOSE` or a broken record still waits for
  each byte before it to reach the application (the gap test of `session_link`, which failed at
  first with the bytes held, passes so). `ACK` and `PONG` cover the bytes written: the pump says
  the bytes it holds to the link's state (`Link::holding`) under the lock of the record; a caller
  that writes each byte as it comes says none, and its acknowledgements are as before.
- Live, here, `move_200mib_each_way_through_a_node` with the repair on both ends: the link carried
  the session to the 48 MiB of a move in 20 s, with no loss, where before each link ended after
  about 35 s and 11 MiB. The move then failed: T-388.
- `PodUtils/podssh:crates/podssh-relay/tests/session_echo.rs`: 32 MiB through a far end that echoes, through a
  stand-in relay with a round trip of 100 ms and 1 MiB held each way: 3.5 s, no link lost. It
  passes on the code before the repair too (3.6 s), so it does not show the defect: on a link of
  its own the old reader stalled nothing. The live link of a node is a session of the reverse
  road, framed with others on the node's one socket; the stand-in that shows the stall must be of
  that road (with T-388's).
- `cargo test -p podssh-relay --features pair`: 320 passed, 0 failed, 15 ignored, in 52 binaries;
  `cargo test -p podssh-cli`: 1178 passed, 0 failed, 49 ignored, in 138; clippy `-D warnings` of
  podssh-relay with `pair`, all targets: clean.
- Closed with T-388 (its Done): the live test passed with both repairs, 7 moves and no link lost
  ("200 MiB each way through the node in 156 s: 7 moves"). The echo test stays as a guard of the
  reader's order; the stall of a node's road is shown by the live test, which T-251 runs before the
  tag.

# T-388: A move through a node on the live relay ends the node's socket with 1003

**Source:** T-387's live run of 2026-11-01 (`move_200mib_each_way_through_a_node`, here), the first
whose link lived to the move: no link had before (T-387).
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

At 48 MiB the client moved, as T-155 designed: "a move to a new link failed (the link failed in
the layer's handshake: unexpected end of file); the link goes on", then at once "the link was
replaced; resuming the session", and the session ended: "the relay ended the session (relay close
1003): unknown session id". A session through a node cannot carry more than the relay's 64 MiB, the
limit that the move exists for.

## Premise

- Read: the relay closes the whole node socket, and each session on it, when the node sends data
  or `ready` for a session id that it never opened or already closed: `1003 unknown session id`
  (`PodUtils/podssh:crates/podssh-relay/src/reverse/sessions.rs`, its head; `docs/reverse.md`, "Node"); the node's
  writer is to refuse such frames before the wire.
- Read: the operator keeps one leg at a time (`next_leg`, `crates/podssh-cli/src/layered.rs`), and
  a move opens the new one while the old still carries the session.
- Inferred: the new leg's session id closed (the relay or the node ended it, and the client's
  handshake met its end), then the node wrote a frame for it, or for the old leg's id after its
  retirement, and the relay closed the node's socket.
- The stand-in relay of the tests (`scripts/fake-relay.py`, the reverse road's stand-ins) did not
  catch it: their moves are of the client road's links, in process (T-155).

## Approach

1. Reproduce against a stand-in of the relay's node socket that answers a frame for a closed id
   with 1003, as the relay does, with a move of a busy session through a node.
2. Find the frame and its race (the retirement of the old leg, the close of the new one); the
   node's writer refuses each frame for an id that is not open, and says it.
3. The live run of T-155, here and from GitHub's network: 6 moves or more, no link lost.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair
cargo test -p podssh-cli --test node_live -- --ignored --exact move_200mib_each_way_through_a_node
```

The live test makes 6 moves or more and loses no link.

## Correction

The Premise's inference is right about the frame and wrong about its side. The node's log, with
`PODSSH_TEST_NODE_LINES=1`, said "the relay closed the node for a fault of this node: 1003 unknown
session id" just after a move. The node's writer refuses no frame it should: the frame was for the
old leg's id, which the node still held as open. On a move the client retires the old leg, and the
operator's leg of that link, at the end of its input, sent its Close to the relay at once. The
relay then forgot the id while the node's last bytes and its acknowledgements for that leg were
still on their way, and the next of them closed the node's whole socket. A guard in the node cannot
know of a Close that the relay has not yet passed on to it.

## Done

2026-11-01: two repairs, each needed, and measured live.

- The operator's leg of a layer's link waits for the node to end the session
  (`PodUtils/podssh:crates/podssh-relay/src/reverse/operator.rs`, `OperatorLimits::node_ends`): at the end of its
  input it takes no more of the node's bytes and sends no Close for up to 35 s (`NODE_ENDS` in
  `crates/podssh-cli/src/layered.rs`, more than the far end's 30 s for a handshake). The node ends
  each retired or closed session itself, after its last bytes; then the relay's close ends the leg.
  Only a node that does not end it in time gets this side's Close, and the answer is awaited as
  before. A plain operator (`podssh operator`) keeps its Close at once (`None`).
- A retired link is still read until its far end closes it, 35 s at most
  (`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs`, `linger`): the pump splits the link, and after a
  `RETIRE` of either side a task drains its reading half, so that the far end's last records are
  taken and its writes never block.
- Tests: `cargo test -p podssh-relay --features pair --test reverse_operator`, 10 passed, two new:
  the end of the input waits for the node's close and sends no Close; a node that does not close
  gets the Close after the wait. `cargo test -p podssh-relay --features pair`: 322 passed, 0
  failed, 15 ignored, in 52 binaries; `cargo test -p podssh-cli`: 1178 passed, 0 failed, 49
  ignored, in 138; clippy `-D warnings` of podssh-relay (with `pair`) and podssh-cli, all targets:
  clean.
- Live, here, through the agent's proxy:
  `cargo test --locked -p podssh-cli --test node_live -- --ignored --exact move_200mib_each_way_through_a_node`,
  "200 MiB each way through the node in 156 s: 7 moves", 1 passed in 159.9 s. Before the linger
  alone (the operator's Close at once), the same run ended at the first move with the 1003 above.
  From GitHub's network (`relay-live.yml`, `node_live`): run after the push, in `docs/STATUS.md`.
- The planted defect (the operator's Close at once again, `node_ends: None` for the layer's legs) is
  the run before this repair: the 1003 at the first move. Its plant as a file waits for T-251.

# T-410: From GitHub's network, the first move through a node still meets a frame for a forgotten id

**Source:** the run of `relay-live.yml` (`node_live`, run 41289022291 at `ea2bd4f`, 2026-11-01),
after T-388's repair passed here with 7 moves.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

From GitHub's network, T-155's move test met at its first move "a move to a new link failed (the
link failed in the layer's handshake: unexpected end of file)", then "the link was replaced", and
the node was gone: the relay had closed it (T-409 now brings it back). Here, with the same code,
the first move failed the same way but the session resumed, and 7 moves passed. A frame for an id
that the relay forgot still reaches it on some paths, and the first move's new link fails in its
handshake each time, here and there.

## Premise

- Measured: the run's client lines (`relay-live.yml`, run 41289022291); the node's were not printed.
- Read: T-388's repair waits for the node's close on a leg's end of input; it does not cover a
  leg whose new link failed in its handshake, nor the node's own frames for a session that the
  operator side never opened.

## Approach

1. The node's lines from GitHub's network (`relay-live.yml` prints them since T-409): which id,
   which frame, and which leg.
2. Why the first move's handshake meets an end of file, here too.
3. Repair the side that sends the frame; T-155's test from GitHub's network makes its moves with
   no line of a node's fault.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test node_live -- --ignored --exact move_200mib_each_way_through_a_node
```

From GitHub's network: `relay-live.yml` with `node_live`, 6 moves or more, no fault of the node.

## Done

2026-11-01: three repairs; the move test passes live with no fault of the node.

- The cause, from a trace of each control frame of the node and the operator (a local patch, not
  kept), live: 40 ms after the move's new leg had its `ready`, the old leg's input ended, and the
  first leg, which has the plain operator's limits, sent its Close at once; the relay forgot the
  old id while the node still sent its bulk for it, and the next of them closed the node's socket
  with `1003 unknown session id`. The input ended because the client's pump shut its side of the
  link after `RETIRE` (`PodUtils/podssh:crates/podssh-relay/src/session/pump/outbox.rs`), which T-388's linger
  could not undo; the legs of `next_leg` hid it, as they wait for the node's close.
- Repaired: after `RETIRE` the writer flushes and leaves the link open; only the far end ends a
  retired link (`Watch::ends_links`, set by `Watch::far_end()` in `far.rs` and `keep.rs`): it shuts
  its side after its last bytes, so that the node's `close` follows its data and the relay then
  ends the operator's leg; the client holds the link until then (`linger` in
  `PodUtils/podssh:crates/podssh-relay/src/session/pump.rs`). Live with the trace: at each of the 7 moves the node
  closed the old session first, then the relay closed the old leg with 1000, and no 1003.
- Also repaired: the node's writer has two queues (`Outbox` in
  `PodUtils/podssh:crates/podssh-relay/src/reverse/serve.rs`): control first (`ready`, `reject`, the relay's close
  of a session, the node's close of a stalled one, the stop); a session's bytes and the `close`
  after its last ones keep their order. One queue of 256 frames of up to 64 KiB held a `ready`
  behind some 16 MiB of a busy session's bytes. `--test reverse_node`,
  `a_ready_does_not_wait_behind_another_session_s_bytes`: passed; planted, one queue: 8.7 MB came
  before the `ready`.
- And: a relay close `1003 unknown session id` resumes the layer (`resumes` in
  `PodUtils/podssh:crates/podssh-relay/src/reverse/closes.rs`), as the node comes back (T-409) and a new session is
  the reopening that the table's row asks for.
- Tests: `cargo test -p podssh-relay --test session_retire`,
  `the_far_end_ends_a_moved_link_before_the_client_does` (a stand-in relay notes which side ends
  each link while a session moves each 256 KiB through an echo): passed 6 runs of 6; planted, the
  client's half-close after `RETIRE` back: failed 3 of 3. `cargo test -p podssh-relay --features
  pair`: 334 passed, 0 failed; the CLI's node tests and the session tests of moves, resumes and
  spares: passed; clippy `-D warnings`: clean.
- Live here, `move_200mib_each_way_through_a_node`: 200 MiB each way in 157 s, 7 moves, no line of a
  node's fault. From GitHub's network, `relay-live.yml` at `0c4bc78` (run 41297719584, the node's
  lines printed): "200 MiB each way through the node in 210 s: 8 moves", no `1003` and no line of a
  fault; `an_idle_session_through_a_node_lives_10_minutes` and `node_command_serves_a_tcp_target`
  passed too. `ssh_to_a_node` failed on its far target: railway.new limited the run's anonymous
  visitor after the login through the node had worked, as it timed out at `c54b7b4`; an outage of
  that service, not of podssh.

# T-586: A node holds each session whose OpenSSH client ended its `operator`, so 16 short logins in 10 minutes fill its budget and it refuses each new one

**Source:** GitHub #112 (a tester's agent, 2026-11-02), with `podssh 1.0.0 (35a0d19)` on a gVisor
sandbox, OpenSSH 10.0p2 as the roost's sshd and OpenSSH's client through
`ProxyCommand=podssh operator`: after a dozen or so `ssh HOST cmd`, the node ended each new
session, in about 1.6 s, with "this node keeps as many resumable sessions as its budget allows (64
MiB of replay buffers)", also a command that reads no input. Read at `3bb42ea`.
**Category:** defect
**Milestone:** none
**Priority:** P1
**Effort:** M
**Status:** done

## Problem

A node of the reverse road stops serving after a run of short sessions that each ended well: its
budget of replay buffers is full of sessions that nobody will resume, and each new session is
refused until the oldest one ages out, 10 minutes later. The refusal names the budget, not what
holds it, when room comes back, or a flag that changes it. A defect: a node serves sessions, and
an ordinary use of its documented ProxyCommand form ends that.

## Premise

- Read, at `3bb42ea` (the lines that this entry's work changed; see the Correction): a new
  session is refused when the kept sessions, each charged a whole replay buffer, leave no room:
  `PodUtils/podssh:crates/podssh-relay/src/session/far.rs` line 219 said
  "let held = keeper.kept_admitted().saturating_mul(settings.replay_capacity);", and the refusal's
  words were at lines 221-224. `kept_admitted` counted each kept session whose client was let in,
  with a link or with none (`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`, lines 121-125). The budget
  is 64 MiB (`PodUtils/podssh:crates/podssh-relay/src/reverse/layered.rs:27`), 16 sessions with the default
  buffer, as the manual said (`crates/podssh-cli/src/man/notes_pair.rs`, lines 17-19).
- Read, at `3bb42ea`: a link whose end is not the session's own keeps the session for the whole
  deadline (`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`, lines 280-281 and 301-305); a loss and a
  `CLOSE` with no answer are such ends (`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:107-113`). The
  node's `CLOSE` after its target's last byte waits 10 s for the operator's answer, and with none
  the end is `End::Closing`: `PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:371` says "_ => End::Closing,".
- Known, from OpenSSH's source (not read here): at its exit, OpenSSH's client sends SIGHUP to its
  ProxyCommand and does not wait for it (`openssh/openssh-portable:sshconnect.c`,
  `ssh_kill_proxy_command`). `podssh operator` took no signal at `3bb42ea`
  (`crates/podssh-cli/src/operator.rs`, lines 82-93), so SIGHUP ends it at once, before it answers
  the node's `CLOSE` or sends its own.
- Inferred, the mechanism, which the Prove measures: each `ssh -o ProxyCommand='podssh operator
  NAME' HOST cmd` leaves its session on the node as a loss or a `CLOSE` with no answer, held 10
  minutes with its connection to sshd and charged a whole buffer; the 17th within 10 minutes is
  refused. The tester did not count the held sessions, as the issue says.
- Read: a session whose target ended can take no more bytes into its buffer, and is charged as
  much as a live one.
- Read: `--resume-deadline` takes 1 minute to 72 h (`crates/podssh-cli/src/layered.rs:129`), and
  `--plain` is a node with no layer.
- Not the cap of GitHub #84 (T-461): that is the relay's 64 MiB for one session.

## Approach

1. Reproduce: the stand-in relay of the reverse road, `podssh node NAME --sshd` in front of the
   test's OpenSSH sshd, `PODSSH_REPLAY_BUFFER` set so that the budget holds 2 sessions, and
   OpenSSH's client 3 times, `ssh -o ProxyCommand='podssh operator NAME' HOST true`: on the code
   before, the third is refused. The node's lines say which end each session had.
2. `operator` ends well when its parent ends it: SIGHUP, SIGTERM and SIGINT (Ctrl-C and Ctrl-Break
   on Windows) are its application's end. The layer sends `CLOSE` after the bytes in flight, waits
   up to 2 s for the node's answer, and the leg closes; the exit is 0 for a session that the node
   took, as for an end of stdin. The same for `pipe` with a `node:` side and for `ssh node://`
   when a signal ends them.
3. The node keeps of a closing session only what it needs: a session whose target ended and whose
   `CLOSE` went out keeps the bytes that the client has not acknowledged, and is charged those,
   not a whole buffer; once the client acknowledged each byte, it keeps its id alone, charged
   nothing, until the deadline, and a resume of it gets its `CLOSE`, as a resume of a session that
   ended on its old link does (`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs:282-286`).
4. The refusal says what holds the budget and when room comes: "this node keeps 16 resumable
   sessions (64 MiB of replay buffers): 3 with a link, 13 waiting for their client, the first of
   them for 4 min 10 s more; --resume-deadline and PODSSH_REPLAY_BUFFER of the node change its budget".
   The node says the same on stderr at a refusal, once a minute at most, and once when its budget
   passes three quarters; a detached node's log keeps it.
5. The notes of `node` and `operator`, `docs/reverse.md`, `docs/design.md` (section 5) and
   `docs/STATUS.md`.

## Decision

Each a call made overnight, for the operator to confirm (Q86):

- A signal of the parent is the end of the operator's application, not a loss: OpenSSH has read
  what it needed when it sends SIGHUP, so the layer closes the session. Lost: a resume after it,
  which keeps a session that no client comes back for; and SIGHUP ignored, which leaves an
  operator running after its OpenSSH, its stdout to nobody.
- A closed session stays as its id alone, charged nothing, so that a client that lost the node's
  `CLOSE` hears the session's end on a resume. Lost: forgetting it at once, which answers that
  client with a forgotten session; and a shorter deadline for it, which charges the budget for
  nothing meanwhile.
- No `--resume-deadline 0` and no `--no-resume` of the operator (the issue's first ask): with items
  2 and 3 a clean end holds nothing, a session lost on its way is what the layer keeps, and
  `--plain` is a node with no layer. Lost: a client that asks the node for a shorter deadline in
  the handshake, a change of the layer's protocol for a case that the repair empties.
- The oldest waiting session is never dropped for a new one: a client that sleeps was promised its
  time (T-306). Lost: eviction by age.
- No counts of the budget in `detached list` or `relay status NAME` (the issue's second ask):
  `detached list` reads no state of a run, and `relay status` asks the relay, which never sees the
  node's budget; the node's line of item 4, in its log, is the place.
- Made while drafting (2026-11-03): a signal that the process was started to ignore stays
  ignored, as a shell keeps it (nohup's SIGHUP, the SIGHUP of a run of `--detach` or `ssh -f`,
  whose notes say that it ignores it); the disposition is read at the start. Lost: taking each
  anyway, which would end a detached `ssh -f node://` at a SIGHUP that its manual says it
  ignores. And `ssh node://` takes SIGHUP and SIGTERM, not SIGINT: its Ctrl-C is the remote
  command's (`podssh ssh`'s own). Lost: SIGINT as an end there too, which would take Ctrl-C from
  the remote command.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --test reverse_layered
cargo test -p podssh-cli --test operator
cargo test -p podssh-cli --test roost
```

New tests: in `reverse_layered`, `a_session_whose_target_ended_holds_only_its_unacknowledged_bytes`
(a budget of 2 sessions; two sessions whose target closes and whose client acknowledges each
byte; then two more are admitted) and `a_resume_of_a_closed_session_gets_its_close`; in `operator`
(Unix), `an_operator_that_its_parent_hangs_up_closes_the_session` (SIGHUP after the target's last
byte: the node keeps no session 3 s later, through the stand-in relay); in `roost`, against
OpenSSH, `short_logins_through_operator_leave_the_node_room` (OpenSSH's client with
`ProxyCommand=podssh operator`, 5 runs of `true` through a node whose budget holds 2: each exits 0;
it says that it did not run where this host has no OpenSSH, as the roost's tests do); and the
refusal's words with its counts, in the lib's tests of `session::far`. Planted:
`t586-hangup-not-taken` (no handler of the signals): the operator's test and the OpenSSH test
fail, the third run refused; `t586-closing-charged-whole` (a closing session charged a whole
buffer): the first test of `reverse_layered` fails.

## Correction

Read while drafting, 2026-11-03:

- A budget of 2 sessions cannot come of `PODSSH_REPLAY_BUFFER`, item 1 and the Prove's OpenSSH
  test: the setting takes 4 to 16 MiB (`PodUtils/podssh:crates/podssh-relay/src/session/replay.rs:18-20`), so the
  node's 64 MiB hold 4 sessions at the least. The OpenSSH test of the roost runs with 16 MiB, a
  budget of 4, and 8 logins: the code before refuses the fifth. `reverse_layered`'s tests give the
  budget to `Layered::new`, and keep 2.
- "The node keeps no session 3 s later": no count of a node's sessions can be read from outside
  its process. The operator's test reads it at its target, a TCP service of the test behind a
  node of the layer and the channel: the node shuts its connection to the target as it forgets
  the session, and keeps it for the deadline with a session that it keeps as a loss.
- Item 2's "as for an end of stdin" holds for the exit, not for the bytes. With the end-to-end
  channel above the layer, the end of stdin is the channel's `END`, a half-close
  (`PodUtils/podssh:crates/podssh-relay/src/e2e/channel.rs` at `cbaa806`, lines 127-129), and the layer's `CLOSE` follows only once
  the TARGET ends too. So a signal ends the layer's own input, the channel's ciphertext, in
  `crates/podssh-cli/src/layered.rs:285`, and the `CLOSE` goes at once, whatever the TARGET does.
- The layer's own wait for the answer to a `CLOSE` stays 10 s
  (`PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:52`), as for an end of stdin. After a signal the
  session has 2 s in all (`crates/podssh-cli/src/hangup.rs:29`), the node's answer and the leg's
  Close included; a session cut then is a clean end of a session that the node took, exit 0. A
  signal before the node took the session ends the wait at once, with the session's fault (70).
- `ssh node://` takes SIGHUP and SIGTERM alone: its Ctrl-C is the remote command's. The same on
  the road that races the node's roads (`crates/podssh-cli/src/ssh/node_roads.rs:234`, moved from
  `crates/podssh-cli/src/ssh/roads.rs` by T-551).
- The plant of the signals is two plants, one for each test, as a plant runs one check:
  `t586-hangup-not-taken` (the operator's test) and `t586-hangup-not-taken-openssh` (the
  roost's), with one patch.
- The Premise's citations of the lines that this work changed read at `3bb42ea`, where the
  Premise was read; the code of those files had not changed between `3bb42ea` and this draft's
  base.

## Done

2026-11-03, drafted by an agent and merged here, at `b5a0709`.

- The node (`PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`, `crates/podssh-relay/src/session/budget.rs`,
  `PodUtils/podssh:crates/podssh-relay/src/session/far.rs`): each slot is charged by what it can hold; a session
  whose target ended, whose `CLOSE` went out and whose client acknowledged each byte keeps its id
  alone (`Slot::Closed`), its target shut, and a resume gets the `CLOSE`; the refusal counts the
  sessions with a link and those waiting, and the first one's time left; the node's lines, once a
  minute at most and once past three quarters, through `budget::tell`, which `podssh node` sets.
- The clients (`crates/podssh-cli/src/hangup.rs`): `operator` and `pipe` with a `node:` side take
  SIGHUP, SIGTERM and SIGINT, `ssh node://` SIGHUP and SIGTERM; the layer's input ends, its
  `CLOSE` goes, and the session has 2 s more.
- `cargo test -p podssh-relay --features pair --test reverse_layered`: 5 passed.
- `cargo test -p podssh-relay --features pair --lib session::` (the refusal's words, the rate of
  the lines): 7 passed.
- `cargo test -p podssh-cli --lib -- hangup layered`: 9 passed; the lib: 657 passed.
- `cargo test -p podssh-cli --test operator` (Unix, the stand-in relay): 7 passed, the signal's
  test among them (0.5 s).
- `cargo test -p podssh-cli --test roost` (OpenSSH's client, the stand-in relay): 9 passed;
  `short_logins_through_operator_leave_the_node_room` ran against OpenSSH here (2.4 s).
- The merge: the refusal had lost the word "budget" that `e2e_layered`'s
  `visitors_with_no_key_take_nothing_of_the_budget` reads (and the user of #112 met), so it ends
  "... of the node change its budget"; clippy's `manual_is_multiple_of` in `budget.rs`. Then
  `cargo test -p podssh-relay --features pair,quick,derp,serve,piping --no-fail-fast`: 533 passed,
  0 failed; clippy of `podssh-relay` (with those features) and `podssh-cli`, all targets, `-D
  warnings`: clean; rustfmt: clean; `man_page` and `flag_table`: 10 and 9 passed. Windows (the
  signals of the console): the gate's job `windows` at the push.
- The gate at the push (`84864f2`, run 41590196203): `exit`'s test failed on macOS and Windows,
  and here too in each of 15 runs: the session's future, with the signal's wait around it, overflowed
  a worker thread's stack in `podssh exit --listen` ("has overflowed its stack"). `layered.rs`
  puts the session's futures on the heap; `exit` 3 passed, 5 runs of 5. The OpenSSH test of
  `roost` is Unix's alone (OpenSSH for Windows sends no SIGHUP, and its `CreateProcessW` took no
  command line of a shell: "error:2").
- Planted: `t586-closing-charged-whole` by `sh scripts/plant-each.sh --here`, and the two of the
  signals by hand (their SETUP is the build image's `apk`): each caught, `reverse_layered`'s first
  test, the operator's test and the OpenSSH test failing.

# T-612: A client of a node can turn the resumable layer off: `--no-resume`

**Source:** the operator's ruling Q90 (2026-11-03) on T-586's call that the layer has no way off
("Add --no-resume").
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A client of a node always opens a resumable session, so the node holds it after its link goes, and
the node's budget counts it until its deadline; a user who wants a session to end with its link has
no way to say so.

## Premise

- Read: T-586's `## Decision`: no `--resume-deadline 0`, no `--no-resume`, no eviction of a waiting
  session (`TODO/resume.md`, T-586).

## Approach

1. `--no-resume` on `ssh`, `cp`, `mv`, `scp`, `sftp`, `proxy`, `pipe` and `operator` to a node: the
   client asks for a session that the node ends with its link, which the layer's handshake says,
   so the node charges it nothing after its link goes; an old node that knows no such ask holds it
   as before, and the client says so at `-v`.
2. The flag rows, the manual's notes and `docs/cli.md`.

## Decision

The calls of the draft (2026-11-03):

- The ask is one more feature name of the layer, `once.v1`: the client names it in its `OPEN` when
  its user asked, and a far end that knows the ask names it in its `GREETING` always; with both
  names the far end forgets the session and shuts its target as the link ends. An old far end
  ignores the name, as each name that it does not know, and the client sees no `once.v1` among the
  names that both gave. Lost: a record or a field of `OPEN` of its own, a change of the layer's
  version, which an old node refuses; and a client's `deadline.0`, which an old far end reads as no
  name, and a new one must tell apart from a bad one.
- With `--no-resume` the client carries the session on its first link alone: no resume, no move
  before the relay's limits and no spare link, as on a node of `--plain`, so the relay's limits (64
  MiB, 12 h) end the session too; a copy goes on over a new connection, as after each broken one
  (T-136). Lost: the moves kept, as a move is a resume of the layer on a new link, which a far end
  asked to keep nothing must not wait for; and a resume where an old node still keeps the session,
  which the user asked against.
- The far end forgets at each end of the link, a `CLOSE` with no answer and a stop included: no id
  is kept alone (T-586's `Slot::Closed`), as no client of the ask resumes. Lost: the id kept alone,
  for a resume that nobody sends.
- A node that does not know the ask is said always, in one line; one that took it at `-v`.
  `operator`, `proxy` and `pipe` show no line of `-v`, and a user who asked counts on the node's
  budget. Lost: both at `-v`, as the Approach said, which those three verbs would never show.
- A loss that ends a session of `--no-resume` is said in one line, the words of the layer's loss and
  "with --no-resume the session ends with it", and the exit is that of the leg's end, as on a node of
  `--plain`. Lost: a code of its own, for an end that the user asked for.
- The switch is one for the process (`crate::no_resume`), as the deadline of `--resume-deadline`,
  and `layered::settings` reads it, so each road to a node takes it (the pair's, iroh, DERP,
  OpenTunnel, the transit and Piping Server roads, a carrier, the exit). Lost: a field carried
  through each road's arguments, a change in a dozen roads. The lines are said on the pair's road
  (`layered::carry`: `operator`, `proxy node://`, `pipe`, `ssh node://` on the pair) and in the race
  of `ssh node://` (`ssh/roads.rs`); the other roads take the switch with no line of their own.
- `ssh`, `cp`, `mv`, `scp` and `sftp` refuse the flag with a destination that is no node (64), by
  the rule of the channel's flags, `--upgrade` included, whose temporary node is there to resume;
  `pipe` with no `node:`, `udp:node:` or `iroh:` side (64). Lost: the flag taken with no effect.
- The client's loss in words, `describe` of `session::resume`, is `End::loss` in `session::pump`,
  for the CLI's line too; `resume.rs` had no room for the switch at its 500 lines.

## Prove

```sh
cargo test -p podssh-relay --test session_newest
cargo test -p podssh-cli --test operator
```

With `--no-resume`, the node's budget is free at once after the client's link goes; without it, the
session waits its deadline; planted, the ask dropped: the test fails.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_newest` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_newest` there.

## Done

Drafted 2026-11-03; merged and measured on this machine the same day.
The Premise holds: T-586's `## Decision` names no `--no-resume` (`TODO/resume.md`, T-586).

- `PodUtils/podssh:crates/podssh-relay/src/session/once.rs` (new): `ONCE`, `asked` (the names of the client's
  `OPEN`) and `agreed`; its unit test. `session/mod.rs`: `Settings::resumes` (default true), and
  `Settings::link` gives `Link::with_once` when both named `once.v1` (`session/link.rs`).
  `session/client.rs`: the `OPEN` names `once::asked`. `session/far.rs`: the `GREETING` names
  `once.v1`. `session/keep.rs`: a session of `Link::once` is forgotten, its target shut, at each end
  of its link. `session/resume.rs`: with `resumes` false, `run` carries the first link alone;
  `describe` went to `End::loss` (`session/pump.rs`).
- `crates/podssh-cli/src/no_resume.rs` (new): the switch (`ask`, `asked`), the line of the far end's
  answer (`heard`) and of a loss that ended the session (`ended`); its unit tests.
  `layered.rs`: `settings` reads it, and `carry` says both lines; `ssh/roads.rs` the same.
- The flags: `ssh/args.rs` (`SshArgs::no_resume`), `ssh/resolve.rs` (refused with no node, as the
  channel's flags), `ssh/mod.rs`, `cp/mod.rs` and `sftp/mod.rs` (the switch), `operator.rs`
  (`OperatorArgs::no_resume`), `tree.rs`, `carrier.rs`, `proxy_node.rs` (the flag of `node://`, to
  operator; its unit test), `pipe/remote.rs` (refused with no `node:`, `udp:node:` or `iroh:` side).
  The rows: `flags/node.rs` (`NO_RESUME`, `OPERATOR_NO_RESUME`, `PROXY_NO_RESUME`,
  `PIPE_NO_RESUME`), in `flags.rs`, `flags/copy.rs`, `flags/scp.rs`, `flags/operator.rs`,
  `flags/relay.rs` and `flags/pipe.rs`.
- The manual: `man/notes_pair.rs` (operator's note, and node's), `man/notes_ssh.rs`, `man/notes.rs`
  (cp, scp, sftp), `man/notes_proxy.rs`, `man/notes_pipe.rs`. `docs/cli.md` (ssh's destinations,
  cp's node, the reverse road's section and pipe's), `docs/reverse.md`, `docs/design.md` (section
  5), `docs/STATUS.md` (a row).
- Tests: `PodUtils/podssh:crates/podssh-relay/tests/session_newest.rs`,
  `a_session_that_ends_with_its_link_leaves_the_far_end_nothing` and its control
  `with_no_ask_a_lost_session_waits_its_deadline`, through a stand-in relay that drops the link both
  ways; `crates/podssh-cli/tests/operator.rs`,
  `an_operator_of_no_resume_leaves_the_node_nothing_at_a_loss` (through the stand-in relay, an
  operator killed after the target's line; and the control, with no ask), the target of T-586's test
  moved to a module of its own for both.
- The plants: `PodUtils/podssh:scripts/plants/t612-ask-dropped.plant` (GROUP=resume) and
  `PodUtils/podssh:scripts/plants/t612-ask-dropped-operator.plant` (GROUP=resume-cli), one patch each, which `git
  apply --check` takes: each caught (below).

Measured at the merge (2026-11-03, Linux, `CARGO_BUILD_JOBS=4`):

- `cargo test -p podssh-relay --test session_newest`: 5 passed; `--lib session::`: 8 passed.
- The relay crate's suite with `pair,quick,derp,serve,piping`, one target at a time (the disk of
  this session holds no more): the library and each of the 67 test targets passed, 563 tests, none
  failed, as the `GREETING` names one more feature.
- `cargo test -p podssh-cli --lib`: 789 passed, once two words were repaired that the draft could not
  see: the help's check reads the last `--no-resume` of a line, which the rows of `proxy` and `pipe`
  had in their own text (`as operator --no-resume: ...`), now `as with operator's`; and the check of
  the names in the notes read `podssh ssh. --timeout` in `sftp`'s note as a flag of `ssh`, now `as
  podssh ssh does.`.
- `cargo test -p podssh-cli --test operator --test proxy --test node_carrier --test node_detach
  --test node_moves --test roost --test non_interactive --test man_flag_parity --test flag_table
  --test man_page`: each passed (operator 10, proxy 15, node_carrier 14, node_detach 8, node_moves 2,
  roost 17).
- clippy `--all-targets -D warnings` of `podssh-cli` and of `podssh-relay` (`pair,quick,derp,serve,
  piping,blocking`), and rustfmt: clean.
- The plants `t612-ask-dropped` and `t612-ask-dropped-operator`: caught. The second, and five others
  of GROUP `resume-cli` and `cli-tests` (t158, t586, t587, t589, t591), had a SETUP of `apk add`
  alone, which fails on a host with no apk, so `--here` missed them: the SETUP now installs only
  what is missing.

# T-600: A resume that comes before the first link's task carries its session ends the session, as while a node opens its target

**Source:** the session of 2026-11-03: `cargo test -p podssh-relay --test session_newest` failed
once in the tests of T-597 on this cloud session's host, under a load of 24 on 4 CPUs (the loop of
T-599 beside it): "the first link stops for B: Elapsed(())", then 3 runs of 60 of its binary
failed the same way. Read at `38f424c`.
**Category:** defect
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A test that fails at random, and a defect under it. The handshake of a new session makes it
resumable (`Sessions` holds its secret) before its first link's task puts the session's slot in
the keeper (`Keeper::run_new`). A resume that comes between them finds no slot, and
`Keeper::take` took that for a session that ended: the client heard `CLOSE` and gave the session
up, then the first link's task carried it on a link that nobody used. On a node the gap is the
dial of its target (`far::serve`, up to 10 s): a client whose first link falls then loses the
session that it could have resumed.

## Premise

- Read, at `38f424c`: `PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`, `take` returned
  `NotTaken::Ended` for `None` from the slots; `run_new_admitted` attaches the state and inserts
  `Slot::Live` only when it is called.
- Read: `PodUtils/podssh:crates/podssh-relay/src/session/far.rs`, `serve` opens the target (`TARGET_LIMIT`, 10 s)
  between `accept` and `run_new_admitted`; `Accepted::close` removes the session from `Sessions`.
- Measured: with a line at the failure, B's run ended with "the session ended on its old link"
  while the keeper held one session (the first link's, put in later).

## Approach

1. No slot while `Sessions` still knows the id: the first link's task has not put it in, so the
   resume waits and looks again, each 50 ms, up to its 10 s; once `Sessions` forgot it (the
   task's `close`), the session ended.
2. A test of each order: a resume before the first link's task, which then stops for it; a resume
   of a session that the first link's task closed, which ends at once.

## Prove

```sh
cargo test -p podssh-relay --test session_newest
```

Three passed; 200 runs of the binary under the load that failed 3 of 60. Planted, the old
`None => Ended`: the new test fails; planted, the check of `Sessions` skipped: the closed
session's test fails.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test target
`session_newest` moved to `pod-session` with its name; run `cargo test -p pod-session --test
session_newest` there.

## Done

2026-11-03.

- `PodUtils/podssh:crates/podssh-relay/src/session/keep.rs`: `take` waits for a slot that the handshake's table
  still knows, and says ended only once the table forgot the session (its entry of `newest` goes
  with it).
- `PodUtils/podssh:crates/podssh-relay/tests/session_newest.rs`: `a_resume_before_the_first_link_is_carried_waits_for_it`
  and `a_resume_of_a_session_closed_before_its_first_link_ends`, beside T-270's.
- `cargo test -p podssh-relay --test session_newest`: 3 passed. Its binary, under a load of 20
  to 24 on 4 CPUs (T-599's loop of 12 copies beside it): 200 runs passed, then 300 more, where
  the code before failed 3 of 60.
- Planted, `None => return Err(NotTaken::Ended)` again: the new test and T-270's failed; planted,
  the check of `Sessions` skipped (`&& false`): the closed session's test failed (Stuck after
  10 s, past its 5 s).

# T-663: Liveness in round trips: a spare link after the larger of three round trips and 1 s, and a check when the host wakes

**Source:** the study of osewa, 2026-11-04 (Q99; `docs/research/osewa.md`, `docs/research/osewa-code.md`, `docs/research/osewa-paper.md`).
**Category:** feature
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

osewa suspects a link after the larger of three round trips and 1 s of an unanswered key, and
redials; podssh opens a spare link after a fixed 3 s of an unanswered question or 20 s of quiet
(T-305), and its measured resume after a new address is 3.0 to 3.2 s on the loopback. A laptop that
wakes from sleep waits for those bounds too.

## Premise

- `PodUtils/podssh:crates/podssh-relay/src/session/beside.rs:38` says "pub const SPARE_AFTER: Duration = Duration::from_secs(3);",
  and `PodUtils/podssh:crates/podssh-relay/src/session/beside.rs:41` the 20 s of quiet.
- T-305 measured 3.0 to 3.2 s with the stand-in proxy's `--move`, no real client.

## Approach

1. The spare opens after the larger of three smoothed round trips and 1 s of an unanswered
   question, 3 s at most; the layer's PING and PONG and its ACKs give the round trip.
2. A wake or a move, with no privilege: a timer that fires more than 2 s late, or a jump between
   the monotonic and the boot-time clocks, asks the far end at once. On the forward road with
   `--persist`, the same check makes T-302's notice sooner.
3. podssh exceeds osewa where osewa cannot follow: the spare races podssh's roads and relay hosts,
   so the resume can come on another road (osewa redials its one host).

## Decision

2026-11-04 (the drafting agent). No row of `docs/decisions.md` settles these, and none changes one:
the spare link is the exception of T-305 already (one at a time, one each 10 s), and the check of
the clocks opens no connection.

1. **The round trip is timed on the layer's own records, one question of each kind at a time**, as
   TCP times one segment (RFC 6298): a `PING` to the `PONG` of its value, and a batch of `DATA` to
   the `ACK` or `PONG` that reaches its end; smoothed by an eighth
   (`PodUtils/podssh:crates/podssh-relay/src/session/round_trip.rs`). A sample of `DATA` holds the 200 ms for
   which the far end may hold its `ACK`: it is the wait of such a question for its answer, which
   the bound must outlast, so it is taken as it is. Lost: `PING` and `PONG` alone, as a `PING`
   goes only after 10 s with nothing sent, so a session that types would never time one; the
   handshake's round trip, as a new session's far end dials its target before its `ACCEPT`, and
   the hearing is attached after the handshake; `DATA`'s samples less 200 ms, as an `ACK` at
   64 KiB comes at once, and the round trip would then be too short and the spare too soon.
2. **Each link times its own round trip** (`Hearing::new_link`, at the start of each link's
   reader), and until its first answer a question waits the 3 s of before. Lost: the last link's
   round trip carried on, as a spare or a move can take another road (iroh, DERP, another relay
   host) whose round trip is many times longer; a bound from the faster road would open a spare
   that the slow road's answer then closes.
3. **The bound**: three smoothed round trips, 1 s at least (`SPARE_SOONEST`) and 3 s at most
   (`SPARE_AFTER`, the constant of the Premise, now the ceiling). `SPARE_QUIET` (20 s),
   `SPARE_EVERY` (10 s), the resume's `LOSS_GRACE` (3 s), `PING_EVERY` (10 s) and the dead bound
   (30 s) are kept: a spare replaces a silent link long before the dead bound, and a shorter dead
   bound would end links that the iroh road's QUIC carries across a move (T-305). The look at the
   silence comes at the instant that a waiting question reaches its bound, where it came each
   250 ms: with a bound of 1 s, a quarter of a second was a quarter of the bound.
4. **The spare asks the old link too**: when it opens, the hearing asks the link's heartbeat for a
   `PING` at once (`Hearing::ask_now`). With a floor of 1 s, a far end whose application holds its
   `ACK`s (an `ACK` covers the bytes written, T-387) would open spares that cost a connect, and a
   leg of the pair; the far end's reader answers a `PING` at once, so the answer closes the spare
   within a round trip, before its handshake, and no resume follows. Lost: no `PING`, where the
   spare waits for the held `ACK`, which a loaded host can hold for seconds (T-305's Decision); a
   `PING` first and the spare a round trip later, which makes each dead link one round trip
   slower to replace.
5. **The wake check** (`crates/podssh-ws/src/wake.rs`): each link's heartbeat reads the clocks
   each second; a tick more than 2 s late, by tokio's clock (a process that stood still) plus the
   time that the host slept, is a wake, and a `PING` goes at once, at each end. The time slept is
   the growth of the gap of `CLOCK_BOOTTIME` and `CLOCK_MONOTONIC` on Linux, which no step of the
   wall clock moves, and elsewhere what the wall clock counted past tokio's; a read of a clock
   that the kernel lacks gives none, and the wall clock stands in. Lost: the timer alone on tokio's
   clock, which is std's monotonic clock and stops while Linux or macOS sleeps, so a timer fires
   on time after a sleep and sees nothing; the wall clock on Linux, whose steps would ask for
   nothing; a poll of the interface addresses each second (osewa-code's hint), as a sleep does not
   always change an address, and a move with no sleep is found by its silent question within the
   same bound. A false wake (a step of the wall clock where no boot clock is read) costs one
   `PING`.
6. **Where it lives**: the check is in podssh-ws, the crate that both the layer (podssh-relay)
   and the forward road's relay stream (podssh-ssh) build on, and the wish to ask goes through the
   hearing, which the watch beside the link and each link's heartbeat share. Lost: a field of the
   pump's `Watch`, which is the link's own, as the watch beside the link then needs one more
   handle; a wish that the next link's heartbeat takes costs one `PING`.
7. **The forward road** (item 2's `--persist`, and each forward session through the relay): a
   wake sends the relay stream's Ping of a question while none waits, so T-302's notice, which
   T-307 gave that road, comes 5 s after the wake with no key typed. The link does not end
   sooner: SSH there has no layer below it, so an early end costs a login (and, with `--persist`,
   an attach of tmux), and a link that only lagged would be lost; the relay stream's pings still
   end a dead link. `--direct` keeps T-332's question on a key alone: its question is SSH's own
   keepalive, in russh's session loop, not a road's.
8. **Item 3 needs no code**: a spare link is whatever the caller's `connect` gives, and on
   `ssh node://` that is the race of the roads again (T-164). That a resume comes on another road
   than the lost link's is not measured here.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --features pair --lib session
cargo test -p podssh-relay --test session_round_trip
cargo test -p podssh-relay --test session_spare --test session_heartbeat
cargo test -p podssh-ws --lib wake
cargo test -p podssh-ssh --test relay_wake
```

A stand-in of 50 ms whose link goes silent: the spare opens within 1.2 s (today 3 s); a planted
fixed 3 s fails it. A live run on the relay with `--move` measures the resume.

In `session_round_trip`, on tokio's paused clock: on a link of 50 ms the spare opens 1.0 to 1.2 s
after a question that nothing answers; before any answer, 3.0 to 3.2 s; a link whose answers take
1.1 s gets none; a tick of the clocks 3 s late sends a `PING` at once; a link that died in a sleep
gets its spare 1.0 to 1.2 s after the wake. `relay_wake`: the forward road's Ping at a late tick,
and the notice's question counted from it. The planted defects: `spare_after` that gives
`SPARE_AFTER` always (the first test fails at 3 s); one that gives `SPARE_SOONEST` always (the
slow link gets a spare); `Wake::tick` that gives `None` always (the last two tests, and
`relay_wake`). The resume after the stand-in proxy's `--move` (T-305's measurement, 3.0 to 3.2 s
with the fixed bound): `cargo test -p podssh-cli --test roam_at_once -- --ignored --test-threads 1
--nocapture measure`.

## Correction

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test targets
`session_round_trip`, `session_spare`, `session_heartbeat` moved to `pod-session` with their names;
run `cargo test -p pod-session --test session_round_trip` `cargo test -p pod-session --test
session_spare` `cargo test -p pod-session --test session_heartbeat` there.

## Done

2026-11-04, merged from its draft (`5cabd12`).

- `crates/podssh-ws/src/wake.rs`: the tick of the clocks (`Wake`, `Reading`, `slept`): a tick more
  than 2 s late by tokio's clock, or by the time that the host slept (CLOCK_BOOTTIME against
  CLOCK_MONOTONIC on Linux, else the wall clock), is a wake. `PodUtils/podssh:crates/podssh-relay/src/session/round_trip.rs`:
  the smoothed round trip of each link, from one `PING` and one batch of `DATA` at a time;
  `session/beside.rs`: `spare_after`, three round trips, 1 s to 3 s, and a `PING` on the old link
  when a spare opens; `session/pump.rs`: a `PING` at a wake. `crates/podssh-ssh/src/relay_stream.rs`:
  the forward road's Ping at a wake. The manual, `docs/design.md`, `docs/terminal.md`,
  `docs/cli.md` and `docs/STATUS.md` say it.
- `cargo test -p podssh-relay --features pair --lib session`: 21 passed; `--test
  session_round_trip --test session_spare --test session_heartbeat`: 5, 3 and 4 passed; `cargo
  test -p podssh-ws --lib wake`: 5 passed; `cargo test -p podssh-ssh --test relay_wake`: 1
  passed. The relay crate with `pair` and podssh-ws whole: 971 passed, 0 failed. `cargo test -p
  podssh-cli --lib man::` 40, `--test man_page --test man_flag_parity --test node_moves --test
  roam_at_once`: 11, 6, 2 and 1 passed. Clippy clean (podssh-relay with `pair`, podssh-ws,
  podssh-ssh); rustfmt clean.
- Planted by hand: `spare_after` fixed at 3 s fails 2 tests of `session_round_trip`; `Wake::tick`
  that never says a wake fails 3 tests of `wake` and `relay_wake`.
- Measured, `cargo test -p podssh-cli --test roam_at_once -- --ignored --test-threads 1 --nocapture
  measure`: after a new address of the client, the pair's road with a spare link resumed after
  1.0, 1.0, 1.0, 1.1 and 1.0 s, where T-305 measured 3.0 to 3.2 s; with no spare link, 35 s.

# T-632: The resumable layer has no record that ends one direction, so a half-close ends the whole session where no channel runs above it

**Source:** GitHub #130 (Nemo-010, 2026-11-04); the operator's ruling Q100.
**Category:** feature
**Milestone:** none
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

A client that writes a request, shuts its writing side and waits for the answer loses the answer on the
resumable layer: the layer's only end is `CLOSE`, the end of the session, so the far end's reply after
the end of the request is never carried. The channel above the layer has an end of one direction; the
layer's own sessions with no channel do not.

## Premise

Read at `2042200`:

- The channel's end of one direction: `PodUtils/podssh:crates/podssh-relay/src/e2e/frame.rs:13` says "The clean end of
  one direction.", and `PodUtils/podssh:crates/podssh-relay/src/e2e/channel.rs` at `cbaa806`, line 128 says "The stream stays open: the
  peer's bytes may still come." The issue's line numbers of `channel.rs` are of an older tree.
- The layer: `PodUtils/podssh:crates/podssh-relay/src/session/record.rs:62` says "pub const CLOSE: u8 = 0x0a;", the
  end of the session; `PodUtils/podssh:crates/podssh-relay/src/session/pump/up.rs:84` says
  "Ok(0) | Err(_) => return None,", and `PodUtils/podssh:crates/podssh-relay/src/session/pump.rs:356` says "The
  application ended its bytes: the writer sends the", then `CLOSE`, which the peer answers with its
  own: the peer's later bytes are not asked for.
- Sessions of the layer with no channel above it: the relay role's road for a standard sshd
  (`crates/podssh-relay/src/serve/layer.rs:1-8`), which `proxy` and `ssh` take unasked for a relay
  host that the user named and that offers it (Q96, `docs/decisions.md:36`); and a node's sessions with
  `--no-e2e` (`crates/podssh-cli/src/flags/node.rs:144`).
- The plain forward road keeps a half-close: `crates/podssh-relay/src/serve/forward.rs:290-293` shuts
  the target's writing side at the client's Close and goes on, as the default relay does
  (`docs/relay.md:530-533`). So `podssh proxy` to a target that reads until its end loses the answer on
  the layer road where it gets it on `/connect/` (Inferred from the code; not measured).
- The layer names its features in its handshake (`PodUtils/podssh:crates/podssh-relay/src/session/record.rs:9-10`), and
  `PodUtils/podssh:crates/podssh-relay/src/session/mod.rs:76` says "pub const FEATURES: &[&str]": a new record goes only
  to a peer that names its feature. The issue proposes the node's `hello`, which is the reverse road's
  control, not the layer's.

## Approach

1. A record `END` (`0x0c`), whose body is the offset of the end of this side's bytes, and a feature
   `end.v1` in `GREETING` and `OPEN`; a peer that does not name it gets today's `CLOSE`.
2. With both sides naming it, a read of 0 sends `END` after the last `DATA` and keeps the session; the
   peer shuts its application's writing side at the `END` and goes on reading; when each side has sent
   and received its `END`, the session ends with `CLOSE` as today.
3. `END` is replayed as `DATA` is, from its offset, so that a resume after a loss carries it; a link that
   ends with no `END` and no `CLOSE` stays a loss (`End::Lost`), as now.
4. `docs/design.md` (section 5), the table of `PodUtils/podssh:crates/podssh-relay/src/session/record.rs`, and
   `docs/relay.md` ("The relay role's resumable layer") say the record.

## Decision

2026-11-04 (the drafting agent of T-632). No row of `docs/decisions.md` settles these, and none
changes one.

1. **A far end of this build names `end.v1` in each `GREETING`; a client names it in its `OPEN` only
   where its settings ask** (`Settings::half_close`, `PodUtils/podssh:crates/podssh-relay/src/session/half_close.rs`),
   as `once.v1` goes (T-612). `podssh proxy` on the relay role's road asks; `podssh ssh`, the
   copies, `podssh operator` and `podssh proxy node://` do not: SSH above the layer, and the
   end-to-end channel with its own `END` (T-088), end both ways at once, so `END` would only add a
   record and a wait at each end. Lost: `end.v1` in `FEATURES` and `SHELL_FEATURES` for each client
   (each road's end would change, and a client whose application closed both ways would hold its
   session until the far end's application ended); a far end that names it by a setting (each far
   end of this build takes it, and the client's ask decides); the node's `hello` as the issue
   proposes (the reverse road's control, not the layer's, and the role's road has none). A client
   of `operator` to a node with `--no-e2e` can ask later, by the same setting, where a tester needs
   it.
2. **The second side's end is its `CLOSE`, not an `END` and then a `CLOSE`**: a `CLOSE` after the
   last `DATA` says as much, and the session ends when it is answered, as before. Where the two
   `END`s cross, each side has sent and received one, its `CLOSE` is due, and each answers the
   other's, as two `CLOSE`s crossed before. Lost: the Approach's `END` from each side and then a
   `CLOSE` (a record and a round trip more, for nothing that the `CLOSE` does not say).
3. **A read of the application that fails is the end of the whole session, `CLOSE`, never `END`**: an
   application that is gone reads nothing more, and a target that reset its connection is gone both
   ways. `podssh proxy` fails its reads at a signal (`crate::hangup::ending_wholly`), so OpenSSH's
   SIGHUP still makes the role forget the session at once (T-586). Lost: `END` at each end of the
   application's bytes (a role would hold a session whose target reset until its client wrote, and
   a signal would leave the role's session to its target's end, or to the deadline).
4. **`END`'s body is the offset after the sender's last byte**, as the Approach says: the receiver
   takes it at its received offset alone (one past it is a gap, one below it bytes after the end),
   once, and `DATA` with a byte past it is refused. Lost: an empty body, as the issue proposes (no
   check that each byte came before the end).
5. **`END` is said again on each new link, not kept in the replay buffer**: the buffer keeps bytes,
   and the state of the session says that the application ended, so each link sends `END` after the
   bytes that it sends again, and the peer takes it once. An application that ended its bytes on an
   earlier link is not read again, as a terminal's input waits after its end. Lost: `END` as bytes
   of the buffer (an offset of its own, which the acknowledgements would count).
6. **The peer's `END` shuts the application's write side once it wrote each byte before it, and the
   reader goes on meanwhile**, on whichever link that happens: a shut at the record, or a wait for the
   bytes before it, would stop the reader on a slow application, as T-387 found.
7. **`podssh proxy` ends its stdin at the target's end too, where `END` is agreed**
   (`crates/podssh-cli/src/relay_layer/half.rs`): the session ends with the target, as on the
   contract's road and before T-632, and a program that keeps stdin open (a terminal) is not left
   with a proxy that waits on it. With a role of an older build, stdin keeps receiving after its end,
   as since T-173. Lost: stdin read on after the target's end (TCP's own half-close, which no user of
   `podssh proxy` asked for); `END` behind a flag (the issue's case is the plain use).
8. **The feature holds from the session's first handshake**: a resume's `OPEN` names the features as
   before, and each end keeps the session's state, as for `replay.v1`. Lost: `end.v1` in each
   resume's `OPEN` (nothing reads it there).
9. **The role's test of the road is in `session_relay_resume`**, beside the road's other tests, not in
   `relay_serve_contract`, whose tests are of the contract's `/connect/`.
10. **A signal after the end of stdin finds its `END` gone, and adds no `CLOSE`**: OpenSSH closes its
    ProxyCommand's stdin, then sends it SIGHUP, so `podssh proxy` most often sends `END` first; the
    session then ends with its target, which an sshd does at once at the end of its input (the
    role's `CLOSE` comes back within a round trip, inside the 2 s after a signal), and a target that
    ignores the end of its input keeps the role's session as a loss for its deadline once the client
    is gone. Lost: a pump that reads its application on after its end, to see a signal (a read at
    the end returns at once again, so the pump would spin); a signal that writes into the session
    (nothing is written when the target is silent).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-relay --test session_half_close
cargo test -p podssh-relay --test session_codec --test session_end --test session_resume
cargo test -p podssh-relay --lib session::
cargo test -p podssh-relay --features serve,plain-ws --test session_relay_resume
cargo test -p podssh-cli --lib -- relay_layer hangup
cargo test -p podssh-cli --test relay_serve -- serve_layer
sh scripts/plant-each.sh --here t632-end-read-as-close t632-end-not-sent-again t632-proxy-asks-no-end \
  t173-stdin-end-closes
```

A side whose application ended its bytes still gets the peer's answer, then the session ends; a peer
with no `end.v1` ends as before; an `END` lost with its link comes again after a resume; through the
role's layer road, a request, its end and the reply after it reach a target that answers at its
input's end; `echo QUERY | podssh proxy` through `podssh relay serve` gets the answer of a target that
answers at its input's end. Planted: `END` read as `CLOSE`, and the test of the answer after the end
fails; no `END` again after a resume, and the test of a lost `END` fails; `podssh proxy` asking for no
`END`, and its test fails; T-173's plant, rewritten for this tree, caught again.

## Correction

2026-11-04 (the drafting agent of T-632). Read in this tree before the draft:

- The Premise's role "goes on" after the client's Close, as the default relay does: it does not. At
  the client's Close the role's `/connect/` shuts the target's writing side and its `up` returns
  `End::Client` (`crates/podssh-relay/src/serve/forward.rs:293` says "return End::Client;"), which
  ends the `select!` of the session (`crates/podssh-relay/src/serve/forward.rs:359-360`): the target's
  later bytes are not carried, where the contract says that they come until the target closes or is
  idle for 15 s (`docs/relay.md:530-533`). That is a difference of the role from the contract, outside
  this entry; the main session files it at the merge. And `podssh proxy` sends no Close at the end of
  stdin on `/connect/` (`crates/podssh-cli/src/proxy.rs:9` says "End of stdin stops sending but keeps
  receiving"), so there the target never gets the end of its input either: `echo QUERY | podssh proxy`
  to a target that answers at its input's end waited on both roads, on the layer since T-173's repair
  (`relay_layer::KeepsReceiving`), until the target's idle. The Approach holds; the layer's `END` is
  the first half-close that `podssh proxy` has through a relay.
- The Approach's second item ends the session with a `CLOSE` after each side sent and received an
  `END`; the second side's end is its `CLOSE` instead (the `## Decision`, item 2).
- The Prove's role test is in `session_relay_resume`, not `relay_serve_contract` (the `## Decision`,
  item 9), and the Prove above names the new targets and the plants.
- `PodUtils/podssh:crates/podssh-relay/tests/session_codec.rs` refused type `0x0c` as unknown; it now decodes `END`, and
  the test refuses `0x0d`.

2026-11-10, the take of `pod-session` (PodUtils/podcrates `v0.15.0`): the test targets
`session_half_close`, `session_end`, `session_resume` moved to `pod-session` with their names; run
`cargo test -p pod-session --test session_half_close` `cargo test -p pod-session --test session_end`
`cargo test -p pod-session --test session_resume` there.

## Done

2026-11-04, merged from its draft (`2aa4813`).

- The layer's `END` (`0x0c`, the offset after the last byte) and its feature `end.v1`: each far end
  names it, and a client asks for it where `Settings::half_close` says so, which `podssh proxy` on
  the role's road does; an older peer never gets `END`. The writer sends `END` after its last
  `DATA` and goes on; the reader shuts the application's write side once each byte before the
  peer's `END` is written; the side that ends second sends `CLOSE`; an `END` that its link lost is
  said again after a resume. `podssh proxy`'s stdin is the layer's `END`, and the target's end ends
  stdin too (`crates/podssh-cli/src/relay_layer/half.rs`). The manual, `docs/design.md`,
  `docs/relay.md`, `docs/cli.md` and `docs/STATUS.md` say it.
- `cargo test -p podssh-relay --test session_half_close --test session_codec --test session_end
  --test session_resume`: 15, 4, 8 and 3 passed; `--lib session::`: 15 passed; `--features
  serve,plain-ws --test session_relay_resume`: 6 passed (at the merge its two digests are written
  in hex by hand, as sha2's array has no `LowerHex`); `cargo test -p podssh-cli --lib --
  relay_layer hangup`: 10 passed; `--test relay_serve`: 22 passed. The relay crate with `pair`: 516
  passed. Plants: `t632-end-read-as-close`, `t632-end-not-sent-again`, `t632-proxy-asks-no-end` (at
  its 60 s bound) and `t173-stdin-end-closes` caught. Clippy and rustfmt clean.
- The draft found that the role's `/connect/` drops a target's bytes after the client's Close, where
  `docs/relay.md` says they still come: T-671.

# T-682: M6's check of a stall of 3 minutes on the iroh road hung after its resume, once in CI

**Source:** the gate of `cbaa806`, step `m6`, 2026-11-05.
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** M
**Status:** done

## Problem

`the_iroh_road_survives_a_stall_of_3_minutes` (`crates/podssh-cli/tests/m6_exit.rs`) failed once in
the gate of `cbaa806`: the client said "the session resumed after 168.6 s, 1148361 bytes sent again",
then the session did not end within 600 s. The code was the code of `07e65ed`, whose gate passed, and
the check passed in each of the four gates since T-666 put the sessions of one process on one iroh
connection; here it passed 3 runs of 3 (195 to 211 s). The failure showed the client's lines and the
proxies' alone, so where the session hung is not known.

## Premise

- `crates/podssh-cli/tests/m6_exit.rs` at `96ad598`, line 378, read the node's stderr into a channel
  for its ticket alone; a check that failed printed the logs of the session's directory, which held
  no line of the node.

## Approach

1. The node's lines after its ticket go to `node.log` in the session's directory, which a failure
   prints (done, 2026-11-05).
2. At the next failure, read where the session hung (the client's link after its resume, the node's
   lane of T-666, the layer's replay), repair it, and run the check 20 times on a runner.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --features iroh-test --test m6_exit -- --ignored --test-threads 1 the_iroh_road_survives_a_stall_of_3_minutes
```

20 runs in a row on a runner, each within its bound.

## Done

2026-11-13: `suite-repeat.yml` (run 43343098264, at `d5403f7`, `ubuntu-24.04`), package podssh-cli with the feature
`iroh-test`, test `m6_exit`, the ignored `the_iroh_road_survives_a_stall_of_3_minutes`, 20 runs in a row: 0 of 20
failed, each within its bound. The hang of the gate of `cbaa806` did not come back; Approach item 1 keeps the node's
lines in `node.log`, so a failure of the gate's step `m6` now says where the session hung, and that failure would
open a new entry with them.


# T-703: A `cf://HOST` node that greets with the resumable layer warns about the SSH keepalives that the user set

**Source:** GitHub #172
**Category:** defect
**Milestone:** none
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

With `ServerAliveInterval` set, a `cf://HOST` run whose far end greets with the layer keeps SSH's
keepalives and prints no line. The keepalives end a session after `ServerAliveCountMax` probes with
no answer, also while the layer would carry it onto a new link. `node://NAME` prints a warning for the
same setting.

## Premise

- Read, at `47e1eba`: `crates/podssh-cli/src/ssh/resolve.rs:339` decides `resumable` from
  `Transport::Node`, `Transport::Iroh` and `Transport::Derp`. `Transport::Cloudflare` is not in the
  list.
- The warning at `crates/podssh-cli/src/ssh/resolve.rs:351-356` sits inside `if resumable`.
- `crates/podssh-cli/src/ssh/cloudflare.rs:167` branches on `greeted.layer()`;
  `crates/podssh-cli/src/ssh/cloudflare.rs:201` returns `layer: Some(done)`. The greeting is known
  only after the connection, so the list at `resolve.rs:375` cannot decide it.
- The guard at `crates/podssh-cli/src/ssh/tries.rs:52` removes the keepalives only when
  `resolved.alive_default` holds, which `crates/podssh-cli/src/ssh/resolve.rs:444` sets when the user
  named no interval.
- T-300 chose "SSH's keepalives off there unless `ServerAliveInterval` is given"
  (`TODO/roads.md:2031-2032`). T-154's Correction (`TODO/resume.md:891-895`) says that the resumable
  road is `node://` alone; T-300 made that sentence false.

## Approach

1. At the guard of `crates/podssh-cli/src/ssh/tries.rs:52`, add the case `reached.layer.is_some()` with
   `!resolved.alive_default` and a keepalive interval that is set. Print the warning of
   `resolve.rs:389-391` there, once, from one shared constant.
2. Keep the user's interval. Do not add `Transport::Cloudflare` to `resolve.rs:375`: a far end that
   greets with no layer would then lose its keepalives and get a false warning.
3. Check the other roads that can greet with the layer (the carrier road, `--exit` over a carrier,
   `Transport::Cloud`, the jump tunnels). Give each the same warning, or write in this entry's
   `## Done` why it needs none.
4. Add a `## Correction` to T-154 that names `cf://` and T-300, as the sentence at
   `TODO/resume.md:891-895` stays as it was written.

## Decision

Q-172 (the call of the triage, 2026-11-09): warn only, and keep the user's explicit interval, as
T-154 ruled for `node://`. `AliveInterval 0` stays the way to switch the keepalives off.
Lost: taking the explicit interval away on a road with the layer. It overrides what the user asked
for, and it differs from `node://`. Lost: adding `Transport::Cloudflare` to the road list. The list
is read before the greeting, so it warns falsely for a far end with no layer.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test cloudflare_layer_alive
```

New tests in `crates/podssh-cli/tests/`, with a stand-in far end on the loopback: a layer and
`AliveInterval 30` gives one warning and the interval stays; a layer and no interval gives no
keepalives and no warning; a far end with no layer gives no warning and the user's keepalives;
`node://NAME` with `AliveInterval 30` prints its warning as before. The test target name is a
proposal; the entry's `## Done` names the real one.

## Done

Partial, 2026-11-09: drafted (DRAFT T-703, `87fb686f`) and merged by the main session, with one
repair: the guard moved from `tries` into `layer_alive::apply`, as rustfmt took `ssh/mod.rs` past
500 lines.

- The warning text is one constant, `layer_alive::WARNING` (`crates/podssh-cli/src/ssh/layer_alive.rs`);
  `resolve.rs` uses it for `node://`, iroh and DERP, and the guard of each try that reached its far end
  (`layer_alive::apply`, from `tries` in `crates/podssh-cli/src/ssh/mod.rs`) warns once, on the first
  try, when the far end greeted with the layer, the user named an interval and `resolve` did not
  already warn. A run with no interval named drops SSH's keepalives, as before. Each road reaches
  `apply` through `tries`. A defect found on the way, repaired: `--persist` reached its far end in a
  loop of its own (`ssh/persist.rs`, `one`) that never dropped SSH's keepalives for the layer, nor
  warned; it calls `apply` too. `--test persist`: 7 passed.
- `cargo test -p podssh-cli --lib`: 1,014 passed, with `layer_alive::tests` (6). Planted, no `Warn`,
  `a_layer_and_an_explicit_interval_warn_once` fails. `--test cloudflare_cli` and `--test node`: passed.
  The Correction of T-154 is added.
2026-11-10: the loopback test of the Prove.

- `crates/podssh-cli/tests/cloudflare_layer_alive.rs` (the proposed name `cloudflare_layer_alive` held),
  five tests, each a `podssh ssh cf://tester@lab.example.test greet` as a process, through a stand-in
  edge in the test: a proxy that takes `CONNECT lab.example.test:443` (`HTTPS_PROXY`, as the road reads
  it) and joins it to a TLS server of the test's own CA (`--ca-file`; the acceptor of
  `tests/update_support`), which takes the WebSocket upgrade at `/` and hands its frames as bytes
  (`podssh_relay::quick::visitor::websocket`, as the quick tunnel's origin does) to a far end. The far
  end is a node's: `Layered<E2e<TcpHandler>>`, the resumable layer with the end-to-end channel above it,
  in front of the tests' SSH server, as `node_quick.rs` serves each visitor; or, for the case with no
  layer, the SSH server's bytes as they are, as `cloudflared`'s service gives them.
- They assert: a layer with `-o ServerAliveInterval=30`: exit 0, the greeting on stdout, the line "the
  far end greets with the resumable layer", the warning once, and no "no SSH keepalives" line (the
  interval stays); a layer with no interval: no warning, and the verbose line that the keepalives are
  dropped; a layer with `ServerAliveInterval=0`: no warning; a far end with no layer and the interval
  30: no warning, no dropped line, the session works; `node://lab` with the interval 30, offline: the
  same warning once, from the one constant.
- Measured: `cargo +1.99 test -q -p podssh-cli --test cloudflare_layer_alive`: `test result: ok. 5
  passed`, 0.5 s, three runs in a row. Planted (`decide` answers `Keep` where it answered `Warn`): the
  first test fails, the other four pass; reverted.

# T-789: The resumable layer comes back about 12.5 s after a cut of 15 s ends, where TCP alone can in under 1 s

**Source:** T-786's outage cell (`feel-netem.yml` run 43709370293, #258).
**Category:** defect
**Milestone:** M10
**Priority:** P2
**Effort:** S
**Status:** done

## Problem

After a cut of the client's leg of 15 s (netem at 100% loss), a session on the relay role's road with the
resumable layer gave its first byte 12.7 and 12.5 s after the link's return, and caught up 14.1 and 13.5 s after
it. OpenSSH over plain TCP in the same cell gave its first byte 0.77 and 0.43 s after the return; podssh
`--direct`, 0.51 s once and 11.7 s once (TCP's backed-off retransmission). The layer survives the cut, which
osewa does not, but it loses about 12 s where a link that redials at once would lose a round trip.

## Premise

- The spare link of T-305 opens one spare each 10 s at most, after 3 s with nothing from the far end while bytes
  wait (T-305's Decision); since podcrates `v0.45.0` the wait doubles after a spare that moved no byte (podcrates
  T-579, COORD-065, T-781). During a cut each spare moves no byte, so the waits grow, and the first spare after
  the return can come seconds after it. Not yet read: the cell's runs had no `-v`, so the spares' times are
  inferred, not seen.

## Approach

1. Read the times: the outage cell with `-v` for the role's road (feel_outage passes it to podssh), from
   Actions, and the spares' lines against the cut's end.
2. If the doubled wait is the cause: ask podcrates by a COORD issue for a spare whose dial did not connect at all
   (no TCP answer, no TLS) to keep the short wait, so that the doubling stays for a spare that connected and moved
   nothing (T-781's case); `pod-session` is podcrates' (Rule Q3). Take the tag, and run the cell again.
3. The target: the first byte within 2 s of the return, both rounds.

## Prove

`feel-netem.yml` with `shapes=outage` and `roads=role`, from Actions: the first byte within 2 s of the return in
each round, and T-781's tunnels of HTTP still make progress (`last-roads-live.yml`).

## Correction

2026-11-15. The Premise's cause is wrong. The stamped `-v` of `feel-netem.yml` run 43710388009 (#259) showed the first
spare open 11.0 and 13.1 s into the cut, not after the doubled wait of T-579, and close each time as "the link spoke
again", 0.5 and 12.9 s after the return. Reproduced here with the same cell in a private network namespace, the cut
an iptables DROP of the role's TCP port: the spare passes `open_on`, the gate and the mint's turn at once (prints in a
copy of pod-relay `v0.51.0`), and no new TCP socket is made for it (`ss`, `strace`). The spare takes its WebSocket over
HTTP/2 from the process's pool (`h2_road::connect`, `ctx.h2_pool()`), on the very connection that carries the silent
link, so it waits for that connection's retransmission. With `PODSSH_H2=no` the same cut came back 0.40 and 0.19 s
after the return, the spare answering 0.30 and 0.11 s after it; with `PODSSH_H2` unset, 12.7 and 12.6 s. The Approach
becomes: podcrates gives a new link of the layer a connection of its own (COORD-078); podssh takes the tag and runs
the cell again.

Step 1's tool, the same day: `feel_outage.py` runs the role's road with `-v`, and writes each line of the
child's stderr after the seconds since the round's start, with "feel: the cut begins" and "feel: the link is back" on
the same clock (`Stamped`). Here, with a stand-in cut that does nothing: the layer's lines ("opened resumable session",
its heartbeat) and the two marks, stamped, in `role.outage.err`; `--self-test` passed. UNVERIFIED: the run from
Actions (`feel-netem.yml`, `shapes=outage`, `roads=role`): read with the Done below.

## Done

2026-11-15. podcrates `v0.53.0` holds COORD-078's fix (`pod-ws`'s numbered HTTP/2 connections: a link that
replaces another takes only a newer one, and a silent connection leaves the pool), taken with `v0.54.0`. The workspace
passes on it (3837 tests, T-684). The outage cell of the role's road from Actions (`feel-netem.yml`, `shapes=outage`,
`roads=role`, run 43770482263 at `d0ef973`, #275): the first byte 129.7 ms after the return and caught up in 918.4 ms,
then 178.0 ms and 1,042.6 ms, where it was 12.7 and 12.5 s before. Both rounds are within the target of 2 s. T-781's
tunnels of HTTP keep their own rule (no spare links through a third party's tunnel), which this fix does not touch.

# T-833: An attach ticket for a kept shell: who may attach, and replay or reset

**Source:** the donor study of 2026-11-18, report 05 (MisterTea/EternalTerminal at bba566b); the tracker issue is PodUtils/podssh#317.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

T-159 keeps a shell, its pty and its ring after the client leaves, and T-158 attaches again. No rule
says who may attach, and none says what happens when the client's count of received bytes is older than
the ring. EternalTerminal answers the first with a ticket that the owner of the pty mints, and the
second with a reset under an authenticated salt; its running client never asks for the reset, so a gap
that cannot be served repeats every second until the user restarts it.

## Premise

- Read: the resumable layer is `pod-session` of PodUtils/podcrates; podssh keeps a sink and a move
  (`crates/podssh-relay/src/session/mod.rs:1`, `crates/podssh-relay/src/session/handover.rs:1`). Its
  session id and proof name a session, not a pty that a far end keeps.
- Read: T-159 holds the shell, the lease and the limits, T-158 the client's side, T-161 what an attach
  shows. None holds the ticket or the choice of replay or reset.
- Read in the donor report: the process that owns the pty mints the id and a passkey, and the router
  checks the passkey before it hands the terminal out
  (MisterTea/EternalTerminal:src/terminal/UserTerminalRouter.cpp:191-192); an attach carries the
  client's count, and a count that cannot be served makes the server send a fresh salt with a reset bit
  (MisterTea/EternalTerminal:src/base/ServerConnection.cpp:216-238); one reclaim is in flight at a time
  and the second is refused (MisterTea/EternalTerminal:src/base/ServerClientConnection.cpp:42-51).
  The donor's gap: the running client always reconnects with `resetIntent` false
  (MisterTea/EternalTerminal:src/base/ClientConnection.cpp:228).

## Approach

1. In `podssh serve`, where the pty is made (T-159): a 16-byte id and a 32-byte ticket at spawn, held in
   a table of the process; the ticket goes back in the reply that the authenticated session gave. The
   table entry, not the connection, owns the pty, the ring and the lease.
2. The attach carries the ticket and the client's count. A count in the ring: replay from it. A count
   older than the ring, or a request to reset: the server says so with a reset the client can
   authenticate, and sends what T-161 decides (a screen, or a replay from a boundary). The running
   client asks for the reset itself on a gap that cannot be served; no repeat loop.
3. One attach at a time: a second one while the first completes is refused with a word; a later one takes
   over and the old end is told why (T-159's note of 2026-11-18 on tsshd).
4. Decide here whether the ticket is bound to the client's key fingerprint. The donor's ticket is a
   bearer: whoever holds it takes the shell. Recommendation: bind it, and refuse another key.
5. Shared code first: the ticket and the attach record belong to `pod-session`. Ask podcrates by a COORD
   issue; podssh writes only the table of `podssh serve`.

## Decision

2026-11-24, the calls of the draft, each with what lost:

- The ticket is bound to the key, as item 4 recommends, and is nothing more than the key and the name:
  serve finds a kept shell by the fingerprint of the key that logged in and the name, and the shell's
  generation counts its owners (a newer attach takes it; an older channel's input and close count no
  more). No bearer secret is minted. A 32-byte ticket in the reply lost: SSH's SUCCESS carries no
  data (T-158's Correction), so it would go on the channel's stderr, into the terminal's scrollback
  and the user's logs, a credential that `AGENTS.md` keeps out of output; and with the key bound, it
  would prove nothing that the login did not. A bearer ticket alone (the donor's) lost: whoever read
  it would take the shell with any key that the server lets in.
- The id is the shell's `PODSSH_SHELL_ID`, 128 random bits, minted at the start (T-159): the 16 bytes
  of item 1.
- The count is an offset of the shell's output from its start, which `shells@podssh` gives for each
  shell (a third word): where it stands, or where it stood at the detach. A count told on stderr at
  each attach lost: a line in each attach for a number that only a later client needs.
- serve chooses the reset itself: a count that the ring does not hold, a count past the output, or
  `reset@podssh yes`, gives one line on stderr and the ring from its first boundary (T-221); with no
  count, the offset at the detach. The reset is said inside SSH, which authenticates it: a salt of
  its own (the donor's) lost, as podssh's stream has no cipher of its own to reseed.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-ssh --test serve_attach_ticket   # a wrong ticket, replay, reset, a second attach
```

## Correction

2026-11-24, read before the draft:

- Item 5 is wrong: a kept shell is `podssh serve`'s (`crates/podssh-ssh/src/server/kept.rs`, T-159),
  above SSH, and an attach is a new SSH login; `pod-session` carries the stream below SSH and keeps
  nothing of a pty. The ticket and the record of an attach are serve's own, and no ask of podcrates
  is needed.
- Item 1's "the ticket goes back in the reply": SSH's SUCCESS carries no data (T-158's Correction,
  russh's server); the Decision binds the ticket to the key instead.
- Item 2's "the running client asks for the reset itself": serve decides the reset, so a client that
  never asks meets no repeat loop. T-158's client sends no count yet: a client that lost its link
  could give the offset that it has, which T-895 holds.
- Item 3's refusal of a second attach while the first completes is T-159's `joining` state; this
  entry pins it with a test and says it in the manual.

## Done

Drafted 2026-11-24 (not built here; the main session builds, tests and closes it), on T-159's draft.

- The server: `count@podssh OFFSET` and `reset@podssh yes` (`crates/podssh-ssh/src/keep.rs`,
  `kept_ask.rs`); the choice of replay or reset and the reset's line in `kept_replay.rs`, with
  `since` moved there so that `kept.rs` stays under 500 lines; `Shell::join` takes the channel's asks;
  `shells@podssh` gives each shell's offset (`kept_shelf.rs`). The tests' helpers moved to
  `crates/podssh-ssh/tests/kept_harness/mod.rs`, shared with `serve_keep.rs`.
- The manual's note of `serve`, `docs/cli.md`, `docs/terminal.md`, `docs/STATUS.md`.
- Prove: `cargo test -p podssh-ssh --test serve_attach_ticket`: 3 passed (2026-11-24, on the stack at `a64e47d`, Rust 1.99.1). Its tests:
  `the_ticket_is_the_key_and_the_name` (another key and a wrong name refused alike);
  `a_count_in_the_ring_replays_from_there`;
  `a_count_older_than_the_ring_or_a_reset_asked_gives_the_last_output` (more than 256 KiB of output,
  then a count of 0 and `reset@podssh yes`). The second attach while one catches up:
  `cargo test -p podssh-ssh --lib server::kept`
  (`a_second_attach_while_one_catches_up_is_refused`, and the table of
  `a_count_in_the_ring_replays_and_any_other_resets`): passed (in `cargo test -p podssh-ssh --lib`: 509 passed, 2026-11-24, on the stack at `a64e47d`, Rust 1.99.1). `cargo test -p podssh-ssh --test
  serve_keep` again, as its helpers moved: 4 passed.
- Waits: the planted servers (one that replays from a
  count that the ring no longer holds, one that lets another key in) with the release check (T-251). The client's count after a lost link is T-895 (done 2026-11-24).

# T-895: `podssh ssh --attach` gives the offset that it has after a lost link

**Source:** T-833's Correction (2026-11-24): `podssh serve` takes `count@podssh OFFSET` and gives each
kept shell's offset in `shells@podssh`, and T-158's client sends no count.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** S
**Status:** done

## Problem

A client whose link died past the resume deadline, with no `~d`, may have missed output that serve
wrote into the dead channel. A new `podssh ssh --attach NAME` joins at the offset that serve counted
at the loss, so those bytes never show.

## Premise

- Read: serve replays from `count@podssh OFFSET` where its ring holds it, and gives a reset where it
  does not (`crates/podssh-ssh/src/server/kept_replay.rs`, T-833); `shells@podssh` gives each shell's
  offset (`crates/podssh-ssh/src/server/kept_shelf.rs`).
- Read: the client asks `attach@podssh`, `take@podssh` and `from@podssh` only
  (`crates/podssh-ssh/src/keep.rs`), and keeps no count across its processes.

## Approach

1. The client counts the bytes of each kept shell's channel from the offset where its attach started
   (the list's offset, read before the attach), and writes the sum, private, beside its other state
   for that destination and name, when the session ends with no `~d`.
2. `--attach NAME` sends `count@podssh` with that sum when one is kept for the destination and name,
   and `--reset` sends `reset@podssh yes`. A count from another shell of the same name is refused by
   serve's reset, never replayed wrong.
3. The manual's note of `--attach`, and `docs/terminal.md`.

## Decision

2026-11-24, the calls of the draft, each with what lost:

- Where an attach's count starts: the count that it gives. With none kept, the client reads
  `shells@podssh` first, on a channel of its own, and gives the listed offset back as its count, so
  that serve's replay starts where the client's count does, also with `--take` (where serve's own
  start moves with the other client's output). Reading the list and not giving it lost: serve's start
  then moves between the list and the join. Reading it before each attach lost: a round trip for a
  count that the record already has.
- A reset's start: serve's line of a reset names the offset where its replay starts, and the client
  reads it on the channel's stderr, as it reads the size of a part that the ring dropped. A channel
  request of serve's own lost: russh's client answers a request that it does not know and hands it
  to no handler, so it needs a patch of `vendor/russh`. No count after a reset lost: a second loss
  would lose the bytes again. The line is one function for both ends (`keep_count::reset_line`), and a
  table pins its read back.
- The record: one private file of the cache, `kept-offsets.txt`, a line for each far end and shell
  name, the far end known by `accepted::host_id` of its host key and the user, as the keys that hosts
  took are kept (T-664); 64 lines, 30 days, the longest lease. By the destination's words lost:
  `node://lab` can name another far end later, and the host key names this one. By the shell's id
  lost: the client never learns it, as `PODSSH_SHELL_ID` lives in the shell.
- When it is kept: at each end where the shell may still be kept (a lost link, `~.`, a signal), and
  also after `~d`, under the name that the far end keeps the shell as. Only with no `~d`, as the
  Approach says, lost: serve's SUCCESS and close of a detach go out from its handler, while the
  shell's output goes through the handle's queue, so the offset at the detach can be past the bytes
  that the client got (`crates/podssh-ssh/tests/serve_attach_ticket.rs` asserts `>=` for it).
  It is forgotten where the shell ended (a status), where another client took it (no status), and
  where the count is unknown. A session whose count never moved leaves the record as it was: a join
  that serve refuses ends with the status 1 and no output (one while serve still holds the dead
  client's channel, before `--take`), and forgetting there would lose the count that the next attach
  needs.
- `--reset` is a flag of its own, refused without `--attach NAME` (64) as `--take` is. A far end
  that refuses `count@podssh` (one from before T-833) joins as before, and the count is unknown; a
  far end that refuses `reset@podssh` fails the attach, as the user asked for it.

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test attach   # a lost link, then --attach: the bytes after the loss come back
```

## Correction

2026-11-24, read before the draft. The Premise holds: serve's choice is `replay_from` in
`crates/podssh-ssh/src/server/kept_replay.rs`, the list's offset is `Shell::listed` through
`Shelf::lines`, and the client's requests are `ask_attach` in `crates/podssh-ssh/src/keep.rs`. Three
parts of the Approach change:

- Item 1's "when the session ends with no `~d`": after `~d` too (Decision).
- Item 1's start of an attach's count: the list's offset is given back as the count, and a reset's
  start is the offset that serve's line of a reset now names; the line of T-833's draft named none,
  so the client could not know where a reset's replay starts.
- Item 2's "A count from another shell of the same name is refused by serve's reset, never replayed
  wrong": only where the new shell's output does not reach that offset. Where it does, serve replays
  the new shell's output from there, as `replay_from` cannot tell two shells apart by an offset. The
  bytes are the new shell's own, never another's; the record is forgotten when the old shell ends
  while this client has it, and an offset older than 30 days is dropped.

## Done

Drafted 2026-11-24 on T-833's draft; merged, built and tested by the main session (2026-11-24, Rust 1.99.1, on `main` at `71f5af7` with the draft). The merge added a `type` for the cases of `keep_count_tests.rs` (clippy's `type_complexity`), rustfmt's form of one `let ... else`, `llms-full.txt` written again, and the remap of the moved citations.

- The client: `crates/podssh-ssh/src/keep_count.rs` (the counter that the pump feeds, serve's two
  lines and their read, the list's offset, the start and end of a session's count) and
  `crates/podssh-ssh/src/keep_record.rs` (the record, as `accepted.rs` keeps its own, whose
  `valid_host` and `now_ms` it shares); `keep.rs`'s `ask_attach` sends `count@podssh` or
  `reset@podssh` (`Joining`); `session.rs` counts each session to a far end that keeps shells;
  `io.rs` and `io/msg.rs` feed the counter with the output and stderr. serve's reset line names its
  offset (`kept.rs`, `kept_replay.rs`).
- The command line: `--reset` (`crates/podssh-cli/src/flags/attach.rs`, `ssh/args.rs`,
  `ssh/attach.rs`); the record in the cache (`pins.rs`). The manual: the note of `--attach`, the
  T-833 note of `serve`, and a FILES row. `docs/cli.md`, `docs/terminal.md`, `docs/STATUS.md`.
- The stand-in far end of `crates/podssh-cli/tests/keep_harness/mod.rs` counts each shell's output,
  lists the offsets, takes `count@podssh` and `reset@podssh`, and `cut TEXT` writes TEXT into the
  output and ends the connection before it is sent.
- Prove: `cargo test -p podssh-cli --test attach`: 7 passed. Its new test
  `a_lost_link_then_attach_gives_back_the_bytes_after_the_loss` (an attach, a lost link with
  `LOST_ONE` unsent, the record kept; the record removed, and the next attach does not get
  `LOST_ONE`; a lost link with `LOST_TWO`; the next attach gets `LOST_TWO` before its word, and
  nothing before it; its exit forgets the record), and the row of `--reset` alone (64): passed.
  The test's assumption holds: the stand-in layer ends the client's session when its SSH server drops
  the connection, so the client reads a lost link (255) and not a resume.
- `cargo test -p podssh-ssh --lib keep_count` (`serve_s_lines_read_back_to_their_offsets`,
  `the_count_follows_the_output_and_serve_s_lines`, `the_list_gives_a_shell_s_offset`,
  `the_record_reads_back_what_it_kept`, `a_session_s_end_keeps_or_forgets_the_offset`): passed (in `cargo test -p podssh-ssh --lib`, 514 passed).
- `cargo test -p podssh-ssh --test serve_attach_ticket`: against `podssh serve` itself, the client's
  count from the reset's line and the bytes after it equals the listed offset: 3 passed; `serve_keep` 4 passed.
- The manual's and the flags' tests: `cargo test -p podssh-cli --lib` 1279 passed; `man_page` 11, `man_flag_parity`
  6, `man_json` 4, `flag_table` 9 passed; rustfmt and the gate's clippy clean.
- Waits: the
  planted client that gives no count (the replay check of the Prove fails) with the release check
  (T-251); a run against `podssh serve NAME` through the relay, as T-159's Done says.

# T-896: Local echo from end to end, for kept and shared shells, and on the Windows console

**Source:** T-160's close (2026-11-24): its draft names what it does not hold.
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

`podssh ssh --predict` shows a typed key at once where `podssh serve` reports the keys that reached its pty (T-160).
Three cases get no guess: a kept shell (T-159) and a shared shell (T-837) send no report, and the Windows console
is not put in the VT mode that the drawing needs. No test runs the client against `podssh serve` through a slow
link from end to end.

## Premise

- `crates/podssh-ssh/src/server/predict.rs`: "A shared or a kept shell sends none".
- `crates/podssh-ssh/src/predict/draw.rs` draws with `CSI C`, `CSI D` and `CSI X`.
- `crates/podssh-cli/tests/faults.rs` holds the fault harness of T-203.

## Approach

1. A test of podssh-cli: `podssh ssh --predict` to `podssh serve --stdio` through the fault harness's 300 ms; typed
   letters show before the echo, and none at a password prompt.
2. The reports from a kept shell's pty (its count of the attached client's bytes) and from the writer of a shared
   shell.
3. On Windows, the console's VT mode where the console takes it, else no prediction with one line at `-v`.

## Decision

2026-11-24, in the draft (each call with the alternatives that lost).

1. **Step 1's far end is `podssh serve --listen 127.0.0.1:0`**, not `--stdio`: the stand-in relay (T-203) dials a TCP
   target, and `--listen` runs the same server on each connection (`serve_with`), so the test reaches serve by the
   relay's road as a user does. The fault is `delay:150`, each byte 150 ms late each way: the round trip of 300 ms.
   Lost: `--stdio` behind a TCP forwarder of the test's own, a second program in the path that the test would have
   to write; the forward road to a node (`podssh serve NAME`), whose login shells are kept (see the Correction), so
   the test of step 1 would hang on step 2.
2. **What "show before the echo" means in the test**: the client's terminal is a pty of the test, read by the terminal
   oracle (`vt100`) every 5 ms; once the first key of a line was echoed and its report came (the epoch's rule of
   T-160), the keys typed after it show on the cursor's row, underlined, less than 250 ms after the last was typed,
   where no echo can come back in less than 300 ms; once the echo came, no cell of the row is underlined. The
   password: no byte of `qvwy` in what podssh writes after the question (none of them is in a sequence that the
   drawing writes), and the row holds the question alone, for 1.5 s. The control runs the same keys without
   `--predict` and needs them to show 250 ms or more after the last key, so a run whose delay was not there fails.
   Lost: a check of the bytes alone (the guess and the echo are the same letter); a check of the time alone (a
   late echo and an early guess differ only by the underline).
3. **A kept shell's reports belong to each channel, not to the pump.** Each channel that asked (the one that started
   the shell, and each that joins with `--attach`) gets a reporter of its own and a count of its own bytes that
   reached the pty, from 0 at its attach, as the client counts its own; the shell's feed counts each write that the
   pty took. The pump tells the reporter of the channel that has the shell then, after the output that it read,
   taking it out of the shell's state for the write so that no lock is held across it, and putting it back only if
   the same channel still has the shell; at each attach a `Notify` wakes the pump to wait on the new channel's count,
   so a key that makes no output is reported too (`crates/podssh-ssh/src/server/kept_flow.rs`, `Teller` in
   `crates/podssh-ssh/src/server/predict.rs`). Lost: one count of the shell's, set to 0 at each attach, which a write
   of the old channel still in flight would raise past what the new client sent; reports from the channel's own
   task, which would not follow the output that the pump read before them; reports while an attach catches up,
   whose output is the replay and not the pump's.
4. **The shared shell (T-837) waits**, as the rest of step 2 (the Done says what is left). Its seats read the output
   through a broadcast that each seat's task copies at its own pace, so a report of a seat must ride the broadcast
   in its place among the output, or it can come before the echo that it counts; that changes the hub of
   `crates/podssh-ssh/src/server/share.rs`, its seats' writers through the lease, and the ask of a seat, which has no
   pty of its own (`predict_ask.rs` takes the ask only on a channel's own pty).
5. **The Windows console's mode is read back, not assumed**: raw mode already asks for
   `ENABLE_VIRTUAL_TERMINAL_PROCESSING` (`terminal/windows.rs`); the client reads the output's mode after it
   (`terminal::vt_output`), and where the flag is not there (an old console refused it), no guess shows, with one
   line at `-v`. A terminal that is not a console (mintty's pipe) reads VT itself. Lost: a second `SetConsoleMode` of
   local echo's own, which raw mode already made; a guess drawn with the console API (`SetConsoleCursorPosition`),
   a second drawing that the far end's bytes, VT sequences on the same console, would not take off.
6. **Shared code first.** Each piece is podssh's: the reports are a word between podssh's client and `podssh serve`,
   the kept and the shared shells are serve's, and `pod-term` at `v0.82.1` holds no screen model or predictor (its
   `docs/design.md`); the console's mode is podssh's raw mode. No ask is filed.
7. **A shared shell's reports ride its broadcast, one item for output and the reports after it** (the draft `d-t896b`).
   Each item of the hub's broadcast is `Said { bytes, told }`: the output, then each asking seat's report at the
   moment after it, made under the output's lock by the one task that reads the tty, after the output that it read. A
   count that falls due with no output is an item with no bytes from the same task (`Ticks`: the pump's `Teller` on a
   kernel pty, a branch of the discipline's loop on serve's own tty). Each seat's view writes its report after the
   item's bytes, once per change; a seat that lags skips to an item that holds the counts of now
   (`crates/podssh-ssh/src/server/share_told.rs`). Lost: a report task of each seat's own, which can pass an echo
   still in the broadcast or in the pump; a report as an item of its own after each output item, which doubles the
   items and fills the 64 of the backlog twice as fast; reports only where they changed, which a lagging seat would
   lose until its next key.
8. **Each seat counts its own bytes at one place, the lease**: `write_leased` counts the bytes of the seat that holds
   the lease, from 0 at its seat, as its client counts them. On a kernel pty a byte counts once the master took it. On
   serve's own tty it counts once the discipline read it: the lease notes each write's seat and length, in the order
   of the discipline's input, and the discipline's input (`Taken`) gives each seat its part of each read; the same
   loop writes the echo before its next tick, so no report passes it. Lost: a count at the lease's write into the
   discipline's pipe, which a tick can pass while the discipline is busy; a count by the discipline of its own, which
   does not know whose byte it read.
9. **The owner's reports ride the same broadcast**, read by a task of the owner's: its output reached its channel
   before the item was made, so each report follows it, on each tty alike. Lost: the owner's reports from the pump's
   `Teller` (`Own`), which serve's own tty has no pump for; a report written inside the `Tee`'s `poll_write`, a second
   write of another stream inside a write.
10. **The ask on a seat**: a login under the `rw-` name takes it after its `pty-req` (its size is all it has), before
    its shell request; a watcher's is refused, as its keys go nowhere and no report could count them. The owner's is
    taken on a pty of serve's own, and on serve's own tty only under `--share`; a command there is not shared and
    sends none, and its client then shows no guess, as it shows none before the first report. Lost: a watcher that
    takes the ask and gets reports of 0, which tell its client nothing; the owner's ask on serve's own tty without
    `--share`, which no report would follow.
11. **The flags of serve's own tty come from the discipline**: always ECHO and ICANON on the line discipline (T-111),
    whose program on pipes cannot turn either off; under `notify` the lflag of the termios state that serve answers
    the child from. The ticks wait while `notify` holds the output (Ctrl-S), whose echo would come after them. Lost:
    the cooked discipline's own state (`pod_term`'s is private to its crate, and it has no ECHO to turn off).

## Prove

```sh
export CARGO_BUILD_JOBS=4
cargo test -p podssh-cli --test predict_e2e
cargo test -p podssh-ssh --test serve_predict_kept --test serve_predict --test serve_keep
cargo test -p podssh-ssh --test serve_predict_share --test serve_share
```

## Correction

2026-11-24 (the draft). The Premise holds at `1c513c2`: `crates/podssh-ssh/src/server/predict.rs` said "A shared or
a kept shell sends none", `crates/podssh-ssh/src/predict/draw.rs` draws with `CSI C`, `CSI D` and `CSI X`, and
`crates/podssh-cli/tests/faults.rs` holds the harness. The Problem is larger than it says: under `podssh serve NAME`
each login shell may be kept (`--keep-lease` defaults to a day, `crates/podssh-cli/src/serve_keep.rs`), so it took
the kept path of `crates/podssh-ssh/src/server/pty_child.rs`, and `podssh ssh --predict node://NAME` to a login shell
showed no guess at all; only a command, or a shell under `--stdio` or `--listen`, got reports. Step 1's `podssh serve
--stdio` is `--listen` (Decision 1).

## Done

2026-11-24, drafted on the branch `d-t896`; merged by the main session on `main` after `25ac08f`, built and tested
(Rust 1.99.1). Partial: steps 1 and 3, and the
kept shell of step 2; the shared shell of step 2 is left. It holds:

- Step 1: `crates/podssh-cli/tests/predict_e2e.rs`, two tests: `podssh ssh -t --predict` in a pty through the
  stand-in relay's `delay:150` to `podssh serve --listen`: the keys after a line's first show, underlined, before any
  echo can come back, then the far end's row with no underline; at a password with no echo no key shows in any byte,
  and the far end reads 4. The control without `--predict`: the keys show only after the round trip.
- Step 2, the kept shell: `crates/podssh-ssh/src/server/kept_flow.rs` (the feed, the output and `watch_close` moved
  out of `kept.rs`, which was at 498 lines, with the reports: `reports_for`, `Shell::tell`, `falls_due`), `Teller` in
  `crates/podssh-ssh/src/server/predict.rs`, `pump_told` of `server/child.rs` on a `Teller`, the wiring in
  `server/kept_run.rs` and `server/kept_join.rs`, the wake at an attach in `server/kept.rs`; the test
  `crates/podssh-ssh/tests/serve_predict_kept.rs` (each channel's own count, after the echo; a first channel that did
  not ask gets none; a key with no echo is reported to a channel that joined).
- Step 3: `terminal::vt_output` (`crates/podssh-ssh/src/terminal/mod.rs`, `unix.rs` and `windows.rs`) and
  `predict::drawable` (`crates/podssh-ssh/src/predict/mod.rs`), asked in `crates/podssh-ssh/src/session.rs`.
- The manual's note (`crates/podssh-cli/src/man/notes_predict.rs`, and `llms-full.txt` by hand at 79 columns),
  `docs/terminal.md` ("A kept shell", "The Windows console", "From end to end"), a row of `docs/STATUS.md`, and the
  citations of `TODO/` to the files changed, moved as `cargo todo remap` moves them (by a diff of each file).

Results (2026-11-24, Rust 1.99.1):

- `cargo test -p podssh-cli --test predict_e2e`: passed, both tests ran here (a pty, Python and openssl present):
  `typed_letters_show_before_the_echo_and_a_password_never_shows` and its control
  `without_predict_a_key_shows_only_after_the_round_trip`, 8.3 s.
- `cargo test -p podssh-ssh --test serve_predict_kept`: 2 passed.
- `cargo test -p podssh-ssh --test serve_predict --test serve_keep --test serve_attach_ticket --test serve_share`
  (the pumps and the kept shells that changed): 3, 4, 3 and 6 passed.
- `cargo test -p podssh-ssh --lib server::` and `--lib predict::`: passed, in `--lib`'s 537.
- `cargo test -p podssh-cli --lib man::`, `--test man_page`, `--test man_json`; `llms-full.txt` against the manual's
  own writer: passed; `llms.txt` and `llms-full.txt` written again by the binary.
- The Windows build (`cargo check -p podssh-ssh --target x86_64-pc-windows-msvc`, or the gate's `windows` job):
  waits for the gate's `windows` job; `kept.rs` and `kept_join.rs` build there, with the reports a type of no value (`Told`).
- rustfmt and the gate's clippy: clean. The whole suite (with T-820's exit codes merged beside it): 427 suites, 4272
  passed, 3 failed (`job_far`, at this container's stand-in of `rm`, as before).

2026-11-24, the shared shell of step 2 drafted on the branch `d-t896b` (Decisions 7 to 11), not built:

- `crates/podssh-ssh/src/server/share_told.rs` (new: `Said`, `Tells`, `Ticks`, `Taken`, `SeatTold`, the owner's
  reports), `crates/podssh-ssh/src/server/predict_count.rs` (new: `Applied` moved out of `predict.rs`, so that the
  seats count on each system), the hub's broadcast of `Said` and the count at the lease in
  `crates/podssh-ssh/src/server/share.rs`, the views and `offer_tty` in `crates/podssh-ssh/src/server/share_view.rs`,
  `Teller::Shared` in `crates/podssh-ssh/src/server/predict.rs`, the ticks in the loops of
  `crates/podssh-ssh/src/server/line.rs` and `crates/podssh-ssh/src/server/notify/run.rs`, the flags of `notify` in
  `crates/podssh-ssh/src/server/notify/mod.rs`, the shared pump in `crates/podssh-ssh/src/server/pty_child.rs`, the
  ask on a seat in `crates/podssh-ssh/src/server/predict_ask.rs`.
- Tests: `crates/podssh-ssh/tests/serve_predict_share.rs` (on each tty that the host gives: the owner and a writer
  that asked each get their own count, each report after the echo of each key that it counts; a writer that did not
  ask and a watcher get none, the watcher's ask refused; a key with no echo is reported to the seat that typed it);
  `share_told_tests.rs` (the count at the discipline's read, a change told once, the wait) and a case of
  `share_tests.rs` (the reports ride the broadcast after the output, and a tick once).
- The manual's note (`crates/podssh-cli/src/man/notes_predict.rs`, and `llms-full.txt` by hand at 79 columns),
  `docs/terminal.md` ("A shell shared by name"), the row of `docs/STATUS.md`; the citations of
  `crates/podssh-ssh/src/server/mod.rs` in `TODO/serve.md` moved by hand as the remap would move them.

Results (2026-11-24, Rust 1.99.1, merged by the main session on `main` after `4d76d55`):

- `cargo test -p podssh-ssh --test serve_predict_share`: 2 passed.
- `cargo test -p podssh-ssh --test serve_share --test serve_predict --test serve_predict_kept`: 6, 3 and 2 passed.
- `cargo test -p podssh-ssh --lib server::share` and `--lib server::predict_count`: passed, in `--lib`'s 547.
- `cargo test -p podssh-cli --lib man::`, `--test man_page`; `llms-full.txt` against the manual's writer: passed; `llms.txt` and `llms-full.txt` written again by the binary.
- The Windows build (`share_told.rs` and `predict_count.rs` build there, unused): `cargo check --locked --tests --target x86_64-pc-windows-gnu`, clean.
- rustfmt and the gate's clippy; `cargo todo check`; `python scripts/check-repo.py`: clean. The whole suite: 428 suites, 4285 passed, 3 failed (`job_far`, at this
  container's stand-in of `rm`, as before).

The planted defects wait for T-251: a pump of a kept shell that tells the first
channel's reporter after a join, a client that draws on a console whose VT mode was refused, and a seat's report
told from a task of its own (not in the broadcast), which `serve_predict_share` must fail.

# T-901: A fresh attach to a shell at a still prompt, and a seat of `--share`, find their screen

**Source:** T-161's measure (2026-11-25, `docs/terminal.md`, "Screen on attach")
**Category:** feature
**Milestone:** backlog
**Priority:** P3
**Effort:** M
**Status:** done

## Problem

A client that attaches to a kept shell with no count, while the shell sits at its prompt, sees an empty screen until
the shell writes: bash draws nothing again at a change of size, and a fresh attach replays the bytes since the detach
alone, which are none. A seat of `podssh serve --share` that joins finds no screen either.

## Premise

- Read: a fresh attach with no count replays from the offset of the detach (`crates/podssh-ssh/src/server/kept_replay.rs:32`,
  `(false, None) => (base, false)`), and the redraw is a change of the pty's size (`crates/podssh-ssh/src/server/kept_screen.rs:1`).
- Measured: bash at a still prompt, joined fresh: 0 of 3 rows; with a reset: 3 of 3 (T-161's Done).
- Read: `pod-term`'s `Tracker::feed` gives each boundary's offset (`Boundary::at`), and `Ring::kept` gives the ring's
  bytes from its first boundary (PodUtils/podcrates:crates/pod-term/src/grammar/ring.rs at `v0.83.0`).

## Approach

1. A fresh attach (no count, no reset) whose modes at the ring's end say the alternate screen is off: replay from the
   first boundary at or after the start of the ring's last N rows (N the client's rows, 24 when it named none), with a
   reset's line that names that offset first, so that a client that counts (T-895) starts there. The alternate screen
   on: as now (the program's redraw gives it).
2. A seat of `--share` that joins: the same tail, then the modes, before the broadcast.
3. `docs/terminal.md`, the manual's note of serve, and the measure's table again.

## Prove

```sh
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test attach_screen
CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test attach_measure -- --ignored --nocapture
```

A case of `attach_screen`: a shell that printed lines and sits at its prompt, joined fresh, shows those lines and its
prompt. The measure's row of bash, fresh, shares its rows. A plant that replays nothing fails the case.

## Done

2026-11-25, in the main session:

- A fresh attach: `crates/podssh-ssh/src/server/kept_screen.rs` (`tail_from`: the first boundary of the grammar at or
  after the start of the ring's last rows, only before the detach, never on the alternate screen, with its table of
  cases), used by the join in `crates/podssh-ssh/src/server/kept.rs` (the pty's rows, else 24), as a reset whose line
  names the offset, so that a client that counts (T-895) stays right.
- A seat of `--share`: `crates/podssh-ssh/src/server/share.rs` keeps 64 KiB of the owner's output in a `pod-term`
  ring, fed under the broadcast's lock, and `subscribe_with_screen` gives a joining seat the modes and its rows' last
  lines (on the alternate screen, the ring from its first boundary) with its receiver, under that lock;
  `crates/podssh-ssh/src/server/share_view.rs` writes them first.
- The manual's notes of serve, `docs/terminal.md` ("Screen on attach", the measure's row of bash), `docs/cli.md`,
  `docs/design.md` (section 5).

Results (2026-11-25): `CARGO_BUILD_JOBS=4 cargo test -p podssh-ssh --test attach_screen`: passed, with the new case of
a shell at a still prompt joined with no count, row for row; the measure (`--test attach_measure -- --ignored
--nocapture`): bash fresh 3 of 3 rows (0 of 3 before), vi, less and top as before; `--lib server::kept`: 11 passed;
`--test serve_share`: 7 passed, with the new case of a seat that joins after the owner wrote; `--test serve_keep
--test serve_attach_ticket --test serve_predict_kept`: 3, 4 and 2 passed; `cargo test -p podssh-cli --test attach`
(T-895's counting client): 7 passed. Planted: no tail on a fresh attach fails `attach_screen`'s shell case; an empty
screen for a seat fails `serve_share`'s new case.

