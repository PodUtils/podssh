# A carrier in DNS: is a poll-driven TXT road worth its deployment (T-835)

The study of T-835 (`TODO/mesh.md`): whether podssh should carry its stream in the
questions and answers of DNS, for a host that reaches a recursive resolver and
nothing else. A drafting agent wrote it on 2026-11-24 from two sources: the
source of `Mygod/dnstt` at the head of its default branch (`plugin`), read
through the services of web.pkgforge.dev, and the source of `pod-link` and
`pod-dns` of PodUtils/podcrates at `v0.82.1`, read in the checkout of the
build. It built nothing, ran nothing, and sent no query to any resolver. Each
number is read in a file, or is arithmetic on what was read. The tags are those
of [relay-measurement.md](relay-measurement.md):

- **Read**: a file says so (a path of this repository at a line, or a file of
  another repository by its name).
- **Inferred**: reasoning from what was read; the measurement that would settle
  it is named.
- **Arithmetic**: a figure computed here from read numbers.
- **UNVERIFIED**: stated for a result that a run must give.

## 1. The verdict

1. **The road exists, and the codec is not podssh's to write.** PodUtils/podcrates
   has the whole road in `pod-link`, feature `dns`: the names, the TXT answers,
   the poll, an authoritative responder, the answer size, the cut answer, a
   selective-repeat ARQ, and TLS 1.3 with a pinned key. The files are identical at
   `v0.82.0` and `v0.82.1`. The entry's step 2 (ask podcrates for a codec) is
   moot, and the entry gets a `## Correction`. What podssh lacks is glue (as
   `--carrier s3:FILE` is glue over `pod-link`'s S3 carrier), a probe, and the
   rulings below.
2. **It is worth having as a last resort.** It reaches
   a class of hosts that no other road reaches: a host with a resolver and nothing
   else. No user of podssh has asked for it. The record holds no report of such a
   host (the issues and the notes of `TODO/issues.md` name none), the target sandbox
   cannot use it (section 2), and the tracker's donor study (#317) is a list of
   mechanisms, not of users. The cost is small now (glue), but the road adds a UDP
   path to a binary whose rule 2 forbids it. So the build waits for a host: a
   user's report, or a measurement of step 1 on a real network. The measurement
   comes first, as a probe (T-875). That was the verdict of 2026-11-24; the owner's
   rule "Decisions" and Q107 then had the road built behind its opt-in (T-877).
3. **A tenth exception of rule 2 is needed, and only the operator can give it.**
   The responder is a listener that the user starts, which exception 1 already
   covers when a probe allows the bind. The client's datagrams to a resolver are not
   covered: they are not through `HTTPS_PROXY`, and they are not a listener. This is
   Q107, settled on 2026-11-24 (`docs/decisions.md`, exception 11 of rule 2). A form over DNS over HTTPS (section 5) needs none.
4. **The road has a deployment cost that the user pays**: a domain, a delegation, a
   host with a public address and UDP 53, and a responder that runs. Section 6.
5. **Three faults and a gap in `pod-link`'s responder** are filed for podcrates
   (T-876): section 4.

## 2. Which hosts

| Host | Reaches | Does a DNS road help |
| --- | --- | --- |
| The target sandbox of podssh | An HTTP CONNECT proxy; every direct connect refused (`EACCES` for port 53), UDP `EPERM` (`docs/target-environment.md:22-24`) | **No.** It has no UDP and no port 53. Its proxy resolves for it, and passes any public host on 443, so the relay is open. |
| A captive network before login, or a locked guest network | Read as common, not measured: UDP 53 to any resolver, or to the network's own, and nothing else | **Yes, if** the network's resolver forwards a name of a zone that it does not know. A portal that answers every name with its own address (a DNS hijack) kills the road. Inferred; the probe of T-875 tells the two apart. |
| A proxy that lists the hosts it passes, where one is a public DNS over HTTPS resolver | CONNECT to that name on 443 | **Yes, by DoH only** (section 5). Not measured: no name of a DoH resolver is known to be on a list (`docs/target-environment.md`, "An egress that lists names for TLS"). |
| A host with a resolver and a proxy that passes 443 | Everything | Not needed: the relay road serves it. |

Port 853 (DNS over TLS) is not on the sandbox's list of ports (443, 80, 8443), so
DoT is no road there. Read: `docs/target-environment.md:19-24`.

## 3. What was read

### dnstt (`Mygod/dnstt`, the `plugin` branch)

- A client sends each KCP segment as a name: the 8-byte client id, a padding
  byte `224 + n` with `n` random bytes (3, or 8 for a poll), the length and the
  packet (under 224 bytes), in base32 labels of at most 63 bytes under the zone
  (`dnstt-client/dns.go`, `send`). The random padding keeps a resolver's cache from
  answering. Read.
- The poll starts at 500 ms, doubles to 10 s, and returns to 500 ms at each send;
  a burst of empty polls after data is limited to 16 (`dnstt-client/dns.go`,
  `initPollDelay`, `maxPollDelay`, `pollLimit`). Read.
- The server holds an answer up to 1 s for a packet to send down
  (`maxResponseDelay` in `dnstt-server/main.go`), so a poll is a long poll. Read.
- The server **refuses a client without EDNS(0)**, or with a payload size under
  1232, with FORMERR (`maxUDPPayload = 1280 - 40 - 8`, in `dnstt-server/main.go`).
  Read.
- The server listens on UDP only: its option `-udp` is required, and there is no
  TCP listener. The client speaks plain UDP, DoH or DoT to the resolver. Read
  (`dnstt-server/main.go`, `README`).
- Its security audit's finding on rate limiting was left unaddressed
  (`CHANGELOG`, UCB-02-008: "Lack of rate limiting in Snowflake and dnstt"). Read.
- The entry cited the lines of the report's pinned commit. They do not match the
  head of `plugin` (the NXDOMAIN check is near line 447, the `-udp` check near line
  1062); the substance of each claim holds.

### pod-link's `dns` carrier (PodUtils/podcrates `v0.82.1`)

- The dialer sends `session(4) || counter(4) || datagram` in base32 labels under
  the zone; the counter makes each name unique, so no resolver caches an answer.
  The TXT answer holds one datagram in each record (`dns/wire.rs`). Read.
- The largest datagram up is the room that the name leaves: 147 bytes for a zone of
  one letter, 139 for `t.example.com` (Arithmetic on `payload_mtu`: a name is at
  most 255 bytes on the wire, 63 to a label). The ARQ's data header is 9 bytes
  (`arq/wire.rs`). The server's datagrams down are held to the same size. Read.
- The settings by default: 20 queries a second (a token bucket), 8 in flight, a
  2 s wait for an answer, a poll from 5 ms doubling to 2 s, an answer of 1232
  bytes (`dns/settings.rs`). The poll returns to 5 ms at each datagram up. Read.
- The responder answers each query at once; it does not hold a poll (`dns/server.rs`,
  `answer`). Read.
- With no OPT record in the query the answer keeps to 512 bytes, with none in it; a
  cut answer (TC) gives its whole records before the cut, and the ARQ sends the rest
  again; no query goes again over TCP (`dns/client.rs`). Read.
- The TLS 1.3 of the tcp carrier runs over the ARQ, each side pinning the other's
  Ed25519 key. The responder is `Dns::bind`, a UDP socket. The dialer's datagrams
  go to `Dns::to(ADDR)`, or through a `Dial` of the caller's (`Dns::with_way`), or
  over any `Datagrams` (`Dns::connect_over`). Read.
- Its tests (`tests/dns.rs`, `dns_loss.rs`, `dns_resolver.rs`) run against a
  stand-in resolver on the loopback that podcrates wrote: whole queries, queries
  with no OPT, and each third answer cut. **No test runs through a resolver that
  nobody at podcrates or podssh wrote** (unbound, BIND, CoreDNS as a recursor, a
  public one). Read.

### Arithmetic on the carrier at its defaults

Zone `t.example.com`, 20 queries a second:

- **Up.** One datagram a query: 139 bytes less the ARQ's 9 are 130 bytes of the
  stream, so about 2.6 KB/s at most (21 kbit/s), less the datagrams that carry
  acknowledgements of a download, less the 22 bytes of each TLS record. A 10 MiB
  upload takes about 67 minutes.
- **Down, with EDNS(0) of 1232.** A poll's answer has room for 7 datagrams (a
  poll's name is 27 bytes, the fixed part 56, each record 152), so 910 bytes of the
  stream, and about 18 KB/s at most (146 kbit/s). 10 MiB takes about 10 minutes.
- **Down, with no OPT record.** The room is 512 bytes: 3 datagrams, 390 bytes, about
  7.8 KB/s. 10 MiB takes about 22 minutes.
- **Idle.** The poll at its ceiling of 2 s is 0.5 queries a second, 1,800 an hour,
  and the layers above send a heartbeat each 10 s and the role a ping each 20 s, so
  about 2,000 queries an hour of names that no one else asks.
- **A key typed.** One query up and its answer; the echo comes in the answer of the
  next poll, 5 ms later, then 10, 20 and 40 ms by the doubling, one query each 50 ms
  at most. So a resolver's round trip plus about 100 ms (Inferred; **UNVERIFIED**).
- **The handshake.** TLS 1.3 with pinned keys sends a few KiB each way, 10 to 20
  datagrams, so seconds at the rate (Inferred; **UNVERIFIED**).

These are ceilings of the code, not measurements. A resolver that limits its own
clients, or a path with loss and a timeout of 2 s for each lost query, lowers them.

## 4. Limits and faults, one by one (the entry's step 4)

| Limit | What dnstt does | What `pod-link` does | What is not known |
| --- | --- | --- | --- |
| A resolver that strips OPT, or sends a size under 1232 | FORMERR to the client: the tunnel cannot start | Answers within 512 bytes, with no OPT record: it runs at 43% of the rate down (section 3) | Which resolvers strip OPT. The probe of T-875 reads whether the answer kept its OPT. |
| A cut answer (TC) | Not read | The whole records before the cut; the ARQ sends the rest again | A resolver that sets TC to the client of a UDP query for an answer under 512. |
| No TCP retry | The server has no TCP listener | The same | A resolver that asks the responder again over TCP after a TC, and gives its client SERVFAIL when the TCP port is closed. The responder keeps each answer under the size that was asked, so it never sets TC itself (Read, `drain`). |
| A cache by name | Random padding in each name | A counter in each name | A resolver that caches a negative answer, or that rewrites the case of a name (the responder lowers the case: Read, `decode_query`). |
| A 429 of a DoH resolver | The client's own concern | Not applicable: the dialer sends UDP | A DoH form needs a pause on 429 and a retry; T-876 asks podcrates for one. |
| QNAME minimisation (RFC 9156) | Not read | See fault 1 below | Whether unbound, BIND and the public resolvers fall back to the full name when a partial one gets no answer. |

### Three faults and a gap in the responder (for podcrates)

1. **A query that is not a TXT of a decodable name gets no answer.** The header of
   `dns/server.rs` says that a wrong name gets an empty answer, but the code returns
   without an answer when the type is not TXT or the name does not decode (`answer`).
   A resolver that minimises names asks the zone's server first for a partial name,
   often of another type, and waits for its time out. The responder should answer
   NOERROR with no record (dnstt answers NXDOMAIN, FORMERR or NOERROR in each case).
   Inferred; the test is unbound with its default settings, which minimise.
2. **Any session id opens a handshake before any proof.** A name with a new session
   id takes one of 64 slots for 20 s (`dns/server.rs`, `answer`; `HANDSHAKE_TIMEOUT`,
   `MAX_HANDSHAKES`); the pinned key is checked only after the handshake. Three
   queries a second keep the slots full and shut out a real client, from any source
   address (UDP, so a spoofed one). Inferred from the code. A cookie of the first
   answer, or a proof under a secret that the dialer holds, would end it.
3. **The responder does not hold a poll.** dnstt holds up to 1 s and so needs fewer
   polls for the same latency. Here the idle cost is the 2,000 queries an hour above,
   and the latency of a sent-down byte is the poll's. A hold of about 1 s, below any
   resolver's time out, is a change of the responder alone.
4. **A gap: the TLS under the ARQ is redundant for podssh.** The end-to-end channel
   of the layer above (Noise XX) ends a session on any change (`docs/carriers.md`,
   "The reverse road"). The 22 bytes of each TLS record are 17% of a 130-byte datagram
   and its handshake is the first seconds. An ARQ stream with no TLS, for a caller
   that seals above, would be a feature of `pod-link`, and the pinned key would stay
   in the layer above.

## 5. The form over DNS over HTTPS

dnstt's client can speak DoH. For podssh this is the form that stays inside rule 2:
one connection to a resolver's name on 443, through `HTTPS_PROXY` with CONNECT,
carrying the queries as HTTP/2 streams. No UDP and no listener at the client. The
public resolver asks the user's responder over UDP 53, so the responder is the same.
`pod-dns` has the DoH wire form of a query (`Doh::wire`, `txt::query`), and
`pod-link`'s `Dns::connect_over` takes any `Datagrams`; a `Datagrams` over DoH is
the missing piece, and a pause on 429 with it. It helps only where a proxy passes a
DoH resolver's name and not the relay's (section 2), which is not known to exist.
It is a lead for a host that needs it, not a plan: it is entry T-877's second form.

## 6. What the deployment needs

| Need | Detail |
| --- | --- |
| A domain, and a name server for a zone of it | A zone `t.example.com`, one NS record `t.example.com NS ns.t.example.com`, and a glue A record for `ns` at the host's address. About the price of a domain. |
| A host with a public address and UDP 53 | Port 53 needs a privilege to bind. dnstt's README redirects 53 to a high port with `iptables`. podssh's rule 1 asks no privilege of the client; the responder's host is the user's own. |
| A responder that runs | Started by the user, never inside `serve` or a node's listener set (a listener only on the user's word, exception 1 of rule 2). A node on the public host runs it, and the client that dials needs only the zone and the node's key. |
| The address of the road | `KEY@ZONE`, with the key pinned: no certificate authority and no account. |
| The abuse footing | Cloudflare Gateway and similar filters class "DNS Tunneling" as a threat (`docs/carriers.md:720-722`). A resolver's operator sees about 2,000 odd queries an hour while idle and up to 20 a second under load, and can block the zone or the client. dnstt has no limit; `pod-link` limits the dialer to 20 a second. A zone of the user's own is the user's risk. The road is a last resort, and `podssh doctor` should say so. |

## 7. The measurement of step 1, and why it is not here

The entry asked for `podssh doctor` on two networks that block 443. Not done: a
drafting agent sends no query, the host of this session has no UDP, and `doctor`
has no such probe (it has one for UDP to a Hysteria server, `crates/podssh-cli/src/doctor/hysteria.rs`,
and one for iroh's UDP). The probe is entry T-875: one TXT query for a name under a
zone that the user names, to the resolver that `resolv.conf` or the user names, and
a line with the RCODE, the size of the answer, TC, whether OPT was kept, and the
time. It sends one datagram, so it needs Q107's ruling too. Until it runs on a real
network, the class of section 2 is a reading of how captive networks are built, not
a count.

## 8. What each result needs to be proved

| Claim | Proved by |
| --- | --- |
| The road carries a stream through a resolver that podssh did not write | `unbound` in the box as the recursor, an authoritative responder of `pod-link` behind it, a transfer of 1 MiB each way; the same with `qname-minimisation` on and off |
| A resolver that strips OPT, or one that sets TC, ends in one true line, never a hang | A planted resolver for each, with the carrier's time out; exit code from the table of `podssh man` |
| The rates of section 3 | A run through the box's resolver: the rate each way and the idle count of queries in 10 minutes |
| Faults 1 and 2 | A query of type A for a partial name, and 64 queries of new session ids, against the responder, each with its answer or its refusal read |
