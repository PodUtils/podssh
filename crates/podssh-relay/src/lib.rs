//! podssh-relay — reaching podssh's WebSocket-to-TCP relay, as a library.
//!
//! - [`relay`]: which relay hosts to use, in what order (an explicit list, or
//!   the default host followed by alternates from the relay's own pool);
//! - [`pool`]: the pool, as the relay publishes it, cached between runs;
//! - [`health`]: one host's `/health`, as `podssh doctor` and `podssh relay
//!   status` read it;
//! - [`token`] and [`cache`]: tokens from the environment, the cache or a
//!   fresh mint, kept between runs in a private file, never printed;
//! - [`addresses`]: the addresses that carried a session to each relay host,
//!   kept in the cache for a run whose resolver fails (T-344);
//! - [`mod@open`]: a forward session, failing over from host to host with backoff,
//!   one bounded attempt per host;
//! - [`gate`]: each relay origin's gate in the process, which the sessions
//!   of a process share, so that a wave of failures costs one probe (T-637);
//! - [`cleartext`]: the road with no TLS on the relay's port, last, with a
//!   token of one session, for a proxy that cuts TLS (T-326);
//! - [`h2_road`]: which forward sessions are streams of one HTTP/2
//!   connection, by RFC 8441's extended CONNECT (T-321), `PODSSH_H2`;
//! - [`quic_road`]: QUIC on UDP to podssh's relay role, raced with the TCP
//!   roads where a probe found that UDP passes (T-667), `PODSSH_QUIC`;
//! - [`http_road`]: the HTTP road (T-319), a forward session over plain
//!   requests of HTTP/1.1 where a proxy refuses the WebSocket upgrade, in its
//!   split form and its serial form, whose server is the relay role's;
//! - [`forward_layer`]: a forward session in the resumable layer, whose far
//!   end is podssh's relay role, so that a standard sshd's session outlives
//!   a drop of the client's link (T-173);
//! - [`keyed`]: a mint or a pair that the relay asks this client's key to
//!   sign (T-448);
//! - `pair` (feature `pair`): the pairs of the reverse road, made, asked
//!   about and stopped on the relay's control host, kept in a private file;
//! - `reverse` (feature `pair`): the node and the operator of the reverse road;
//! - [`session`]: the resumable layer between two podssh ends: its records,
//!   offsets and handshake, and its client and far end over tokio streams;
//! - [`identity`]: who an end is: its key file, its fingerprint, a node's
//!   allowlist and an operator's pins, the same on each road;
//! - [`e2e`]: the channel between two podssh ends, Noise XX above the
//!   resumable layer, in which each end proves its key;
//! - `grant` (feature `grant`): grants used once (T-226), OpenSSH user
//!   certificates that the node checks in the channel before it dials, and
//!   its record of each one used;
//! - [`udp`]: UDP in a stream (T-168): each datagram after its length, and
//!   the flow at the far end, a UDP socket connected to the target;
//! - [`quick`]: a quick tunnel of Cloudflare's that podssh makes itself, with
//!   no `cloudflared` (T-300): the registration's Cap'n Proto and its RPC,
//!   and the headers of its answers;
//! - `derp` (feature `derp`): the DERP road (T-349), through Tailscale's
//!   servers for tailcat or a derper of the user's own, with an adapter
//!   under the resumable layer that sends again what a server drops;
//! - [`transit`]: the transit road (T-436), a pair's carrier through a
//!   magic-wormhole transit relay, Least Authority's by default;
//! - `croc` (feature `croc`): croc's relay road (T-694), a pair's carrier
//!   through croc's public relays behind the WebSocket bridge of croc-web,
//!   a last fallback of Q78;
//! - `piping` (feature `piping`): the Piping Server road (T-437), a POST
//!   and a GET for each way of a link, for a proxy that refuses the
//!   WebSocket upgrade;
//! - `smee` (feature `smee`): the smee.io road (T-741), a last fallback of
//!   Q78 for a proxy that refuses the upgrade: a POST for each frame and a
//!   stream of server-sent events for each way of a link;
//! - `opentunnel` (feature `opentunnel`): the OpenTunnel road (T-530), a
//!   blind TLS tunnel with no account, whose client's leg is TLS by name
//!   with no upgrade;
//! - `pinggy` (feature `pinggy`): the Pinggy road (T-548), a last fallback
//!   through Pinggy's free TLS tunnels: the node's leg is SSH inside TLS
//!   (its SSH client is the caller's), the client's TLS by name;
//! - `serveo` (feature `serveo`): the Serveo road (T-549), a last fallback
//!   through Serveo's private aliases: an alias of the node's key, which a
//!   client computes (both legs' SSH clients are the caller's);
//! - `ssh_http` (feature `ssh-http`): a tunnel of HTTP made by `ssh -R`
//!   (T-565), a last fallback through localhost.run: each visitor's plain
//!   HTTP down the forward, a WebSocket of the layer or the relay role's
//!   request (the node's SSH client is the caller's);
//! - `localtunnel` (feature `localtunnel`): the localtunnel road (T-568), a
//!   last fallback through localtunnel's public server: the node's TCP
//!   connections served by the relay role and the node's layer, the
//!   client's WebSocket by name;
//! - `hostc` (feature `hostc`): the hostc road (T-742), a last fallback
//!   through hostc's public server: one WebSocket of the node's, each
//!   visitor's request or WebSocket a stream on it, served as a visitor of a
//!   tunnel of `ssh -R` is (the relay role, or a link of the node's layer);
//! - `bore` (feature `bore`): the bore road (T-569), a last fallback
//!   through bore.pub: a public TCP port of the node's key, whose client
//!   reaches it through the caller's roads;
//! - `code` (feature `code`): pairing by a short code (T-086), SPAKE2 over a
//!   magic-wormhole mailbox, which moves a pair's operator's part and each
//!   end's key;
//! - `blocking` (feature `blocking`): a synchronous facade over all of these,
//!   for a caller with no async runtime: it owns a runtime on the current
//!   thread, and refuses a call from inside a tokio runtime.
//!
//! Other projects (podvm, podnet) depend on it; its shared parts move to
//! the crates of PodUtils/podcrates (T-684). The relay client is
//! `pod-relay`'s: each of its modules here is the glue of podssh's process
//! ([`context`]: its way out, its cache, its variables, its shared state).

pub mod addresses;
// A peer's answer, read by one rule (T-633): pod-session of PodUtils/podcrates.
pub use pod_session::answer;
#[cfg(feature = "blocking")]
pub mod blocking;
#[cfg(feature = "bore")]
pub mod bore;
pub mod cache;
pub mod cleartext;
#[cfg(feature = "code")]
pub mod code;
// podssh's context of the relay client of pod-relay (T-684).
pub mod context;
#[cfg(feature = "croc")]
pub mod croc;
#[cfg(feature = "derp")]
pub mod derp;
// The Dev Tunnels forward road, glue over pod-devtunnel (T-755).
#[cfg(feature = "devtunnel")]
pub mod devtunnel;
pub mod e2e;
pub mod failover;
pub mod failures;
pub mod forward_layer;
// A gate for each relay origin, shared by the sessions of a process (T-637).
pub mod gate;
#[cfg(feature = "grant")]
pub mod grant;
pub mod h2_road;
pub mod health;
#[cfg(feature = "hostc")]
pub mod hostc;
pub mod http_road;
pub mod identity;
pub mod keyed;
#[cfg(feature = "localtunnel")]
pub mod localtunnel;
pub mod open;
#[cfg(feature = "opentunnel")]
pub mod opentunnel;
#[cfg(feature = "pair")]
pub mod pair;
#[cfg(feature = "pinggy")]
pub mod pinggy;
// Tox's TCP relays, a last road of a pair (T-734).
#[cfg(feature = "hyperdht")]
pub mod hyperdht;
#[cfg(any(feature = "tox", feature = "yggdrasil"))]
pub mod packet_stream;
#[cfg(feature = "piping")]
pub mod piping;
pub mod pool;
#[cfg(feature = "serveo")]
pub mod serveo;
#[cfg(feature = "smee")]
pub mod smee;
#[cfg(feature = "strelay")]
pub mod strelay;
#[cfg(feature = "tox")]
pub mod tox;
#[cfg(feature = "yggdrasil")]
pub mod ygg;
// QUIC to the relay role, raced with the TCP roads (T-667).
pub mod quic_road;
// The rank of the relay hosts as measured from this host (T-606).
pub mod quick;
pub mod rank;
// A rank made in a session's background, with RelayRank auto alone (T-608).
pub mod rank_auto;
// The default list in the rank's order, and the samples of each race (T-607).
pub mod rank_list;
pub mod relay;
#[cfg(feature = "pair")]
pub mod reverse;
#[cfg(feature = "serve")]
pub mod serve;
pub mod session;
#[cfg(feature = "ssh-http")]
pub mod ssh_http;
// The file of the TLS groups that servers took (T-664).
pub mod tls_groups;
pub mod token;
pub mod transit;
// UDP over a byte stream (T-168): pod-session of PodUtils/podcrates.
pub use pod_session::udp;

pub use open::{open, Failure, OpenError, Opened, Request};
pub use relay::{default_relay_host, Relay, RELAY_ENV};
