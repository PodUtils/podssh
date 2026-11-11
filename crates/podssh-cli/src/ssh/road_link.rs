//! A link of `podssh ssh node://NAME` on any of its roads (`super::roads`):
//! one type for the race and the resumable layer above it, whichever road
//! won; the words of a race's order and of its end; and what takes the
//! layered stream in the place of SSH, for a copy that races the same roads
//! (T-551). Apart from `roads.rs`, for the length of that file.

use std::pin::Pin;
use std::task::{Context, Poll};

use std::time::Duration;

use podssh_relay::session::client;
use podssh_relay::session::race::{WonAt, HEAD_START};
use podssh_ssh::Log;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::layered::Shell;

/// A link on any road.
pub enum Road {
    #[cfg(feature = "iroh")]
    Iroh(podssh_iroh::Stream),
    Pair(DuplexStream),
    Derp(podssh_relay::derp::Link),
    Transit(podssh_relay::transit::Link),
    Piping(podssh_relay::piping::Link),
    OpenTunnel(podssh_relay::opentunnel::client::Link),
    /// A link over a node's Pinggy tunnel (T-548).
    Pinggy(podssh_relay::pinggy::Link),
    /// A channel to a node's alias at Serveo (T-549).
    Serveo(podssh_relay::opentunnel::dial::BoxIo),
    /// A link through ssh-j.com, to a node's name there (T-570).
    SshJ(crate::sshj::client::Link),
    /// A WebSocket to a node's tunnel of HTTP made by `ssh -R` (T-565).
    SshHttp(DuplexStream),
    /// A WebSocket to a node's name at localtunnel's server (T-568).
    LocalTunnel(DuplexStream),
    /// A connection to a port of a node's key at bore.pub (T-569).
    Bore(podssh_relay::opentunnel::dial::BoxIo),
    /// A connection over the pair's ZeroTier network, through ZeroTier
    /// Inc.'s roots and TCP relay (T-733), which a build with the road makes.
    #[cfg_attr(not(feature = "zerotier"), allow(dead_code))]
    ZeroTier(podssh_relay::opentunnel::dial::BoxIo),
    /// A WebSocket to a node's quick tunnel, of its record (T-445), which a
    /// build with the iroh road reads.
    #[cfg(feature = "iroh")]
    Tunnel(DuplexStream),
}

impl AsyncRead for Road {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_read(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_read(cx, buf),
            Road::Derp(link) => Pin::new(link).poll_read(cx, buf),
            Road::Transit(link) => Pin::new(link).poll_read(cx, buf),
            Road::Piping(link) => Pin::new(link).poll_read(cx, buf),
            Road::OpenTunnel(link) => Pin::new(link).poll_read(cx, buf),
            Road::Pinggy(link) => Pin::new(link).poll_read(cx, buf),
            Road::Serveo(link) => Pin::new(link).poll_read(cx, buf),
            Road::SshJ(link) => Pin::new(link).poll_read(cx, buf),
            Road::SshHttp(link) => Pin::new(link).poll_read(cx, buf),
            Road::LocalTunnel(link) => Pin::new(link).poll_read(cx, buf),
            Road::Bore(link) => Pin::new(link).poll_read(cx, buf),
            Road::ZeroTier(link) => Pin::new(link).poll_read(cx, buf),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Road {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_write(cx, buf),
            Road::Pair(link) => Pin::new(link).poll_write(cx, buf),
            Road::Derp(link) => Pin::new(link).poll_write(cx, buf),
            Road::Transit(link) => Pin::new(link).poll_write(cx, buf),
            Road::Piping(link) => Pin::new(link).poll_write(cx, buf),
            Road::OpenTunnel(link) => Pin::new(link).poll_write(cx, buf),
            Road::Pinggy(link) => Pin::new(link).poll_write(cx, buf),
            Road::Serveo(link) => Pin::new(link).poll_write(cx, buf),
            Road::SshJ(link) => Pin::new(link).poll_write(cx, buf),
            Road::SshHttp(link) => Pin::new(link).poll_write(cx, buf),
            Road::LocalTunnel(link) => Pin::new(link).poll_write(cx, buf),
            Road::Bore(link) => Pin::new(link).poll_write(cx, buf),
            Road::ZeroTier(link) => Pin::new(link).poll_write(cx, buf),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_flush(cx),
            Road::Pair(link) => Pin::new(link).poll_flush(cx),
            Road::Derp(link) => Pin::new(link).poll_flush(cx),
            Road::Transit(link) => Pin::new(link).poll_flush(cx),
            Road::Piping(link) => Pin::new(link).poll_flush(cx),
            Road::OpenTunnel(link) => Pin::new(link).poll_flush(cx),
            Road::Pinggy(link) => Pin::new(link).poll_flush(cx),
            Road::Serveo(link) => Pin::new(link).poll_flush(cx),
            Road::SshJ(link) => Pin::new(link).poll_flush(cx),
            Road::SshHttp(link) => Pin::new(link).poll_flush(cx),
            Road::LocalTunnel(link) => Pin::new(link).poll_flush(cx),
            Road::Bore(link) => Pin::new(link).poll_flush(cx),
            Road::ZeroTier(link) => Pin::new(link).poll_flush(cx),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            #[cfg(feature = "iroh")]
            Road::Iroh(link) => Pin::new(link).poll_shutdown(cx),
            Road::Pair(link) => Pin::new(link).poll_shutdown(cx),
            Road::Derp(link) => Pin::new(link).poll_shutdown(cx),
            Road::Transit(link) => Pin::new(link).poll_shutdown(cx),
            Road::Piping(link) => Pin::new(link).poll_shutdown(cx),
            Road::OpenTunnel(link) => Pin::new(link).poll_shutdown(cx),
            Road::Pinggy(link) => Pin::new(link).poll_shutdown(cx),
            Road::Serveo(link) => Pin::new(link).poll_shutdown(cx),
            Road::SshJ(link) => Pin::new(link).poll_shutdown(cx),
            Road::SshHttp(link) => Pin::new(link).poll_shutdown(cx),
            Road::LocalTunnel(link) => Pin::new(link).poll_shutdown(cx),
            Road::Bore(link) => Pin::new(link).poll_shutdown(cx),
            Road::ZeroTier(link) => Pin::new(link).poll_shutdown(cx),
            #[cfg(feature = "iroh")]
            Road::Tunnel(link) => Pin::new(link).poll_shutdown(cx),
        }
    }
}

/// Which road a place of the race is.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    Iroh,
    Pair,
    Derp,
    Transit,
    Piping,
    OpenTunnel,
    /// A node's Pinggy tunnel, a last fallback of Q78 (T-548).
    Pinggy,
    /// croc's relay, a last fallback of Q78 (T-694).
    Croc,
    /// The pair's ZeroTier network, a last fallback of Q78 (T-733).
    #[cfg_attr(not(feature = "zerotier"), allow(dead_code))]
    ZeroTier,
    /// A node's alias at Serveo, a last fallback of Q78 (T-549).
    Serveo,
    /// A node's name at ssh-j.com, a last fallback of Q78 (T-570).
    SshJ,
    /// A node's tunnel of HTTP made by `ssh -R`, the last of the fallbacks of
    /// Q78 (T-565), whether its name was given in this run, and whether the
    /// name known before the race is Sandhole's (T-743).
    SshHttp(bool, bool),
    /// A node's name at localtunnel's server, the last of the fallbacks of Q78 (T-568).
    LocalTunnel,
    /// A port of a node's key at bore.pub, the last of the fallbacks of Q78 (T-569).
    Bore,
    /// The tunnel's name of `ssh -R` through a Bare node, the last of all (T-740).
    Bare,
    /// A road of the node's record, by its name.
    Record(&'static str),
    /// A leg at a member of the net with the relay role (T-434).
    Member,
    /// A visit to the node's STCP service at the user's frps (T-498).
    Frp,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::Record(name) => name,
            Kind::Iroh => "the iroh road",
            Kind::Pair => "the pair's road",
            Kind::Derp => "the DERP road",
            Kind::Transit => "the transit road",
            Kind::Piping => "the Piping Server road",
            Kind::OpenTunnel => "the OpenTunnel road",
            Kind::Pinggy => "the Pinggy road",
            Kind::Croc => "croc's relay road",
            Kind::ZeroTier => "ZeroTier's road",
            Kind::Serveo => "the Serveo road",
            Kind::SshJ => "the ssh-j road",
            Kind::SshHttp(_, false) => "the localhost.run road",
            Kind::SshHttp(_, true) => "the Sandhole road",
            Kind::LocalTunnel => "the localtunnel road",
            Kind::Bore => "the bore road",
            Kind::Bare => "the Bare hop",
            Kind::Member => "a member's relay role",
            Kind::Frp => "the frp road",
        }
    }
}

/// The roads of a race that are fallbacks which nobody asked for, for the
/// words of its order.
#[derive(Clone, Copy)]
pub(super) struct Unasked {
    /// A DERP ticket kept, or of the net (Q50).
    pub derp: bool,
    /// An OpenTunnel name kept (Q76).
    pub opentunnel: bool,
    /// The Piping Server road that `PODSSH_PIPING` did not ask for (Q65).
    pub piping: bool,
    /// Where a Pinggy address that nobody gave comes from, the last
    /// fallback (Q78): the node's record, a kept name, or both.
    pub pinggy: Option<&'static str>,
}

/// The order of the roads, for `-v`.
pub(super) fn order(kinds: &[Kind], unasked: Unasked) -> String {
    let mut words = Vec::new();
    for (at, kind) in kinds.iter().enumerate() {
        let when = match (at, kind) {
            (0, _) => "first".to_string(),
            (_, Kind::Derp) if unasked.derp => "when each road before it failed (a kept ticket)".to_string(),
            (_, Kind::Transit) => "when each road before it failed (Q65)".to_string(),
            (_, Kind::Croc | Kind::ZeroTier) => {
                "when each road before it failed (the last fallback of Q78)".to_string()
            }
            (_, Kind::OpenTunnel) if unasked.opentunnel => {
                "when each road before it failed (a kept name, Q76)".to_string()
            }
            (_, Kind::Record(_)) if !matches!(kinds[at - 1], Kind::Record(_)) => {
                "when each road before it failed (the node's record of pkarr, T-445)".to_string()
            }
            (_, Kind::Member) => "when each road before it failed (a member of the net that relays, T-434)".to_string(),
            (_, Kind::Frp) => "when each road before it failed (the user's frps, T-498)".to_string(),
            (_, Kind::Pinggy) if unasked.pinggy.is_some() => {
                let from = unasked.pinggy.unwrap_or_default();
                format!("when each road before it failed ({from}, the last fallback of Q78)")
            }
            (_, Kind::Serveo) => {
                "when each road before it failed (the alias of the node's key, the last fallback of Q78)".to_string()
            }
            (_, Kind::SshJ | Kind::LocalTunnel | Kind::Bore) => {
                "when each road before it failed (the node's key, the last fallback of Q78)".to_string()
            }
            (_, Kind::Bare) => {
                "when each road before it failed (the tunnel's name through a Bare node, the last fallback of Q78)"
                    .to_string()
            }
            (_, Kind::SshHttp(false, _)) => {
                "when each road before it failed (a kept name or its record, the last fallback of Q78)".to_string()
            }
            (_, Kind::Piping) if unasked.piping => {
                "when each road before it failed and one found the WebSocket upgrade refused (Q65)".to_string()
            }
            _ => format!("{} ms after", HEAD_START.as_millis()),
        };
        words.push(format!("{} {when}", kind.name()));
    }
    words.join(", ")
}

/// What a race serves beside its stream (T-551): the shell of `podssh ssh`,
/// whose far end may keep it and whose silence is a notice, and the signals
/// that it takes; a copy has neither, and reads those its command took.
#[derive(Clone, Copy)]
pub(super) struct Rider<'s> {
    pub shell: Option<Shell<'s>>,
    pub take: Option<crate::hangup::Which>,
}

/// The layered stream of a race, once a road answered and the layer is up.
pub(super) struct Handed {
    /// The bytes of SSH, under the end-to-end channel and the layer.
    pub stream: DuplexStream,
    /// Whether the end-to-end channel runs above the layer (T-588).
    pub channel: bool,
}

/// Each road's reason, in the order of the race.
pub(super) fn lost_words(kinds: &[Kind], lost: &[String]) -> String {
    let each: Vec<String> = kinds.iter().zip(lost).map(|(kind, why)| format!("{}: {why}", kind.name())).collect();
    each.join("; ")
}

/// The winner's link, with the bytes that the race read given back first,
/// and a line with `-v`; the road is kept as the one that last reached the
/// node.
pub(super) fn winner(
    won: WonAt<Road>,
    took: Duration,
    kinds: &[Kind],
    shown: &str,
    log: &Log,
) -> client::Rewound<Road> {
    let road = kinds.get(won.at).map_or("a road", |kind| kind.name());
    log.verbose(&format!("{shown}: {road} answered first, in {} ms", took.as_millis()));
    // The road that reached the node, for `podssh status --net` (T-435);
    // `shown` is `node://` and the label, as `super::roads::ride` makes it.
    if let Some(label) = shown.strip_prefix(super::node::SCHEME) {
        crate::net::reached::reached(label, road, took);
    }
    won.link.rewound()
}
