//! The public proxy nodes of aggregator lists (T-574, the operator's rulings
//! Q78 and Q90): VLESS, Trojan and VMess nodes that anonymous operators run, which
//! take the target from the client and dial it. They are the last fallback
//! of the forward road, so each one is a third party that nobody vouches for:
//! it sees the target's name and the bytes that the session sends, which SSH
//! and its host key keep private. This module holds what has no I/O of the
//! list's fetching: the nodes, the filters of Q79 ([`filter`]), the reading
//! of a list's body ([`list`]) and the round that tries nodes in turn
//! ([`carry`]). Where the lists and the built-in nodes are named is the
//! caller's: they are the services of `pod-services`, never a host here.

pub mod filter;
pub mod list;

use std::time::Duration;

use crate::trojan;
use crate::via::Duplex;
use crate::vless;
use crate::vmess;

pub use crate::vless::Dial;

/// A node of a list, in the road that speaks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    Vless(vless::Server),
    Trojan(trojan::Server),
    Vmess(vmess::Server),
}

impl Node {
    /// The scheme's name, for a line.
    pub fn road(&self) -> &'static str {
        match self {
            Node::Vless(_) => "VLESS",
            Node::Trojan(_) => "Trojan",
            Node::Vmess(_) => "VMess",
        }
    }

    /// `vless://HOST:PORT/PATH`, `trojan://HOST:PORT/PATH` or
    /// `vmess://HOST:PORT/PATH`: no ID and no password, which a line of a log
    /// has no use for.
    pub fn shown(&self) -> String {
        match self {
            Node::Vless(s) => s.shown(),
            Node::Trojan(s) => s.shown(),
            Node::Vmess(s) => s.shown(),
        }
    }

    /// The address that TCP dials, and its port.
    pub fn address(&self) -> (&str, u16) {
        match self {
            Node::Vless(s) => (&s.host, s.port),
            Node::Trojan(s) => (&s.host, s.port),
            Node::Vmess(s) => (&s.host, s.port),
        }
    }

    /// The name that TLS asks for, and the one that HTTP names.
    pub fn names(&self) -> (&str, &str) {
        match self {
            Node::Vless(s) => (&s.sni, &s.authority),
            Node::Trojan(s) => (&s.sni, &s.authority),
            Node::Vmess(s) => (&s.sni, &s.authority),
        }
    }

    /// Whether the node's TLS is on: Trojan's always is.
    pub fn tls(&self) -> bool {
        match self {
            Node::Vless(s) => s.tls,
            Node::Trojan(_) => true,
            Node::Vmess(s) => s.tls,
        }
    }
}

/// A node that carried the session.
pub struct Carried {
    pub stream: Box<dyn Duplex>,
    pub node: Node,
    /// What carried it: "a WebSocket", "TLS", ...
    pub how: String,
}

/// The stream to `host:port` through the first of `nodes` that carries it:
/// at most `most` of them are tried, each within `each`. `say` has the line
/// of each failure, as it comes; a target that no node can name ends the
/// round, as the next would refuse it too. `Err` holds each failure's line.
pub async fn carry(
    nodes: &[Node],
    host: &str,
    port: u16,
    dial: &Dial<'_>,
    (each, most): (Duration, usize),
    say: &mut (dyn FnMut(&str) + Send),
) -> Result<Carried, Vec<String>> {
    let target = crate::dial::authority(host, port);
    let mut failed = Vec::new();
    for node in nodes.iter().take(most) {
        let shown = node.shown();
        let (why, no_node_can) = match tokio::time::timeout(each, one(node, (host, port), dial, &shown, &target)).await
        {
            Ok(Ok((stream, how))) => return Ok(Carried { stream, node: node.clone(), how }),
            Ok(Err(failure)) => failure,
            Err(_) => (format!("the {} node {shown} gave no session within {} s", node.road(), each.as_secs()), false),
        };
        say(&why);
        failed.push(why);
        if no_node_can {
            break;
        }
    }
    Err(failed)
}

/// One node's session, or its failure's line and whether the target cannot
/// go to any node.
async fn one(
    node: &Node,
    (host, port): (&str, u16),
    dial: &Dial<'_>,
    shown: &str,
    target: &str,
) -> Result<(Box<dyn Duplex>, String), (String, bool)> {
    match node {
        Node::Vless(server) => match vless::open(server, host, port, dial).await {
            Ok(o) => Ok((o.stream, o.how)),
            Err(e) => Err((e.line(shown, target), matches!(e, vless::VlessError::Target(_)))),
        },
        Node::Trojan(server) => match trojan::open(server, host, port, dial).await {
            Ok(o) => Ok((o.stream, o.how.to_string())),
            Err(e) => Err((e.line(shown, target), matches!(e, trojan::TrojanError::Target(_)))),
        },
        Node::Vmess(server) => match vmess::open(server, host, port, dial).await {
            Ok(o) => Ok((o.stream, o.how.to_string())),
            Err(e) => Err((e.line(shown, target), matches!(e, vmess::VmessError::Target(_)))),
        },
    }
}
