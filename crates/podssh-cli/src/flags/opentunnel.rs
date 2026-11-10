//! The flag rows of the roads of a tunnel of a service with no account:
//! OpenTunnel's (T-531) and Pinggy's (T-548, a last fallback of Q78), TLS
//! tunnels by name, `node`'s road and `ssh`'s name of a node's race; and
//! Serveo's (T-549, a last fallback too), whose alias a client computes from
//! the node's key, so `ssh` takes no flag of it. Each road is in each build.

use super::{row, FlagKind, FlagRow};

/// `node --opentunnel`.
#[rustfmt::skip]
pub const NODE_OPENTUNNEL: FlagRow = row(None, "opentunnel", None, FlagKind::Supported,
    "serve TARGET over the OpenTunnel road, a blind TLS tunnel of opentunnel.xyz with no account (or the service of env PODSSH_OPENTUNNEL): one tunnel for the node, kept in the cache; a client dials the name that the node prints, by TLS with no upgrade; beside the pair's road; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);

/// `ssh node://NAME --opentunnel-name HOST`.
#[rustfmt::skip]
pub const SSH_OPENTUNNEL_NAME: FlagRow = row(None, "opentunnel-name", Some("HOST"), FlagKind::Supported,
    "node://NAME: race the OpenTunnel road to HOST, the name that the node prints (ROUTE.ID.opentunnel.xyz), 250 ms after the road before it; the name is kept under NAME, and a later run that gives none dials it when each road before it failed", None);

/// `node --pinggy`.
#[rustfmt::skip]
pub const NODE_PINGGY: FlagRow = row(None, "pinggy", None, FlagKind::Supported,
    "serve TARGET over the Pinggy road, a TLS tunnel of Pinggy's free tier with no account (or the server of env PODSSH_PINGGY): SSH on port 443 through the proxy, raw, else inside TLS that --ca-file or this host's roots verify; a new name each hour, which the node prints with the pin of its TLS key, kept beside its key; a client dials it by TLS with no upgrade, which takes that key alone; a third party that nobody vouches for, so a last fallback; beside the pair's road; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);

/// `ssh node://NAME --pinggy-name HOST#PIN`.
#[rustfmt::skip]
pub const SSH_PINGGY_NAME: FlagRow = row(None, "pinggy-name", Some("HOST#PIN"), FlagKind::Supported,
    "node://NAME: race the Pinggy road to HOST, the tunnel's name that the node prints, 250 ms after the road before it; its TLS takes only a certificate of the key of PIN (SHA256:..., which the node prints with the name), and a name with no pin is refused (64); the address is kept under NAME, and a later run that gives none dials it last, when each road before it failed; a free tunnel's name changes each hour, its pin does not", None);

/// `node --serveo`.
#[rustfmt::skip]
pub const NODE_SERVEO: FlagRow = row(None, "serveo", None, FlagKind::Supported,
    "serve TARGET over the Serveo road, a private alias at Serveo with no account (the server that podssh's list of services names, or the one of env PODSSH_SERVEO): raw SSH on port 443, then 22, through the proxy; the alias is derived from the node's key, the next of its series where another holds it, so a client that holds the key (its pins, --node-key, the net) jumps to it with no name given, last, when each road before it failed; a third party that nobody vouches for, so a last fallback; beside the pair's road; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);
