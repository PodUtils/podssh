//! The flag rows of the roads of a tunnel of a service with no account:
//! OpenTunnel's (T-531) and Pinggy's (T-548, a last fallback of Q78), TLS
//! tunnels by name, `node`'s road and `ssh`'s name of a node's race; and
//! Serveo's (T-549, a last fallback too), whose alias a client computes from
//! the node's key, so `ssh` takes no flag of it; and ssh-j.com's (T-570, a
//! last fallback too), whose name a client derives from the node's key too;
//! and localhost.run's (T-565), a tunnel of HTTP made by `ssh -R`, whose
//! name `ssh` takes as a URL; and localtunnel's (T-568, after it), whose
//! name a client derives from the node's key. Each road is pure Rust, in
//! each build.

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
/// `node --ssh-j`.
#[rustfmt::skip]
pub const NODE_SSH_J: FlagRow = row(None, "ssh-j", None, FlagKind::Supported,
    "serve TARGET over the ssh-j road, a public SSH jump and forwarding server with no account (ssh-j.com where podssh's list of services names it, or the server of env PODSSH_SSH_J): SSH on port 22, directly or through the proxy's CONNECT, as a user and with a remote forward of a name that the node's key gives; a client that holds the key (--node-key, the net, or the pins of NAME) derives the name and races the road last; a third party that nobody vouches for, which ends that SSH, so a last fallback; the road alone, with no pair's road beside it; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);

/// `node --localhost-run`.
#[rustfmt::skip]
pub const NODE_LOCALHOST_RUN: FlagRow = row(None, "localhost-run", None, FlagKind::Supported,
    "serve TARGET over the localhost.run road, a tunnel of HTTP made by ssh -R with no account (localhost.run where podssh's list of services names it, or the server of env PODSSH_LOCALHOST_RUN): SSH on port 22, directly or through the proxy's CONNECT, as the user nokey, with the remote forward of port 80; the service ends each visitor's TLS at an HTTPS name, new after a few hours, which the node prints, keeps under NAME in the cache and puts in its record; a client takes a WebSocket at / of that name; with --relay, the relay role behind it too, and TARGET may be left out; a third party that nobody vouches for, so a last fallback; the road alone, with no pair's road beside it; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);

/// `ssh node://NAME --tunnel-url https://HOST`.
#[rustfmt::skip]
pub const SSH_TUNNEL_URL: FlagRow = row(None, "tunnel-url", Some("URL"), FlagKind::Supported,
    "node://NAME: race the road of a tunnel of HTTP made by ssh -R (localhost.run's) to https://HOST, the name that the node prints, 250 ms after the road before it: a WebSocket at / of HOST, whose TLS this host's roots verify; the name is kept under NAME, and a later run that gives none dials it, or the one of the node's record, last, when each road before it failed; a free name changes after a few hours", None);
/// `node --localtunnel`.
#[rustfmt::skip]
pub const NODE_LOCALTUNNEL: FlagRow = row(None, "localtunnel", None, FlagKind::Supported,
    "serve TARGET over the localtunnel road, an HTTPS name at localtunnel's public server with no account (where podssh's list of services names it, or the server of env PODSSH_LOCALTUNNEL): the node asks the server over HTTPS for a name that its key gives, then keeps TCP connections to a port that the server names, directly or through the proxy's CONNECT, so its egress must reach that port; a client that holds the key (--node-key, the net, or the pins of NAME) derives the name and races the road last, by TLS and a WebSocket on port 443; with --relay, the relay role answers its paths there too, and TARGET may be left out; the URL is the line on stdout; a third party that nobody vouches for, which ends the visitors' TLS, so a last fallback; the road alone, with no pair's road beside it; needs the end-to-end channel, and --allow or a key that the net held here names, whose members are then the door", None);
