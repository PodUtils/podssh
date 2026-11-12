//! The roads of servers that the user names in place of the relay: the
//! forwarders (T-369), Shadowsocks servers (T-373), a forward proxy over TLS
//! (T-439), VLESS servers (T-440), a wstunnel server (T-441), a chisel
//! server (T-490), Trojan servers (T-491), TUIC servers (T-581) and Hysteria 2
//! servers (T-580), where UDP passes, and a TURN server (T-621). Each takes
//! the relay's place when named, and each refuses the others, as a run has
//! one road; here so that the resolver stays one file. An exit of the net
//! (T-431, `super::exit_road`) takes it first. The stream through each of
//! these roads, and the word of each road for the session log, are here
//! too, so that `transport.rs` and `mod.rs` stay short.

use std::sync::Arc;

use podssh_ssh::Log;

use super::args::SshArgs;
use super::resolve::{Env, Resolved, Transport};
use super::transport::{NotReached, Reached};
use crate::relay_settings::Refusal;

/// The road of a run that resolved to the relay: a server's road when the
/// command line or the environment names one, else the relay. chisel,
/// VLESS and wstunnel come before `--via`, so that each flag wins over
/// `PODSSH_VIA`.
pub(super) fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    if args.exit.is_some() {
        return super::exit_road::or_exit(args, env, relay);
    }
    // TURN first, then TUIC: each or_relay names each other server's flag
    // (T-621, T-581).
    let relay = crate::turn::or_relay(args, env, relay)?;
    let relay = crate::tuic::or_relay(args, relay)?;
    let relay = crate::hysteria::or_relay(args, relay)?;
    let relay = crate::chisel::or_relay(args, env, relay)?;
    let relay = crate::trojan::or_relay(args, relay)?;
    let relay = crate::vless::or_relay(args, relay)?;
    let relay = crate::via::or_relay(args, env, crate::wstunnel::or_relay(args, env, relay)?)?;
    crate::shadowsocks::or_relay(args, crate::forwarder::or_relay(args, env, relay)?)
}

/// Each server's flag beside a road of its own, which [`or_relay`] never
/// took: a usage error; and the exit's word, once the first hop is known.
/// A carrier beside a destination that is no node is refused first (T-595).
pub(super) fn check(args: &SshArgs, resolved: &mut Resolved) -> Result<(), Refusal> {
    super::carried::check(args, resolved)?;
    super::exit_road::fill(args, resolved)?;
    let resolved: &Resolved = resolved;
    crate::forwarder::check(args, resolved)
        .and_then(|()| crate::shadowsocks::check(args, resolved))
        .and_then(|()| crate::via::check(args, resolved))
        .and_then(|()| crate::vless::check(args, resolved))
        .and_then(|()| crate::wstunnel::check(args, resolved))
        .and_then(|()| crate::chisel::check(args, resolved))
        .and_then(|()| crate::trojan::check(args, resolved))
        .and_then(|()| crate::tuic::check(args, resolved))
        .and_then(|()| crate::hysteria::check(args, resolved))
        .and_then(|()| crate::turn::check(args, resolved))
}

/// The words of a run's road, for the refusal of a flag of another road
/// beside it (T-490; the other roads keep their own lists).
pub(crate) fn road_name(transport: &Transport) -> &'static str {
    match transport {
        Transport::Direct => "--direct",
        Transport::Relay { .. } => "the relay",
        Transport::Forwarder { .. } => "the forwarders",
        Transport::Shadowsocks { .. } => "--shadowsocks",
        Transport::Via { .. } => "--via",
        Transport::Vless { .. } => "--vless",
        Transport::Wstunnel { .. } => "--wstunnel",
        Transport::Chisel { .. } => "--chisel",
        Transport::Trojan { .. } => "--trojan",
        Transport::Tuic { .. } => "--tuic",
        Transport::Hysteria { .. } => "--hysteria",
        Transport::Turn { .. } => "--turn",
        Transport::Node { .. } => "a node:// destination",
        Transport::Iroh { .. } => "an iroh: destination",
        Transport::Cloudflare { .. } => "a cf://HOST destination or first hop",
        Transport::Cloud { .. } => "an iap://, eice://, warp:// or tor:// destination or first hop",
        Transport::Derp { .. } => "a derp: destination",
    }
}

/// The road of a run, as the session log names it when no relay host does.
pub(crate) fn road(transport: &Transport) -> &'static str {
    match transport {
        Transport::Relay { .. } => "relay",
        Transport::Direct => "direct",
        Transport::Node { .. } => "node",
        Transport::Iroh { .. } => "iroh",
        Transport::Cloudflare { .. } => "cloudflare",
        Transport::Cloud { road, .. } => road.word(),
        Transport::Derp { .. } => "derp",
        Transport::Forwarder { .. } => "forwarder",
        Transport::Shadowsocks { .. } => "shadowsocks",
        Transport::Via { .. } => "via",
        Transport::Vless { .. } => "vless",
        Transport::Wstunnel { .. } => "wstunnel",
        Transport::Chisel { .. } => "chisel",
        Transport::Trojan { .. } => "trojan",
        Transport::Tuic { .. } => "tuic",
        Transport::Hysteria { .. } => "hysteria",
        Transport::Turn { .. } => "turn",
    }
}

/// The stream to `host:port` through the road of a server that the user
/// named; a road of another kind is not one of these, and says so.
pub(super) async fn reach(resolved: &Resolved, host: &str, port: u16, log: &Arc<Log>) -> Result<Reached, NotReached> {
    match &resolved.transport {
        // Other products' forwarders, in order (T-369).
        Transport::Forwarder { forwarders, trust } => {
            crate::forwarder::reach::reach(forwarders, trust, host, port, log).await
        }
        // The Shadowsocks servers of a file, in order (T-373).
        Transport::Shadowsocks { servers, trust } => {
            crate::shadowsocks::reach::reach(servers, trust, host, port, log).await
        }
        // A forward proxy over TLS that the user runs (T-439).
        Transport::Via { road } => crate::via::reach::reach(road, host, port, resolved.connection_attempts, log).await,
        // The VLESS servers of a file, in order (T-440).
        Transport::Vless { servers, trust } => crate::vless::reach::reach(servers, trust, host, port, log).await,
        // A wstunnel server that the user runs (T-441).
        Transport::Wstunnel { road } => {
            crate::wstunnel::reach::reach(road, host, port, resolved.connection_attempts, log).await
        }
        // The Trojan servers of a file, in order (T-491).
        Transport::Trojan { servers, trust } => crate::trojan::reach::reach(servers, trust, host, port, log).await,
        // The TUIC servers of a file, in order, where UDP passes (T-581).
        Transport::Tuic { servers, trust } => crate::tuic::reach::reach(servers, trust, host, port, log).await,
        // The Hysteria 2 servers of a file, where UDP passes (T-580).
        Transport::Hysteria { servers, trust } => crate::hysteria::reach::reach(servers, trust, host, port, log).await,
        // A TURN server's TCP allocation (T-621).
        Transport::Turn { road } => {
            crate::turn::reach::reach(road, host, port, resolved.connection_attempts, log).await
        }
        // A chisel server that the user runs (T-490).
        Transport::Chisel { road } => {
            crate::chisel::reach::reach(road, host, port, resolved.connection_attempts, log).await
        }
        other => {
            let line = format!("{} is not the road of a server that the user named", road_name(other));
            Err(NotReached { lines: vec![line], code: crate::exitmap::sysexits::EX_SOFTWARE })
        }
    }
}
