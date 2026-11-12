//! `--turn turns:HOST[:PORT]` (T-621, the operator's rulings Q66, Q93 and
//! Q95): a TURN server that the user runs (coturn beside a server of calls)
//! dials the TCP target of RFC 6062's allocations, so it is the road in
//! place of the relay. podssh opens the control connection and, once the
//! server reached the target, a second connection to the same server that
//! carries the bytes (`podssh_ws::turn`), each through `HTTPS_PROXY` when
//! one is set; SSH's host key protects the session, as on each road.
//!
//! The server comes from `--turn`, else `PODSSH_TURN` where the command line
//! names no other road. Its credential comes from a private file,
//! `--turn-auth-file` or `PODSSH_TURN_AUTH_FILE`, never from the URI, where
//! argv would show it: `USER:PASSWORD`, or `auth-secret SECRET` for a
//! coturn of `use-auth-secret`.

pub mod pipe;
pub mod reach;

use std::path::Path;

use podssh_ws::turn::{Credentials, Server};
use podssh_ws::Trust;
use zeroize::Zeroizing;

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::resolve::{Env, Resolved, Transport};

/// The variable of the server, as `--turn`.
pub const TURN_ENV: &str = "PODSSH_TURN";
/// The variable of its credential file, as `--turn-auth-file`.
pub const AUTH_ENV: &str = "PODSSH_TURN_AUTH_FILE";

/// The flags of a command that takes `--turn`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flags {
    pub url: Option<String>,
    pub auth_file: Option<String>,
}

impl Flags {
    pub fn of(args: &SshArgs) -> Flags {
        Flags { url: args.turn.clone(), auth_file: args.turn_auth_file.clone() }
    }

    pub fn given(&self) -> bool {
        self.url.is_some() || self.auth_file.is_some()
    }
}

/// The server of a run, its credential, and the trust of its TLS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Road {
    pub server: Server,
    pub credentials: Credentials,
    pub trust: Trust,
}

impl Road {
    /// The server as each line names it: its URI, which holds no secret.
    pub fn shown(&self) -> String {
        self.server.shown()
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

/// The road of the flags, else of the variables; none when neither names a
/// server. A bad flag is a usage error (64), a bad variable or credential
/// file a configuration error (78).
pub fn chosen(flags: &Flags, trust: Trust) -> Result<Option<Road>, Refusal> {
    from(flags, var(TURN_ENV), var(AUTH_ENV), trust)
}

/// [`chosen`] with the variables given.
pub fn from(
    flags: &Flags,
    url_env: Option<String>,
    auth_env: Option<String>,
    trust: Trust,
) -> Result<Option<Road>, Refusal> {
    let (url, flag) = match (&flags.url, url_env) {
        (Some(url), _) => (url.clone(), true),
        (None, Some(url)) => (url, false),
        (None, None) if flags.auth_file.is_some() => {
            return Err(Refusal::usage(format!("--turn-auth-file is for --turn, or {TURN_ENV}")))
        }
        (None, None) => return Ok(None),
    };
    let bad = |why: String| match flag {
        true => Refusal::usage(format!("--turn: {why}")),
        false => Refusal::config(format!("{TURN_ENV}: {why}")),
    };
    let server = Server::parse(&url).map_err(bad)?;
    podssh_ws::turn::check(&server).map_err(bad)?;
    // Each TURN server that allocates for a client asks its credential:
    // with no file there is nothing to answer its 401 with.
    let Some(path) = flags.auth_file.clone().or(auth_env) else {
        return Err(bad(format!("a TURN server asks a credential: give --turn-auth-file FILE, or {AUTH_ENV}")));
    };
    let at = format!("--turn-auth-file {path}");
    let text =
        podssh_relay::cache::read_private(Path::new(&path)).map_err(|why| Refusal::config(format!("{at}: {why}")))?;
    let text = Zeroizing::new(text);
    let credentials = Credentials::parse(&text).map_err(|why| Refusal::config(format!("{at}: {why}")))?;
    Ok(Some(Road { server, credentials, trust }))
}

/// The flag of another road on the command line, if one is given.
fn other_road(args: &SshArgs) -> Option<&'static str> {
    let flags = [
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.is_some()),
        ("--vless", args.vless.is_some()),
        ("--trojan", args.trojan.is_some()),
        ("--tuic", args.tuic.is_some()),
        ("--hysteria", args.hysteria.is_some()),
        ("--wstunnel", args.wstunnel.is_some()),
        ("--chisel", args.chisel.is_some()),
    ];
    flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag)
}

/// The variable of another road beside `PODSSH_TURN`, if one is set.
fn other_variable(env: &Env) -> Option<&'static str> {
    if env.relay.is_some() {
        return Some(podssh_relay::relay::RELAY_ENV);
    }
    let others = [
        crate::forwarder::FORWARDER_ENV,
        crate::via::VIA_ENV,
        crate::wstunnel::WSTUNNEL_ENV,
        crate::chisel::CHISEL_ENV,
    ];
    others.into_iter().find(|name| var(name).is_some())
}

/// The road of a run that resolved to the relay: the TURN server when
/// `--turn` names one, or `PODSSH_TURN` where neither the command line nor
/// another variable names another road; else the road as it was. It runs
/// first among the servers' roads, so that its flag refuses each other's.
pub fn or_relay(args: &SshArgs, env: &Env, relay: Transport) -> Result<Transport, Refusal> {
    let Transport::Relay { trust, family, .. } = &relay else { return Ok(relay) };
    let flags = Flags::of(args);
    match (&flags.url, other_road(args)) {
        (Some(_), Some(other)) => {
            return Err(Refusal::usage(format!("--turn and {other} name two roads; a run has one")))
        }
        (None, Some(_)) if flags.auth_file.is_none() => return Ok(relay),
        (None, None) if var(TURN_ENV).is_some() => {
            if let Some(other) = other_variable(env) {
                return Err(Refusal::config(format!("{TURN_ENV} and {other} name two roads; a run has one")));
            }
        }
        _ => {}
    }
    let Some(road) = chosen(&flags, trust.clone())? else { return Ok(relay) };
    if family.is_some() {
        let why = "-4 and -6 choose the family that the relay dials; the TURN server dials the target's address";
        return Err(Refusal::usage(why));
    }
    Ok(Transport::Turn { road })
}

/// `--turn` beside a road of its own, which [`or_relay`] never took, and
/// `--turn-auth-file` with no server: a usage error.
pub fn check(args: &SshArgs, resolved: &Resolved) -> Result<(), Refusal> {
    let other = match &resolved.transport {
        Transport::Turn { .. } => return Ok(()),
        other => crate::ssh::servers::road_name(other),
    };
    if args.turn.is_some() {
        let why = format!("--turn cannot go with {other}, which is a road of its own; a run has one road");
        return Err(Refusal::usage(why));
    }
    if args.turn_auth_file.is_some() {
        let why = format!("--turn-auth-file is for --turn, or {TURN_ENV}, which {other} does not take");
        return Err(Refusal::usage(why));
    }
    Ok(())
}

/// The server that `podssh doctor --turn` checks: the flags alone, as
/// doctor names each road that it checks.
pub fn for_doctor(flags: &Flags, ca_file: Option<&str>) -> Result<Option<Road>, Refusal> {
    match flags.url {
        Some(_) => from(flags, None, None, crate::via::trust(ca_file)),
        None if flags.auth_file.is_some() => Err(Refusal::usage("--turn-auth-file is for --turn")),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests;
