//! `podssh proxy --turn turns:HOST HOST PORT` (T-621): the pipe to the
//! target through a TURN server's TCP allocation, as OpenSSH's
//! `ProxyCommand` takes it. The data connection carries the target's bytes
//! as they are, so the end of stdin is its half-close, which the server
//! passes on to the target: the target's bytes come until it closes.

use std::io::Write;
use std::sync::Arc;

use podssh_ws::turn::Dial;
use podssh_ws::ProxyChoice;

use super::Road;
use crate::exit_codes::EXIT_NOT_IMPLEMENTED;
use crate::exitmap::sysexits::EX_UNAVAILABLE;
use crate::pipe::pump::End;
use crate::proxy::ProxyArgs;
use crate::relay_settings::Refusal;

/// The schemes of a target whose road is its own.
const OWN_ROADS: &[&str] =
    &["cf://", "iap://", "eice://", "warp://", "tor://", "upterm://", "upterm+ws://", "devtunnel://"];

/// `--turn` beside another road of `proxy`: a usage error.
pub fn beside(args: &ProxyArgs) -> Result<(), Refusal> {
    if args.turn.url.is_none() {
        return Ok(());
    }
    let own = args.target.as_deref().is_some_and(|t| OWN_ROADS.iter().any(|s| t.starts_with(s)));
    let flags = [
        ("--forwarder", args.forwarder.is_some()),
        ("--shadowsocks", args.shadowsocks.is_some()),
        ("--via", args.via.url.is_some()),
        ("--vless", args.vless.is_some()),
        ("--trojan", args.trojan.is_some()),
        ("--tuic", args.tuic.is_some()),
        ("--hysteria", args.hysteria.is_some()),
        ("--relay-host", args.relay_host.is_some()),
        ("--relay-failover", args.relay_failover.is_some()),
        ("--wstunnel", args.wstunnel.url.is_some()),
        ("--chisel", args.chisel.url.is_some()),
        ("--exit", args.exit.name.is_some()),
    ];
    let other = match own {
        true => Some("a cf://, iap://, eice://, warp:// or tor:// target, which is a road of its own"),
        false => flags.into_iter().find(|(_, given)| *given).map(|(flag, _)| flag),
    };
    match other {
        Some(other) => Err(Refusal::usage(format!("--turn cannot go with {other}; a run has one road"))),
        None => Ok(()),
    }
}

/// The TURN server of `proxy`: the flag, else `PODSSH_TURN` where the
/// command line names no other road and no other road's variable is set.
pub fn chosen(args: &ProxyArgs) -> Result<Option<Road>, Refusal> {
    let others = args.forwarder.is_some()
        || args.shadowsocks.is_some()
        || args.via.url.is_some()
        || args.relay_host.is_some()
        || args.relay_failover.is_some()
        || args.vless.is_some()
        || args.trojan.is_some()
        || args.tuic.is_some()
        || args.hysteria.is_some()
        || args.wstunnel.url.is_some()
        || args.chisel.url.is_some();
    if !args.turn.given() && others {
        return Ok(None);
    }
    // The variable beside another road's variable: neither wins.
    if args.turn.url.is_none() && super::var(super::TURN_ENV).is_some() {
        let other = [
            podssh_relay::relay::RELAY_ENV,
            crate::forwarder::FORWARDER_ENV,
            crate::via::VIA_ENV,
            crate::wstunnel::WSTUNNEL_ENV,
            crate::chisel::CHISEL_ENV,
        ];
        if let Some(other) = other.into_iter().find(|name| super::var(name).is_some()) {
            let why = format!("{} and {other} name two roads; a run has one", super::TURN_ENV);
            return Err(Refusal::config(why));
        }
    }
    super::chosen(&args.turn, crate::via::trust(args.ca_file.as_deref()))
}

/// The pipe of stdin and stdout to `host:port` through `road`: its exit
/// code.
pub fn run(road: &Road, host: &str, port: u16, err: &mut dyn Write) -> i32 {
    crate::session_log::target(host, Some(port), "turn");
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = writeln!(err, "podssh proxy: could not start the async runtime: {e}");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    let code = runtime.block_on(session(road, host, port, err));
    // A read on stdin may still be blocked in a helper thread.
    runtime.shutdown_background();
    code
}

async fn session(road: &Road, host: &str, port: u16, err: &mut dyn Write) -> i32 {
    let mut lines: Vec<String> = Vec::new();
    let opened = open(road, host, port, &mut |line: &str| lines.push(line.to_string())).await;
    for line in &lines {
        let _ = writeln!(err, "podssh: {line}");
    }
    match opened {
        Ok(end) => crate::forwarder::pipe::carry(end, err).await,
        Err(code) => code,
    }
}

/// The end of the road to `host:port`, or the exit code once `say` has the
/// line of the failure. The keeper's word on an allocation that ended goes
/// to stderr as it comes, as the pipe's own lines do.
pub async fn open(road: &Road, host: &str, port: u16, say: &mut (dyn FnMut(&str) + Send)) -> Result<End, i32> {
    if podssh_relay::open::offline() {
        say(&format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV));
        return Err(EX_UNAVAILABLE);
    }
    let dial = Dial {
        trust: &road.trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        note: Arc::new(|line: &str| podssh_ssh::err_line!("podssh: {line}")),
    };
    let target = podssh_ws::dial::authority(host, port);
    match podssh_ws::turn::open(&road.server, &road.credentials, host, port, &dial).await {
        Ok(opened) => {
            let (read, write) = tokio::io::split(opened.stream);
            Ok(End::plain(Box::new(read), Box::new(write)))
        }
        Err(e) => {
            say(&format!("could not connect to {target}: {}", e.line(&road.shown())));
            Err(super::reach::exit_code(&e))
        }
    }
}
