//! The stream to the first hop through the servers of `--hysteria` (T-580),
//! each in turn until one carries it: the probe of UDP to its port, QUIC,
//! the credential, then the target, whose answer says whether the server
//! reached it. Each failure is said as it comes, so the last line is the one
//! that the run ends with.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::hysteria::{self, Dial, HysteriaError};
use podssh_ws::Trust;

use super::Servers;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::transport::{NotReached, Reached};

/// The settings of a dial of a run: podssh's bound of a connection, and the
/// probe's wait.
pub fn dial(trust: &Trust) -> Dial<'_> {
    Dial { trust, timeout: podssh_relay::open::CONNECT_TIMEOUT, probe_wait: hysteria::probe::WAIT }
}

/// The stream to `host:port` through the first server that carries it.
pub async fn reach(
    servers: &Servers,
    trust: &Trust,
    host: &str,
    port: u16,
    log: &Arc<Log>,
) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let target = podssh_ws::dial::authority(host, port);
    let dial = dial(trust);
    let mut code = EX_UNAVAILABLE;
    for server in &servers.servers {
        let shown = server.shown();
        log.verbose(&format!("connecting to {target} through the Hysteria 2 server {shown}, where UDP passes"));
        match hysteria::open(server, host, port, &dial).await {
            Ok(opened) => {
                let ms = opened.probe.as_millis();
                log.verbose(&format!(
                    "UDP reached {shown} at {} in {ms} ms; it carries the session to {target} over QUIC",
                    opened.addr
                ));
                // A write that makes no progress fails as on the relay leg,
                // never a wait for ever (T-227).
                let stream = podssh_ws::write_limit::WriteLimit::new(opened.stream, podssh_ws::client::WRITE_TIMEOUT);
                return Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&e.line(&shown, &target));
                code = exit_code(&e);
                // A target that no server takes: the next would refuse it too.
                if code == EX_USAGE {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The exit code of a server that carried nothing, as `proxy` exits: 64 for
/// a target that Hysteria cannot name, 78 for a proxy's variable that cannot
/// be read, 77 for a credential that the server did not take, else 69 (a
/// proxy set for the host, no UDP, QUIC, TLS, or a target that the server
/// could not reach).
pub fn exit_code(e: &HysteriaError) -> i32 {
    match e {
        HysteriaError::Target(_) => EX_USAGE,
        HysteriaError::ProxySetting(_) => EX_CONFIG,
        HysteriaError::Auth(_) => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_the_code_of_proxy() {
        assert_eq!(exit_code(&HysteriaError::Target("x".into())), EX_USAGE);
        assert_eq!(exit_code(&HysteriaError::Auth(404)), EX_NOPERM);
        assert_eq!(exit_code(&HysteriaError::NoUdp("silent".into())), EX_UNAVAILABLE);
        assert_eq!(exit_code(&HysteriaError::Proxied("http://p.example:3128".into())), EX_UNAVAILABLE);
        assert_eq!(exit_code(&HysteriaError::ProxySetting("bad".into())), EX_CONFIG);
        assert_eq!(exit_code(&HysteriaError::Refused("no".into())), EX_UNAVAILABLE);
    }
}
