//! The stream to the first hop through the servers of `--tuic` (T-581),
//! each in turn until one carries it. Each goes only where its probe of UDP
//! was answered; an SSH server speaks first, so each waits for its version
//! line: a server that closes the connection did not take the UUID or the
//! password, one that ends the stream could not reach the target, and the
//! next is tried. Each failure is said as it comes, so the last line is the
//! one that the run ends with.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::tuic::{self, Dial, TuicError};
use podssh_ws::Trust;

use super::Servers;
use crate::exitmap::sysexits::{EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::transport::{NotReached, Reached};

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
    let dial = Dial {
        trust,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        answer: tuic::ANSWER_WAIT,
        silence_is_ready: false,
        probe_wait: tuic::PROBE_WAIT,
    };
    let mut code = EX_UNAVAILABLE;
    for server in &servers.servers {
        let shown = server.shown();
        // QUIC is UDP: a proxy of the host carries none of it, so say that
        // the road goes beside one.
        let beside = if podssh_ws::dial::PROXY_VARS.iter().any(|v| std::env::var_os(v).is_some()) {
            ", over UDP beside the host's proxy, which carries no UDP"
        } else {
            ", over UDP"
        };
        log.verbose(&format!("connecting to {target} through the TUIC server {shown}{beside}"));
        match tuic::open(server, host, port, &dial).await {
            Ok(opened) => {
                log.verbose(&format!("the TUIC server {shown} carries the session to {target} over {}", opened.how));
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

/// The exit code of a server that carried nothing, as `proxy` exits: 64
/// for a target that TUIC cannot name, 77 for a connection that the server
/// closed (a UUID or a password that it did not take), else 69, a probe of
/// UDP with no answer among them.
pub fn exit_code(e: &TuicError) -> i32 {
    match e {
        TuicError::Target(_) => EX_USAGE,
        TuicError::Closed { .. } => EX_NOPERM,
        _ => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_has_the_code_of_proxy() {
        assert_eq!(exit_code(&TuicError::Target("x".into())), EX_USAGE);
        assert_eq!(exit_code(&TuicError::Closed { code: 0, reason: String::new() }), EX_NOPERM);
        assert_eq!(exit_code(&TuicError::NoUdp("silent".into())), EX_UNAVAILABLE);
        assert_eq!(exit_code(&TuicError::TargetEnded), EX_UNAVAILABLE);
    }
}
