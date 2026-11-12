//! The stream to the first hop through the TURN server of `--turn` (T-621),
//! with `ConnectionAttempts` as `--direct` takes them: each try says why it
//! failed as it comes, and a refusal of the server's (the credential, its
//! policy, no TCP allocation) or a setting that cannot work ends the tries.

use std::sync::Arc;

use podssh_ssh::Log;
use podssh_ws::turn::{Dial, TurnError};
use podssh_ws::{ConnectError, DialError, ProxyChoice};

use super::Road;
use crate::exitmap::sysexits::{EX_CONFIG, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use crate::ssh::transport::{NotReached, Reached};

/// The stream to `host:port` through `road`, in at most `rounds` tries.
pub async fn reach(road: &Road, host: &str, port: u16, rounds: u32, log: &Arc<Log>) -> Result<Reached, NotReached> {
    if podssh_relay::open::offline() {
        let line = format!("{} is set, so podssh does not connect anywhere", podssh_relay::open::OFFLINE_ENV);
        return Err(NotReached { lines: vec![line], code: EX_UNAVAILABLE });
    }
    let (target, shown) = (podssh_ws::dial::authority(host, port), road.shown());
    // The keeper of the allocation says why it ended, once the session runs.
    let said = log.clone();
    let dial = Dial {
        trust: &road.trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: podssh_relay::open::CONNECT_TIMEOUT,
        note: Arc::new(move |line: &str| said.error(line)),
    };
    let rounds = rounds.max(1);
    let mut code = EX_UNAVAILABLE;
    for round in 1..=rounds {
        if round > 1 {
            let wait = podssh_relay::open::backoff(round - 1);
            log.info(&format!("retrying in {:.1} s (attempt {round} of {rounds})", wait.as_secs_f32()));
            tokio::time::sleep(wait).await;
        }
        log.verbose(&format!("connecting to {target} through the TURN server {shown}"));
        match podssh_ws::turn::open(&road.server, &road.credentials, host, port, &dial).await {
            Ok(opened) => {
                log.verbose(&said_of(&shown, &target, &opened));
                // A write that makes no progress fails as on the relay leg,
                // never a wait for ever (T-227).
                let stream = podssh_ws::write_limit::WriteLimit::new(opened.stream, podssh_ws::client::WRITE_TIMEOUT);
                return Ok(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None });
            }
            Err(e) => {
                log.error(&format!("could not connect to {target}: {}", e.line(&shown)));
                code = exit_code(&e);
                // The server's answer, or a setting, is the same at each try.
                if code != EX_UNAVAILABLE || matches!(e, TurnError::NoTcp { .. }) {
                    break;
                }
            }
        }
    }
    Err(NotReached { lines: Vec::new(), code })
}

/// The line of `-v` of a road that opened: the allocation, then the target.
pub fn said_of(shown: &str, target: &str, opened: &podssh_ws::turn::Opened) -> String {
    let software = opened.software.as_deref().map(|s| format!(" ({s})")).unwrap_or_default();
    let relayed = opened.relayed.map(|a| format!(" at {a}")).unwrap_or_default();
    format!(
        "the TURN server {shown}{software} allocated{relayed} for {} s in {} ms, and reached {target} in {} ms; \
         a second connection carries the session",
        opened.lifetime,
        opened.allocate.as_millis(),
        opened.connect.as_millis()
    )
}

/// The exit code of a road that did not open, as `proxy` exits: 64 for a
/// target that cannot go, 78 for a setting, 77 for a credential or a
/// target that the server refused, and for a 403 or 407 of the host's
/// proxy, else 69 (no TCP allocation, a target not reached, the network).
pub fn exit_code(e: &TurnError) -> i32 {
    match e {
        TurnError::Target(_) => EX_USAGE,
        TurnError::Connect(c) => match c {
            ConnectError::Config(_) | ConnectError::Dial(DialError::BadProxy(_) | DialError::InvalidTarget(_)) => {
                EX_CONFIG
            }
            ConnectError::Dial(DialError::ProxyRefused { status: 403 | 407, .. }) => EX_NOPERM,
            _ => EX_UNAVAILABLE,
        },
        TurnError::Auth(_) | TurnError::Forbidden(_) => EX_NOPERM,
        TurnError::NoTcp { .. }
        | TurnError::Unreached(_)
        | TurnError::Refused { .. }
        | TurnError::Protocol(_)
        | TurnError::Timeout { .. } => EX_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_refusal_of_step_5_has_its_code() {
        assert_eq!(exit_code(&TurnError::NoTcp { code: 442, reason: "x".into() }), EX_UNAVAILABLE);
        assert_eq!(exit_code(&TurnError::NoTcp { code: 508, reason: "x".into() }), EX_UNAVAILABLE);
        assert_eq!(exit_code(&TurnError::Auth("401 Unauthorized".into())), EX_NOPERM);
        assert_eq!(exit_code(&TurnError::Forbidden("Forbidden IP".into())), EX_NOPERM);
        assert_eq!(exit_code(&TurnError::Unreached("Connection Timeout".into())), EX_UNAVAILABLE);
        assert_eq!(exit_code(&TurnError::Target("x".into())), EX_USAGE);
        assert_eq!(exit_code(&TurnError::Connect(ConnectError::Config("x".into()))), EX_CONFIG);
    }

    #[test]
    fn a_refusal_says_the_server_and_its_words() {
        let e = TurnError::NoTcp { code: 442, reason: "Unsupported Transport Protocol".into() };
        assert_eq!(
            e.line("turns:t.example.org"),
            "the TURN server turns:t.example.org: it refused a TCP allocation (442 Unsupported Transport \
             Protocol): the server offers no RFC 6062"
        );
        let e = TurnError::Forbidden("Forbidden IP".into());
        assert!(e.line("turns:t").ends_with("its policy refuses the target (403 Forbidden IP)"));
    }
}
