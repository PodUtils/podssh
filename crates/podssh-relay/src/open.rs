//! Opening a forward session through the relay, with failover: `pod-relay` of
//! PodUtils/podcrates (T-684). podssh's request has no context: [`open`] gives
//! it the context of the process (`crate::context`). The variable that
//! forbids each connection is podssh's.

use podssh_ws::Trust;

pub use pod_relay::open::*;

use crate::failover::Mode;
use crate::relay::RelayList;

/// Environment variable that forbids every network connection. Test suites
/// set it for the binaries they run, so no test can reach the relay by
/// accident; it is not meant for users.
pub const OFFLINE_ENV: &str = "PODSSH_OFFLINE";

/// Whether [`OFFLINE_ENV`] is set (to anything but empty or `0`).
pub fn offline() -> bool {
    std::env::var(OFFLINE_ENV).is_ok_and(|v| !v.is_empty() && v != "0")
}

/// What to open.
pub struct Request<'a> {
    pub relays: &'a RelayList,
    /// `/connect/<host>/<port>`, with the relay's connect knobs if any.
    pub path: &'a str,
    pub trust: &'a Trust,
    /// `host:port`, for messages.
    pub target: &'a str,
    /// Rounds over the whole list (`ConnectionAttempts`); at least one.
    pub rounds: u32,
    /// How the hosts of a round are tried (T-220).
    pub failover: Mode,
}

/// Open a session for `req` through the context of the process, as
/// `pod_relay::open` does; `notes` hears each step.
pub async fn open(req: &Request<'_>, notes: &mut (dyn FnMut(&str) + Send)) -> Result<Opened, Failure> {
    let ctx = crate::context::process();
    let Request { relays, path, trust, target, rounds, failover } = *req;
    pod_relay::open::open(&pod_relay::open::Request { ctx: &ctx, relays, path, trust, target, rounds, failover }, notes)
        .await
}

/// `pod-relay`'s words for an offline run and a rejected token, which name
/// no variable; podssh's name the one that the user sets.
const GENERIC_OFFLINE: &str = "the offline setting is on, so no connection goes anywhere";
const GENERIC_TOKEN: &str = "the relay token that was given was rejected";

/// The lines of `failure` for `target`, as `Failure::lines` gives them, in
/// podssh's words where `pod-relay`'s name no variable: `PODSSH_OFFLINE`
/// and `PODSSH_RELAY_TOKEN`, as before the crate moved (T-684).
pub fn words(failure: &Failure, target: &str) -> Vec<String> {
    failure
        .lines(target)
        .into_iter()
        .map(|line| {
            line.replace(GENERIC_OFFLINE, &format!("{OFFLINE_ENV} is set, so no connection goes anywhere"))
                .replace(GENERIC_TOKEN, &format!("the token in {} was rejected", crate::token::TOKEN_ENV))
        })
        .collect()
}

#[cfg(test)]
mod words_tests {
    use super::*;

    #[test]
    fn the_lines_name_podssh_s_variables() {
        let failure = Failure { attempts: vec![(String::from("relay.example"), OpenError::Offline)] };
        let lines = words(&failure, "host:22");
        assert!(lines.iter().any(|l| l.contains("PODSSH_OFFLINE is set")), "{lines:?}");
        assert!(!lines.iter().any(|l| l.contains(GENERIC_OFFLINE)), "{lines:?}");
    }
}
