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
pub async fn open(req: &Request<'_>, notes: &mut dyn FnMut(&str)) -> Result<Opened, Failure> {
    let ctx = crate::context::process();
    let Request { relays, path, trust, target, rounds, failover } = *req;
    pod_relay::open::open(&pod_relay::open::Request { ctx: &ctx, relays, path, trust, target, rounds, failover }, notes)
        .await
}
