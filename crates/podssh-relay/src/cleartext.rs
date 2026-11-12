//! The cleartext road on the relay's port, last (T-326): `pod-relay` of
//! PodUtils/podcrates (T-684), over podssh's context and its variable.

use std::time::Duration;

use podssh_ws::{ProxyChoice, RelaySession};

pub use pod_relay::cleartext::*;

use crate::open::OpenError;
use crate::relay::Relay;

/// The variable that turns the cleartext road off, the forwarders' `ws://`
/// form with it.
pub const CLEARTEXT_ENV: &str = "PODSSH_CLEARTEXT";

/// Whether the road is on: unset, empty or yes; no turns it off; another
/// word is refused, with why.
pub fn on_from(value: Option<&str>) -> Result<bool, String> {
    pod_relay::cleartext::on_from(value, CLEARTEXT_ENV)
}

/// [`on_from`] of this process's variable.
pub fn on() -> Result<bool, String> {
    on_from(std::env::var(CLEARTEXT_ENV).ok().as_deref())
}

/// The road after the TLS road failed with `attempts`, as the process's
/// context takes it; `notes` hears each step.
pub async fn last(
    hosts: &[Relay],
    attempts: &[(String, OpenError)],
    path: &str,
    notes: &mut dyn FnMut(&str),
) -> Option<(Relay, RelaySession)> {
    pod_relay::cleartext::last(&crate::context::process(), hosts, attempts, path, notes).await
}

/// The road to `tried`, in order, as [`last`] takes it.
pub async fn over(tried: Vec<Relay>, path: &str, notes: &mut dyn FnMut(&str)) -> Option<(Relay, RelaySession)> {
    pod_relay::cleartext::over(&crate::context::process(), tried, path, notes).await
}

/// One host in cleartext through `proxy`: the mint of a token of one
/// session, then the upgrade at `path` with it, each step within `step`.
pub async fn attempt(relay: &Relay, path: &str, proxy: &ProxyChoice, step: Duration) -> Result<RelaySession, String> {
    pod_relay::cleartext::attempt(&crate::context::of(proxy), relay, path, step).await
}
