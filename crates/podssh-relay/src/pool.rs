//! The relay's pool of hosts, as the relay publishes it, cached between runs:
//! `pod-relay` of PodUtils/podcrates (T-684), in podssh's cache, with the
//! limits of the relay that the process uses in podssh's context.

use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};

pub use pod_relay::pool::*;

use crate::relay::Relay;

pub mod kept;
pub mod members;
pub mod signed;

/// The limits of the pool of `primary` that the cache keeps.
pub fn cached_limits(primary: &str) -> Limits {
    pod_relay::pool::cached_limits(&crate::context::cache(), primary)
}

/// Keep `limits` as the process's, for the budgets of its sessions.
pub fn set_in_use(limits: Limits) {
    crate::context::process().set_in_use(limits)
}

/// The limits of the relay that the process's sessions use.
pub fn in_use() -> Limits {
    crate::context::process().in_use()
}

/// The pool of `primary` that the cache keeps, the default host left out.
pub fn alternates(primary: &str) -> Vec<String> {
    pod_relay::pool::alternates(&crate::context::cache(), primary)
}

/// When the cache last took the pool of `primary`, and its size.
pub fn cached(primary: &str) -> Option<(i64, usize)> {
    pod_relay::pool::cached(&crate::context::cache(), primary)
}

/// Whether the pool of `primary` in the cache is stale at `now_ms`.
pub fn needs_refresh(primary: &str, now_ms: i64) -> bool {
    pod_relay::pool::needs_refresh(&crate::context::cache(), primary, now_ms)
}

/// Ask `relay` for the pool of `primary` through `proxy`, and keep it.
pub async fn refresh(
    relay: &Relay,
    primary: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<usize, String> {
    pod_relay::pool::refresh(&crate::context::of(proxy), relay, primary, trust, timeout).await
}
