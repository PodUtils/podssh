//! A `GET /health` on one relay host (T-058), over the same proxy-aware,
//! verified path as a session: `pod-relay` of PodUtils/podcrates (T-684).
//! `podssh doctor` and `podssh relay status` read a host the same way.

use std::time::Duration;

use podssh_ws::{ProxyChoice, Trust};

pub use pod_relay::health::*;

use crate::relay::Relay;

/// The health of `relay` through `proxy`, each step within `timeout`.
pub async fn fetch(
    relay: &Relay,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<Health, HealthError> {
    pod_relay::health::fetch(&crate::context::of(proxy), relay, trust, timeout).await
}
