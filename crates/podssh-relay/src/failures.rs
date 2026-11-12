//! The relay hosts as the runs found them lately (T-059, T-563), kept across
//! runs, for each road apart: `pod-relay` of PodUtils/podcrates (T-684), in
//! podssh's cache (`crate::context::cache`).

use std::time::Duration;

pub use pod_relay::failures::*;

/// The record of the cache, a session of `road` through `host` ended after
/// `lasted`, cut on the host's side when `cut`: kept when it changed.
pub fn ended(road: &str, host: &str, lasted: Duration, cut: bool) {
    pod_relay::failures::ended(&crate::context::cache(), road, host, lasted, cut)
}
