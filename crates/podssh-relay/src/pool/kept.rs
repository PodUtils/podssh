//! The signed lists kept in the cache (T-346): `pod-relay` of
//! PodUtils/podcrates (T-684), in podssh's cache.

pub use pod_relay::pool::kept::*;

use super::signed::{Checked, Keys, Refused, Signed};
use crate::relay::Relay;

/// Check `signed` and keep it, when it holds and is not older than the list
/// kept of its key: what was done, or why not.
pub fn take(signed: &Signed, keys: &Keys, now_ms: i64) -> Result<Taken, Refused> {
    pod_relay::pool::kept::take(&crate::context::cache(), signed, keys, now_ms)
}

/// Each list kept, checked again now with `keys`.
pub fn seen(keys: &Keys, now_ms: i64) -> Vec<Seen> {
    pod_relay::pool::kept::seen(&crate::context::cache(), keys, now_ms)
}

/// The lists that hold now, in the order kept.
pub fn in_force(keys: &Keys, now_ms: i64) -> Vec<Checked> {
    pod_relay::pool::kept::in_force(&crate::context::cache(), keys, now_ms)
}

/// The hosts of other deployments that follow the default list in this
/// process.
pub fn other_hosts(now_ms: i64) -> Vec<Relay> {
    pod_relay::pool::kept::other_hosts(&crate::context::process(), now_ms)
}
