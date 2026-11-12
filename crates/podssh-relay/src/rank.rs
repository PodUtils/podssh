//! The rank of the relay hosts as measured from this host (T-606):
//! `pod-relay` of PodUtils/podcrates (T-684), kept in podssh's cache.

use std::path::PathBuf;

pub use pod_relay::rank::*;

/// The rank of the cache, when one is kept.
pub fn load() -> Option<Rank> {
    pod_relay::rank::load(&crate::context::cache())
}

/// Keep `rank` in the cache.
pub fn save(rank: &Rank) -> Result<PathBuf, String> {
    pod_relay::rank::save(&crate::context::cache(), rank)
}

/// Forget the rank of the cache.
pub fn forget() {
    pod_relay::rank::forget(&crate::context::cache())
}
