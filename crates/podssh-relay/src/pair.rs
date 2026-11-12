//! The pairs of the reverse road (feature `pair`): `pod-relay` of
//! PodUtils/podcrates (T-684). A call to the relay takes podssh's context
//! (`crate::context`); the pairs are kept in podssh's cache.

use std::path::PathBuf;

pub use pod_relay::pair::*;

pub mod part;

/// Save `pair` under `label` in the cache.
pub fn store(label: &str, pair: &Pair) -> Result<PathBuf, PairError> {
    pod_relay::pair::store(&crate::context::cache(), label, pair)
}

/// The pair kept under `label`, if any.
pub fn load(label: &str) -> Result<Option<Pair>, PairError> {
    pod_relay::pair::load(&crate::context::cache(), label)
}

/// The labels of the pairs that the cache keeps, sorted.
pub fn labels() -> Vec<String> {
    pod_relay::pair::labels(&crate::context::cache())
}

/// Forget the pair kept under `label`.
pub fn remove(label: &str) -> Result<(), PairError> {
    pod_relay::pair::remove(&crate::context::cache(), label)
}
