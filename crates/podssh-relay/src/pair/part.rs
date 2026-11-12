//! The operator's part kept under a label on an operator's host (T-086):
//! `pod-relay` of PodUtils/podcrates (T-684), in podssh's cache.

use std::path::PathBuf;

pub use pod_relay::pair::part::*;

use super::{OperatorPart, PairError};

/// Save `part` under `label` in the cache.
pub fn store(label: &str, part: &OperatorPart) -> Result<PathBuf, PairError> {
    pod_relay::pair::part::store(&crate::context::cache(), label, part)
}

/// The part kept under `label`, if any.
pub fn load(label: &str) -> Result<Option<OperatorPart>, PairError> {
    pod_relay::pair::part::load(&crate::context::cache(), label)
}

/// Forget the part kept under `label`.
pub fn remove(label: &str) -> Result<(), PairError> {
    pod_relay::pair::part::remove(&crate::context::cache(), label)
}
