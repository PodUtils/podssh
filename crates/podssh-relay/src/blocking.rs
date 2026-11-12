//! A synchronous facade over the pairs, the runners and the forward sessions,
//! for a caller with no async runtime (T-081): `pod-relay` of
//! PodUtils/podcrates (T-684). [`config`] gives its configuration over
//! podssh's context of the process.

pub use pod_relay::blocking::*;

/// The configuration of the facade over podssh's context of the process.
pub fn config() -> Config {
    Config::new(crate::context::process())
}
