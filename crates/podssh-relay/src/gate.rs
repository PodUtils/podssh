//! A gate for each relay origin in the process (T-637, GitHub #135):
//! `pod-relay` of PodUtils/podcrates (T-684). The gates are the process's, in
//! podssh's context (`crate::context`).

pub use pod_relay::gate::*;

/// The process's gates, which each session of the process shares.
pub fn process() -> &'static Gates {
    crate::context::gates()
}
