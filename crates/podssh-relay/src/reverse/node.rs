//! The node of the reverse road: `pod-relay` of PodUtils/podcrates (T-684),
//! with the upgrade of the process's node (T-668).

pub use pod_relay::reverse::node::*;

/// This node's next stop is for the binary that takes its place, or no
/// longer is: its `close` of each session says which.
pub fn set_upgrading(on: bool) {
    super::node_state().set_upgrading(on);
}

/// The words of a stop's `close` of each session, for the process's node.
pub fn stopping_words() -> &'static str {
    pod_relay::reverse::node::stopping_words(&super::node_state())
}
