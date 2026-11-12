//! The legs of a pair and the rotation of its stop token (T-434, T-615):
//! `pod-relay` of PodUtils/podcrates (T-684), with the process's node.

pub use pod_relay::reverse::legs::*;

use super::control::Hello;

/// A socket of the process's node heard `hello`.
pub fn heard(hello: &Hello) {
    pod_relay::reverse::legs::heard(&super::node_state(), hello)
}

/// How many sockets of the process's node heard a role that rotates the
/// pair's stop token.
pub fn offers() -> u64 {
    pod_relay::reverse::legs::offers(&super::node_state())
}

/// Whether a socket of the process's node heard a role that rotates.
pub fn rotates() -> bool {
    pod_relay::reverse::legs::rotates(&super::node_state())
}
