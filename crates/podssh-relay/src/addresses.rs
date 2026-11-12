//! The addresses that carried a session to each relay host (T-344), kept
//! across runs: `pod-relay` of PodUtils/podcrates (T-684), in podssh's cache,
//! for the process's resolver (`podssh_ws::resolve`).

pub use pod_relay::addresses::*;

/// Give the process's resolver the record of the cache, before a command
/// dials a relay host. The process keeps it, so that a resolver made again
/// for new pins has it too.
pub fn install() {
    podssh_ws::resolve::set_remembered(Addresses::load(&crate::context::cache()).remembered());
}
