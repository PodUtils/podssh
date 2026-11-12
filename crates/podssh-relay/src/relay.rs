//! Which relay hosts to use, in what order: `pod-relay` of PodUtils/podcrates
//! (T-684), with podssh's variables and the limits that its process uses.

pub use pod_relay::relay::*;

/// Environment variable that replaces the relay: `host`, `host:port`, or an
/// ordered list of them separated by commas.
pub const RELAY_ENV: &str = "PODSSH_RELAY";

/// Lowers the byte budget, for a relay with smaller caps or a test; it never
/// raises it.
pub const SESSION_BUDGET_ENV: &str = "PODSSH_SESSION_BUDGET";

/// The byte budget, with `env` (the value of [`SESSION_BUDGET_ENV`]) lowering
/// it, under the limits of the relay that the process uses.
pub fn byte_budget(env: Option<&str>) -> u64 {
    pod_relay::relay::byte_budget(&crate::context::process(), env)
}
