//! Which sessions of the forward road take the WebSocket over HTTP/2 (T-321):
//! `pod-relay` of PodUtils/podcrates (T-684), by podssh's variable
//! [`H2_ENV`], which the settings of podssh's context hold.

pub use pod_relay::h2_road::*;

/// The variable that says which sessions take the road.
pub const H2_ENV: &str = "PODSSH_H2";

/// The choice of this process's variable; another word is refused, with
/// why.
pub fn from_env() -> Result<Choice, String> {
    Choice::of(&crate::context::process())
}
