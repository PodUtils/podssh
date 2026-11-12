//! The default list of relay hosts takes the rank (T-607): `pod-relay` of
//! PodUtils/podcrates (T-684), with podssh's variable and settings file.

pub use pod_relay::rank_list::*;

use crate::relay::{Relay, RelayList};

/// `PODSSH_RELAY_RANK=no` leaves the rank and the samples out of the order.
pub const ENV: &str = "PODSSH_RELAY_RANK";

/// What the settings file says of the rank: `false` for `RelayRank no`.
pub fn set_by_settings(on: bool) {
    crate::context::give_rank(on);
}

/// Whether the rank and the samples order the default list.
pub fn enabled() -> bool {
    pod_relay::rank_list::enabled(&crate::context::settings())
}

/// The egress of a run to `host`: the proxy that it goes through, by its
/// digest, or `direct`.
pub fn egress_for(host: &str) -> String {
    pod_relay::rank_list::egress_for(&crate::context::process(), host)
}

/// The list of a run, read from the cache.
pub fn placed_now(list: &RelayList) -> Vec<Relay> {
    pod_relay::rank_list::placed_now(&crate::context::process(), list)
}

/// Which order a run of the default list takes now, in a word.
pub fn order_now(primary: &str) -> &'static str {
    pod_relay::rank_list::order_now(&crate::context::process(), primary)
}

/// Keep the samples of a run in the rank's file.
pub fn keep(samples: &Samples) {
    pod_relay::rank_list::keep(&crate::context::process(), samples)
}
