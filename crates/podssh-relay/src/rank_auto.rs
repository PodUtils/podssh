//! A rank made in a session's background, with `RelayRank auto` alone (T-608):
//! `pod-relay` of PodUtils/podcrates (T-684). The races of the process are in
//! podssh's context (`crate::context`).

use std::future::Future;

pub use pod_relay::rank_auto::*;

/// For tests only, `DELAY_MS,GAP_MS` in place of the waits of Q89: read by a
/// build with debug assertions alone, so each release binary keeps Q89's
/// bounds.
pub const PACE_ENV: &str = "PODSSH_RELAY_RANK_PACE";

/// What the settings file says: `true` for `RelayRank auto`.
pub fn set_by_settings(auto: bool) {
    crate::context::give_rank_auto(auto);
}

/// What asks for a rank in the background, in the words that set it, or
/// none: never by default (Q89).
pub fn asked_by() -> Option<&'static str> {
    pod_relay::rank_auto::asked_by(&crate::context::settings())
}

/// Whether a session may rank in its background.
pub fn asked() -> bool {
    pod_relay::rank_auto::asked(&crate::context::settings())
}

/// Q89's waits, or in a build with debug assertions those of [`PACE_ENV`].
pub fn pace() -> Pace {
    pod_relay::rank_auto::pace(&crate::context::settings())
}

/// Count a race that starts in the process: a background probe waits for
/// its end.
pub fn racing() -> Racing {
    pod_relay::rank_auto::racing(crate::context::process().races())
}

/// Whether a race of the process runs now.
pub fn a_race_runs() -> bool {
    crate::context::process().races().a_race_runs()
}

/// Wait until no race of the process runs.
pub async fn calm() {
    crate::context::process().races().calm().await
}

/// `work`, unless a race of the process runs or starts before it ends.
pub async fn unless_a_race<F: Future>(work: F) -> Option<F::Output> {
    crate::context::process().races().unless_a_race(work).await
}

/// The hosts of a day's rank, in order.
pub fn hosts() -> Vec<String> {
    pod_relay::rank_auto::hosts(&crate::context::cache())
}
