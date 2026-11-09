//! SSH's keepalives on a road that carries the resumable layer (T-154, T-300, T-703).
//!
//! Some roads are known to run the layer before they connect (a node, iroh,
//! DERP); `cf://` and the carrier roads learn it from the far end's greeting,
//! after `resolve`. The decision is one pure function so that the guard in
//! `tries` and its tests share it.

use super::resolve::Transport;

/// Said once when the user's `ServerAliveInterval` stays on a layered road.
pub(crate) const WARNING: &str =
    "ServerAliveInterval ends the session after ServerAliveCountMax keepalives with no answer, \
     also while the resumable layer would carry it onto a new link";

/// The roads whose layer is certain before the connection: `resolve` warns for them.
pub(crate) fn known_before_connect(transport: &Transport) -> bool {
    matches!(transport, Transport::Node { .. } | Transport::Iroh { .. } | Transport::Derp { .. })
}

/// What the guard does after a road connected.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Keepalives {
    /// Leave them as they are.
    Keep,
    /// The user named no interval and the layer's heartbeat finds a dead link.
    Drop,
    /// The user's interval stays (T-154), with one warning.
    Warn,
}

/// `layer`: the far end greeted with it. `alive_default`: no interval was named.
/// `interval_on`: SSH's keepalives are set. `warned`: `resolve` already warned.
pub(crate) fn decide(layer: bool, alive_default: bool, interval_on: bool, warned: bool) -> Keepalives {
    match (layer, interval_on) {
        (true, true) if alive_default => Keepalives::Drop,
        (true, true) if !warned => Keepalives::Warn,
        _ => Keepalives::Keep,
    }
}

/// The guard of a try that reached its far end: SSH's keepalives dropped
/// where the layer came and the user named no interval, or one warning on
/// the first try where the user named one and `resolve` could not know.
pub(crate) fn apply(
    layer: bool,
    resolved: &super::resolve::Resolved,
    interval: &mut Option<std::time::Duration>,
    first: bool,
    log: &podssh_ssh::Log,
) {
    let known = known_before_connect(&resolved.transport);
    match decide(layer, resolved.alive_default, interval.is_some(), known) {
        Keepalives::Drop => {
            *interval = None;
            log.verbose("the far end runs the resumable layer, whose heartbeat finds a dead link: no SSH keepalives");
        }
        Keepalives::Warn if first => log.warning(WARNING),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_layer_and_an_explicit_interval_warn_once() {
        assert_eq!(decide(true, false, true, false), Keepalives::Warn);
    }

    #[test]
    fn a_layer_and_the_default_interval_drop_it_with_no_warning() {
        assert_eq!(decide(true, true, true, false), Keepalives::Drop);
    }

    #[test]
    fn no_layer_means_no_warning_and_the_keepalives_stay() {
        assert_eq!(decide(false, false, true, false), Keepalives::Keep);
        assert_eq!(decide(false, true, true, false), Keepalives::Keep);
    }

    #[test]
    fn an_interval_of_zero_has_nothing_to_warn_about() {
        assert_eq!(decide(true, false, false, false), Keepalives::Keep);
    }

    #[test]
    fn a_road_that_resolve_warned_for_is_not_warned_twice() {
        assert_eq!(decide(true, false, true, true), Keepalives::Keep);
    }

    #[test]
    fn the_warning_names_the_setting_and_the_layer() {
        assert!(WARNING.contains("ServerAliveInterval") && WARNING.contains("resumable layer"));
    }
}
