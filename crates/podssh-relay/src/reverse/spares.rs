//! The sessions that the relay role keeps readied ahead for a node (T-650):
//! `pod-relay` of PodUtils/podcrates (T-684), with the process's node and
//! podssh's sink of its line.

use std::sync::OnceLock;

pub use pod_relay::reverse::spares::*;

use super::control::Hello;

/// Where the node's line of its spares goes.
type Say = Box<dyn Fn(&str) + Send + Sync>;

static SAY: OnceLock<Say> = OnceLock::new();

/// Send the node's line of its spares to `say` from now on: its stderr, which
/// a detached node's log keeps. The first call holds.
pub fn tell(say: impl Fn(&str) + Send + Sync + 'static) {
    let _ = SAY.set(Box::new(say));
}

/// Say `line` where [`tell`] sends it, if anywhere.
pub(crate) fn say(line: &str) {
    if let Some(say) = SAY.get() {
        say(line);
    }
}

/// What the process's node asks of a role whose `hello` it heard, wanting
/// `want`: the frame of its ask, where the role offers spares.
pub fn heard(hello: &Hello, want: u8) -> Option<String> {
    pod_relay::reverse::spares::heard(&super::node_state(), hello, want)
}
