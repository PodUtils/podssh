//! The channel between two podssh ends (T-088): `pod-e2e` of
//! PodUtils/podcrates. Noise XX over the bytes of a session, so that the
//! relay sees ciphertext only, and each end proves its key of T-087
//! (`crate::identity`). podssh keeps three parts of its own: the net's
//! documents of this process ([`net`], T-429), the holds of this process's
//! channels and the move of a channel's pipe at a handover ([`hold`],
//! T-668), and podssh's lines of a node's events ([`events`], [`say`]).

/// The events of a node's lines, for the users of this module.
pub use pod_core::{Event, Events, NoEvents};
pub use pod_e2e::*;

pub mod hold;
pub mod net;

use std::sync::Arc;

/// A node's lines, as the crate's events: the text of each to `say`.
pub fn events(say: Arc<dyn Fn(String) + Send + Sync>) -> Arc<dyn Events> {
    Arc::new(move |event: Event| say(event.text))
}

/// A node of this process: its lines go to `say`, and it reads the net's
/// documents and the holds of this process.
pub fn node(
    identity: Arc<pod_identity::Identity>,
    admit: Arc<ends::Admit>,
    say: Arc<dyn Fn(String) + Send + Sync>,
    redeem: Option<Arc<ends::Redeem>>,
    gate: Option<Arc<person::Gate>>,
) -> ends::Node {
    let (events, docs, holds) = (events(say), net::process(), hold::holds());
    ends::Node { identity, admit, events, redeem, leases: Default::default(), gate, docs, holds }
}

/// The kind of the events of podssh's own lines through a node's sink.
pub const LINE: &str = "podssh.node";

/// podssh's own lines of a node, through the node's events.
pub fn say(node: &ends::Node) -> Arc<dyn Fn(String) + Send + Sync> {
    let events = node.events.clone();
    Arc::new(move |line: String| events.event(Event::info(LINE, line)))
}
