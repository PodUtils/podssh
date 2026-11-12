//! The node and the operator of the reverse road (feature `pair`): `pod-relay`
//! of PodUtils/podcrates (T-684). A runner takes podssh's context
//! (`crate::context`). What a node keeps across its sockets is one
//! `NodeState` for the process ([`node_state`]), as one node runs in a
//! process; its lines go where podssh sends them: the line of the spares to
//! the sink of [`spares::tell`], the line of a relay's close to the budget's
//! sink (`crate::session::budget`).

use std::sync::{Arc, OnceLock};

use pod_core::{Event, Events};

pub use pod_relay::reverse::*;

pub mod legs;
pub mod node;
pub mod spares;
pub mod tcp;

/// The node of the process.
static NODE: OnceLock<Arc<NodeState>> = OnceLock::new();

/// What the node of the process keeps across its sockets and its pairs.
pub fn node_state() -> Arc<NodeState> {
    NODE.get_or_init(|| Arc::new(NodeState::new(Arc::new(Lines)))).clone()
}

/// The settings of a node's socket, with the node of the process: give each
/// runner these, so that its upgrade, its rotations and its lines are the
/// process's.
pub fn settings() -> Settings {
    Settings { node: node_state(), ..Settings::default() }
}

/// The node's lines, as podssh said them.
struct Lines;

impl Events for Lines {
    fn event(&self, event: Event) {
        match event.kind {
            pod_relay::reverse::spares::EVENT => spares::say(&event.text),
            _ => crate::session::budget::say(&event.text),
        }
    }
}
