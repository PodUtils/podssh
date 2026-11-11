//! A node's channel held for the binary that takes its place (T-668):
//! `pod-e2e`'s, with the holds of this process, which each road of a node
//! shares ([`holds`]), and the move of a channel's pipe at a handover
//! ([`Movable`] of tokio's `DuplexStream`).

pub use pod_e2e::hold::*;

use std::future::Future;
use std::sync::{Arc, OnceLock};

use tokio::io::DuplexStream;

use crate::session::handover::{Movable, Moving};
use crate::session::SessionId;

/// The holds of the channels of this process: each node takes them
/// (`ends::Node::holds`), so a handover finds the channel of each road.
pub fn holds() -> Arc<Holds> {
    static HOLDS: OnceLock<Arc<Holds>> = OnceLock::new();
    HOLDS.get_or_init(Arc::default).clone()
}

/// `task`, the channel's task of a session that the layer opens now, with a
/// hold of this process that a handover finds by the layer's id of the
/// session ([`Holds::holding`]).
pub fn holding<F>(task: F) -> impl Future<Output = ()>
where
    F: Future<Output = ()>,
{
    holds().holding(task)
}

/// The layer's side of a session's pipe to its channel: the channel stops
/// between two messages, and moves with its TCP target. One that runs no
/// channel in this process (a pipe that copies a target as it is) does not.
impl Movable for DuplexStream {
    fn move_out(self, id: SessionId) -> Moving {
        holds().move_out(self, id)
    }
}
