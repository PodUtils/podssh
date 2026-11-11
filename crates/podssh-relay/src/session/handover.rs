//! A far end's sessions handed to the binary that takes its place (T-668):
//! `pod-session` of PodUtils/podcrates. The move of a target is podssh's
//! trait: the pipe to the end-to-end channel (`crate::e2e::hold`) is
//! tokio's `DuplexStream`, which cannot take a trait of another crate.

use pod_session::SessionId;

pub use pod_session::handover::*;

/// A target that the binary after this one can take: a TCP connection, or
/// the channel above one. One that cannot says why.
pub trait Movable: Sized + Send + 'static {
    fn move_out(self, id: SessionId) -> Moving;
}

impl Movable for tokio::net::TcpStream {
    fn move_out(self, id: SessionId) -> Moving {
        pod_session::handover::Movable::move_out(self, id)
    }
}
