//! The resumable layer (milestone M6): `pod-session` of PodUtils/podcrates.
//! What lets a session between two podssh ends outlive its link to the
//! relay. podssh keeps two parts of its own: the sink of a node's budget
//! lines ([`budget`]), and the move of a target at a handover
//! ([`handover::Movable`]), which the pipe to the end-to-end channel takes.

pub use pod_session::*;

pub mod budget;
pub mod handover;
