//! Tox's TCP relays as a last road and a meeting point of a pair (T-734,
//! a last fallback of the operator's ruling Q78): a client of the relay
//! protocol (`wire`) and one routed connection as a stream (`routed`).

pub mod routed;
pub mod wire;
