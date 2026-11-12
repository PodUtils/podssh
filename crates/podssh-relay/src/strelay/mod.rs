//! Syncthing's relays as a last road of a pair (T-571, a last fallback of
//! the operator's ruling Q78): the relays of its pool that listen on 443,
//! each by its IP literal. The node joins a relay in protocol mode (TLS with
//! a certificate of the pair's, [`cert`]) and waits for invitations; a
//! client asks the relay to connect it to the node's device ID; both then
//! join the session in session mode, a plain TCP connection to the relay
//! that carries the bytes ([`pair`]). The end-to-end channel above it keeps
//! them from the relay.

pub mod cert;
pub mod pair;
pub mod wire;
