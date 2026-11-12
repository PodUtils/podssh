//! Yggdrasil's network as a last road of a pair (T-735, a last fallback of
//! the operator's ruling Q78): one WebSocket (`ygg-ws`) to a public peer of
//! the network, its `meta` handshake ([`meta`]), and Ironwood, Yggdrasil's
//! router (the crate `ironwood` of Revertron/Yggdrasil-ng, MPL-2.0), over it
//! ([`router`]). Two ends that peer anywhere in the network reach each other
//! by their Ed25519 keys; the key's transform that Ironwood's bloom filters
//! take is Yggdrasil's ([`key`]), so that a lookup across the network finds
//! the other end. For the time of a session, an end routes for the network
//! too: Ironwood has no leaf.

pub mod key;
pub mod link;
pub mod meta;
pub mod pair;
pub mod router;

/// An end's key in the network.
pub use ed25519_dalek::SigningKey;
