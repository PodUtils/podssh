//! Tor through Arti (T-353, the operator's ruling Q52): a stream to a host
//! and a port through the Tor network, for a host whose only way out is
//! HTTPS. Arti builds its circuits as it would anywhere; each connection
//! that it opens to a Tor relay goes through podssh's own dial ([`runtime`]),
//! so through `HTTPS_PROXY` and its credentials as each other road does,
//! and only to the ports that the proxy allows.
//!
//! Bridges (T-385) take their first hops in place of the directory's
//! relays ([`bridges`]); meek_lite and WebTunnel, the two transports that
//! pass where HTTPS passes, run in this process ([`transport`]), with no
//! other program.
//!
//! An onion service (T-578) reaches a node by its onion address
//! ([`onion`]): Arti's service in this process, whose every circuit is a
//! connection out to a relay, so the node binds nothing.

pub mod bridges;
pub mod client;
pub mod onion;
pub mod runtime;
mod socks;
pub mod transport;

pub use bridges::Bridge;
pub use client::{Failure, Options, Tor, TorStream};
pub use onion::{Discovery, Onion, ServiceOptions};
