//! The RFC 6455 opening handshake: `pod-ws` of PodUtils/podcrates. The
//! token travels in the `X-Relay-Token` header and never in the URL.

pub use pod_ws::handshake::*;
