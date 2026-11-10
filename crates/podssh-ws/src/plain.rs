//! A WebSocket session over plain TCP to the loopback, for tests only
//! (feature `plain-ws`, T-068): `pod-ws` of PodUtils/podcrates. The binary
//! never enables the feature.

pub use pod_ws::plain::*;
