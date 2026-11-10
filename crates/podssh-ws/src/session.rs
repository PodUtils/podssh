//! An open WebSocket session, to the relay unless made otherwise, usable
//! from two tasks at once: `pod-ws` of PodUtils/podcrates. Its stream is
//! TLS, TCP alone on the cleartext road (T-326), a stream of HTTP/2 (T-321)
//! or a stream of another crate (T-667) ([`crate::url::Stream`]).

pub use pod_ws::session::*;

pub use crate::close::Remedy;
