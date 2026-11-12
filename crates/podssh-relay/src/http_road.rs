//! The HTTP road (T-319): a forward session over plain requests of HTTP/1.1
//! where a proxy refuses the WebSocket upgrade, in its split form and its
//! serial form, whose server is the relay role's: `pod-relay` of
//! PodUtils/podcrates (T-684). A road takes podssh's way out
//! (`podssh_ws::client::way`), whose user agent is podssh's.

pub use pod_relay::http_road::*;
