//! The smee.io road (T-741): a carrier of a pair through smee.io, Probot's
//! public relay of webhooks, a last fallback of the operator's ruling Q78
//! after the Piping Server road and OpenTunnel's, for a proxy that refuses
//! the WebSocket upgrade. smee.io sends the JSON of each `POST /CHANNEL` as
//! an event to each stream `GET /CHANNEL` that is open then
//! (probot/smee.io:lib/server.js), over plain HTTPS by name on 443 with no
//! account, so both ends dial out and nothing asks for an upgrade.
//!
//! The channels come from the pair's secret ([`names`]), with labels of this
//! road's own. The node reads its door; a client opens the stream of its
//! way down, then posts a hello at the door that names a random id for its
//! link, and both ends take the two channels of that id, one for each way:
//! each end posts its way one frame at a time, a number and the bytes in
//! base64 ([`frame`]), and reads the other's events ([`sse`], [`http`],
//! [`link`]). smee.io keeps no event, replays none to a late reader, and
//! may pass two POSTs in flight, so a frame waits for the `200` of the one
//! before it, and a frame missed ends the link: the resumable layer numbers
//! the bytes and sends again what the far end did not get.
//!
//! Each session over it runs the resumable layer and, above the layer, the
//! end-to-end channel (`crate::e2e`), so smee.io is trusted for
//! availability only: anyone who knows a channel's name reads and writes
//! it, and sees the sizes and the times; a change that they make ends the
//! session. The server is the one of `pod-services` of the kind
//! [`SERVICE_KIND`], or one that the user names; podssh names no host of
//! its own.

pub mod client;
pub mod far;
pub mod frame;
pub mod http;
pub mod link;
pub mod names;
pub mod sse;

use std::sync::Arc;

pub use client::{carry, Dialer};
pub use far::Node;
pub use http::Http;
pub use link::Link;
pub use names::Secret;

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The features of the resumable layer that each end offers over smee.io:
/// those of the Piping Server road, whose links it shares the form of.
pub const FEATURES: &[&str] = crate::piping::FEATURES;

/// What podssh says it is, in each request: smee.io sends a POST's headers
/// to each reader, so this is all that it learns of the poster's program.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// The kind of `pod-services` whose services are smee.io's servers, and the
/// name of a server's endpoint.
pub const SERVICE_KIND: &str = "smee";
pub const ENDPOINT: &str = "server";

/// The servers of `pod-services`, in its order; none until it lists one
/// (asked of PodUtils/podcrates as a COORD issue).
pub fn listed() -> Vec<crate::piping::Server> {
    let servers = pod_services::of_kind(SERVICE_KIND).filter_map(|service| service.endpoint(ENDPOINT));
    let server = |e: &pod_services::Endpoint| crate::piping::Server {
        host: e.host().to_ascii_lowercase(),
        port: e.port(),
        prefix: String::new(),
    };
    servers.map(server).collect()
}
