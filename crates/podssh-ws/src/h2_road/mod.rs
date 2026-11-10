//! The WebSocket over HTTP/2's extended CONNECT (RFC 8441, T-321, GitHub
//! #51): `pod-ws` of PodUtils/podcrates, with one pool of connections for
//! the process ([`POOL`]) and podssh's way out for the proxy of each
//! configuration.

use std::time::Duration;

pub use pod_ws::h2_road::{
    duplex, Fallback, Offered, Pool, Road, Stream, CONNECTION_WINDOW, H2, HTTP1, IDLE, REMEMBERED, STREAMS,
    STREAM_WINDOW,
};

use crate::client::{ConnectError, WsClientConfig};
use crate::dial::ProxyChoice;
use crate::session::RelaySession;
use crate::tls::Trust;

/// The connections of the road in this process, each host's apart.
pub static POOL: Pool = Pool::new();

/// Connect as [`crate::connect`] does, with `token` in a field and nowhere
/// else, on this road where the host takes it, else by the upgrade of
/// HTTP/1.1: the session, and how it is carried.
pub async fn connect(config: &WsClientConfig, token: &str) -> Result<(RelaySession, Road), ConnectError> {
    pod_ws::h2_road::connect(&POOL, &config.pod(), token).await
}

/// What `host:port` offers the road, with nothing sent but HTTP/2's
/// preface, its SETTINGS and a PING, all within `limit` each: TLS checked
/// for `server_name` as each road checks it, through `proxy`.
pub async fn probe(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    limit: Duration,
) -> Result<Offered, ConnectError> {
    pod_ws::h2_road::probe(&crate::client::way(proxy), host, port, server_name, trust, limit).await
}
