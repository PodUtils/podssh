//! A WebSocket that the user names (T-368): `wss://HOST[:PORT]/PATH` or
//! `ws://HOST[:PORT]/PATH`, dialed with no token: `pod-ws` of
//! PodUtils/podcrates, over podssh's trust and the proxy that the
//! environment names, as each road is. podssh's own lines show the URL
//! without its query, which may hold the service's own secret.

use std::time::Duration;

pub use pod_ws::url::{failure, request_target, Carried, Stream, WsUrl};

use crate::client::ConnectError;
use crate::dial::ProxyChoice;
use crate::session::RelaySession;
use crate::tls::Trust;

/// What podssh says it is, as on the road of `cloudflared`.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));

/// The upgrade request of `url`, with `key`: no token, no subprotocol, no
/// extension and no `Origin`, as a program sends it.
pub fn request(url: &WsUrl, key: &str) -> Result<Vec<u8>, ConnectError> {
    pod_ws::url::request(url, key, USER_AGENT)
}

/// [`request`], offering `protocol` in `Sec-WebSocket-Protocol` when one is
/// given: a Wisp server speaks its version 2 only where the request names
/// one (T-438). The value is podssh's own constant, never a user's text.
pub fn offering(url: &WsUrl, key: &str, protocol: Option<&str>) -> Result<Vec<u8>, ConnectError> {
    pod_ws::url::offering(url, key, USER_AGENT, protocol)
}

/// Dial `url` and upgrade, with no token: each step bounded by `timeout`,
/// each read of the session by `idle`. The session names the other end
/// `the server` in its errors.
pub async fn dial(
    url: &WsUrl,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<Stream>, ConnectError> {
    dial_offering(url, None, trust, proxy, timeout, idle).await
}

/// [`dial`], its upgrade offering `protocol` ([`offering`]).
pub async fn dial_offering(
    url: &WsUrl,
    protocol: Option<&str>,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    idle: Option<Duration>,
) -> Result<RelaySession<Stream>, ConnectError> {
    pod_ws::url::dial_offering(url, protocol, &crate::client::way(proxy), trust, timeout, idle).await
}
