//! The cleartext road on the relay's port (T-326, the operator's ruling
//! Q45): `pod-ws` of PodUtils/podcrates, over podssh's way out. Each hop
//! reads what crosses it, the token's header among them, so the caller
//! gives a token of one session alone and tries this road last, once its
//! TLS failed on the way ([`tls_failed`]). [`probe`] asks a host in
//! cleartext with nothing secret, as GitHub #56 asks.

use std::time::Duration;

pub use pod_ws::cleartext::{tls_failed, Heard, PLAIN_TO_TLS, PROBE_PATH};

use crate::client::{ConnectError, WsClientConfig};
use crate::dial::ProxyChoice;
use crate::session::RelaySession;

/// Dial `config`'s endpoint through its proxy, and upgrade at its path with
/// `token` in the `X-Relay-Token` header, as [`crate::connect`] does, with
/// no TLS.
pub async fn connect(config: &WsClientConfig, token: &str) -> Result<RelaySession, ConnectError> {
    pod_ws::cleartext::connect(&config.pod(), token).await
}

/// Ask `host:port` for [`PROBE_PATH`] in cleartext, through `proxy`, each
/// wait within `wait`: what came back.
pub async fn probe(host: &str, port: u16, proxy: &ProxyChoice, wait: Duration) -> Heard {
    pod_ws::cleartext::probe(&crate::client::way(proxy), host, port, wait).await
}
