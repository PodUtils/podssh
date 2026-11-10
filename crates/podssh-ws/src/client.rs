//! Connecting to the relay: `pod-ws` of PodUtils/podcrates, over podssh's
//! way out ([`way`]): its dial for a [`ProxyChoice`], its TLS context, its
//! reader of HTTPS records for ECH, and `podssh/VERSION`. Every step is
//! bounded, and every failure says which step failed and why.
//!
//! Verdicts from [`doctor`] are three-valued (`ok`, `FAIL`, `????`): a check
//! that could not run is never reported as passing.

use std::sync::Arc;
use std::time::Duration;

pub use pod_ws::client::{
    is_policy_refusal, next_event, next_event_capped, read_frame_over, relay_knobs_only, upgrade, upgrade_with,
    ConnectError, Endpoint, Event, DEFAULT_IDLE_TIMEOUT, DEFAULT_TIMEOUT, LIVENESS_ALLOWED, LIVENESS_EVERY,
    UPGRADE_HEAD, WRITE_TIMEOUT,
};
pub use pod_ws::Limits;

use crate::dial::{self, ProxyChoice};
use crate::error::Verdict;
use crate::http;
pub use crate::session::{RelaySession, RelayStream};
use crate::tls::{self, Trust};

// The GET over HTTPS: pod-proxy's client with podssh's settings.
mod get;
pub use get::{getter, https_get, https_get_accepting};

/// podssh's way out for `proxy`: its dial, the process's TLS, the read of a
/// name's HTTPS record through the same proxy, and `podssh/VERSION`.
pub fn way(proxy: &ProxyChoice) -> pod_ws::Way {
    let dial = Arc::new(dial::dialer(proxy, false));
    pod_ws::Way::new(tls::context().clone(), dial, dial::user_agent())
        .with_records(Arc::new(crate::ech::Records(proxy.clone())))
}

/// How to connect. (Named so it is not confused with `rustls::ClientConfig`.)
#[derive(Debug, Clone)]
pub struct WsClientConfig {
    pub endpoint: Endpoint,
    /// Trust anchors for the relay's certificate.
    pub trust: Trust,
    /// The name the certificate must carry. Required: there is no way to
    /// skip hostname verification.
    pub server_name: String,
    /// Bound on connecting (proxy, TCP, TLS, upgrade).
    pub timeout: Duration,
    /// Bound on waiting for each frame once connected (`None`: no bound).
    pub idle_timeout: Option<Duration>,
    /// Direct, a given proxy, or whatever the environment names.
    pub proxy: ProxyChoice,
}

impl WsClientConfig {
    /// Refuses a path whose query string is anything but the relay's connect
    /// knobs: the token travels in a header, and a query string ends up in
    /// proxy and access logs. The path is not echoed, in case a token is what
    /// it carries.
    pub fn validate(&self) -> Result<(), String> {
        pod_ws::client::check_path(&self.endpoint.path, &self.server_name)
    }

    /// The configuration of `pod-ws`, over podssh's way out for its proxy,
    /// with the relay's limits.
    pub fn pod(&self) -> pod_ws::WsClientConfig {
        pod_ws::WsClientConfig {
            endpoint: self.endpoint.clone(),
            trust: self.trust.clone(),
            server_name: self.server_name.clone(),
            timeout: self.timeout,
            idle_timeout: self.idle_timeout,
            way: way(&self.proxy),
            limits: Limits::RELAY,
        }
    }
}

/// Connect, verify the relay's certificate and hostname, and upgrade.
///
/// The token goes into the `X-Relay-Token` header and nowhere else; it is not
/// stored, formatted or logged.
pub async fn connect(config: &WsClientConfig, token: &str) -> Result<RelaySession, ConnectError> {
    pod_ws::connect(&config.pod(), token).await
}

/// TCP (direct or through the proxy) and a verified TLS handshake.
pub async fn open_tls(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<RelayStream, ConnectError> {
    open_tls_offering(host, port, server_name, trust, proxy, timeout, &[]).await.map(|(tls, _)| tls)
}

/// [`open_tls`], offering `alpn`, with the address that the TCP reached.
/// Sealed where the user asked for ECH and the name publishes a list (T-642).
pub async fn open_tls_offering(
    host: &str,
    port: u16,
    server_name: &str,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
    alpn: &[&[u8]],
) -> Result<(RelayStream, Option<std::net::SocketAddr>), ConnectError> {
    way(proxy).open_tls(host, port, server_name, trust, timeout, alpn).await
}

/// POST a JSON body over HTTPS and return the response, through the same
/// proxy-aware, verified path as [`connect`]. Used to mint relay tokens.
pub async fn https_post_json(
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<http::Response, ConnectError> {
    pod_ws::client::https_post_json(&way(proxy), host, port, path, body, trust, timeout).await
}

/// A request over HTTPS with a relay token in its `X-Relay-Token` header, as
/// the pairing calls need (`/v1/status/<name>`, `/v1/stop/<name>`), through
/// the same proxy-aware, verified path as [`connect`]. The token goes into the
/// header and nowhere else: no error of this path quotes a header.
#[allow(clippy::too_many_arguments)]
pub async fn https_with_token(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    body: &[u8],
    token: &str,
    max_body: usize,
    trust: &Trust,
    proxy: &ProxyChoice,
    timeout: Duration,
) -> Result<http::Response, ConnectError> {
    let way = way(proxy);
    pod_ws::client::https_with_token(&way, method, host, port, path, body, token, max_body, trust, timeout).await
}

/// What can be checked without a token: the crypto provider and the trust
/// store. The TLS handshake is reported as not attempted (`????`), never as
/// passing, because a session needs a minted token.
pub async fn doctor(config: &WsClientConfig) -> Vec<(String, Verdict)> {
    let mut out = vec![(
        "crypto provider".to_string(),
        match crate::crypto::suites::self_check() {
            Ok(()) => Verdict::Ok { detail: "podssh's own pure-Rust provider is internally consistent".into() },
            Err(why) => Verdict::Failed { detail: why },
        },
    )];
    out.extend(pod_ws::doctor(&config.pod()).await);
    out
}
