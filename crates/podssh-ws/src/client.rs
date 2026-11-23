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
pub use get::{getter, getter_trusting, https_get, https_get_accepting};

/// podssh's way out for `proxy`: its dial, the process's TLS, the read of a
/// name's HTTPS record through the same proxy, and `podssh/VERSION`.
pub fn way(proxy: &ProxyChoice) -> pod_ws::Way {
    let dial = Arc::new(dial::dialer(proxy, false));
    pod_ws::Way::new(tls::context().clone(), dial, dial::user_agent())
        .with_records(Arc::new(crate::ech::Records(proxy.clone())))
        // The credentials of Cloudflare Access, for a host that the user
        // named alone (T-718).
        .with_headers(crate::access::process_headers())
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

/// Why a covered connection did not open: the handshake or the upgrade
/// ([`ConnectError`]), or the credential that the server issued.
#[derive(Debug)]
pub enum CoverError {
    Connect(ConnectError),
    Credential(crate::delegated::DelegatedError),
}

impl std::fmt::Display for CoverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CoverError::Connect(error) => error.fmt(f),
            CoverError::Credential(error) => write!(f, "the cover credential: {error}"),
        }
    }
}

impl std::error::Error for CoverError {}

impl From<ConnectError> for CoverError {
    fn from(error: ConnectError) -> Self {
        CoverError::Connect(error)
    }
}

impl From<crate::delegated::DelegatedError> for CoverError {
    fn from(error: crate::delegated::DelegatedError) -> Self {
        CoverError::Credential(error)
    }
}

/// [`connect`], with the application-layer credential of a cover relay
/// (T-765): after the handshake, `POST /v1/delegate` on this connection,
/// checked against the operator key that the authenticated connection
/// delivered, the name, the window and the exporter, and then the upgrade on
/// the same connection, carrying the credential in `X-Cover-Credential`. A
/// server that refuses the credential, or one whose credential names another
/// issuer, window or exporter, opens no session.
pub async fn connect_with_cover(
    config: &WsClientConfig,
    token: &str,
    subject: [u8; 32],
) -> Result<RelaySession, CoverError> {
    config.validate().map_err(ConnectError::Config).map_err(CoverError::Connect)?;
    if token.contains(['\r', '\n']) {
        return Err(CoverError::Connect(ConnectError::Config("the relay token contains a line break".into())));
    }
    let at = &config.endpoint;
    let way = way(&config.proxy);
    let extra = way.extra(&at.host).map_err(CoverError::Connect)?;
    let (mut tls, peer) = way
        .open_tls(&at.host, at.port, &config.server_name, &config.trust, config.timeout, &[])
        .await
        .map_err(CoverError::Connect)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0);
    let (credential, _issuer) =
        crate::delegated::request_and_verify(&mut tls, token, subject, &config.server_name, now)
            .await
            .map_err(CoverError::Credential)?;
    if credential.subject_key != subject {
        return Err(CoverError::Credential(crate::delegated::DelegatedError::Decode(
            "the credential's subject key is not the one asked for".into(),
        )));
    }
    // The credential goes in its own header, after the caller's: the relay
    // checks it on this live upgrade, before it admits the tunnel.
    let mut carried: Vec<pod_ws::headers::Header> =
        extra.iter().map(|(name, value)| (name, pod_ws::headers::Zeroizing::new(value.to_string()))).collect();
    carried.push((
        crate::delegated::CREDENTIAL_HEADER,
        pod_ws::headers::Zeroizing::new(crate::delegated::encode_wire(&credential)),
    ));
    let extra = pod_ws::headers::Extra::checked(carried).map_err(CoverError::Connect)?;
    let host_header = pod_proxy::authority(&at.host, at.port);
    let upgraded = pod_ws::client::upgrade_carrying(tls, &host_header, &at.path, token, &extra);
    let (tls, pending) = tokio::time::timeout(config.timeout, upgraded).await.map_err(|_| {
        CoverError::Connect(ConnectError::Timeout { step: "the WebSocket upgrade", after: config.timeout })
    })??;
    Ok(RelaySession::over_tls(tls, peer, pending, config.idle_timeout, WRITE_TIMEOUT).with_limits(Limits::RELAY))
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
