//! The quick tunnel over QUIC (T-301), as cloudflared makes one when no
//! protocol is named: QUIC to UDP port 7844 of the edge, with the name
//! `quic.cftunnel.com` and the ALPN `argotunnel` (`connection/protocol.go`),
//! and cloudflared's settings of the transport (`quic/constants.go`,
//! `connection/quic_config.go`): 5 s for the handshake and for a silence, a
//! keepalive each second, first packets of 1232 bytes over IPv4 and 1252 over
//! IPv6, and datagrams on. QUIC is UDP, which no HTTP proxy carries, so the
//! node takes it only with no proxy set; its socket is the connection's own,
//! on a port that the system picks, and nothing listens on it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use noq::{Connection, Endpoint, EndpointConfig, VarInt};
use pod_quic::Settings;
use podssh_ws::tls::TlsRoots;

use super::edge;

/// cloudflared's settings of the transport, which pod-quic holds as its
/// default.
pub use pod_quic::{FIRST_PACKET_V4, FIRST_PACKET_V6, HANDSHAKE_WAIT, KEEPALIVE, MAX_STREAMS, SILENCE};

/// The edge over QUIC: the first endpoint of the role `quic` of
/// `cloudflare-tunnel-edge` (`pod-services`).
fn quic_edge() -> &'static pod_services::Endpoint {
    super::edge::service().endpoints_of("quic").next().expect("cloudflare-tunnel-edge has the role quic")
}

/// The name of the edge's certificate over QUIC.
pub fn server_name() -> &'static str {
    quic_edge().server_name()
}

/// The ALPN of the edge over QUIC.
pub fn alpn() -> &'static [u8] {
    quic_edge().alpn().first().map_or(b"argotunnel".as_slice(), |a| a.as_bytes())
}

/// TLS 1.3 alone, as QUIC needs, on podssh's provider, with `roots` and the
/// ALPN.
pub fn tls(roots: &TlsRoots) -> Result<Arc<rustls::ClientConfig>, String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    pod_quic::connect::tls(provider, Arc::new(roots.roots.clone()), &[alpn()]).map_err(|e| e.to_string())
}

/// The configuration of an endpoint, with a reset key of its own.
pub fn endpoint_config() -> Result<EndpointConfig, String> {
    pod_quic::endpoint::config().map_err(|e| e.to_string())
}

/// An endpoint for one connection: a UDP socket of the family `v6`, on a
/// port that the system picks. A socket that does not bind is the probe's
/// answer: no QUIC here.
pub fn endpoint(v6: bool) -> Result<Endpoint, String> {
    pod_quic::endpoint::system(v6).map_err(|e| e.to_string())
}

/// A QUIC connection to `addr` as `server_name`, within the handshake's wait.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<Connection, String> {
    pod_quic::connect::connect(endpoint, addr, server_name, tls, &Settings::default()).await.map_err(|e| e.to_string())
}

/// A connection to the edge over QUIC, with the endpoint that carries it.
pub struct EdgeConnection {
    endpoint: Endpoint,
    connection: Connection,
}

impl EdgeConnection {
    /// Serve it as `quic_serve::serve` does, then let the endpoint go.
    pub async fn serve<V: super::origin::Visit>(
        self,
        registration: &super::register::Registration<'_>,
        visit: V,
        steps: tokio::sync::mpsc::UnboundedSender<super::serve::Step>,
        stop: impl std::future::Future<Output = ()>,
    ) -> Result<(), super::serve::Ended> {
        let served = super::quic_serve::serve(self.connection, registration, visit, steps, stop).await;
        self.endpoint.close(VarInt::from_u32(0), b"");
        served
    }
}

/// QUIC to `found`, the edge: each region in turn, at its first address of
/// each family that it has.
pub async fn connect_edge(found: &edge::Edge) -> Result<EdgeConnection, String> {
    let tls = tls(&edge::roots()?)?;
    let mut failed = Vec::new();
    for region in &found.regions {
        let deadline = tokio::time::Instant::now() + edge::DIAL_LIMIT;
        let addrs = match podssh_ws::resolve::resolve(region, found.port, deadline).await {
            Ok(addrs) => addrs,
            Err(e) => {
                failed.push(format!("{region}: {e}"));
                continue;
            }
        };
        let firsts = [addrs.iter().find(|a| a.is_ipv4()), addrs.iter().find(|a| a.is_ipv6())];
        for addr in firsts.into_iter().flatten() {
            let endpoint = match endpoint(addr.is_ipv6()) {
                Ok(endpoint) => endpoint,
                Err(e) => {
                    failed.push(e);
                    continue;
                }
            };
            match connect(&endpoint, *addr, server_name(), tls.clone()).await {
                Ok(connection) => return Ok(EdgeConnection { endpoint, connection }),
                Err(e) => failed.push(format!("{region} {e}")),
            }
        }
    }
    Err(format!("no region of the edge answered over QUIC: {}", failed.join("; ")))
}

/// A QUIC handshake with the edge, as `podssh doctor` asks it (T-359): the
/// first address of each family of each region of `found`, all at once, where
/// [`connect_edge`] tries them in turn, each within the handshake's wait. The
/// address that answered first and the time that its handshake took, the
/// connection closed at once with nothing registered; else why none answered.
pub async fn handshake(found: &edge::Edge, tls: Arc<rustls::ClientConfig>) -> Result<(SocketAddr, Duration), String> {
    let mut addrs = Vec::new();
    let mut failed = Vec::new();
    for region in &found.regions {
        let deadline = tokio::time::Instant::now() + edge::DIAL_LIMIT;
        match podssh_ws::resolve::resolve(region, found.port, deadline).await {
            Ok(resolved) => {
                let firsts = [resolved.iter().find(|a| a.is_ipv4()), resolved.iter().find(|a| a.is_ipv6())];
                addrs.extend(firsts.into_iter().flatten().copied());
            }
            Err(e) => failed.push(format!("{region}: {e}")),
        }
    }
    if !addrs.is_empty() {
        match pod_quic::connect::handshake(&addrs, server_name(), tls, &Settings::default()).await {
            Ok(answered) => return Ok(answered),
            Err(e) => failed.push(e.to_string()),
        }
    }
    Err(format!("no region of the edge answered over QUIC: {}", failed.join("; ")))
}
