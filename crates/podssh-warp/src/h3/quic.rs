//! QUIC under connect-ip: pod-quic's settings and connection on noq, from an
//! endpoint of its own whose Connection IDs are 20 bytes long, as usque's
//! (`quic.Transport{ConnectionIDLength: 20}`: with quic-go's default WARP's
//! edge closed the connection with PROTOCOL_VIOLATION now and then), with
//! datagrams on, a first packet of usque's 1242 bytes, and a keepalive
//! that holds a NAT's binding open.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use pod_quic::noq::{self, ConnectionId, ConnectionIdGenerator, Endpoint, EndpointConfig, TokioRuntime};
use pod_quic::Settings;
use rustls::crypto::SecureRandom as _;

/// The Connection IDs of this end.
pub const CID_LEN: usize = 20;
/// usque's `InitialPacketSize` and its keepalive.
pub const FIRST_PACKET: u16 = 1242;
pub const KEEPALIVE: Duration = Duration::from_secs(30);
/// A silence that ends the connection: past two keepalives.
pub const SILENCE: Duration = Duration::from_secs(75);

/// Random Connection IDs of [`CID_LEN`] bytes, from this host's source.
#[derive(Debug, Default)]
struct LongIds;

impl ConnectionIdGenerator for LongIds {
    fn generate_cid(&mut self) -> ConnectionId {
        let mut bytes = [0u8; CID_LEN];
        // With no source of the system, noq would have none either; a
        // constant ID still routes, as a server keys on its own IDs.
        let _ = podssh_ws::crypto::random::OsRandom.fill(&mut bytes);
        ConnectionId::new(&bytes)
    }

    fn cid_len(&self) -> usize {
        CID_LEN
    }

    fn cid_lifetime(&self) -> Option<Duration> {
        None
    }
}

/// The transport's settings of the road, within `limit` for the handshake.
pub fn settings(limit: Duration) -> Settings {
    Settings {
        handshake_wait: limit,
        silence: SILENCE,
        keepalive: Some(KEEPALIVE),
        first_packet_v4: FIRST_PACKET,
        first_packet_v6: FIRST_PACKET,
        ..Settings::default()
    }
}

/// An endpoint for one connection toward `addr`: a UDP socket of its family
/// on a port that the system picks, and nothing that listens.
pub fn endpoint(addr: SocketAddr) -> Result<Endpoint, String> {
    let any: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any).map_err(|e| format!("no UDP socket for QUIC: {e}"))?;
    let reset = pod_quic::keys::ResetKey::random().map_err(|e| e.to_string())?;
    let mut config = EndpointConfig::new(Arc::new(reset));
    config.cid_generator(Arc::new(|| Box::new(LongIds) as Box<dyn ConnectionIdGenerator>));
    Endpoint::new(config, None, socket, Arc::new(TokioRuntime)).map_err(|e| format!("no QUIC endpoint: {e}"))
}

/// The TLS alert `access_denied` (49) of a server that took no certificate
/// of this device, as QUIC carries it: CRYPTO_ERROR 0x131 (RFC 9001, section
/// 4.8), which noq says as "the cryptographic handshake failed: error 49".
pub fn access_denied(text: &str) -> bool {
    text.contains("handshake failed: error 49") || text.contains("AccessDenied") || text.contains("access denied")
}

/// A connection to `addr` as `server_name`, with `tls`, within `limit`.
pub async fn connect(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    tls: Arc<rustls::ClientConfig>,
    limit: Duration,
) -> Result<noq::Connection, String> {
    pod_quic::connect::connect(endpoint, addr, server_name, tls, &settings(limit)).await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each ID is 20 bytes, and two are not the same.
    #[test]
    fn the_ids_are_usque_s_length() {
        let mut ids = LongIds;
        let (a, b) = (ids.generate_cid(), ids.generate_cid());
        assert_eq!((a.len(), ids.cid_len()), (CID_LEN, CID_LEN));
        assert_ne!(a, b);
    }

    /// The text of noq's CRYPTO_ERROR of the alert 49 reads as a refusal of
    /// the device; another alert does not.
    #[test]
    fn a_crypto_error_of_alert_49_is_access_denied() {
        assert!(access_denied("1.2.3.4:443: QUIC: aborted by peer: the cryptographic handshake failed: error 49"));
        assert!(!access_denied("the cryptographic handshake failed: error 40"));
    }
}
