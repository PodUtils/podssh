//! The relay role over QUIC (T-667): an endpoint on the UDP socket that
//! `podssh relay serve --quic yes` binds beside its TCP listener, at the same
//! address and port. TLS 1.3 with the certificate that the listener presents
//! now ([`Served`], read again on SIGHUP and renewed by ACME), and the ALPN
//! [`ALPN`] alone, so that a client of HTTP/3, or a CA's TLS-ALPN-01, gets no
//! connection here. Each bidirectional stream that a client opens is one
//! connection of HTTP/1.1 to the role's routes ([`super::serve_from`]): its
//! token, its checks, its brake by the client's address and its limits are
//! those of a connection over TCP. The role opens no stream, and keeps
//! nothing of a connection once its streams end.

use std::net::{IpAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use noq::crypto::rustls::{HandshakeData, QuicServerConfig};
use noq::{Endpoint, IdleTimeout, Incoming, ServerConfig, TransportConfig, VarInt};
use pod_quic::keys::TokenKey;
use podssh_ws::tls_server::Served;

use super::Config;
use crate::quic_road::stream::QuicStream;
use crate::quic_road::ALPN;

/// The sessions that one connection may hold at once.
pub const STREAMS: u32 = 64;
/// How long a client has for QUIC's handshake.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// A silence that ends a connection: the client's keepalive is 10 s.
pub const SILENCE: Duration = Duration::from_secs(30);

/// The settings of a connection at the role.
fn transport() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(IdleTimeout::try_from(SILENCE).ok())
        .max_concurrent_bidi_streams(VarInt::from_u32(STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    transport
}

/// The configuration of the role's QUIC: TLS 1.3 with what `served` holds
/// at each handshake, and [`ALPN`] alone.
pub fn server_config(served: Arc<Served>) -> Result<ServerConfig, String> {
    let provider = Arc::new(podssh_ws::crypto::provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("QUIC's TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(served);
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let crypto = QuicServerConfig::try_from(tls).map_err(|e| format!("QUIC's TLS: {e}"))?;
    // The tokens of address validation: HMAC-SHA-256 in pure Rust, of a
    // random key of the process (pod-quic), as noq's own needs a provider of
    // AEAD that podssh's provider does not lend.
    let tokens = TokenKey::random().map_err(|e| e.to_string())?;
    let mut server = ServerConfig::new(Arc::new(crypto), Arc::new(tokens));
    server.transport_config(Arc::new(transport()));
    Ok(server)
}

/// The role's endpoint on `socket`, a UDP socket that the caller bound; it
/// must be made in a runtime, which drives it.
pub fn endpoint(socket: UdpSocket, served: Arc<Served>) -> Result<Endpoint, String> {
    let server = server_config(served)?;
    pod_quic::endpoint::on_socket(socket, Some(server)).map_err(|e| e.to_string())
}

/// Serve each connection that `endpoint` takes, until it is closed.
pub async fn serve(endpoint: Endpoint, cfg: Arc<Config>) {
    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(connection(incoming, cfg.clone()));
    }
}

/// One client's connection: its handshake, then each stream that it opens,
/// served as a connection over TCP is, for its address.
async fn connection(incoming: Incoming, cfg: Arc<Config>) {
    // An IPv4 client of a socket of both families, by its IPv4 address, as
    // the brake counts the client over TCP.
    let peer: IpAddr = incoming.remote_address().ip().to_canonical();
    let Ok(connecting) = incoming.accept() else { return };
    let Ok(Ok(connection)) = tokio::time::timeout(HANDSHAKE_WAIT, connecting).await else { return };
    // The name that the client asked for, which a key's signed mint must
    // name (T-448), as over TCP.
    let sni = connection
        .handshake_data()
        .and_then(|data| data.downcast::<HandshakeData>().ok())
        .and_then(|data| data.server_name);
    // A harness counts the connections, as `h2` for HTTP/2's.
    cfg.event("quic");
    while let Ok((send, recv)) = connection.accept_bi().await {
        let stream = QuicStream::new(send, recv, connection.clone());
        tokio::spawn(super::serve_from(stream, cfg.clone(), sni.clone(), Some(peer)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The role's TLS takes QUIC's configuration, with no certificate yet as
    /// an ACME role's before its first.
    #[test]
    fn the_role_s_configuration_is_tls_1_3_with_its_alpn_alone() {
        assert!(server_config(Served::new(None)).is_ok());
    }
}
