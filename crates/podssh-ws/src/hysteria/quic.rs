//! The road's QUIC, once the probe found UDP: an endpoint of its own on a UDP
//! socket that the system picks (wrapped in Salamander when the link names
//! it), the handshake to the address that answered the probe, HTTP/3's
//! control stream, `POST /auth` and its status, then the TCP request on a
//! stream of its own and the server's answer (Hysteria 2's "Proxy
//! Requests"). The settings of the transport are Hysteria's client's: a
//! silence of 30 s ends the connection, and a keepalive goes each 10 s.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pod_core::entropy::{Entropy, OsEntropy};
use pod_core::SystemDatagrams;
use pod_quic::noq::{Connection, Endpoint, RecvStream, SendStream};
use pod_quic::Settings;

use super::link::{hex, Server};
use super::salamander::{Salamander, SALT};
use super::{h3, HysteriaError};
use crate::tls::Trust;

/// Hysteria's client's `MaxIdleTimeout` and `KeepAlivePeriod`.
pub const SILENCE: Duration = Duration::from_secs(30);
pub const KEEPALIVE: Duration = Duration::from_secs(10);
/// The status of a server that took the credential.
pub const AUTH_OK: u16 = 233;
/// The TCP request's ID, and the server's longest address and message
/// (`core/internal/protocol/proxy.go`).
pub const TCP_REQUEST: u64 = 0x401;
pub const MOST_ADDRESS: usize = 2048;
const MOST_MESSAGE: u64 = 2048;
const MOST_PADDING: u64 = 4096;
/// The largest UDP payload that QUIC's discovery of the path goes to, less
/// Salamander's salt: noq's own ceiling is 1452.
const SALTED_CEILING: u16 = 1452 - SALT as u16;

/// The transport's settings for this road.
pub fn settings(salamander: bool) -> Settings {
    let mtu_ceiling = salamander.then_some(SALTED_CEILING);
    Settings { silence: SILENCE, keepalive: Some(KEEPALIVE), mtu_ceiling, ..Settings::default() }
}

/// A padding of `least` to `most` letters and digits, as Hysteria's
/// (`core/internal/protocol/padding.go`); its length is all that it says.
pub fn padding(least: usize, most: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut bytes = vec![0u8; most + 2];
    // With no source of the system, a padding of the least length and one
    // letter still hides nothing that it should.
    let _ = OsEntropy.fill(&mut bytes);
    let span = (most - least).max(1);
    let len = least + usize::from(u16::from_be_bytes([bytes[0], bytes[1]])) % span;
    bytes[2..2 + len].iter().map(|b| char::from(CHARS[usize::from(*b) % CHARS.len()])).collect()
}

/// The TCP request of `target` (`host:port`).
pub fn tcp_request(target: &str) -> Vec<u8> {
    let pad = padding(64, 512);
    let mut out = Vec::with_capacity(target.len() + pad.len() + 16);
    h3::put_varint(&mut out, TCP_REQUEST);
    h3::put_varint(&mut out, target.len() as u64);
    out.extend_from_slice(target.as_bytes());
    h3::put_varint(&mut out, pad.len() as u64);
    out.extend_from_slice(pad.as_bytes());
    out
}

/// An endpoint for one connection toward `addr`, wrapped in Salamander when
/// `obfs` holds its key.
pub async fn endpoint(addr: SocketAddr, obfs: Option<&[u8]>) -> Result<Endpoint, HysteriaError> {
    let Some(psk) = obfs else {
        return pod_quic::endpoint::system(addr.is_ipv6()).map_err(|e| HysteriaError::Quic(e.to_string()));
    };
    let any: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = SystemDatagrams::bind(any).await.map_err(|e| HysteriaError::Quic(format!("no UDP socket: {e}")))?;
    let way = Arc::new(Salamander::new(socket, psk));
    pod_quic::endpoint::over(way, None).map_err(|e| HysteriaError::Quic(e.to_string()))
}

/// QUIC to `addr`, then the credential: the connection, once the server
/// answered 233.
pub async fn authenticated(
    endpoint: &Endpoint,
    server: &Server,
    addr: SocketAddr,
    trust: &Trust,
) -> Result<(Connection, SendStream), HysteriaError> {
    let (tls, pinned) = super::tls::config(&server.check, trust).map_err(HysteriaError::Quic)?;
    let settings = settings(server.obfs.is_some());
    let connection = match pod_quic::connect::connect(endpoint, addr, &server.sni, tls, &settings).await {
        Ok(connection) => connection,
        Err(e) => match pinned.and_then(|p| p.refused()) {
            Some(seen) => return Err(HysteriaError::Pin { seen, pinned: pin_of(server) }),
            None => return Err(HysteriaError::Quic(e.to_string())),
        },
    };
    let mut control = connection.open_uni().await.map_err(http3)?;
    control.write_all(&h3::control_stream()).await.map_err(http3)?;
    let (mut send, mut recv) = connection.open_bi().await.map_err(http3)?;
    let request = h3::auth_request(server.auth.text(), &padding(256, 2048));
    send.write_all(&h3::frame(h3::HEADERS, &request)).await.map_err(http3)?;
    // No body: the request ends with its headers.
    let _ = send.finish();
    let status = h3::status(&headers(&mut recv).await?).map_err(http3)?;
    if status != AUTH_OK {
        // Hysteria's client closes so (`closeErrCodeProtocolError`).
        connection.close(pod_quic::noq::VarInt::from_u32(0x101), b"");
        return Err(HysteriaError::Auth(status));
    }
    Ok((connection, control))
}

fn pin_of(server: &Server) -> String {
    match &server.check {
        super::link::Check::Pin(pin) => hex(pin),
        super::link::Check::Roots => String::new(),
    }
}

fn http3(e: impl std::fmt::Display) -> HysteriaError {
    HysteriaError::Http3(e.to_string())
}

/// A whole variable-length integer from `recv`.
async fn varint(recv: &mut RecvStream) -> Result<u64, HysteriaError> {
    let mut bytes = [0u8; 8];
    recv.read_exact(&mut bytes[..1]).await.map_err(http3)?;
    let len = h3::varint_len(bytes[0]);
    recv.read_exact(&mut bytes[1..len]).await.map_err(http3)?;
    Ok(h3::varint(&bytes[..len]))
}

/// The field section of the answer's first HEADERS frame; a frame of an
/// unknown type before it is skipped (RFC 9114, section 9), and DATA before
/// it is a broken answer.
async fn headers(recv: &mut RecvStream) -> Result<Vec<u8>, HysteriaError> {
    loop {
        let (kind, len) = (varint(recv).await?, varint(recv).await?);
        if len > h3::MOST_HEADERS {
            return Err(http3(format!("a frame of {len} bytes before the answer's headers")));
        }
        let mut payload = vec![0u8; len as usize];
        recv.read_exact(&mut payload).await.map_err(http3)?;
        match kind {
            h3::HEADERS => return Ok(payload),
            h3::DATA => return Err(http3("a body before the answer's headers")),
            _ => {}
        }
    }
}

/// The TCP request of `target` on a stream of its own, and the server's
/// answer: the stream, once the server reached the target.
pub async fn tcp(connection: &Connection, target: &str) -> Result<(SendStream, RecvStream), HysteriaError> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(http3)?;
    send.write_all(&tcp_request(target)).await.map_err(http3)?;
    let mut status = [0u8; 1];
    recv.read_exact(&mut status).await.map_err(|e| HysteriaError::Ended(e.to_string()))?;
    let len = varint(&mut recv).await?;
    if len > MOST_MESSAGE {
        return Err(http3(format!("the answer's message of {len} bytes")));
    }
    let mut message = vec![0u8; len as usize];
    recv.read_exact(&mut message).await.map_err(http3)?;
    let pad = varint(&mut recv).await?;
    if pad > MOST_PADDING {
        return Err(http3(format!("the answer's padding of {pad} bytes")));
    }
    recv.read_exact(&mut vec![0u8; pad as usize]).await.map_err(http3)?;
    match status[0] {
        0x00 => Ok((send, recv)),
        _ => Err(HysteriaError::Refused(crate::text::one_line(&String::from_utf8_lossy(&message)))),
    }
}
