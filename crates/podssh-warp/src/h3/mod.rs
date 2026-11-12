//! MASQUE's connect-ip over HTTP/3 (T-582, the operator's ruling Q82): the
//! road where a probe found that UDP passes, with each IP packet in a QUIC
//! datagram, so that no TCP runs inside TCP. As usque speaks it to WARP's
//! endpoint (`api/masque.go`, `connectTunnelHTTP3`) and connect-ip-go's
//! fork (`client.go`, `Dial`) to any server of RFC 9484:
//!
//! - [`quic`]: QUIC on noq through pod-quic, from an endpoint whose
//!   Connection IDs are 20 bytes long, as usque's;
//! - [`open`]: HTTP/3's control streams and the extended CONNECT (RFC 9220)
//!   with the protocol `cf-connect-ip` (WARP) or `connect-ip`;
//! - [`pump`]: the packets in HTTP Datagrams (RFC 9297) both ways, and the
//!   capsules of the request stream, ADDRESS_ASSIGN among them;
//! - [`wire`]: the bytes of each, sans-IO;
//! - [`server`]: a server of connect-ip that the user runs, by its URL.
//!
//! The TCP inside is the same smoltcp stack as over HTTP/2 (`crate::stack`).
//! Rule 2 holds: one UDP socket, connected to the one server, through no
//! proxy (UDP has none; the road runs only where the probe of UDP answered),
//! and nothing listens.

pub mod open;
pub mod pump;
pub mod quic;
pub mod server;
pub mod wire;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::stack::{Link, Why};

/// How long the probe of UDP waits for a server of the user's, which may be
/// across the world; WARP's edge, near each host, answers within pod-quic's
/// 300 ms.
pub const PROBE_WAIT_FAR: Duration = Duration::from_millis(1500);
pub const PROBE_WAIT_EDGE: Duration = pod_quic::probe::WAIT;

/// Why the road over HTTP/3 did not open, by its step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The probe of UDP got no answer: UDP does not pass here.
    Udp(String),
    /// QUIC's handshake failed.
    Quic(String),
    /// A certificate of another key than WARP's pinned one, and its issuer.
    Intercepted { issuer: String },
    /// A certificate of another digest than the user's pin.
    Pin { seen: String },
    /// The edge took no certificate of this device.
    NotEnrolled(String),
    /// HTTP/3 failed, or the server answered as podssh does not read.
    Http3(String),
    /// The server's SETTINGS do not allow HTTP Datagrams.
    NoDatagrams,
    /// The server answered the CONNECT with this status.
    Refused { status: u16 },
    /// No address came in time from a server that gives it (ADDRESS_ASSIGN).
    NoAddress,
    /// Within the limit, no answer.
    Timeout(&'static str),
    /// This host's part.
    Local(String),
}

impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Failed::Udp(why) => write!(f, "UDP does not pass: {why}"),
            Failed::Quic(why) => write!(f, "QUIC: {why}"),
            Failed::Intercepted { issuer } => write!(f, "a certificate of {issuer}, not of the pinned key"),
            Failed::Pin { seen } => write!(f, "a certificate whose SHA-256 is {seen}, not the pinned one"),
            Failed::NotEnrolled(why) => write!(f, "no certificate of this device was taken ({why})"),
            Failed::Http3(why) => write!(f, "HTTP/3: {why}"),
            Failed::NoDatagrams => f.write_str("the server's HTTP/3 SETTINGS do not allow HTTP Datagrams (RFC 9297)"),
            Failed::Refused { status } => write!(f, "the server refused the CONNECT (HTTP {status})"),
            Failed::NoAddress => f.write_str("the server assigned no address (ADDRESS_ASSIGN, RFC 9484) in time"),
            Failed::Timeout(step) => write!(f, "{step} did not end in time"),
            Failed::Local(why) => f.write_str(why),
        }
    }
}

/// One tunnel to open: where, as what name, with which TLS, and what to ask.
pub struct Dial {
    pub addr: SocketAddr,
    pub server_name: String,
    pub tls: Arc<rustls::ClientConfig>,
    pub ask: open::Ask,
    /// The addresses inside, when a record gives them (WARP's device);
    /// `None` waits for the server's ADDRESS_ASSIGN.
    pub addresses: Option<Vec<IpAddr>>,
}

/// An opened tunnel, as the stack takes it, with its addresses and the
/// largest packet that a datagram carries.
pub struct Tunnel {
    pub link: Link,
    pub addresses: Vec<IpAddr>,
    pub mtu: usize,
}

/// The probe of UDP at `addrs` within `wait`: the first that answered.
pub async fn probe(addrs: &[SocketAddr], wait: Duration) -> Result<SocketAddr, Failed> {
    pod_quic::probe::probe(addrs, wait).await.map(|(addr, _)| addr).map_err(|e| Failed::Udp(e.to_string()))
}

/// QUIC, HTTP/3 and the CONNECT of `dial`, each step within `limit`; then
/// the addresses, the record's or the server's.
pub async fn open(dial: Dial, limit: Duration) -> Result<Tunnel, Failed> {
    let endpoint = quic::endpoint(dial.addr).map_err(Failed::Local)?;
    let connection = quic::connect(&endpoint, dial.addr, &dial.server_name, dial.tls, limit).await.map_err(|why| {
        match quic::access_denied(&why) {
            true => Failed::NotEnrolled(why),
            false => Failed::Quic(why),
        }
    })?;
    let why = Why::default();
    let opened = open::exchange(&connection, &dial.ask, &why, limit).await;
    let opened = match opened {
        Ok(opened) => opened,
        Err(e) => {
            connection.close(pod_quic::noq::VarInt::from_u32(0x100), b"");
            return Err(e);
        }
    };
    let stream_id = u64::from(opened.recv.id());
    let room = connection.max_datagram_size().ok_or(Failed::NoDatagrams)?;
    let mtu = room.saturating_sub(wire::overhead(stream_id)).min(crate::MTU);
    let (link, mut assigned) = pump::link(endpoint, connection, opened, why);
    let addresses = match dial.addresses {
        Some(addresses) => addresses,
        None => {
            let given = tokio::time::timeout(limit, assigned.wait_for(|a| !a.is_empty())).await;
            let addresses = match given {
                Ok(Ok(list)) => Ok(wire::stack_addresses(&list)),
                Ok(Err(_)) => Err(ended(&link)),
                Err(_) => Err(Failed::NoAddress),
            };
            // A link's tasks end with its stack; with no stack, here.
            if addresses.is_err() {
                link.tasks.iter().for_each(|task| task.abort());
            }
            addresses?
        }
    };
    Ok(Tunnel { link, addresses, mtu })
}

/// The line of a tunnel that ended before its addresses came.
fn ended(link: &Link) -> Failed {
    Failed::Http3(link.why.get().unwrap_or_else(|| "the tunnel ended before the server assigned an address".into()))
}

/// The line of a refused pin of WARP's endpoint, or of the user's.
pub fn refused(
    failed: Failed,
    warp: Option<&crate::tls::Pinned>,
    own: Option<&Arc<podssh_ws::hysteria::tls::PinnedLeaf>>,
) -> Failed {
    if let Some(issuer) = warp.and_then(|p| p.refused()) {
        return Failed::Intercepted { issuer };
    }
    if let Some(seen) = own.and_then(|p| p.refused()) {
        return Failed::Pin { seen };
    }
    failed
}
