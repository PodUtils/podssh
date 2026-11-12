//! The probe of UDP before QUIC (T-400's, of pod-quic): one QUIC packet of a
//! reserved version to the server's port, which a server of QUIC answers with
//! a Version Negotiation in one round trip (RFC 9000, section 6); quic-go,
//! Hysteria's QUIC, sends one to a packet of 1200 bytes or more. With
//! Salamander the packet and its answer are Salamander's, as each of the
//! server's datagrams is. A network that drops UDP answers nothing, and the
//! road ends at the probe's wait, where QUIC's own handshake would wait 5 s.
//! The packet goes again twice within the wait, as one UDP datagram may be
//! lost; each socket is connected to its address alone, and nothing listens.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use pod_core::entropy::{Entropy, OsEntropy};
use pod_quic::probe::{answers, packet};
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::salamander;

/// How long the probe waits: a few round trips to a server across the
/// world, where pod-quic's 300 ms is the edge of Cloudflare, near each host.
pub const WAIT: Duration = Duration::from_millis(1500);
/// How many times the packet goes within the wait.
const SENDS: u32 = 3;

/// What the probe found of one address.
#[derive(Debug)]
pub enum Probed {
    /// The round trip of the answer.
    Answered(Duration),
    /// The system said that nothing serves the port (ICMP).
    Refused,
}

/// The probe of `addr`, with Salamander's key when the server has one,
/// within `wait`: its answer, or none (silence).
pub async fn one(addr: SocketAddr, obfs: Option<&[u8]>, wait: Duration) -> io::Result<Option<Probed>> {
    let any: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(any).await?;
    socket.connect(addr).await?;
    let mut dcid = [0u8; 8];
    OsEntropy.fill(&mut dcid).map_err(|_| io::Error::other("no random ID for the probe"))?;
    let plain = packet(&dcid);
    let started = Instant::now();
    let deadline = started + wait;
    let mut datagram = vec![0u8; 2048];
    for send in 0..SENDS {
        let wire = match obfs {
            Some(psk) => salamander::obfuscate(psk, salamander::salt()?, &plain),
            None => plain.clone(),
        };
        match socket.send(&wire).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(Some(Probed::Refused)),
            Err(e) => return Err(e),
        }
        let until = (started + wait * (send + 1) / SENDS).min(deadline);
        loop {
            let n = match tokio::time::timeout_at(until, socket.recv(&mut datagram)).await {
                Err(_) => break,
                Ok(Ok(n)) => n,
                Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => return Ok(Some(Probed::Refused)),
                Ok(Err(e)) => return Err(e),
            };
            let len = match obfs {
                Some(psk) => salamander::deobfuscate(psk, &mut datagram[..n]).unwrap_or(0),
                None => n,
            };
            // Another datagram from the address answers no packet of this one.
            if answers(&datagram[..len], &dcid) {
                return Ok(Some(Probed::Answered(started.elapsed())));
            }
        }
    }
    Ok(None)
}

/// The probe of each of `addrs` at once: the first that answered and its
/// round trip; else the line of what each did.
pub async fn probe(
    addrs: &[SocketAddr],
    obfs: Option<&[u8]>,
    wait: Duration,
) -> Result<(SocketAddr, Duration), String> {
    let mut tries = tokio::task::JoinSet::new();
    for &addr in addrs {
        let obfs = obfs.map(|k| zeroize::Zeroizing::new(k.to_vec()));
        tries.spawn(async move { (addr, one(addr, obfs.as_deref().map(|k| k.as_slice()), wait).await) });
    }
    let mut said = Vec::new();
    while let Some(joined) = tries.join_next().await {
        match joined {
            Ok((addr, Ok(Some(Probed::Answered(took))))) => return Ok((addr, took)),
            Ok((addr, Ok(Some(Probed::Refused)))) => said.push(format!("{addr} refused it, as no server is there")),
            Ok((addr, Ok(None))) => said.push(format!("{addr} said nothing within {} ms", wait.as_millis())),
            Ok((addr, Err(e))) => said.push(format!("{addr}: {e}")),
            Err(e) => said.push(format!("a probe ended: {e}")),
        }
    }
    Err(said.join("; "))
}
