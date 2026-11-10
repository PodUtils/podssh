//! The probe of UDP before QUIC (T-400): one QUIC packet of a reserved
//! version to the edge's port, which a server of QUIC answers with a Version
//! Negotiation in one round trip (RFC 9000, sections 6 and 17.2.1); cfrs's
//! testers saw the edge answer so, with 27 bytes (`docs/design.md`,
//! "Measured by cfrs's testers"). A network that drops UDP answers nothing,
//! and the node's race gives QUIC up at the probe's end, where QUIC's own
//! handshake waits 5 s at each address. Each socket is connected to one
//! address of the edge: it sends there and takes datagrams from there alone,
//! nothing listens, and a port that the system says is closed (ICMP) comes
//! back on it as a refusal.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

use super::edge::{self, Edge};

/// The packet, its answer and the wait are pod-quic's.
pub use pod_quic::probe::{answers, packet, PADDED, RESERVED, WAIT};

/// The probe: a packet to each of `addrs` at once; the address that answered
/// first within `wait`, and its round trip; else what each address did.
pub async fn probe(addrs: &[SocketAddr], wait: Duration) -> Result<(SocketAddr, Duration), String> {
    pod_quic::probe::probe(addrs, wait).await.map_err(|e| e.to_string())
}

/// The probe to `found`: the first address of each family of its first
/// region that resolves within the dial's limit.
pub async fn edge(found: &Edge, wait: Duration) -> Result<(SocketAddr, Duration), String> {
    let deadline = Instant::now() + edge::DIAL_LIMIT;
    let mut unresolved = Vec::new();
    for region in &found.regions {
        match podssh_ws::resolve::resolve(region, found.port, deadline).await {
            Ok(addrs) => {
                let firsts = [addrs.iter().find(|a| a.is_ipv4()), addrs.iter().find(|a| a.is_ipv6())];
                let firsts: Vec<SocketAddr> = firsts.into_iter().flatten().copied().collect();
                if !firsts.is_empty() {
                    return probe(&firsts, wait).await;
                }
                unresolved.push(format!("{region}: no address"));
            }
            Err(e) => unresolved.push(format!("{region}: {e}")),
        }
    }
    Err(format!("UDP to the edge was not probed: no region resolved: {}", unresolved.join("; ")))
}
