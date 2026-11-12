//! The road over HTTP/3 as one call (T-582): [`Warp::open_h3`] to WARP's
//! endpoint with the device of the road over HTTP/2, and
//! [`Warp::open_server`] to a server of connect-ip that the user runs. Each
//! probes UDP first ([`crate::h3::probe`]), so that a network that drops UDP
//! costs one short wait and no QUIC handshake; then the tunnel, its stack
//! with the MTU that a datagram carries, and the probe inside the tunnel of
//! T-560, as over HTTP/2. A proxy is never on this road: UDP has none.

use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_ws::Trust;

use crate::device::Device;
use crate::h3::open::Ask;
use crate::h3::server::Server;
use crate::h3::{self, wire, Dial, Failed, Tunnel};
use crate::probe::Verdict;
use crate::road::{silent, Fault, Warp};
use crate::stack::Stack;

/// The line of a failure over HTTP/3 at `at`, for the road's [`Fault`].
pub fn fault(failed: Failed, at: &str) -> Fault {
    let line = format!("{at} over HTTP/3: {failed}");
    match failed {
        Failed::Udp(_) | Failed::Quic(_) | Failed::Timeout(_) => Fault::Unreachable(line),
        Failed::Intercepted { .. } | Failed::Pin { .. } => Fault::Intercepted(line),
        Failed::NotEnrolled(_) | Failed::Refused { status: 401 | 403 } => Fault::Device(line),
        Failed::Http3(_) | Failed::NoDatagrams | Failed::NoAddress | Failed::Refused { .. } => Fault::Edge(line),
        Failed::Local(why) => Fault::Local(why),
    }
}

/// The road's words for an endpoint over HTTP/3.
fn words(at: SocketAddr) -> String {
    format!("WARP's endpoint {at}")
}

impl Warp {
    /// The tunnel of `device` over HTTP/3, at the first of its endpoints
    /// whose UDP port 443 answered the probe, each step within `limit`. A
    /// certificate of another key than the record's is named as over
    /// HTTP/2; the record is read again by the road over HTTP/2 alone.
    pub async fn open_h3(device: &Device, limit: Duration) -> Result<Warp, Fault> {
        let endpoints = device.endpoints();
        let shown: Vec<String> = endpoints.iter().map(|at| at.to_string()).collect();
        let at = h3::probe(&endpoints, h3::PROBE_WAIT_EDGE)
            .await
            .map_err(|failed| fault(failed, &format!("WARP's endpoints {}", shown.join(", "))))?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        // A certificate from a minute ago, for a clock a little ahead of the edge's.
        let (tls, pinned) = crate::tls::config_for(&device.key, &device.endpoint_point, now - 60, crate::tls::ALPN_H3)
            .map_err(Fault::Local)?;
        let ask = Ask {
            authority: crate::authority_h3(),
            path: "/".into(),
            protocol: wire::CF_CONNECT_IP,
            needs_extended_connect: false,
            draft_datagram: true,
        };
        let dial =
            Dial { addr: at, server_name: crate::server_name().into(), tls, ask, addresses: Some(device.addresses()) };
        let tunnel = h3::open(dial, limit)
            .await
            .map_err(|failed| fault(h3::refused(failed, Some(pinned.as_ref()), None), &words(at)))?;
        Warp::over_h3(tunnel, at, device.probe, limit).await
    }

    /// The tunnel of the user's `server` over HTTP/3, its certificate by
    /// `trust` or its pin; the address inside is the server's to assign.
    /// `probe` is the target of the probe inside the tunnel (T-560), none
    /// to take the tunnel as it opens.
    pub async fn open_server(
        server: &Server,
        trust: &Trust,
        probe: Option<SocketAddr>,
        limit: Duration,
    ) -> Result<Warp, Fault> {
        let shown = server.shown();
        let addrs = server.addresses(limit).await.map_err(|failed| fault(failed, &shown))?;
        let at = h3::probe(&addrs, h3::PROBE_WAIT_FAR).await.map_err(|failed| fault(failed, &shown))?;
        let (dial, pinned) = server.dial(at, trust).map_err(|failed| fault(failed, &shown))?;
        let tunnel = h3::open(dial, limit)
            .await
            .map_err(|failed| fault(h3::refused(failed, None, pinned.as_ref()), &format!("{shown} ({at})")))?;
        Warp::over_h3(tunnel, at, probe, limit).await
    }

    /// The stack over an opened tunnel, once the probe inside it found that
    /// it carries a packet each way; with no probe, as it opened.
    async fn over_h3(
        tunnel: Tunnel,
        at: SocketAddr,
        probe: Option<SocketAddr>,
        limit: Duration,
    ) -> Result<Warp, Fault> {
        let Tunnel { link, addresses, mtu } = tunnel;
        let stack = Stack::start_mtu(&addresses, link, mtu).map_err(Fault::Local)?;
        let mut warp = Warp { stack, endpoint: at, proxy: None, probed: None };
        let Some(to) = probe else { return Ok(warp) };
        match crate::probe::run(&warp.stack, to, limit).await {
            Verdict::Carried => {
                warp.probed = Some(to);
                Ok(warp)
            }
            Verdict::Silent(why) => Err(silent(&format!("{} over HTTP/3", words(at)), to, &why)),
            Verdict::Ended(why) => Err(Fault::Edge(format!(
                "{} over HTTP/3: the tunnel ended before a packet came back: {why}",
                words(at)
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each failure goes to the fault whose exit code the CLI gives it: a
    /// network that drops UDP is unreachable, a refused device is the
    /// device's, a broken answer the edge's.
    #[test]
    fn each_failure_has_its_fault() {
        let at = "WARP's endpoint 162.159.198.2:443";
        assert!(matches!(fault(Failed::Udp("silent".into()), at), Fault::Unreachable(_)));
        assert!(matches!(fault(Failed::NotEnrolled("error 49".into()), at), Fault::Device(_)));
        assert!(matches!(fault(Failed::Refused { status: 403 }, at), Fault::Device(_)));
        assert!(matches!(fault(Failed::Refused { status: 500 }, at), Fault::Edge(_)));
        assert!(matches!(fault(Failed::NoDatagrams, at), Fault::Edge(_)));
        assert!(matches!(fault(Failed::Pin { seen: "ab".into() }, at), Fault::Intercepted(_)));
        let line = fault(Failed::Udp("silent".into()), at).to_string();
        assert!(line.starts_with("WARP's endpoint 162.159.198.2:443 over HTTP/3: UDP does not pass"), "{line}");
    }
}
