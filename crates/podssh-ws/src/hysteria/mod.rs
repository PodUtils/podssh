//! Hysteria 2 (T-580, the operator's ruling Q82): a server that the user
//! runs (`apernet/hysteria`, or another that speaks its protocol) dials each
//! target over QUIC, and to one who has no credential it is an HTTP/3 web
//! server. So where UDP passes, it is a road in place of the relay. QUIC is
//! UDP, which no HTTP proxy carries: where a proxy is set for the server's
//! host, the road is not tried (as the quick tunnel's QUIC), and else it is
//! tried only where a probe found that UDP reaches the server's port
//! ([`probe`]); with no answer it ends at once, with no wait for QUIC's
//! handshake. QUIC is pod-quic's,
//! on noq, with podssh-ws's provider; TLS is checked for the link's name or
//! its pin ([`tls`]); HTTP/3's one request is [`h3`]'s; Salamander, where
//! the link names it, is [`salamander`]'s.
//!
//! The link and its credential come from a private file ([`link`]). Each
//! session is a QUIC connection of its own: its stream carries the TCP
//! request of the target, and the server answers whether it reached it.

pub mod h3;
pub mod link;
pub mod probe;
mod quic;
pub mod salamander;
mod stream;
pub mod tls;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::time::Instant;

use crate::tls::Trust;
use crate::via::Duplex;

pub use link::Server;
pub use quic::{AUTH_OK, KEEPALIVE, SILENCE};

/// Why a Hysteria 2 server carried no session.
#[derive(Debug)]
pub enum HysteriaError {
    /// The target cannot go in Hysteria's request.
    Target(String),
    /// The server's name did not resolve.
    Resolve(String),
    /// A proxy is set for the server's host, which carries no UDP: the proxy.
    Proxied(String),
    /// The proxy's variable cannot be read: why.
    ProxySetting(String),
    /// The probe had no answer: UDP does not pass, or no QUIC serves there.
    NoUdp(String),
    /// QUIC or TLS failed: what failed.
    Quic(String),
    /// The server's certificate is not the one that the link pins: its
    /// digest, and the pinned one.
    Pin { seen: String, pinned: String },
    /// The server answered the credential with another status than 233:
    /// a web server's answer to one who has no credential.
    Auth(u16),
    /// HTTP/3, or the request's stream, broke.
    Http3(String),
    /// The server ended the request's stream before its answer.
    Ended(String),
    /// The server could not reach the target: its message.
    Refused(String),
    /// Nothing within the wait.
    Silent(Duration),
}

impl HysteriaError {
    /// The line that says it, for the server `shown` and the target. No line
    /// holds the credential or Salamander's key.
    pub fn line(&self, shown: &str, target: &str) -> String {
        match self {
            HysteriaError::Target(why) => format!("{target} cannot go to the Hysteria 2 server {shown}: {why}"),
            HysteriaError::Resolve(why) => format!("the Hysteria 2 server {shown}: {why}"),
            HysteriaError::Proxied(proxy) => format!(
                "the Hysteria 2 server {shown} is not tried: the proxy {proxy} is set for its host, and no HTTP \
                 proxy carries UDP; NO_PROXY with its host lets UDP go straight to it"
            ),
            HysteriaError::ProxySetting(why) => format!("the Hysteria 2 server {shown}: {why}"),
            HysteriaError::NoUdp(why) => format!(
                "UDP does not reach the Hysteria 2 server {shown}: a packet of QUIC got no answer ({why}); this \
                 host's network drops UDP, or no QUIC serves that port{}",
                if shown.ends_with("(Salamander)") { ", or its Salamander password is another" } else { "" }
            ),
            HysteriaError::Quic(why) => format!("the Hysteria 2 server {shown}: {why}"),
            HysteriaError::Pin { seen, pinned } => format!(
                "the Hysteria 2 server {shown} showed a certificate whose SHA-256 is {seen}, not the pinSHA256 \
                 {pinned} of the link"
            ),
            HysteriaError::Auth(status) => format!(
                "the Hysteria 2 server {shown} answered the credential with HTTP {status}, not {AUTH_OK}: the \
                 link's credential is not the server's, or the server is a web server and no Hysteria"
            ),
            HysteriaError::Http3(why) => format!("the Hysteria 2 server {shown}, for {target}: {why}"),
            HysteriaError::Ended(why) => {
                format!("the Hysteria 2 server {shown} ended the stream of {target} before its answer: {why}")
            }
            HysteriaError::Refused(message) => {
                format!("the Hysteria 2 server {shown} could not reach {target}: it said {message:?}")
            }
            HysteriaError::Silent(after) => {
                format!("the Hysteria 2 server {shown} gave no answer for {target} within {} s", after.as_secs())
            }
        }
    }
}

/// The settings of a dial.
#[derive(Debug, Clone, Copy)]
pub struct Dial<'a> {
    /// The roots that check a server whose link pins nothing.
    pub trust: &'a Trust,
    /// The bound of the whole open, from the name's resolution to the
    /// server's answer.
    pub timeout: Duration,
    /// The probe's wait ([`probe::WAIT`]).
    pub probe_wait: Duration,
}

/// A session to the target.
pub struct Opened {
    pub stream: Box<dyn Duplex>,
    /// The address that answered the probe, and its round trip.
    pub addr: SocketAddr,
    pub probe: Duration,
}

/// A session to `host:port` through `server`: the probe of UDP, QUIC, the
/// credential, then the target.
pub async fn open(server: &Server, host: &str, port: u16, dial: &Dial<'_>) -> Result<Opened, HysteriaError> {
    let target = crate::dial::authority(host, port);
    if target.len() > quic::MOST_ADDRESS {
        return Err(HysteriaError::Target(format!("its address has more than {} bytes", quic::MOST_ADDRESS)));
    }
    // No HTTP proxy carries UDP: one set for the server's host is a way out
    // that the road would pass, so it is not tried (rule 2, as the quick
    // tunnel's QUIC).
    match crate::dial::proxy_from_env(&server.host) {
        Ok(None) => {}
        Ok(Some(proxy)) => return Err(HysteriaError::Proxied(proxy.to_string())),
        Err(why) => return Err(HysteriaError::ProxySetting(why)),
    }
    let deadline = Instant::now() + dial.timeout;
    let addrs = crate::resolve::resolve(&server.host, server.port, deadline).await.map_err(HysteriaError::Resolve)?;
    // The first address of each family, as the quick tunnel's probe takes.
    let firsts = [addrs.iter().find(|a| a.is_ipv4()), addrs.iter().find(|a| a.is_ipv6())];
    let firsts: Vec<SocketAddr> = firsts.into_iter().flatten().copied().collect();
    if firsts.is_empty() {
        return Err(HysteriaError::Resolve(format!("{} has no address", server.host)));
    }
    let obfs = server.obfs.as_ref().map(|k| k.bytes());
    let (addr, rtt) = probe::probe(&firsts, obfs, dial.probe_wait).await.map_err(HysteriaError::NoUdp)?;
    let opened = async {
        let endpoint = quic::endpoint(addr, obfs).await?;
        let (connection, control) = quic::authenticated(&endpoint, server, addr, dial.trust).await?;
        let streams = quic::tcp(&connection, &target).await?;
        Ok::<_, HysteriaError>(stream::Stream::new(streams, connection, endpoint, control))
    };
    match tokio::time::timeout_at(deadline, opened).await {
        Ok(Ok(stream)) => Ok(Opened { stream: Box::new(stream), addr, probe: rtt }),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(HysteriaError::Silent(dial.timeout)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_names_the_server_and_never_the_credential() {
        let shown = "hysteria2://h.example:443";
        let auth = HysteriaError::Auth(404).line(shown, "h:22");
        assert!(auth.contains("HTTP 404, not 233") && auth.contains("credential is not the server's"), "{auth}");
        let udp = HysteriaError::NoUdp("192.0.2.1:443 said nothing within 1500 ms".into()).line(shown, "h:22");
        assert!(udp.starts_with("UDP does not reach the Hysteria 2 server") && !udp.contains("Salamander"), "{udp}");
        let salted = HysteriaError::NoUdp("x".into()).line("hysteria2://h.example:443 (Salamander)", "h:22");
        assert!(salted.contains("its Salamander password is another"), "{salted}");
        let refused = HysteriaError::Refused("dial tcp: connection refused".into()).line(shown, "h:22");
        assert!(refused.contains("could not reach h:22: it said \"dial tcp: connection refused\""), "{refused}");
        let pin = HysteriaError::Pin { seen: "ab".into(), pinned: "cd".into() }.line(shown, "h:22");
        assert!(pin.contains("SHA-256 is ab, not the pinSHA256 cd"), "{pin}");
        let proxied = HysteriaError::Proxied("http://proxy.example:3128".into()).line(shown, "h:22");
        assert!(proxied.contains("not tried") && proxied.contains("NO_PROXY"), "{proxied}");
    }

    #[test]
    fn the_tcp_request_is_hysteria_s_frame_with_a_padding_of_its_range() {
        let request = quic::tcp_request("h.example:22");
        assert_eq!(&request[..15], b"\x44\x01\x0ch.example:22");
        let pad = h3::varint(&request[15..15 + h3::varint_len(request[15])]) as usize;
        assert!((64..512).contains(&pad), "{pad}");
        assert_eq!(request.len(), 15 + h3::varint_len(request[15]) + pad);
        let auth = quic::padding(256, 2048);
        assert!((256..2048).contains(&auth.len()) && auth.bytes().all(|b| b.is_ascii_alphanumeric()));
    }
}
