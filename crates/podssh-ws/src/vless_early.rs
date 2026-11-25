//! TLS 1.3 early data (0-RTT) on VLESS's WebSocket road (T-758).
//!
//! [`open`] is [`pod_egress::vless::open`] with one addition: where the link
//! is `type=ws` over `security=tls`, the caller asked for early data, and the
//! name's hello would not be sealed by ECH, the upgrade request goes to the
//! TLS handshake itself. rustls hands it to the session before the server's
//! answer when the store of the process holds a ticket for this name, and
//! `tokio-rustls` replays it at 1-RTT on **the same connection** when the
//! server refuses it. Every other road, and every road with no nonce, is
//! pod-egress's, unchanged.
//!
//! **The first session of a process is 1-RTT.** A ticket comes from a
//! session that has ended, and a `podssh` run opens one session to a server,
//! so a run that asks for 0-RTT announces the link's `ed` size and sends no
//! early data. The second session in the same process — a `doctor` that
//! tries each server, an embedder, or the second of two runs of a library
//! caller — is where the mechanism shows. [`Opened::early`] says what the
//! wire did, not what was asked for.
//!
//! **Why the hand-rolled handshake.** `pod_tls`'s connector has no early
//! data: `enable_early_data` stays off in its configurations. The one thing
//! that decides it is the configuration the handshake uses, so this module
//! clones the process's configuration for the trust (its store of tickets is
//! shared with the clone), sets `enable_early_data`, and drives
//! `tokio_rustls` itself. The cost is that ECH cannot be applied on this
//! path, so a name that ECH would seal takes the ordinary road instead.
//!
//! **No ticket file, and why.** A ticket cannot be written to disk here.
//! rustls 0.23 keeps the ticket and its secret in `Tls13ClientSessionValue`
//! behind private fields with no serialization, and only a `ClientSessionStore`
//! can make one; `pod_tls`'s store keeps them in `ClientSessionMemoryCache`
//! and has no load or save. Reading the fields would mean unsafe code or a
//! fork of either crate, and `podcrates` is outside this repository. It is
//! also the safer default: a TLS 1.3 ticket is a bearer secret that resumes
//! the session as this user, so a state file would be a credential at rest,
//! and 0-RTT data is replayable by design. The anti-replay window that makes
//! a replay fall back to 1-RTT belongs to the VLESS server, not to podssh.
//! Persisting the ticket would widen the window in which a stolen file can
//! speak for the user; nothing here does that.

use std::sync::Arc;

use pod_core::BoxedIo;
use pod_egress::coalesce::{self, First};
use pod_egress::vless::early::Offer;
use pod_egress::vless::{Dial, Server, Transport, VlessError};
use tokio::io::AsyncWriteExt;

use crate::client;
use crate::session::RelaySession;

mod copy;
use copy::{request, spawn, upgrade, upgrade_failed, Answered};

/// The largest message taken: gorilla's writer sends what each write gave.
const RECEIVE_CAP: usize = 1024 * 1024;

/// A session to the target, with what its opening did.
pub struct Opened {
    pub stream: Box<dyn pod_egress::Duplex>,
    /// What carried it: "a WebSocket". This module opens no other road.
    pub how: String,
    /// VLESS's answer came within the wait.
    pub answered: bool,
    /// The write that carried the upgrade request: its bytes, whether they
    /// were short of [`coalesce::TARGET`] and padded, and that they were
    /// coalesced.
    pub first_write: coalesce::Report,
    /// What the session offered of early data, as the wire took it:
    /// [`Offer::ZeroRtt`] only where the server accepted the early data,
    /// [`Offer::OneRtt`] where none was accepted (a repeat of the nonce, no
    /// ticket in this process, or a server that refused it).
    pub early: Offer,
    /// What TLS did with the early data: `Some(true)` accepted,
    /// `Some(false)` refused and replayed at 1-RTT on the same connection,
    /// `None` when none was offered.
    pub early_accepted: Option<bool>,
}

impl Opened {
    /// pod-egress's shape, for a caller that takes a session as its roads do.
    pub fn into_vless(self) -> pod_egress::vless::Opened {
        pod_egress::vless::Opened {
            stream: self.stream,
            how: self.how,
            answered: self.answered,
            first_write: self.first_write,
            early: self.early,
        }
    }
}

/// The session to `host:port` through `server`, with TLS 1.3 early data where
/// this road can carry it.
///
/// # Errors
///
/// As [`pod_egress::vless::open`]: the target that the header cannot name, the
/// dial, the TLS handshake, the upgrade's refusal, an end before VLESS's
/// answer, the answer of another protocol, or a silence.
pub async fn open(server: &Server, host: &str, port: u16, dial: &Dial) -> Result<Opened, VlessError> {
    let Some(_) = dial.early.as_ref().filter(|_| early_road(server, dial)) else {
        return Ok(delegated(pod_egress::vless::open(server, host, port, dial).await?));
    };
    let offer = Offer::of(dial.early.as_ref());
    // The link's `ed` size goes in the path where the window took the nonce,
    // as it does today; the wire decides whether the session keeps 0-RTT.
    let server = if offer.zero_rtt() { server.with_early_data() } else { server.clone() };
    let request = request(&server.id, host, port).map_err(VlessError::Target)?;
    let key = crate::handshake::generate_key().map_err(|e| VlessError::Carry(e.to_string()))?;
    let head = upgrade(&server, &key, &dial.way.user_agent);
    let mut first = First::new();
    let (frame, _) = first.write(&head, &[]);
    let report = first.report();
    let opening = link(&server, &frame, &key, dial, offer);
    let (tls, pending, accepted) = tokio::time::timeout(dial.timeout, opening)
        .await
        .map_err(|_| VlessError::Carry(format!("no answer to the upgrade within {} s", dial.timeout.as_secs())))??;
    let session = RelaySession::new(tls, pending, Some(client::DEFAULT_IDLE_TIMEOUT), client::WRITE_TIMEOUT)
        .naming("the VLESS server");
    session.set_receive_cap(RECEIVE_CAP);
    // The request goes before the answer is read: the server answers with the
    // target's first bytes, as pod-egress's road does.
    session
        .send_binary(&request)
        .await
        .map_err(|e| VlessError::Carry(format!("sending VLESS's request failed: {}", crate::text::said(&e))))?;
    let mut stream = Answered::new(spawn(session, dial.at_end));
    let answered = match tokio::time::timeout(dial.answer, stream.answer()).await {
        Ok(Ok(())) => true,
        Ok(Err(e)) => return Err(e.into_vless()),
        Err(_) if dial.silence_is_ready => false,
        Err(_) => return Err(VlessError::Silent(dial.answer)),
    };
    Ok(Opened {
        stream: Box::new(stream),
        how: Transport::Ws.name(),
        answered,
        first_write: report,
        early: match accepted {
            Some(true) => Offer::ZeroRtt,
            _ => Offer::OneRtt,
        },
        early_accepted: accepted,
    })
}

/// Whether this module opens `server` for `dial`: a WebSocket over TLS, with
/// a nonce, and a name that ECH would not seal. Another road is pod-egress's
/// as it was.
fn early_road(server: &Server, dial: &Dial) -> bool {
    server.tls && server.transport == Transport::Ws && !crate::ech::wanted(&server.sni, &dial.trust)
}

/// pod-egress's session in this module's shape: it sends no TLS early data,
/// so `early_accepted` is none.
fn delegated(opened: pod_egress::vless::Opened) -> Opened {
    Opened {
        stream: opened.stream,
        how: opened.how,
        answered: opened.answered,
        first_write: opened.first_write,
        early: opened.early,
        early_accepted: None,
    }
}

/// TCP through the way out, then TLS 1.3 with the request written before the
/// server's answer; the upgrade's answer, its leftover bytes, and what TLS
/// did with the early data.
async fn link(
    server: &Server,
    frame: &[u8],
    key: &str,
    dial: &Dial,
    offer: Offer,
) -> Result<(tokio_rustls::client::TlsStream<BoxedIo>, Vec<u8>, Option<bool>), VlessError> {
    let tcp = dial.way.tcp(&server.host, server.port, dial.timeout).await.map_err(VlessError::Dial)?;
    let config = crate::tls::config_for(&dial.trust).map_err(|e| VlessError::Carry(format!("TLS: {e}")))?;
    // A copy: its store of sessions is shared with the kept configuration,
    // which is what lets the second session of a process resume the first.
    let mut config = (*config).clone();
    // The WebSocket of Xray-core offers no ALPN, as pod-egress's road does
    // not; the link's own protocols are XHTTP's.
    config.alpn_protocols = Vec::new();
    let send = offer.zero_rtt();
    config.enable_early_data = send;
    let name = rustls_pki_types::ServerName::try_from(server.sni.clone())
        .map_err(|e| VlessError::Carry(format!("{:?} is not a valid server name: {e}", server.sni)))?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config)).early_data(send);
    let mut tls = connector
        .connect(name, tcp.io)
        .await
        .map_err(|e| VlessError::Carry(format!("TLS: {}", crate::tls::handshake_failure(&e))))?;
    // Before the handshake's answer this write is early data; after it, it is
    // the request of a 1-RTT session. `flush` drives the handshake to its end
    // and replays the write at 1-RTT on this connection where the server
    // refused it, so the write happens once and is never sent twice.
    tls.write_all(frame)
        .await
        .map_err(|e| VlessError::Carry(format!("sending the upgrade failed: {}", crate::text::said(&e))))?;
    tls.flush().await.map_err(|e| VlessError::Carry(format!("TLS: {}", crate::tls::handshake_failure(&e))))?;
    let accepted = send.then(|| tls.get_ref().1.is_early_data_accepted());
    let (tls, pending) = client::upgrade_with(tls, &[], key).await.map_err(|e| upgrade_failed(e, &server.path))?;
    Ok((tls, pending, accepted))
}

#[cfg(test)]
mod tests {
    use super::copy::*;
    use super::*;
    use pod_egress::vless::Id;
    use tokio::io::AsyncReadExt;

    fn id() -> Id {
        Id::parse("550e8400-e29b-41d4-a716-446655440000").unwrap()
    }

    /// The request is the bytes of Xray-core's `EncodeRequestHeader`, as
    /// pod-egress's own test states them: version, ID, no add-ons, TCP, the
    /// port, then the address.
    #[test]
    fn the_request_is_xray_s_bytes_for_a_name_and_each_family() {
        let mut head = vec![0u8];
        head.extend_from_slice(&[0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16]);
        head.extend_from_slice(&[0x44, 0x66, 0x55, 0x44, 0x00, 0x00, 0x00, 0x01]);
        let name = request(&id(), "github.com", 22).unwrap();
        assert_eq!(&name[..19], &head[..]);
        assert_eq!(&name[19..], b"\x00\x16\x02\x0agithub.com");
        assert_eq!(&request(&id(), "192.0.2.7", 443).unwrap()[19..], &[0x01, 0xbb, 1, 192, 0, 2, 7]);
        let v6 = request(&id(), "[2001:db8::1]", 22).unwrap();
        assert_eq!((v6[21], v6.len()), (ADDRESS_IPV6, 22 + 16));
        assert!(request(&id(), "a b", 22).is_err() && request(&id(), &"a".repeat(256), 22).is_err());
        assert!(request(&id(), "h", 0).is_err());
    }

    /// The answer is read before the target's bytes, in pieces, with
    /// add-ons, and with the target's first bytes after it.
    #[tokio::test]
    async fn the_answer_is_taken_and_the_target_s_bytes_follow() {
        for wire in [&b"\x00\x00SSH-2.0-x\r\n"[..], b"\x00\x03abcSSH-2.0-x\r\n"] {
            let (ours, mut theirs) = tokio::io::duplex(64);
            let mut stream = Answered::new(ours);
            for byte in wire {
                theirs.write_all(&[*byte]).await.unwrap();
            }
            stream.answer().await.unwrap();
            let mut banner = [0u8; 11];
            stream.read_exact(&mut banner).await.unwrap();
            assert_eq!(&banner, b"SSH-2.0-x\r\n");
        }
    }

    /// An end before the answer, and bytes of another protocol, are said in
    /// pod-egress's words.
    #[tokio::test]
    async fn an_end_before_the_answer_and_another_protocol_are_said() {
        let (ours, theirs) = tokio::io::duplex(64);
        drop(theirs);
        let mut stream = Answered::new(ours);
        assert!(matches!(stream.answer().await, Err(AnswerError::Ended)));
        let (ours, mut theirs) = tokio::io::duplex(64);
        theirs.write_all(b"HTTP/1.1 400 Bad Request\r\n").await.unwrap();
        let mut stream = Answered::new(ours);
        let mut byte = [0u8; 1];
        let e = stream.read(&mut byte).await.unwrap_err();
        assert!(e.to_string().contains("first byte is 72"), "{e}");
    }
}
