//! TUIC version 5 (T-581, the operator's ruling Q82): a server that the user
//! runs, sing-box's, mihomo's, shoes's or Itsusinn's tuic, takes a target
//! over QUIC and dials it, so that it is a road with no relay where UDP
//! passes. The protocol is EAimTY/tuic's `SPEC.md` ([`command`]); the link
//! and its credential come from a private file ([`link`]).
//!
//! QUIC is UDP, which no HTTP proxy carries, so the road goes beside
//! `HTTPS_PROXY` and only after a probe found that UDP reaches the server:
//! one QUIC packet of a reserved version, which a server of QUIC answers in
//! one round trip (`pod_quic::probe`, as the quick tunnel's probe of the
//! edge). With no answer the road ends at once, with no wait for QUIC's own
//! handshake. Then QUIC on noq (`pod_quic::connect`) with podssh's provider,
//! TLS 1.3 checked for the link's name against podssh's trust;
//! `Authenticate` on a unidirectional stream with the token of the TLS
//! exporter; `Connect` on a bidirectional stream, the session's bytes after
//! it at once ([`stream`]); and a `Heartbeat` datagram while it runs.
//!
//! The server never answers a command: a wrong token is a connection that
//! it closes, and a target that it cannot reach is a stream that it ends
//! with no byte. podssh names each by what it saw.

pub mod command;
pub mod link;
pub mod stream;

use std::sync::Arc;
use std::time::Duration;

use pod_quic::noq::ConnectionError;
use pod_quic::Settings;

use crate::tls::Trust;
use stream::{First, TuicStream};

pub use link::{Password, Server, Uuid};

/// How long a session whose server speaks first waits for its first bytes.
pub const ANSWER_WAIT: Duration = Duration::from_secs(10);
/// How long a pipe waits before it takes the stream: a wrong token closes
/// the connection within a round trip.
pub const EARLY_WAIT: Duration = Duration::from_secs(3);
/// How long the probe of UDP waits: a few round trips to a server across the
/// world; the edge of Cloudflare answers the quick tunnel's within 60 ms.
pub const PROBE_WAIT: Duration = Duration::from_secs(1);
/// After a stream that ended with no byte, how long podssh waits to see
/// whether the connection closes too: sing-box ends each waiting stream
/// before it closes a connection whose token is wrong.
const SETTLE: Duration = Duration::from_millis(500);
/// A silence that ends the connection: past the heartbeat, which keeps it.
const SILENCE: Duration = Duration::from_secs(30);

/// The settings of a dial.
pub struct Dial<'a> {
    /// The trust that QUIC's TLS checks the server's certificate with.
    pub trust: &'a Trust,
    /// The wait for the name, and for QUIC's handshake.
    pub timeout: Duration,
    /// The wait for the target's first bytes.
    pub answer: Duration,
    /// A silence of [`Dial::answer`] takes the stream (a pipe), rather than
    /// failing (an SSH session, whose server speaks first).
    pub silence_is_ready: bool,
    /// The wait of the probe of UDP.
    pub probe_wait: Duration,
}

/// Why a TUIC server carried no session.
#[derive(Debug)]
pub enum TuicError {
    /// The target cannot go in `Connect`.
    Target(String),
    /// The server's name has no address.
    Resolve(String),
    /// UDP got no answer from the server's port: the probe's words.
    NoUdp(String),
    /// QUIC or its TLS failed: what failed.
    Quic(String),
    /// The server closed the connection: its code and its words, if any.
    Closed { code: u64, reason: String },
    /// The server ended the stream with no byte of the target.
    TargetEnded,
    /// The stream failed before the target's bytes.
    Carry(String),
    /// No byte within the wait.
    Silent(Duration),
}

impl TuicError {
    /// The line that says it, for the server `shown` and the target. No line
    /// holds the UUID, the password or the token.
    pub fn line(&self, shown: &str, target: &str) -> String {
        match self {
            TuicError::Target(why) => format!("{target} cannot go to the TUIC server {shown}: {why}"),
            TuicError::Resolve(why) => format!("the TUIC server {shown}: {why}"),
            TuicError::NoUdp(why) => format!(
                "the TUIC server {shown}: UDP does not pass to it from here ({why}); TUIC is QUIC, which no HTTP \
                 proxy carries"
            ),
            TuicError::Quic(why) => format!("the TUIC server {shown}: {why}"),
            TuicError::Closed { code, reason } => {
                let said = if reason.is_empty() { String::new() } else { format!(", saying {reason:?}") };
                format!(
                    "the TUIC server {shown} closed the connection (code {code}{said}) before the target said \
                     anything: the UUID or the password of the link is not the server's"
                )
            }
            TuicError::TargetEnded => format!(
                "the TUIC server {shown} ended the stream to {target} with no byte: it could not reach the target, \
                 or its rules refuse it"
            ),
            TuicError::Carry(why) => format!("the TUIC server {shown}, for {target}: {why}"),
            TuicError::Silent(after) => format!(
                "the TUIC server {shown} gave nothing for {target} within {} s: the target said nothing, or the \
                 server holds the session",
                after.as_secs()
            ),
        }
    }
}

/// A session to the target.
pub struct Opened {
    pub stream: TuicStream,
    /// What carried it: "QUIC to ADDR".
    pub how: String,
    /// The target's first bytes came within the wait.
    pub answered: bool,
}

/// A session to `host:port` through `server`.
pub async fn open(server: &Server, host: &str, port: u16, dial: &Dial<'_>) -> Result<Opened, TuicError> {
    let connect = command::connect(host, port).map_err(TuicError::Target)?;
    let deadline = tokio::time::Instant::now() + dial.timeout;
    let addrs = crate::resolve::resolve(&server.host, server.port, deadline).await.map_err(TuicError::Resolve)?;
    // UDP first: a network that drops it answers nothing, and QUIC's own
    // handshake would wait its whole limit to say so.
    let (addr, _) =
        pod_quic::probe::probe(&addrs, dial.probe_wait).await.map_err(|f| TuicError::NoUdp(f.to_string()))?;
    let roots = crate::tls::roots_for(dial.trust).map_err(|e| TuicError::Quic(format!("QUIC's TLS: {e}")))?;
    let alpn: Vec<&[u8]> = server.alpn.iter().map(|a| a.as_bytes()).collect();
    let provider = Arc::new(crate::crypto::provider());
    let tls =
        pod_quic::connect::tls(provider, Arc::new(roots.roots), &alpn).map_err(|f| TuicError::Quic(f.to_string()))?;
    let endpoint = pod_quic::endpoint::system(addr.is_ipv6()).map_err(|f| TuicError::Quic(f.to_string()))?;
    // QUIC's keepalive beside TUIC's heartbeat: a server that takes no
    // datagram still sees the connection alive.
    let settings = Settings {
        handshake_wait: dial.timeout,
        silence: SILENCE,
        keepalive: Some(stream::HEARTBEAT),
        ..Settings::default()
    };
    let connection = pod_quic::connect::connect(&endpoint, addr, &server.sni, tls, &settings)
        .await
        .map_err(|f| TuicError::Quic(f.to_string()))?;
    let token = command::token(&server.uuid, &server.password, |out, label, context| {
        connection.export_keying_material(out, label, context).map_err(|_| "TLS gave no keying material".to_string())
    })
    .map_err(TuicError::Quic)?;
    // Both streams go at once: a server holds `Connect` until the token is
    // checked (`SPEC.md`, "Authentication").
    let sent = async {
        let mut auth = connection.open_uni().await.map_err(|e| lost(&e))?;
        auth.write_all(&command::authenticate(&server.uuid, &token)).await.map_err(|e| e.to_string())?;
        let _ = auth.finish();
        let (mut send, recv) = connection.open_bi().await.map_err(|e| lost(&e))?;
        send.write_all(&connect).await.map_err(|e| e.to_string())?;
        Ok::<_, String>((send, recv))
    };
    let (send, recv) = match tokio::time::timeout(dial.timeout, sent).await {
        Ok(Ok(streams)) => streams,
        Ok(Err(why)) => return Err(closed(&connection).unwrap_or(TuicError::Carry(why))),
        Err(_) => {
            let why = format!("TUIC's commands not sent within {} s", dial.timeout.as_secs());
            return Err(TuicError::Carry(why));
        }
    };
    let how = format!("QUIC to {addr}");
    let mut stream = TuicStream::new(endpoint, connection, send, recv);
    let first = tokio::time::timeout(dial.answer, stream.first()).await;
    let answered = match first {
        Ok(First::Bytes) => true,
        Ok(First::Lost(e)) => return Err(why_lost(e)),
        Ok(First::Ended) => {
            // sing-box ends the waiting stream a moment before it closes a
            // connection whose token is wrong: the connection's end, if it
            // comes, is the cause.
            let closing = tokio::time::timeout(SETTLE, stream.connection().closed()).await;
            return Err(match closing {
                Ok(e) => why_lost(e),
                Err(_) => TuicError::TargetEnded,
            });
        }
        Ok(First::Failed(why)) => return Err(TuicError::Carry(format!("before the target's bytes: {why}"))),
        Err(_) if dial.silence_is_ready => match closed(stream.connection()) {
            Some(e) => return Err(e),
            None => false,
        },
        Err(_) => return Err(closed(stream.connection()).unwrap_or(TuicError::Silent(dial.answer))),
    };
    Ok(Opened { stream, how, answered })
}

/// The words of a stream that could not open on a lost connection.
fn lost(e: &ConnectionError) -> String {
    format!("the connection ended: {e}")
}

/// The connection's end, if it ended, as the cause of a failure.
fn closed(connection: &pod_quic::noq::Connection) -> Option<TuicError> {
    connection.close_reason().map(why_lost)
}

/// A connection's end in TUIC's words: the server's close is a token that it
/// did not take, as no other command closes a connection.
fn why_lost(e: ConnectionError) -> TuicError {
    match e {
        ConnectionError::ApplicationClosed(close) => TuicError::Closed {
            code: close.error_code.into_inner(),
            reason: crate::text::one_line(&String::from_utf8_lossy(&close.reason)),
        },
        ConnectionError::TimedOut => TuicError::Quic(format!("QUIC went silent for {} s", SILENCE.as_secs())),
        other => TuicError::Quic(format!("QUIC: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_failure_names_the_server_and_never_the_credential() {
        let shown = "tuic://t.example:8443";
        let closed = TuicError::Closed { code: 0, reason: "auth failed".into() }.line(shown, "h.example:22");
        assert!(closed.contains("closed the connection (code 0, saying \"auth failed\")"), "{closed}");
        assert!(closed.contains("UUID or the password of the link is not the server's"), "{closed}");
        let quiet = TuicError::Closed { code: 0, reason: String::new() }.line(shown, "h:22");
        assert!(quiet.contains("(code 0)"), "{quiet}");
        assert!(TuicError::TargetEnded.line(shown, "h:22").contains("could not reach the target"));
        let udp = TuicError::NoUdp("x said nothing within 1000 ms".into()).line(shown, "h:22");
        assert!(udp.contains("UDP does not pass") && udp.contains("no HTTP proxy carries"), "{udp}");
        assert!(TuicError::Silent(ANSWER_WAIT).line(shown, "h:22").contains("within 10 s"));
    }
}
