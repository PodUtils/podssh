//! Copies of `pod-egress`'s private pieces, which this road needs to write
//! the request before the handshake's answer.
//!
//! pod-egress keeps the upgrade request, VLESS's request, the stream that
//! reads VLESS's answer, and the pump between a session and its pipe to
//! itself, so a caller that drives the TLS handshake cannot reuse them. This
//! module holds the same bytes and the same behaviour, copied, so a link
//! reads the same however this module opens it.

use std::sync::Arc;

use pod_egress::vless::{AtEnd, Id, Server, VlessError};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;

use crate::client::{self, ConnectError};
use crate::session::RelaySession;

/// The pipe in memory, each way: pod-egress's size for the same pump.
pub(super) const PIPE: usize = 256 * 1024;
/// The largest message sent, as a CDN in front of the server may cut a
/// larger one.
pub(super) const CHUNK: usize = crate::frame::FORWARD_SEND_PAYLOAD;

/// The version of VLESS's request, the only one that Xray-core speaks.
pub(super) const VERSION: u8 = 0;
pub(super) const COMMAND_TCP: u8 = 1;
pub(super) const ADDRESS_IPV4: u8 = 1;
pub(super) const ADDRESS_NAME: u8 = 2;
pub(super) const ADDRESS_IPV6: u8 = 3;

/// The upgrade request: the link's path and `Host`, no subprotocol, no
/// extension and no `Origin`, as Xray-core's client sends it. A copy of
/// pod-egress's, which is private there.
pub(super) fn upgrade(server: &Server, key: &str, user_agent: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n",
        server.path, server.authority, user_agent
    )
    .into_bytes()
}

/// VLESS's request for `host:port`: version 0, the ID, no add-ons, TCP, the
/// port, then the address. A copy of `pod_egress::vless::header::request`,
/// which is private there.
pub(super) fn request(id: &Id, host: &str, port: u16) -> Result<Vec<u8>, String> {
    if port == 0 {
        return Err("port 0 is no port".into());
    }
    let mut out = Vec::with_capacity(24 + host.len());
    out.push(VERSION);
    out.extend_from_slice(id.bytes());
    out.push(0);
    out.push(COMMAND_TCP);
    out.extend_from_slice(&port.to_be_bytes());
    match host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            out.push(ADDRESS_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            out.push(ADDRESS_IPV6);
            out.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let readable = host.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
            if host.is_empty() || host.len() > 255 || !readable {
                return Err(format!("{host:?} is no name that a VLESS server reads"));
            }
            out.push(ADDRESS_NAME);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(out)
}

/// A failure of the upgrade, in this road's words: a copy of pod-egress's
/// private mapping, so that a link reads the same either way.
pub(super) fn upgrade_failed(e: ConnectError, path: &str) -> VlessError {
    let path = path.split('?').next().unwrap_or("/");
    match e {
        ConnectError::Dial(e) => VlessError::Dial(e),
        ConnectError::Refused { status, body } => {
            let said = if body.is_empty() { String::new() } else { format!(" ({body})") };
            let why = format!(
                "the WebSocket upgrade at {path}{said}; a path that it does not serve, or a proxy or a front end \
                 that does not pass the upgrade, answers so: type=xhttp passes where the upgrade does not"
            );
            VlessError::Refused { status, why }
        }
        other => VlessError::Carry(other.to_string()),
    }
}

/// Why no answer came. A copy of pod-egress's private `header::AnswerError`.
#[derive(Debug)]
pub(super) enum AnswerError {
    /// The server ended the stream before its answer.
    Ended,
    /// The first byte is not VLESS's version.
    NotVless(u8),
    Io(std::io::Error),
}

impl AnswerError {
    pub(super) fn into_vless(self) -> VlessError {
        match self {
            AnswerError::Ended => VlessError::Ended,
            AnswerError::NotVless(v) => VlessError::NotVless(v),
            AnswerError::Io(e) => VlessError::Carry(format!("before VLESS's answer: {e}")),
        }
    }

    fn into_io(self) -> std::io::Error {
        match self {
            AnswerError::Ended => std::io::Error::new(std::io::ErrorKind::ConnectionAborted, pod_egress::vless::ENDED),
            AnswerError::NotVless(v) => {
                std::io::Error::new(std::io::ErrorKind::InvalidData, pod_egress::vless::not_vless(v))
            }
            AnswerError::Io(e) => e,
        }
    }
}

/// The stream of a session, which reads VLESS's answer before the target's
/// bytes and passes writes through. A copy of pod-egress's private
/// `header::Answered`.
pub(super) struct Answered<S> {
    inner: S,
    waiting: Option<Vec<u8>>,
    ahead: Vec<u8>,
    at: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Answered<S> {
    pub(super) fn new(inner: S) -> Answered<S> {
        Answered { inner, waiting: Some(Vec::new()), ahead: Vec::new(), at: 0 }
    }

    /// Read until VLESS's answer is whole.
    pub(super) async fn answer(&mut self) -> Result<(), AnswerError> {
        std::future::poll_fn(|cx| self.poll_answer(cx)).await
    }

    fn poll_answer(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), AnswerError>> {
        loop {
            let Some(waiting) = self.waiting.as_mut() else { return std::task::Poll::Ready(Ok(())) };
            if let Some(len) = whole(waiting)? {
                self.ahead = waiting.split_off(len);
                self.at = 0;
                self.waiting = None;
                return std::task::Poll::Ready(Ok(()));
            }
            let mut chunk = [0u8; 4096];
            let mut read = ReadBuf::new(&mut chunk);
            std::task::ready!(std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut read)).map_err(AnswerError::Io)?;
            if read.filled().is_empty() {
                return std::task::Poll::Ready(Err(AnswerError::Ended));
            }
            waiting.extend_from_slice(read.filled());
        }
    }
}

/// The length of a whole answer at the start of `bytes`, or none yet.
fn whole(bytes: &[u8]) -> Result<Option<usize>, AnswerError> {
    match bytes {
        [] => Ok(None),
        [v, ..] if *v != VERSION => Err(AnswerError::NotVless(*v)),
        [_] => Ok(None),
        [_, addons, ..] => {
            let len = 2 + usize::from(*addons);
            Ok((bytes.len() >= len).then_some(len))
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Answered<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        std::task::ready!(this.poll_answer(cx)).map_err(AnswerError::into_io)?;
        if this.at < this.ahead.len() {
            let n = (this.ahead.len() - this.at).min(buf.remaining());
            buf.put_slice(&this.ahead[this.at..this.at + n]);
            this.at += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Answered<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Two tasks between the session and one end of a pipe, as pod-egress's
/// WebSocket road pumps them: the bytes out in binary messages, the binary
/// messages in as bytes. A copy of that module's private `spawn`.
pub(super) fn spawn<S>(session: RelaySession<S>, at: AtEnd) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (ours, theirs) = tokio::io::duplex(PIPE);
    let session = Arc::new(session);
    let (mut from_local, mut to_local) = tokio::io::split(theirs);
    let up_failed = Arc::new(Notify::new());
    let down_ended = Arc::new(Notify::new());
    let (up_session, up_failed_tx, down_ended_rx) = (session.clone(), up_failed.clone(), down_ended.clone());
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            let read = tokio::select! {
                read = from_local.read(&mut buf) => read,
                () = down_ended_rx.notified() => return,
            };
            match read {
                Ok(0) | Err(_) => {
                    let close = async {
                        let _ = up_session.send_close(1000, "").await;
                    };
                    pod_egress::end::end_of_input(at, down_ended_rx.notified(), close).await;
                    return;
                }
                Ok(n) => {
                    if up_session.send_binary(&buf[..n]).await.is_err() {
                        up_failed_tx.notify_one();
                        return;
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        let liveness = session.watch_liveness(client::LIVENESS_EVERY, client::LIVENESS_ALLOWED);
        tokio::pin!(liveness);
        loop {
            let read = tokio::select! {
                read = session.read_frame() => read,
                _ = &mut liveness => break,
                () = up_failed.notified() => break,
            };
            let Ok(f) = read else { break };
            match f.opcode {
                crate::frame::OPCODE_CLOSE => break,
                crate::frame::OPCODE_BINARY if !f.payload.is_empty() => {
                    if to_local.write_all(&f.payload).await.is_err() {
                        break;
                    }
                }
                crate::frame::OPCODE_BINARY | crate::frame::OPCODE_TEXT => {}
                _ => {
                    let _ = session.send_close(1002, "").await;
                    break;
                }
            }
        }
        down_ended.notify_one();
        let _ = to_local.shutdown().await;
    });
    ours
}
