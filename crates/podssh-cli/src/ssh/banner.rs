//! The server's version line on a connection that opened (RFC 4253, section
//! 4.2): `podssh doctor`'s check that a connection to port 22 carries SSH,
//! and the check of the direct road that follows the relay hosts (T-363). A
//! `200` to CONNECT proves that a proxy took the request, not that the
//! tunnel carries bytes as they are: a proxy that intercepts TLS waits for a
//! ClientHello, and sends nothing or resets (T-317). The bytes that the check
//! read go to the SSH client first ([`Prefixed`]).
//!
//! The rule is the roost's (`podssh_relay::reverse::sshd::judge`, T-702):
//! lines before the version line pass, within 4 KiB. A loop of reads, not a
//! peek: a proxy's stream through podssh-ws, and a stream inside TLS, offer
//! none.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::reverse::sshd::{judge, READ_MAX};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The refusal: it names no line, as what came may be a proxy's bytes.
const NOT_SSH: &str = "what came was not an SSH banner";

/// The first bytes of `stream` within `wait`, read until they hold a whole
/// SSH version line (a server may send other lines before it), or until
/// they cannot; else why not. A part of a line waits for the rest.
pub(crate) async fn read<S: AsyncRead + Unpin>(stream: &mut S, wait: Duration) -> Result<Vec<u8>, String> {
    let mut got = Vec::with_capacity(READ_MAX);
    let result = tokio::time::timeout(wait, judged(stream, &mut got)).await;
    match result {
        Ok(Ok(())) => Ok(got),
        Ok(Err(why)) => Err(why),
        Err(_) if got.is_empty() => Err(format!("nothing came in {} s", wait.as_secs())),
        Err(_) => Err(NOT_SSH.into()),
    }
}

/// Reads into `got` until [`judge`] decides, which it does by [`READ_MAX`]
/// bytes at the latest; `got` keeps each byte, for [`Prefixed`].
async fn judged<S: AsyncRead + Unpin>(stream: &mut S, got: &mut Vec<u8>) -> Result<(), String> {
    let mut buf = vec![0u8; READ_MAX];
    loop {
        let room = READ_MAX.saturating_sub(got.len());
        if room == 0 {
            return Err(NOT_SSH.into());
        }
        let n = match stream.read(&mut buf[..room]).await {
            Ok(0) if got.is_empty() => return Err("it was closed with nothing sent".into()),
            Ok(0) => return Err(NOT_SSH.into()),
            Ok(n) => n,
            Err(e) if got.is_empty() => return Err(format!("it broke with nothing sent ({e})")),
            Err(e) => return Err(format!("{NOT_SSH}, then it broke ({e})")),
        };
        got.extend_from_slice(&buf[..n]);
        match judge(got) {
            Some(Ok(_)) => return Ok(()),
            Some(Err(_)) => return Err(NOT_SSH.into()),
            None => {}
        }
    }
}

/// A stream whose first bytes were read already: it gives them again first,
/// then reads on; writes go through as they are.
pub(crate) struct Prefixed<S> {
    first: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Prefixed<S> {
    pub(crate) fn new(first: Vec<u8>, inner: S) -> Prefixed<S> {
        Prefixed { first, at: 0, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.at < self.first.len() {
            let n = (self.first.len() - self.at).min(buf.remaining());
            let at = self.at;
            buf.put_slice(&self.first[at..at + n]);
            self.at += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The five inputs of T-702 for the direct road's reader, on a paused
/// clock, so that each wait is measured to the instant.
#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    /// The direct road's own bound (`VERSION_WAIT`).
    const WAIT: Duration = Duration::from_secs(10);

    /// A stream in memory whose far end stays open until it is dropped.
    fn pair() -> (DuplexStream, DuplexStream) {
        tokio::io::duplex(READ_MAX * 2)
    }

    #[tokio::test(start_paused = true)]
    async fn a_whole_version_line_is_read_and_kept() {
        let (mut near, mut far) = pair();
        far.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        assert_eq!(read(&mut near, WAIT).await.unwrap(), b"SSH-2.0-OpenSSH_9.6\r\n");
    }

    /// The first piece is shorter than `SSH-`: T-363's one read held no line
    /// that starts so, and refused it (T-702).
    #[tokio::test(start_paused = true)]
    async fn a_version_line_in_two_pieces_waits_for_the_second() {
        let (mut near, mut far) = pair();
        far.write_all(b"SS").await.unwrap();
        let reader = tokio::spawn(async move { (read(&mut near, WAIT).await, near) });
        tokio::time::sleep(Duration::from_secs(2)).await;
        far.write_all(b"H-2.0-dropbear_2024.86\r\n").await.unwrap();
        let (got, _near) = reader.await.unwrap();
        assert_eq!(got.unwrap(), b"SSH-2.0-dropbear_2024.86\r\n");
    }

    #[tokio::test(start_paused = true)]
    async fn a_greeting_then_the_version_line_in_one_write_passes() {
        let (mut near, mut far) = pair();
        far.write_all(b"Welcome to the lab\r\nSSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        assert_eq!(read(&mut near, WAIT).await.unwrap(), b"Welcome to the lab\r\nSSH-2.0-OpenSSH_9.6\r\n");
    }

    /// A greeting alone, then the version line a moment later: the case of
    /// GitHub #170 that T-363's one read refused.
    #[tokio::test(start_paused = true)]
    async fn a_greeting_alone_then_the_version_line_passes() {
        let (mut near, mut far) = pair();
        far.write_all(b"Welcome to the lab\r\n").await.unwrap();
        let reader = tokio::spawn(async move { (read(&mut near, WAIT).await, near) });
        tokio::time::sleep(Duration::from_secs(1)).await;
        far.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
        let (got, _near) = reader.await.unwrap();
        assert_eq!(got.unwrap(), b"Welcome to the lab\r\nSSH-2.0-OpenSSH_9.6\r\n");
    }

    /// An HTTP answer alone: refused at once when its server closes, and at
    /// the bound when it stays open, as its lines may be a greeting.
    #[tokio::test(start_paused = true)]
    async fn an_http_answer_alone_is_no_banner() {
        let (mut near, mut far) = pair();
        far.write_all(b"HTTP/1.1 400 Bad Request\r\n").await.unwrap();
        drop(far);
        let started = tokio::time::Instant::now();
        assert_eq!(read(&mut near, WAIT).await.unwrap_err(), NOT_SSH);
        assert_eq!(started.elapsed(), Duration::ZERO);
        let (mut near, mut far) = pair();
        far.write_all(b"HTTP/1.1 400 Bad Request\r\n").await.unwrap();
        assert_eq!(read(&mut near, WAIT).await.unwrap_err(), NOT_SSH);
        assert_eq!(started.elapsed(), WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn silence_is_named_at_the_bound() {
        let (mut near, _far) = pair();
        let started = tokio::time::Instant::now();
        assert_eq!(read(&mut near, WAIT).await.unwrap_err(), "nothing came in 10 s");
        assert_eq!(started.elapsed(), WAIT);
    }

    /// The bytes after the version line, the server's first packet, are
    /// kept for the client too; 4 KiB of lines with no version line end the
    /// read at once, and a record of TLS too.
    #[tokio::test(start_paused = true)]
    async fn what_follows_the_line_is_kept_and_4_kib_of_lines_end_the_read() {
        let (mut near, mut far) = pair();
        far.write_all(b"SSH-2.0-x\r\n\x00\x00\x01\x14").await.unwrap();
        assert_eq!(read(&mut near, WAIT).await.unwrap(), b"SSH-2.0-x\r\n\x00\x00\x01\x14");
        let (mut near, mut far) = pair();
        far.write_all(&b"a line of a greeting\r\n".repeat(200)).await.unwrap();
        let started = tokio::time::Instant::now();
        assert_eq!(read(&mut near, WAIT).await.unwrap_err(), NOT_SSH);
        let (mut near, mut far) = pair();
        far.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x50]).await.unwrap();
        assert_eq!(read(&mut near, WAIT).await.unwrap_err(), NOT_SSH);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }
}
