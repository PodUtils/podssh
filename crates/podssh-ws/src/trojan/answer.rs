//! What came first from a Trojan server. The protocol has no answer: a
//! server that took the request relays the target's bytes at once, and one
//! that did not (a wrong password, a request that it cannot read) hands the
//! connection to its fallback, an HTTP server by default, which answers the
//! request's bytes with an `HTTP/` line, or the server closes. A fallback
//! that reads the request as HTTP/0.9 (Python 3.12's `http.server`, for a
//! line it cannot parse) answers with its page alone, with no status line:
//! an HTML page is a fallback's too (T-693). So the first bytes tell them
//! apart for a target that speaks first (SSH), and a target that waits for
//! its client gives silence, which a pipe takes as a stream. No target
//! speaks `HTTP/` or HTML first: a server of HTTP waits for its request.

use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The start of a fallback's answer: a status line.
const HTTP: &[u8] = b"HTTP/";
/// The starts of a fallback's page with no status line (HTTP/0.9).
const PAGES: [&[u8]; 2] = [b"<!DOCTYPE", b"<html"];
/// What a line says of a page with no status line; the page is never shown,
/// as it may quote the request, whose first bytes are the password's hash.
const PAGE: &str = "an HTML page with no status line";

/// Why the first bytes are not the target's.
#[derive(Debug)]
pub enum FirstError {
    /// The server closed with no byte.
    Ended,
    /// The server's fallback answered: its status line.
    Fallback(String),
    Io(std::io::Error),
}

/// A stream whose first bytes were read to tell the target from a fallback;
/// a reader gets them back first.
pub struct Answered<S> {
    inner: S,
    first: Vec<u8>,
    at: usize,
}

impl<S: AsyncRead + Unpin> Answered<S> {
    pub fn new(inner: S) -> Answered<S> {
        Answered { inner, first: Vec::new(), at: 0 }
    }

    /// Read until the first bytes say which: the target's, a fallback's
    /// `HTTP/` line, or the end. A short read that is a prefix of `HTTP/`
    /// reads on, so a line in two pieces is still known.
    pub async fn first(&mut self) -> Result<(), FirstError> {
        let mut buf = [0u8; 512];
        loop {
            let n = self.inner.read(&mut buf).await.map_err(FirstError::Io)?;
            if n == 0 {
                return match self.first.is_empty() {
                    true => Err(FirstError::Ended),
                    false => Ok(()),
                };
            }
            self.first.extend_from_slice(&buf[..n]);
            if starts(&self.first, HTTP) {
                let line = self.first.split(|b| *b == b'\n').next().unwrap_or_default();
                return Err(FirstError::Fallback(status_of(&String::from_utf8_lossy(line))));
            }
            if PAGES.iter().any(|page| starts(&self.first, page)) {
                return Err(FirstError::Fallback(PAGE.to_string()));
            }
            // Read on only while the bytes may still become one of them.
            let may = |start: &[u8]| self.first.len() < start.len() && starts(start, &self.first);
            if !may(HTTP) && !PAGES.iter().any(|page| may(page)) {
                return Ok(());
            }
        }
    }
}

/// Whether `bytes` begin with `start`, in any case.
fn starts(bytes: &[u8], start: &[u8]) -> bool {
    bytes.len() >= start.len() && bytes[..start.len()].eq_ignore_ascii_case(start)
}

/// A fallback's status line as a line may show it: a fallback can quote
/// the request it could not read (Python's `http.server` says "Bad request
/// syntax ('...')"), and the request begins with the hash of the link's
/// password. So the line ends before a quote or a bracket, and a long run
/// of hex digits is left out (T-693).
fn status_of(line: &str) -> String {
    let line = line.trim();
    let cut = line.find(['\'', '"', '(', '[', '{', '<']).unwrap_or(line.len());
    let mut shown = String::new();
    for word in line[..cut].split_whitespace() {
        let hex = word.chars().filter(char::is_ascii_hexdigit).count();
        let word = if hex >= 16 { "..." } else { word };
        if !shown.is_empty() {
            shown.push(' ');
        }
        shown.push_str(word);
    }
    shown.chars().take(80).collect()
}

impl<S: AsyncRead + Unpin> AsyncRead for Answered<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.at < this.first.len() {
            let take = (this.first.len() - this.at).min(buf.remaining());
            buf.put_slice(&this.first[this.at..this.at + take]);
            this.at += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Answered<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn first_of(pieces: &[&[u8]]) -> (Result<(), FirstError>, Vec<u8>) {
        let (mut far, near) = tokio::io::duplex(4096);
        for piece in pieces {
            far.write_all(piece).await.unwrap();
        }
        drop(far);
        let mut answered = Answered::new(near);
        let first = answered.first().await;
        let mut rest = Vec::new();
        if first.is_ok() {
            answered.read_to_end(&mut rest).await.unwrap();
        }
        (first, rest)
    }

    #[tokio::test]
    async fn the_target_s_bytes_come_back_whole_and_a_fallback_or_an_end_is_named() {
        let (ok, rest) = first_of(&[b"SSH-2.0-x\r\n"]).await;
        assert!(ok.is_ok() && rest == b"SSH-2.0-x\r\n");
        let (ok, rest) = first_of(&[b"HT", b"TPS-like but not HTTP/"]).await;
        assert!(ok.is_ok() && rest.starts_with(b"HTTPS"), "a prefix that parts from HTTP/ is the target's");
        match first_of(&[b"HTT", b"P/1.1 400 Bad Request\r\n\r\n"]).await.0 {
            Err(FirstError::Fallback(line)) => assert_eq!(line, "HTTP/1.1 400 Bad Request"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(first_of(&[]).await.0, Err(FirstError::Ended)));
    }

    /// Python 3.12's `http.server`, the fallback of the interop run on a
    /// runner, reads a line that it cannot parse as HTTP/0.9 and answers with
    /// its page alone: the fallback is named, and the page, which quotes the
    /// request and so the password's hash, is not shown (T-693).
    #[tokio::test]
    async fn a_fallback_s_page_with_no_status_line_is_named_and_not_shown() {
        let page: &[u8] =
            b"<!DOCTYPE HTML>\n<html lang=\"en\">\n<p>Message: Bad request syntax ('eee932074e9cd0e99fecc001').</p>";
        for pieces in [vec![page], vec![&page[..3], &page[3..]], vec![b"<HTML><body>400</body></html>".as_slice()]] {
            match first_of(&pieces).await.0 {
                Err(FirstError::Fallback(line)) => assert_eq!(line, PAGE),
                other => panic!("{other:?}"),
            }
        }
        let (ok, rest) = first_of(&[b"<", b"?xml version"]).await;
        assert!(ok.is_ok() && rest == b"<?xml version", "a start that parts from a page is the target's");
    }

    /// trojan-gfw's and trojan-go's fallback, Python's `http.server` here,
    /// quotes the request, whose first bytes are the hash of the password:
    /// the line keeps the status and leaves the hash out (T-693).
    #[tokio::test]
    async fn a_fallback_that_quotes_the_request_shows_no_hash() {
        let hash = "eee932074e9cd0e99fecc0017f0e1974863359ea66c840aabbccdd";
        let answer = format!("HTTP/1.0 400 Bad request syntax ('{hash}\\r\\n')\r\n\r\n");
        match first_of(&[answer.as_bytes()]).await.0 {
            Err(FirstError::Fallback(line)) => {
                assert_eq!(line, "HTTP/1.0 400 Bad request syntax");
                assert!(!line.contains("eee932"), "{line}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(super::status_of("HTTP/1.1 400 eee932074e9cd0e99fecc001 x"), "HTTP/1.1 400 ... x");
    }
}
