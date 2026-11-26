//! A node that runs the end-to-end channel, met by an operator of
//! `--no-e2e` (T-1023): the node's first bytes are the channel's preamble,
//! which would reach stdout as the session's bytes, and the run would end
//! 0. The writer here holds the first bytes from the node while they are a
//! part of the preamble; the whole preamble is refused and never written,
//! and any other start is written as it came.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use podssh_relay::e2e::MAGIC;
use tokio::io::AsyncWrite;

/// The line of an operator of `--no-e2e` whose node runs the channel.
pub const WORDS: &str = "the node runs the end-to-end channel, which --no-e2e turns off at this end: drop --no-e2e";

/// `inner`, whose first bytes are checked for the channel's preamble when
/// `seen` is given; with none, each write goes as it is.
pub struct Watched<W> {
    inner: W,
    /// Bytes from the node that are a part of the preamble so far, not
    /// written yet.
    held: Vec<u8>,
    /// Whether the start is known: not the preamble, or no check asked.
    decided: bool,
    seen: Option<Arc<AtomicBool>>,
}

impl<W> Watched<W> {
    /// `inner`, with the check when `seen` is given: it is set when the
    /// preamble came.
    pub fn new(inner: W, seen: Option<Arc<AtomicBool>>) -> Self {
        Watched { inner, held: Vec::new(), decided: seen.is_none(), seen }
    }
}

impl<W: AsyncWrite + Unpin> Watched<W> {
    /// The held bytes out, once the start is known not to be the preamble.
    fn poll_held(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.held.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.held))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.held.drain(..n);
        }
        Poll::Ready(Ok(()))
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Watched<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.decided {
            let take = buf.len().min(MAGIC.len() - this.held.len());
            let mut next = this.held.clone();
            next.extend_from_slice(&buf[..take]);
            if MAGIC.starts_with(&next) {
                if next.len() == MAGIC.len() {
                    if let Some(seen) = &this.seen {
                        seen.store(true, Ordering::SeqCst);
                    }
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, WORDS)));
                }
                this.held = next;
                return Poll::Ready(Ok(take));
            }
            this.decided = true;
        }
        ready!(this.poll_held(cx))?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // A part of the preamble stays held through a flush: it is written
        // once the start is known.
        if this.decided {
            ready!(this.poll_held(cx))?;
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        // The node ended within a part of the preamble: those were its bytes.
        this.decided = true;
        ready!(this.poll_held(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// Each start, in writes of each size: the preamble is refused and
    /// never written; any other bytes are written whole, also a part of
    /// the preamble that the node ended on.
    #[test]
    fn the_preamble_is_refused_and_each_other_start_is_written() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut preamble_then_more = MAGIC.to_vec();
        preamble_then_more.extend_from_slice(b"frame");
        // (the node's bytes, the preamble seen)
        let cases: [(&[u8], bool); 6] = [
            (&MAGIC[..], true),
            (&preamble_then_more[..], true),
            (&b"SSH-2.0-OpenSSH_9.6\r\n"[..], false),
            (&b"podssh-other\n"[..], false),
            (&b"pod"[..], false),
            (&b""[..], false),
        ];
        for (bytes, preamble) in cases {
            for chunk in [1, 3, 13, 64] {
                let seen = Arc::new(AtomicBool::new(false));
                let mut out = Watched::new(Vec::new(), Some(seen.clone()));
                let wrote = runtime.block_on(async {
                    for part in bytes.chunks(chunk) {
                        out.write_all(part).await?;
                    }
                    out.shutdown().await
                });
                let shown = String::from_utf8_lossy(bytes);
                assert_eq!(seen.load(Ordering::SeqCst), preamble, "{shown:?} in writes of {chunk}");
                assert_eq!(wrote.is_err(), preamble, "{shown:?} in writes of {chunk}");
                match preamble {
                    true => assert!(out.inner.is_empty(), "{shown:?}: nothing of the preamble is written"),
                    false => assert_eq!(out.inner, bytes, "{shown:?} in writes of {chunk}"),
                }
            }
        }
    }

    /// With no check, each byte goes as it is: the channel's own run.
    #[test]
    fn with_no_check_the_preamble_is_written() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let mut out = Watched::new(Vec::new(), None);
        runtime.block_on(out.write_all(MAGIC)).unwrap();
        assert_eq!(out.inner, MAGIC);
    }
}
