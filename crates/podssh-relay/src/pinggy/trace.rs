//! The bytes of each visitor of a node's tunnel, each way (T-548): Pinggy's
//! leg is a third party's SSH channel, and a stall there leaves no other
//! trace. The node says each visitor's end with its bytes and why it ended;
//! with `PODSSH_PINGGY_TRACE=1`, also a line each few seconds while a visitor
//! lives, which names a write that waits and since when, so that a run says
//! on which side the bytes stop.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// `1` adds the lines of each live visitor.
pub const ENV: &str = "PODSSH_PINGGY_TRACE";
/// How often a live visitor's line comes, with the variable set.
pub const EVERY: Duration = Duration::from_secs(5);

/// Whether the variable asks for the lines of each live visitor.
pub fn on() -> bool {
    std::env::var(ENV).is_ok_and(|value| value == "1")
}

/// What one visitor's stream carried, which its wrapper counts.
#[derive(Debug)]
pub struct Counts {
    born: Instant,
    /// The bytes that came from the visitor, and that went to it.
    pub read: AtomicU64,
    pub written: AtomicU64,
    /// Since when a write waits for the stream, in ms from `born`; 0 when
    /// none waits.
    waits_since: AtomicU64,
    /// The writes that waited, each once.
    pub waited: AtomicU64,
    /// What ended the stream first, as the stream saw it: its end of
    /// input, or a read or a write that failed.
    end: Mutex<Option<String>>,
}

impl Counts {
    pub fn new() -> Arc<Counts> {
        Arc::new(Counts {
            born: Instant::now(),
            read: AtomicU64::new(0),
            written: AtomicU64::new(0),
            waits_since: AtomicU64::new(0),
            waited: AtomicU64::new(0),
            end: Mutex::new(None),
        })
    }

    /// Keep `why` when nothing ended the stream before.
    fn ended(&self, why: impl FnOnce() -> String) {
        let mut end = self.end.lock().unwrap_or_else(PoisonError::into_inner);
        if end.is_none() {
            *end = Some(why());
        }
    }

    /// What ended the stream first, if anything did.
    pub fn end(&self) -> Option<String> {
        self.end.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    fn now_ms(&self) -> u64 {
        // 1 at least, so that 0 stays "none waits".
        (self.born.elapsed().as_millis() as u64).max(1)
    }

    /// How long the write that waits now has waited, if one does.
    pub fn waiting(&self) -> Option<Duration> {
        match self.waits_since.load(Ordering::Relaxed) {
            0 => None,
            since => Some(Duration::from_millis(self.now_ms().saturating_sub(since))),
        }
    }

    /// The visitor's bytes and time, for its lines: `N bytes in, M out over
    /// T s`, and the write that waits.
    pub fn line(&self) -> String {
        let (read, written) = (self.read.load(Ordering::Relaxed), self.written.load(Ordering::Relaxed));
        let secs = self.born.elapsed().as_secs_f64();
        let waits = match self.waiting() {
            Some(wait) => format!("; a write waits for {:.1} s", wait.as_secs_f64()),
            None => String::new(),
        };
        let waited = self.waited.load(Ordering::Relaxed);
        format!("{read} bytes in, {written} out over {secs:.1} s ({waited} writes waited){waits}")
    }
}

/// A stream whose bytes each way are counted in its [`Counts`].
pub struct Traced<S> {
    inner: S,
    counts: Arc<Counts>,
}

impl<S> Traced<S> {
    pub fn new(inner: S, counts: Arc<Counts>) -> Traced<S> {
        Traced { inner, counts }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Traced<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len().saturating_sub(before);
        self.counts.read.fetch_add(n as u64, Ordering::Relaxed);
        match &polled {
            Poll::Ready(Ok(())) if n == 0 && buf.remaining() > 0 => {
                self.counts.ended(|| "the visitor's end of input came".into())
            }
            Poll::Ready(Err(e)) => self.counts.ended(|| format!("a read failed: {e}")),
            _ => {}
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> Traced<S> {
    /// Note whether a write waits now, from when it first did.
    fn note<T>(&self, polled: &Poll<T>) {
        let counts = &self.counts;
        match polled {
            Poll::Pending => {
                let now = counts.now_ms();
                if counts.waits_since.compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                    counts.waited.fetch_add(1, Ordering::Relaxed);
                }
            }
            Poll::Ready(_) => counts.waits_since.store(0, Ordering::Relaxed),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Traced<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, bytes);
        self.note(&polled);
        match &polled {
            Poll::Ready(Ok(n)) => {
                self.counts.written.fetch_add(*n as u64, Ordering::Relaxed);
            }
            Poll::Ready(Err(e)) => self.counts.ended(|| format!("a write failed: {e}")),
            Poll::Pending => {}
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let polled = Pin::new(&mut self.inner).poll_flush(cx);
        self.note(&polled);
        polled
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn the_bytes_each_way_and_a_write_that_waits_are_counted() {
        let (near, mut far) = tokio::io::duplex(8);
        let counts = Counts::new();
        let mut traced = Traced::new(near, counts.clone());
        traced.write_all(b"12345678").await.unwrap();
        // The pipe is full: the next write waits, and the line says so.
        let mut waiting = Box::pin(traced.write_all(b"9"));
        assert!(tokio::time::timeout(Duration::from_millis(20), waiting.as_mut()).await.is_err());
        assert!(counts.waiting().is_some_and(|wait| wait >= Duration::from_millis(10)), "{counts:?}");
        assert!(counts.line().contains("a write waits for"), "{}", counts.line());
        let mut got = [0u8; 8];
        far.read_exact(&mut got).await.unwrap();
        waiting.await.unwrap();
        far.write_all(b"abc").await.unwrap();
        let mut back = [0u8; 3];
        traced.read_exact(&mut back).await.unwrap();
        assert_eq!(counts.waiting(), None);
        let line = counts.line();
        assert!(line.starts_with("3 bytes in, 9 out over "), "{line}");
        assert!(line.contains("(1 writes waited)") && !line.contains("waits for"), "{line}");
        assert_eq!(counts.end(), None);
        drop(far);
        assert_eq!(traced.read(&mut back).await.unwrap(), 0);
        assert_eq!(counts.end().as_deref(), Some("the visitor's end of input came"));
    }
}
