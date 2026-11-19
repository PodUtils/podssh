//! SSH's end of the iroh road's pipe, watched (T-780): a write of the
//! channel that waits for SSH to read is said once it held 20 s, with the
//! bytes that went to SSH so far. pod-session's line of a stall names the
//! application above the layer (the end-to-end channel) as the one that took
//! no byte; this line tells whether the channel waits for SSH, or holds for a
//! cause of its own.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// How long a write may wait before it is said.
pub(crate) const HOLD: Duration = Duration::from_secs(20);

/// What the watch has seen: since when a write waits, and the bytes written.
#[derive(Default)]
pub(crate) struct Seen {
    waiting: Mutex<Option<Instant>>,
    written: AtomicU64,
}

impl Seen {
    /// The line of a write that waited `HOLD` at `now`, once for each wait.
    pub(crate) fn line(&self, now: Instant, said: &mut Option<Instant>) -> Option<String> {
        let since = (*self.waiting.lock().unwrap_or_else(|e| e.into_inner()))?;
        if now.duration_since(since) < HOLD || *said == Some(since) {
            return None;
        }
        *said = Some(since);
        Some(format!(
            "SSH read nothing for {} s while the channel waits to give it bytes; {} bytes went to SSH so far",
            now.duration_since(since).as_secs(),
            self.written.load(Ordering::Relaxed)
        ))
    }
}

/// `inner` with its writes watched in `seen`.
pub(crate) struct Held<S> {
    inner: S,
    seen: Arc<Seen>,
}

impl<S> Held<S> {
    pub(crate) fn new(inner: S, seen: Arc<Seen>) -> Held<S> {
        Held { inner, seen }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Held<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Held<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.inner).poll_write(cx, data);
        let mut waiting = this.seen.waiting.lock().unwrap_or_else(|e| e.into_inner());
        match &polled {
            Poll::Pending => {
                waiting.get_or_insert_with(Instant::now);
            }
            Poll::Ready(done) => {
                *waiting = None;
                if let Ok(n) = done {
                    this.seen.written.fetch_add(*n as u64, Ordering::Relaxed);
                }
            }
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Say each wait of `seen` that holds [`HOLD`], while `seen` has a holder
/// beside this task.
pub(crate) async fn watch(seen: Arc<Seen>, say: impl Fn(String)) {
    let mut said = None;
    while Arc::strong_count(&seen) > 1 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Some(line) = seen.line(Instant::now(), &mut said) {
            say(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A write into a full pipe that nobody reads is said once after 20 s,
    /// with the bytes written before it; a read that frees it ends the wait.
    #[tokio::test(start_paused = true)]
    async fn a_write_that_waits_for_ssh_is_said_once() {
        let (ours, mut theirs) = tokio::io::duplex(8);
        let seen = Arc::new(Seen::default());
        let mut held = Held::new(ours, seen.clone());
        held.write_all(b"12345678").await.unwrap();
        let blocked = tokio::spawn(async move { held.write_all(b"more").await.map(|()| held) });
        tokio::task::yield_now().await;
        let mut said = None;
        assert_eq!(seen.line(Instant::now(), &mut said), None, "not before 20 s");
        tokio::time::advance(HOLD).await;
        let line = seen.line(Instant::now(), &mut said).expect("said after 20 s");
        assert!(line.contains("SSH read nothing for 20 s") && line.contains("8 bytes went to SSH"), "{line}");
        assert_eq!(seen.line(Instant::now(), &mut said), None, "once for each wait");
        let mut buf = [0u8; 8];
        tokio::io::AsyncReadExt::read_exact(&mut theirs, &mut buf).await.unwrap();
        blocked.await.unwrap().unwrap();
        assert!(seen.waiting.lock().unwrap().is_none(), "the read ended the wait");
    }
}
