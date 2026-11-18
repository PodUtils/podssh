//! A writer each of whose writes is done only once it is flushed: tokio's
//! stdout hands each write to a thread of its own, and a write still there
//! when the command ends its runtime in the background is lost. The tail of
//! a session's bytes went so on Windows (`podssh operator`, the gate at
//! `6c5a680`: 65518 of 65536 bytes, exit 0).

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::AsyncWrite;

/// `inner`, each write of which returns once it is flushed.
pub struct Flushing<W> {
    inner: W,
    /// A write that went, whose flush has not ended yet.
    written: Option<usize>,
}

impl<W> Flushing<W> {
    pub fn new(inner: W) -> Self {
        Flushing { inner, written: None }
    }
}

/// stdout, each write of which is out of the process when it returns.
pub fn stdout() -> Flushing<tokio::io::Stdout> {
    Flushing::new(tokio::io::stdout())
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Flushing<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.written.is_none() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
            this.written = Some(n);
        }
        let flushed = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        let n = this.written.take().unwrap_or(0);
        flushed.map(|()| n).into()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// A writer whose bytes count as out only once flushed, and whose flush
    /// waits once, as tokio's stdout does.
    #[derive(Default)]
    struct Slow {
        buffered: Vec<u8>,
        out: Arc<Mutex<Vec<u8>>>,
        waited: bool,
    }

    impl AsyncWrite for Slow {
        fn poll_write(mut self: Pin<&mut Self>, _: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.buffered.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if !std::mem::replace(&mut self.waited, true) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            self.waited = false;
            let bytes = std::mem::take(&mut self.buffered);
            self.out.lock().unwrap().extend(bytes);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.poll_flush(cx)
        }
    }

    /// Each write is out when it returns, once each, though its flush
    /// waited; the last one too, with no flush of the caller's.
    #[tokio::test]
    async fn each_write_is_out_when_it_returns() {
        use tokio::io::AsyncWriteExt;
        let out = Arc::new(Mutex::new(Vec::new()));
        let mut w = Flushing::new(Slow { out: out.clone(), ..Slow::default() });
        for part in [&b"first "[..], b"second ", b"last"] {
            w.write_all(part).await.unwrap();
        }
        assert_eq!(out.lock().unwrap().as_slice(), b"first second last");
    }
}
