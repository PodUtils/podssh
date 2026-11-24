//! The client's end under `podssh serve --stdio` (T-869). OpenSSH closes its
//! ProxyCommand's pipes as it exits, then sends it SIGHUP: that signal is
//! the client's end, not an operator's reload, and a reload then said a line
//! at each logout. A SIGHUP that comes with the end of the input, or within
//! [`GRACE`] before it, reads no keys and says nothing; an operator's SIGHUP
//! on a live connection still reloads, [`GRACE`] later.
//!
//! The end is seen where russh reads the input ([`Watched`]), and, on Unix,
//! asked of descriptor 0 besides, as a read can wait behind the output.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::watch;

/// How long a SIGHUP waits for the end of the input before it is taken as a
/// reload: OpenSSH's signal follows the close of its pipes at once.
pub const GRACE: Duration = Duration::from_millis(250);

/// A reader that tells when its input ended: the end of the file, or a read
/// that failed.
pub struct Watched<R> {
    inner: R,
    ended: watch::Sender<bool>,
}

/// The end of a [`Watched`] reader, as the loop of signals sees it.
pub struct Input {
    ended: watch::Receiver<bool>,
    /// Whether the reader is descriptor 0, which can be asked as well.
    stdin: bool,
}

/// `inner`, watched; `stdin` when it reads descriptor 0.
pub fn watch<R>(inner: R, stdin: bool) -> (Watched<R>, Input) {
    let (ended, seen) = watch::channel(false);
    (Watched { inner, ended }, Input { ended: seen, stdin })
}

impl<R: AsyncRead + Unpin> AsyncRead for Watched<R> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let (room, before) = (buf.remaining() > 0, buf.filled().len());
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        let ended = match &polled {
            // No byte into a buffer with room: the end of the file.
            Poll::Ready(Ok(())) => room && buf.filled().len() == before,
            Poll::Ready(Err(_)) => true,
            Poll::Pending => false,
        };
        if ended {
            self.ended.send_replace(true);
        }
        polled
    }
}

impl Input {
    /// Whether the input has ended now.
    pub fn has_ended(&self) -> bool {
        *self.ended.borrow() || (self.stdin && stdin_hung_up())
    }

    /// Whether the input ends within `grace`: true at once when it has.
    pub async fn ends_within(&self, grace: Duration) -> bool {
        if self.has_ended() {
            return true;
        }
        let mut seen = self.ended.clone();
        // The guard of `wait_for` goes before any other await.
        let came = tokio::time::timeout(grace, async { seen.wait_for(|ended| *ended).await.is_ok() }).await;
        matches!(came, Ok(true)) || self.has_ended()
    }
}

/// Whether descriptor 0 is a pipe or a socket whose other end closed.
#[cfg(unix)]
fn stdin_hung_up() -> bool {
    let mut fd = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
    // SAFETY: one pollfd that lives through the call; a timeout of 0 never
    // blocks, and poll changes nothing of the descriptor.
    let ready = unsafe { libc::poll(&mut fd, 1, 0) };
    ready == 1 && fd.revents & (libc::POLLHUP | libc::POLLERR) != 0
}

#[cfg(not(unix))]
fn stdin_hung_up() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// A live input does not end within the grace; its end is seen where it
    /// is read, and then at once; a read that fails is an end too.
    #[tokio::test]
    async fn the_end_of_the_input_is_seen_where_it_is_read() {
        let (mut near, far) = tokio::io::duplex(64);
        let (mut read, input) = watch(far, false);
        near.write_all(b"SSH-2.0-x\r\n").await.unwrap();
        let mut buf = [0u8; 64];
        assert!(read.read(&mut buf).await.unwrap() > 0);
        assert!(!input.has_ended() && !input.ends_within(Duration::from_millis(50)).await, "a live input");
        drop(near);
        let reading = tokio::spawn(async move {
            let n = read.read(&mut buf).await;
            (n, read)
        });
        assert!(input.ends_within(Duration::from_secs(5)).await, "the end comes within the grace");
        let (n, _read) = reading.await.unwrap();
        assert_eq!(n.unwrap(), 0);
        assert!(input.has_ended() && input.ends_within(Duration::ZERO).await);

        struct Failing;
        impl AsyncRead for Failing {
            fn poll_read(self: Pin<&mut Self>, _: &mut Context<'_>, _: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
                Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
            }
        }
        let (mut read, input) = watch(Failing, false);
        assert!(read.read(&mut [0u8; 8]).await.is_err());
        assert!(input.has_ended());
    }

    /// A read into a full buffer reads nothing and is no end.
    #[tokio::test]
    async fn a_read_with_no_room_is_no_end() {
        let (_near, far) = tokio::io::duplex(64);
        let (mut read, input) = watch(far, false);
        let mut none = [0u8; 0];
        let _ = tokio::time::timeout(Duration::from_millis(20), read.read(&mut none)).await;
        assert!(!input.has_ended());
    }
}
