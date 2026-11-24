//! The far end's half of local echo (T-160): with `env predict@podssh v1`
//! on a channel with a pty, serve counts the client's bytes that reached the
//! pty's master, and tells the client, as extended data of podssh's own code
//! (`crate::predict::report`), the count that is `ECHO_WAIT` old, and the
//! pty's ECHO and ICANON flags.
//!
//! A report goes out of the task that copies the pty's output, after each
//! write of output and when a count falls due, so it always follows the
//! output that was read before it: the client judges its guesses against a
//! screen that holds their echo. A shared or a kept shell sends none; its
//! client's guesses then never show.

use std::collections::VecDeque;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use russh::server::Msg;
use russh::ChannelWriteHalf;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::predict::report::{encode, Flags, Report, ECHO_WAIT, EXT};

/// The writes not yet reported, kept at most: past them the oldest goes,
/// and a later write's count covers it.
const KEPT: usize = 1024;

#[derive(Debug, Default)]
struct State {
    offset: u64,
    writes: VecDeque<(u64, Instant)>,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    /// Wakes the task of the output at a write: a key that makes no output
    /// (a line with no echo) must still get its report.
    wake: Notify,
}

/// The count of the client's bytes written to the pty, shared by the
/// writer of the input and the task of the output.
#[derive(Debug, Clone, Default)]
pub(super) struct Applied(Arc<Shared>);

impl Applied {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn wrote(&self, n: usize, now: Instant) {
        let mut state = self.state();
        state.offset += n as u64;
        let end = state.offset;
        if state.writes.len() == KEPT {
            state.writes.pop_front();
        }
        state.writes.push_back((end, now));
        drop(state);
        // A permit is kept where no task waits, so no write is missed.
        self.0.wake.notify_one();
    }

    /// Until the oldest write not reported falls due, waiting for a write
    /// where none waits.
    async fn fall_due(&self) {
        loop {
            match self.due() {
                Some(at) => return tokio::time::sleep_until(at).await,
                None => self.0.wake.notified().await,
            }
        }
    }

    /// The count of the writes that are [`ECHO_WAIT`] old at `now`, if any
    /// is new; they are reported once.
    fn ripe(&self, now: Instant) -> Option<u64> {
        let mut state = self.state();
        let mut ripe = None;
        while let Some(&(end, at)) = state.writes.front() {
            if at + ECHO_WAIT > now {
                break;
            }
            ripe = Some(end);
            state.writes.pop_front();
        }
        ripe
    }

    /// When the oldest write not reported falls due.
    fn due(&self) -> Option<Instant> {
        self.state().writes.front().map(|&(_, at)| at + ECHO_WAIT)
    }
}

/// A writer of the client's bytes to the pty, each byte counted once the
/// pty took it.
pub(super) struct Applying<W> {
    inner: W,
    applied: Applied,
}

impl<W: AsyncWrite + Unpin> AsyncWrite for Applying<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let polled = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &polled {
            self.applied.wrote(*n, Instant::now());
        }
        polled
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The reports of one channel.
pub(super) struct Reporter {
    applied: Applied,
    out: Pin<Box<dyn AsyncWrite + Send>>,
    master: Arc<AsyncFd<OwnedFd>>,
    told: Option<Report>,
}

impl Reporter {
    /// The reports of the channel of `write`, for the pty of `master`.
    pub(super) fn new(write: &ChannelWriteHalf<Msg>, master: Arc<AsyncFd<OwnedFd>>) -> Reporter {
        let out = Box::pin(write.make_writer_ext(Some(EXT)));
        Reporter { applied: Applied::default(), out, master, told: None }
    }

    /// The writer of the client's bytes to the pty through `inner`.
    pub(super) fn applying<W>(&self, inner: W) -> Applying<W> {
        Applying { inner, applied: self.applied.clone() }
    }

    /// Ends when the next report falls due: a write's count is
    /// [`ECHO_WAIT`] old. It owns what it reads, so the pump can wait on it
    /// beside its read of the output.
    pub(super) fn falls_due(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let applied = self.applied.clone();
        async move { applied.fall_due().await }
    }

    /// After output went out, or when a report falls due: a report where
    /// the count or the pty's flags changed. `Err`: the channel is gone.
    pub(super) async fn tell(&mut self) -> io::Result<()> {
        let offset = self.applied.ripe(Instant::now()).or(self.told.map(|t| t.offset)).unwrap_or(0);
        // Flags that cannot be read are a line with no echo: nothing shows.
        let flags = flags_of(self.master.get_ref().as_raw_fd()).unwrap_or(Flags { echo: false, canonical: true });
        let report = Report { offset, flags };
        if self.told == Some(report) {
            return Ok(());
        }
        self.out.write_all(&encode(report)).await?;
        self.told = Some(report);
        Ok(())
    }
}

/// The ECHO and ICANON flags of the pty of `fd`: a master reads its
/// slave's modes, as mosh-server reads them.
fn flags_of(fd: RawFd) -> io::Result<Flags> {
    // SAFETY: an all-zero termios is valid, and tcgetattr writes into it,
    // on a descriptor that the caller holds open.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Flags { echo: t.c_lflag & libc::ECHO != 0, canonical: t.c_lflag & libc::ICANON != 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A count is reported once it is ECHO_WAIT old, and once only; the
    /// next write's time is the next report's.
    #[test]
    fn a_count_ripens_after_the_echo_wait_and_is_reported_once() {
        let applied = Applied::default();
        let start = Instant::now();
        applied.wrote(3, start);
        applied.wrote(2, start + Duration::from_millis(30));
        assert_eq!(applied.due(), Some(start + ECHO_WAIT));
        assert_eq!(applied.ripe(start + ECHO_WAIT - Duration::from_millis(1)), None);
        assert_eq!(applied.ripe(start + ECHO_WAIT), Some(3));
        assert_eq!(applied.ripe(start + ECHO_WAIT), None, "once");
        assert_eq!(applied.due(), Some(start + Duration::from_millis(30) + ECHO_WAIT));
        assert_eq!(applied.ripe(start + Duration::from_secs(1)), Some(5));
        assert_eq!(applied.due(), None);
    }

    /// A write while the task waits with nothing due wakes it, and it
    /// ends once that write's count is ECHO_WAIT old; with no write it
    /// never ends.
    #[tokio::test(start_paused = true)]
    async fn a_write_while_nothing_is_due_wakes_the_wait() {
        let applied = Applied::default();
        let waiting = applied.clone();
        let wait = tokio::spawn(async move { waiting.fall_due().await });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!wait.is_finished(), "nothing written, nothing due");
        let start = Instant::now();
        applied.wrote(1, start);
        wait.await.unwrap();
        assert!(Instant::now() >= start + ECHO_WAIT, "after the echo wait");
        assert_eq!(applied.ripe(Instant::now()), Some(1));
    }
}
