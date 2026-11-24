//! The far end's half of local echo (T-160): with `env predict@podssh v1`
//! on a channel with a pty, serve counts the client's bytes that reached the
//! pty's master (`predict_count.rs`), and tells the client, as extended data
//! of podssh's own code (`crate::predict::report`), the count that is
//! `ECHO_WAIT` old, and the pty's ECHO and ICANON flags.
//!
//! A report goes out of the task that copies the pty's output, after each
//! write of output and when a count falls due, so it always follows the
//! output that was read before it: the client judges its guesses against a
//! screen that holds their echo. A kept shell's pump tells the reporter of
//! the channel that has the shell then (`kept_flow.rs`, T-896). A shell
//! shared by name puts each seat's report in its broadcast, after the
//! output read before it (`share_told.rs`, T-896).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use russh::server::Msg;
use russh::ChannelWriteHalf;
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use super::predict_count::Applied;
use crate::predict::report::{encode, Flags, Report, EXT};

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

    /// The count of the client's bytes, for a writer of its own: a kept
    /// shell's input counts each write that the pty took (T-896).
    pub(super) fn applied(&self) -> Applied {
        self.applied.clone()
    }

    /// Ends when the next report falls due: a write's count is
    /// `ECHO_WAIT` old. It owns what it reads, so the pump can wait on it
    /// beside its read of the output.
    pub(super) fn falls_due(&self) -> impl std::future::Future<Output = ()> + Send + 'static {
        let applied = self.applied.clone();
        async move { applied.fall_due().await }
    }

    /// After output went out, or when a report falls due: a report where
    /// the count or the pty's flags changed. `Err`: the channel is gone.
    pub(super) async fn tell(&mut self) -> io::Result<()> {
        let offset = self.applied.ripe(Instant::now()).or(self.told.map(|t| t.offset)).unwrap_or(0);
        let flags = master_flags(&self.master);
        let report = Report { offset, flags };
        if self.told == Some(report) {
            return Ok(());
        }
        self.out.write_all(&encode(report)).await?;
        self.told = Some(report);
        Ok(())
    }
}

/// Who tells a pump's reports: a channel's own pty's reporter, a kept
/// shell, whose reports go to the channel that has it then, or a shell
/// shared by name, whose reports go to each seat that asked (T-896).
pub(super) enum Teller {
    Own(Reporter),
    Kept(Arc<super::kept::Shell>),
    Shared(super::share_told::Ticks),
}

impl Teller {
    /// Ends when the next report falls due; it owns what it reads.
    pub(super) fn falls_due(&self) -> Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>> {
        match self {
            Teller::Own(reporter) => Box::pin(reporter.falls_due()),
            Teller::Kept(shell) => Box::pin(super::kept::falls_due(shell.clone())),
            Teller::Shared(ticks) => ticks.falls_due(),
        }
    }

    /// A report where one is due. `Err`: the channel is gone, and the
    /// pump tells no more; a kept shell's channel that is gone ends its
    /// own reports alone, and so does a shared shell's seat.
    pub(super) async fn tell(&mut self) -> io::Result<()> {
        match self {
            Teller::Own(reporter) => reporter.tell().await,
            Teller::Kept(shell) => {
                shell.tell().await;
                Ok(())
            }
            Teller::Shared(ticks) => {
                ticks.tick();
                Ok(())
            }
        }
    }
}

/// The flags of the pty of `master`, read now. Flags that cannot be read
/// are a line with no echo: nothing shows.
pub(super) fn master_flags(master: &AsyncFd<OwnedFd>) -> Flags {
    flags_of(master.get_ref().as_raw_fd()).unwrap_or(super::share_told::UNREAD)
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
