//! The bytes of a kept shell (T-159), apart from `kept.rs` so that each file
//! stays short: a channel's input to the pty while its generation has the
//! shell, the shell's output to the channel that has it and into the ring,
//! and local echo's reports to that channel (T-160, T-896).
//!
//! A kept shell outlives its channels, so its reports cannot belong to the
//! pump, as a channel's own pty's do (`server/predict.rs`): each channel
//! that asked has its own reporter and its own count, from 0, of its bytes
//! that reached the pty, and the pump tells the reporter of the channel that
//! has the shell now. A channel that joins gets its reports from its attach
//! on; one that did not ask gets none, and its guesses never show.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::{watch, Notify};

use super::{Attached, Held, Shell, PASTE};

/// A channel's reports: serve's reporter on a Unix host; none elsewhere,
/// where serve runs no program.
#[cfg(unix)]
pub(in crate::server) type Told = super::super::predict::Reporter;
#[cfg(not(unix))]
pub(in crate::server) type Told = std::convert::Infallible;

/// What a channel's input counts each write to the pty with.
pub(in crate::server) type Count = Box<dyn Fn(usize) + Send + Sync>;

/// Local echo's part of a kept shell: the pty whose flags a report reads,
/// set by the shell's start, and a wake of the pump at each attach, whose
/// channel may have a reporter that the pump does not wait on yet.
#[derive(Default)]
pub(super) struct Tells {
    #[cfg(unix)]
    master: std::sync::OnceLock<Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>>,
    pub(super) attached: Notify,
}

impl Attached {
    /// The channel with its reports, where it asked for them.
    pub(in crate::server) fn with_reports(mut self, told: Option<Told>) -> Attached {
        self.told = told;
        self
    }
}

/// The reporter of the channel of `write`, and the count of its input,
/// where the channel `asked` (`env predict@podssh v1`) and the shell's pty
/// is known. A channel with frames (T-303) has its reports go in the queue
/// of the frames of `framed`, each after the frame of the output before it.
#[cfg(unix)]
pub(in crate::server) fn reports_for(
    shell: &Shell,
    asked: bool,
    write: &russh::ChannelWriteHalf<russh::server::Msg>,
    framed: Option<&Arc<super::super::frames::Shared>>,
) -> (Option<Told>, Option<Count>) {
    let Some(master) = shell.tells.master.get().filter(|_| asked) else { return (None, None) };
    let told = match framed {
        Some(frames) => Told::to(Box::pin(frames.reports()), master.clone()),
        None => Told::new(write, master.clone()),
    };
    let applied = told.applied();
    let count: Count = Box::new(move |n| applied.wrote(n, tokio::time::Instant::now()));
    (Some(told), Some(count))
}

/// Serve runs no program on Windows: no reports.
#[cfg(not(unix))]
pub(in crate::server) fn reports_for(
    _shell: &Shell,
    _asked: bool,
    _write: &russh::ChannelWriteHalf<russh::server::Msg>,
    _framed: Option<&Arc<super::super::frames::Shared>>,
) -> (Option<Told>, Option<Count>) {
    (None, None)
}

#[cfg(unix)]
impl Shell {
    /// The pty of the shell, whose flags each report reads.
    pub(in crate::server) fn reports_from(&self, master: Arc<tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>>) {
        let _ = self.tells.master.set(master);
    }

    /// A report to the channel that has the shell, where it asked for them.
    /// The reporter is taken out for its write, so that no lock is held
    /// across it, and put back only if that channel still has the shell; a
    /// channel that is gone ends its reports, not the output.
    pub(in crate::server) async fn tell(&self) {
        let taken = {
            let mut state = self.state();
            let generation = state.generation;
            state.attached.as_mut().and_then(|a| a.told.take()).map(|told| (told, generation))
        };
        let Some((mut told, generation)) = taken else { return };
        if told.tell().await.is_err() {
            return;
        }
        let mut state = self.state();
        if state.generation == generation
            && let Some(attached) = state.attached.as_mut()
            && attached.told.is_none()
        {
            attached.told = Some(told);
        }
    }
}

/// Until the next report of the channel that has `shell` falls due; with
/// no such channel, until an attach brings one.
#[cfg(unix)]
pub(in crate::server) async fn falls_due(shell: Arc<Shell>) {
    loop {
        // Made before the look, so that an attach between them wakes it.
        let attached = shell.tells.attached.notified();
        let applied = shell.state().attached.as_ref().and_then(|a| a.told.as_ref()).map(Told::applied);
        match applied {
            Some(applied) => {
                tokio::select! {
                    () = applied.fall_due() => return,
                    () = attached => {}
                }
            }
            None => attached.await,
        }
    }
}

/// Copy a channel's input to the pty while its generation is the shell's;
/// then the dropped pipe tells the channel's feeder, which drops the rest.
/// Each write that the pty took is counted for local echo, where asked.
pub(super) async fn feed(shell: Arc<Shell>, generation: u64, mut from: DuplexStream, count: Option<Count>) {
    let mut buf = vec![0u8; PASTE];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if !shell.current(generation) {
            return;
        }
        let mut input = shell.input.lock().await;
        if input.write_all(&buf[..n]).await.is_err() {
            return;
        }
        if let Some(count) = count.as_ref() {
            count(n);
        }
    }
}

/// When the channel of `held` closes, the shell lets it go.
pub(in crate::server) fn watch_close(held: &Held, mut closed: watch::Receiver<bool>) {
    let (shell, generation) = (held.shell.clone(), held.generation);
    tokio::spawn(async move {
        // The guard of `wait_for` is dropped in its statement: the task stays Send.
        let _ = closed.wait_for(|closed| *closed).await;
        shell.left(generation);
    });
}

/// The shell's output: to the attached channel, into the ring, and into
/// the model of the screen where the shell has one (T-303). It never
/// fails, so the pump reads the pty to its end with no client too. A
/// channel with frames takes its bytes at once and goes on: its frames go
/// by their own task, so its link never holds the shell back.
pub(in crate::server) struct Out(pub(in crate::server) Arc<Shell>);

impl AsyncWrite for Out {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let (n, frames) = {
            let mut guard = self.0.state();
            let state = &mut *guard;
            let mut taken = buf.len();
            if let Some(attached) = state.attached.as_mut() {
                match attached.out.as_mut().poll_write(cx, buf) {
                    Poll::Ready(Ok(n)) if n > 0 => taken = n,
                    // The client's window holds the shell back, as without T-159.
                    Poll::Pending => {
                        state.waker = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    // The channel is gone: its close follows, and the ring
                    // keeps the output until then.
                    _ => state.attached = None,
                }
            }
            state.ring.push(&buf[..taken], Instant::now());
            (taken, state.frames.clone())
        };
        // The model is fed out of the shell's lock, which a window change
        // takes on the SSH session's task; only this pump feeds it.
        if let Some(frames) = frames {
            frames.fed(&buf[..n]);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// The channel's end is the program's status, sent at its end.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
