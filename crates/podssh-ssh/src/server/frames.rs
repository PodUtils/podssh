//! The far end's half of the frames (T-303): with `env frames@podssh v1`
//! on a channel with a pty, serve keeps a model of the pty's screen
//! (`crate::frames::screen`), and sends the client the difference of
//! screens as frames (`crate::frames::wire`), in extended data of podssh's
//! own code, in place of each byte of the pty.
//!
//! The task that copies the pty's output writes it into [`Sink`], which
//! feeds the model and never waits: the pty is read at its own pace
//! whatever the link carries, so a flood fills no queue. A second task
//! ([`Shared::run`]) sends a frame when the sender's pace lets one go
//! (`crate::frames::sender`), writes the model's answers to the pty, and at
//! the end of the output sends the whole screen once more, before the
//! program's status. The handler gives it the client's acknowledgements
//! and each new size of the window.
//!
//! The model costs a grid for each state kept: the screen now, the base,
//! and at most `HELD` frames that wait, some 60 KiB each at 80 by 24, for
//! a channel that asked, and for no other.

#![cfg_attr(not(unix), allow(dead_code))]

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::frames::screen::Model;
use crate::frames::sender::Sender;
use crate::frames::wire::{encode, Ack};
use crate::terminal::Size;

/// How long an answer to a program's question may wait on a pty whose
/// program reads nothing; past it the answer is dropped, not the frames.
const ANSWER_WAIT: Duration = Duration::from_millis(200);

struct Inner {
    model: Model,
    sender: Sender,
    /// The pty's output ended: the last frame goes.
    ended: bool,
}

/// The frames of one channel: its model and its sender, shared by the
/// pty's pump, the task that sends, and the handler.
pub(super) struct Shared {
    inner: Mutex<Inner>,
    /// Output came, an acknowledgement came, the size changed, or the
    /// output ended: the task that sends looks again.
    wake: Notify,
}

fn cells(n: u32) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX).max(1)
}

impl Shared {
    /// For a pty of `size`, whose screen is empty.
    pub(super) fn new(size: Size) -> Arc<Shared> {
        let model = Model::new(cells(size.rows), cells(size.cols), true);
        let inner = Inner { model, sender: Sender::default(), ended: false };
        Arc::new(Shared { inner: Mutex::new(inner), wake: Notify::new() })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The pty has a new size (`window-change`): the model too, and the
    /// next frame is the whole screen in that size.
    pub(super) fn resize(&self, size: Size) {
        let mut inner = self.lock();
        inner.model.resize(cells(size.rows), cells(size.cols));
        inner.sender.changed(Instant::now());
        drop(inner);
        self.wake.notify_one();
    }

    /// The client's acknowledgement (`env frames-ack@podssh`).
    pub(super) fn acked(&self, ack: Ack) {
        self.lock().sender.acked(ack, Instant::now());
        self.wake.notify_one();
    }

    /// Where the pty's pump writes the pty's output.
    pub(super) fn sink(self: &Arc<Self>) -> Sink {
        Sink(self.clone())
    }

    /// Send the frames on `out` (the channel's extended data of
    /// `crate::frames::EXT`) until the pty's output ends, then the last
    /// one; `answers` is the pty's master, for the model's answers. A
    /// channel that is gone ends it.
    pub(super) async fn run(
        self: Arc<Self>,
        mut out: impl AsyncWrite + Unpin + Send,
        mut answers: impl AsyncWrite + Unpin + Send,
    ) {
        loop {
            let (ended, due, answer) = {
                let mut inner = self.lock();
                (inner.ended, inner.sender.due(), inner.model.take_answers())
            };
            if !answer.is_empty() {
                // One write: an answer is never cut by the client's keys.
                let _ = tokio::time::timeout(ANSWER_WAIT, answers.write_all(&answer)).await;
            }
            if ended {
                break;
            }
            let now = Instant::now();
            match due {
                Some(at) if at <= now => {
                    let frame = {
                        let mut guard = self.lock();
                        let inner = &mut *guard;
                        let bell = inner.model.bell();
                        let frame = inner.sender.frame(&inner.model.state(), bell, now);
                        if frame.is_some() {
                            inner.model.clear_bell();
                        }
                        frame
                    };
                    if let Some((head, body)) = frame
                        && out.write_all(&encode(head, &body)).await.is_err()
                    {
                        return;
                    }
                }
                Some(at) => {
                    tokio::select! {
                        () = self.wake.notified() => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                None => self.wake.notified().await,
            }
        }
        let (head, body) = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            let bell = inner.model.bell();
            inner.sender.last(&inner.model.state(), bell, Instant::now())
        };
        let _ = out.write_all(&encode(head, &body)).await;
        let _ = out.flush().await;
    }
}

/// The pty's output, into the model. It never waits and never fails, so
/// the pump reads the pty to its end whatever the client takes.
pub(super) struct Sink(Arc<Shared>);

impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut inner = self.0.lock();
        inner.model.feed(buf);
        let first = inner.sender.changed(Instant::now());
        let asked = inner.model.answers_wait();
        drop(inner);
        // The task that sends looks again at the first change since its
        // last frame, and when an answer waits; the rest of a flood wakes
        // nothing.
        if first || asked {
            self.0.wake.notify_one();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for Sink {
    /// The pump ended: the pty's output did, or the channel closed.
    fn drop(&mut self) {
        self.0.lock().ended = true;
        self.0.wake.notify_one();
    }
}

#[cfg(test)]
#[path = "frames_tests.rs"]
mod tests;
