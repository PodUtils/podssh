//! The far end's half of the frames (T-303): with `env frames@podssh v2`
//! (or `v1`, an older client's) on a channel with a pty, serve keeps a
//! model of the pty's screen (`crate::frames::screen`), and sends the client
//! the difference of screens as frames (`crate::frames::wire`), in extended
//! data of podssh's own code, in place of each byte of the pty. Frames of
//! version 2 also carry the lines that left the top of the screen since
//! their base (`crate::frames::scroll`).
//!
//! The task that copies the pty's output writes it into [`Sink`], which
//! feeds the model and never waits: the pty is read at its own pace
//! whatever the link carries, so a flood fills no queue. A second task
//! ([`Shared::run`]) sends the frames, writes the model's answers to the
//! pty, and at the end of the output sends the whole screen once more,
//! before the program's status. The handler gives the client's
//! acknowledgements and each new size of the window.
//!
//! Under a flood the pump holds the model nearly all the time, and a lock
//! of the standard library is not fair: a task that waits for it can wait
//! for seconds. So nothing waits for it but the pump. The handler runs on
//! the SSH session's task, which also takes the client's Ctrl-C to the
//! pty: it puts what the client said beside the model ([`Told`]). The pump
//! applies it, and makes the frame that is due, at each write; the task
//! that sends only tries the model's lock, and while the pump has it,
//! looks again a moment later.
//!
//! The model costs a grid for each state kept: the screen now, the base,
//! and at most `HELD` frames that wait, some 60 KiB each at 80 by 24, and
//! the text of one screen of lines that left its top, for a channel that
//! asked, and for no other.

#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::frames::screen::Model;
use crate::frames::sender::{Sender, COLLECT};
use crate::frames::wire::{encode, Ack, Head, Version};
use crate::terminal::Size;

/// How long an answer to a program's question may wait on a pty whose
/// program reads nothing; past it the answer is dropped, not the frames.
const ANSWER_WAIT: Duration = Duration::from_millis(200);
/// While the pump holds the model, how soon the task that sends tries it
/// again: the pump makes the frames that fall due meanwhile itself.
const BUSY: Duration = COLLECT;
/// The most acknowledgements kept for the model; the newest count, so the
/// oldest go past it.
const TOLD_MOST: usize = 8;

struct Inner {
    model: Model,
    sender: Sender,
    /// The pty's output ended: the last frame goes.
    ended: bool,
}

/// What the client said, apart from the model, so that saying it never
/// waits for the pump: each acknowledgement with when it came, and the
/// newest size of the window.
#[derive(Default)]
struct Told {
    acks: VecDeque<(Ack, Instant)>,
    size: Option<Size>,
}

/// The frames of one channel: its model and its sender, shared by the
/// pty's pump, the task that sends, and the handler.
pub(super) struct Shared {
    inner: Mutex<Inner>,
    told: Mutex<Told>,
    /// The frames made and not written yet, in the order of their numbers.
    made: Mutex<VecDeque<Vec<u8>>>,
    /// A frame was made, output came, an acknowledgement came, the size
    /// changed, or the output ended: the task that sends looks again.
    wake: Notify,
    /// The version that the client asked for.
    version: Version,
}

fn cells(n: u32) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX).max(1)
}

fn unpoisoned<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|p| p.into_inner())
}

impl Shared {
    /// For a pty of `size`, whose screen is empty, in frames of `version`.
    pub(super) fn new(size: Size, version: Version) -> Arc<Shared> {
        let model = Model::new(cells(size.rows), cells(size.cols), true);
        // Version 1 carries no line: its model counts none, so a flood that
        // only scrolls makes no frame, as before the lines.
        let model = if version == Version::Two { model } else { model.without_lines() };
        let inner = Inner { model, sender: Sender::default(), ended: false };
        let (told, made) = (Mutex::new(Told::default()), Mutex::new(VecDeque::new()));
        Arc::new(Shared { inner: Mutex::new(inner), told, made, wake: Notify::new(), version })
    }

    /// The bytes of a frame of `head` and `body`, with the lines after the
    /// sender's base where the version carries them.
    fn encoded(&self, inner: &Inner, head: Head, body: &[u8]) -> Vec<u8> {
        let lines = match self.version {
            Version::One => Vec::new(),
            Version::Two => inner.model.lines_after(inner.sender.since()),
        };
        encode(self.version, head, &lines, body)
    }

    /// The model, for the pump and the end alone: each other one tries it.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        unpoisoned(&self.inner)
    }

    /// The model where no one holds it; `None` while the pump feeds it.
    fn try_lock(&self) -> Option<MutexGuard<'_, Inner>> {
        match self.inner.try_lock() {
            Ok(inner) => Some(inner),
            Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(TryLockError::WouldBlock) => None,
        }
    }

    /// The pty has a new size (`window-change`): the model too, before the
    /// next output, and the next frame is the whole screen in that size.
    pub(super) fn resize(&self, size: Size) {
        unpoisoned(&self.told).size = Some(size);
        self.wake.notify_one();
    }

    /// The client's acknowledgement (`env frames-ack@podssh`), timed now.
    pub(super) fn acked(&self, ack: Ack) {
        let mut told = unpoisoned(&self.told);
        if told.acks.len() >= TOLD_MOST {
            told.acks.pop_front();
        }
        told.acks.push_back((ack, Instant::now()));
        drop(told);
        self.wake.notify_one();
    }

    /// What the client said, into the model and the sender; under the
    /// model's lock.
    fn heard(&self, inner: &mut Inner, now: Instant) {
        let told = std::mem::take(&mut *unpoisoned(&self.told));
        if let Some(size) = told.size {
            inner.model.resize(cells(size.rows), cells(size.cols));
            inner.sender.changed(now);
        }
        for (ack, at) in told.acks {
            inner.sender.acked(ack, at);
        }
    }

    /// The frame that is due at `now`, made and queued for the task that
    /// sends; under the model's lock. Whether one was made. The last frame
    /// is the task's own.
    fn make(&self, inner: &mut Inner, now: Instant) -> bool {
        if inner.ended || inner.sender.due().is_none_or(|at| at > now) {
            return false;
        }
        let bell = inner.model.bell();
        let Some((head, body)) = inner.sender.frame(&inner.model.state(), bell, now) else { return false };
        inner.model.clear_bell();
        let bytes = self.encoded(inner, head, &body);
        unpoisoned(&self.made).push_back(bytes);
        true
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
            let now = Instant::now();
            // Never a wait for the model: while the pump has it, it makes
            // the frames itself, and this task looks again a moment later.
            let looked = self.try_lock().map(|mut guard| {
                let inner = &mut *guard;
                self.heard(inner, now);
                self.make(inner, now);
                (inner.ended, inner.sender.due(), inner.model.take_answers())
            });
            let made = std::mem::take(&mut *unpoisoned(&self.made));
            for bytes in made {
                if out.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            let (ended, due) = match looked {
                Some((ended, due, answer)) => {
                    if !answer.is_empty() {
                        // One write: an answer is never cut by the client's keys.
                        let _ = tokio::time::timeout(ANSWER_WAIT, answers.write_all(&answer)).await;
                    }
                    (ended, due)
                }
                None => (false, Some(now + BUSY)),
            };
            if ended {
                break;
            }
            match due {
                Some(at) => {
                    tokio::select! {
                        () = self.wake.notified() => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                None => self.wake.notified().await,
            }
        }
        // The pump is gone: the model is this task's alone.
        let last = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            let bell = inner.model.bell();
            let (head, body) = inner.sender.last(&inner.model.state(), bell, Instant::now());
            self.encoded(inner, head, &body)
        };
        let mut made = std::mem::take(&mut *unpoisoned(&self.made));
        made.push_back(last);
        for bytes in made {
            if out.write_all(&bytes).await.is_err() {
                return;
            }
        }
        let _ = out.flush().await;
    }
}

/// The pty's output, into the model. It never waits and never fails, so
/// the pump reads the pty to its end whatever the client takes.
pub(super) struct Sink(Arc<Shared>);

impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let now = Instant::now();
        let mut guard = self.0.lock();
        let inner = &mut *guard;
        // A new size goes before the output that follows it.
        self.0.heard(inner, now);
        inner.model.feed(buf);
        let first = inner.sender.changed(now);
        let made = self.0.make(inner, now);
        let asked = inner.model.answers_wait();
        drop(guard);
        // The task that sends looks again at the first change since its
        // last frame, at a frame made here, and when an answer waits; the
        // rest of a flood wakes nothing.
        if first || made || asked {
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
