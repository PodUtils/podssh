//! The far end's half of the frames (T-303): with `env frames@podssh v2`
//! (or `v1`, an older client's) on a channel with a pty, serve keeps a
//! model of the pty's screen (`crate::frames::screen`), and sends the client
//! the difference of screens as frames (`crate::frames::wire`), in extended
//! data of podssh's own code, in place of each byte of the pty. Frames of
//! version 2 also carry the lines that left the top of the screen since
//! their base (`crate::frames::scroll`).
//!
//! The task that copies the pty's output writes it into a `Sink`, which
//! feeds the model and never waits: the pty is read at its own pace
//! whatever the link carries, so a flood fills no queue. A second task
//! ([`Shared::run_told`]) sends the frames, writes the model's answers to the
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
//! Local echo's reports (T-160), where the client asked for them too, go
//! through the same queue as the frames ([`Shared::reported`]): a report that
//! comes while the screen has a change that no frame holds waits for that
//! frame, and goes right after it. The client then judges its guesses on a
//! screen that holds the echo of each key that the report counts, as it
//! does with bytes, where each report follows the output read before it.
//!
//! A kept shell (T-159) holds its model for its whole life, as its ring:
//! each channel that has the shell with frames is an epoch of the model's
//! sender, with a base of its own and a task of its own; a channel with
//! bytes, or none, has the model fed and no frame made (`frames_epoch.rs`).
//!
//! The model costs a grid for each state kept: the screen now, the base,
//! and at most `HELD` frames that wait, some 60 KiB each at 80 by 24, and
//! the text of one screen of lines that left its top, for a channel that
//! asked, and for no other.

#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::frames::screen::Model;
use crate::frames::sender::{Sender, COLLECT};
use crate::frames::wire::{encode, Ack, Head, Version};
use crate::terminal::Size;

// The epochs of a kept shell's model, the writers of the pump and of the
// reports.
#[path = "frames_epoch.rs"]
mod epoch;

/// How long an answer to a program's question may wait on a pty whose
/// program reads nothing; past it the answer is dropped, not the frames.
const ANSWER_WAIT: Duration = Duration::from_millis(200);
/// While the pump holds the model, how soon the task that sends tries it
/// again: the pump makes the frames that fall due meanwhile itself.
const BUSY: Duration = COLLECT;
/// The most acknowledgements kept for the model; the newest count, so the
/// oldest go past it.
const TOLD_MOST: usize = 8;
/// The most reports of local echo that wait for a frame; past it the
/// oldest goes, as a later report's count covers it.
const PARKED_MOST: usize = 64;

struct Inner {
    model: Model,
    sender: Sender,
    /// The pty's output ended: the last frame goes.
    ended: bool,
    /// Reports of local echo made while a change waited for its frame.
    parked: VecDeque<Vec<u8>>,
    /// The version that the channel of this epoch asked for.
    version: Version,
    /// A channel with frames has the screen: frames are made. A kept
    /// shell's model with no such channel is fed alone.
    feeding: bool,
}

/// What the task that sends writes, in this order: a frame, on the frames'
/// code, or a report of local echo, on its own.
enum Out {
    Frame(Vec<u8>),
    Report(Vec<u8>),
}

/// What the client said, apart from the model, so that saying it never
/// waits for the pump: each acknowledgement with when it came, and the
/// newest size of the window.
#[derive(Default)]
struct Told {
    acks: VecDeque<(Ack, Instant)>,
    size: Option<Size>,
}

/// The queue of one epoch: the channel that has the screen now.
struct Made {
    /// 0 for the first channel; each later channel of a kept shell, one
    /// more.
    epoch: u64,
    /// The frames made and not written yet, in the order of their numbers,
    /// each report of local echo after the frame that it waited for.
    queue: VecDeque<Out>,
    /// A frame was made, output came, an acknowledgement came, the size
    /// changed, or the output ended: the epoch's task looks again.
    wake: Arc<Notify>,
    /// The number of this epoch's first frame: an acknowledgement of a
    /// lower one is an older channel's.
    first: u64,
}

impl Made {
    fn new(epoch: u64, first: u64) -> Made {
        Made { epoch, queue: VecDeque::new(), wake: Arc::new(Notify::new()), first }
    }
}

/// The frames of one channel, or of a kept shell's channels in turn: the
/// model and its sender, shared by the pty's pump, the task that sends,
/// and the handler.
pub(super) struct Shared {
    inner: Mutex<Inner>,
    told: Mutex<Told>,
    made: Mutex<Made>,
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
        let (sender, parked) = (Sender::default(), VecDeque::new());
        let inner = Inner { model, sender, ended: false, parked, version, feeding: true };
        let (told, made) = (Mutex::new(Told::default()), Mutex::new(Made::new(0, 1)));
        Arc::new(Shared { inner: Mutex::new(inner), told, made })
    }

    /// The bytes of a frame of `head` and `body`, with the lines after the
    /// sender's base where the version carries them.
    fn encoded(&self, inner: &Inner, head: Head, body: &[u8]) -> Vec<u8> {
        let lines = match inner.version {
            Version::One => Vec::new(),
            Version::Two => inner.model.lines_after(inner.sender.since()),
        };
        encode(inner.version, head, &lines, body)
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

    /// The task of the epoch now looks again.
    fn wake(&self) {
        unpoisoned(&self.made).wake.notify_one();
    }

    /// The pty has a new size (`window-change`): the model too, before the
    /// next output, and the next frame is the whole screen in that size.
    pub(super) fn resize(&self, size: Size) {
        unpoisoned(&self.told).size = Some(size);
        self.wake();
    }

    /// The client's acknowledgement (`env frames-ack@podssh`), timed now.
    /// One of a frame before this epoch is an older channel's, and goes.
    pub(super) fn acked(&self, ack: Ack) {
        let first = unpoisoned(&self.made).first;
        if ack.number != 0 && ack.number < first {
            return;
        }
        let mut told = unpoisoned(&self.told);
        if told.acks.len() >= TOLD_MOST {
            told.acks.pop_front();
        }
        told.acks.push_back((ack, Instant::now()));
        drop(told);
        self.wake();
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
    /// sends, with the reports that waited for it; under the model's lock.
    /// Whether anything was queued. The last frame is the task's own.
    fn make(&self, inner: &mut Inner, now: Instant) -> bool {
        if inner.ended || !inner.feeding || inner.sender.due().is_none_or(|at| at > now) {
            return false;
        }
        let bell = inner.model.bell();
        let framed = inner.sender.frame(&inner.model.state(), bell, now);
        let mut made = unpoisoned(&self.made);
        if let Some((head, body)) = framed.as_ref() {
            inner.model.clear_bell();
            made.queue.push_back(Out::Frame(self.encoded(inner, *head, body)));
        }
        // The change went into a frame, or the client's screen needs none:
        // the reports that waited for it go after it.
        let mut queued = framed.is_some();
        if !inner.sender.pending() && !inner.parked.is_empty() {
            made.queue.extend(inner.parked.drain(..).map(Out::Report));
            queued = true;
        }
        queued
    }

    /// The pty's output, into the model, and the frame that is due; it
    /// never waits but for the model. The pump of a channel's own pty
    /// writes it through a `Sink`; a kept shell's pump, at each write that
    /// its ring takes.
    pub(super) fn fed(&self, buf: &[u8]) {
        let now = Instant::now();
        let mut guard = self.lock();
        let inner = &mut *guard;
        // A new size goes before the output that follows it.
        self.heard(inner, now);
        inner.model.feed(buf);
        let first = inner.sender.changed(now);
        let made = self.make(inner, now);
        let asked = inner.model.answers_wait();
        let feeding = inner.feeding;
        drop(guard);
        // The task that sends looks again at the first change since its
        // last frame, at a frame made here, and when an answer waits; the
        // rest of a flood wakes nothing.
        if feeding && (first || made || asked) {
            self.wake();
        }
    }

    /// A report of local echo of the channel of `epoch`, made by the pump
    /// after the output that it read: it waits for the frame of a change
    /// that no frame holds yet, and else goes after the frames made. The
    /// pump alone calls it, so it may wait for the model. A report of an
    /// older channel goes nowhere.
    fn reported(&self, epoch: u64, report: Vec<u8>) {
        let mut inner = self.lock();
        let mut made = unpoisoned(&self.made);
        if made.epoch != epoch {
            return;
        }
        if inner.sender.pending() {
            if inner.parked.len() >= PARKED_MOST {
                inner.parked.pop_front();
            }
            inner.parked.push_back(report);
        } else {
            made.queue.push_back(Out::Report(report));
        }
        made.wake.notify_one();
    }

    /// [`Shared::run_told`] with no reports of local echo.
    #[cfg(test)]
    pub(super) async fn run(
        self: Arc<Self>,
        out: impl AsyncWrite + Unpin + Send,
        answers: impl AsyncWrite + Unpin + Send,
    ) {
        self.run_told(out, answers, None::<tokio::io::Sink>).await;
    }

    /// Send the frames on `out` (the channel's extended data of
    /// `crate::frames::EXT`) until the pty's output ends, then the last
    /// one; `answers` is the pty's master, for the model's answers. A
    /// channel that is gone ends it. Local echo's reports go on `reports`
    /// (the extended data of `crate::predict::EXT`), each after the frame
    /// that it waited for. The channel of the epoch now.
    pub(super) async fn run_told(
        self: Arc<Self>,
        out: impl AsyncWrite + Unpin + Send,
        answers: impl AsyncWrite + Unpin + Send,
        reports: Option<impl AsyncWrite + Unpin + Send>,
    ) {
        let epoch = self.epoch();
        self.run_epoch(epoch, out, answers, reports).await;
    }

    /// [`Shared::run_told`] for the channel of `epoch`: it ends with no
    /// last frame once another epoch starts, as its channel left.
    pub(super) async fn run_epoch(
        self: Arc<Self>,
        epoch: u64,
        mut out: impl AsyncWrite + Unpin + Send,
        mut answers: impl AsyncWrite + Unpin + Send,
        mut reports: Option<impl AsyncWrite + Unpin + Send>,
    ) {
        let Some(wake) = self.wake_of(epoch) else { return };
        loop {
            let now = Instant::now();
            // Never a wait for the model: while the pump has it, it makes
            // the frames itself, and this task looks again a moment later.
            let looked = match self.try_lock() {
                Some(mut guard) => {
                    // The answers and what the client said are the new
                    // channel's once another epoch started.
                    if self.epoch() != epoch {
                        return;
                    }
                    let inner = &mut *guard;
                    self.heard(inner, now);
                    self.make(inner, now);
                    Some((inner.ended, inner.sender.due(), inner.model.take_answers()))
                }
                None => None,
            };
            // The channel of another epoch has the screen: this one left.
            let Some(made) = self.take(epoch) else { return };
            if !sent(made, &mut out, &mut reports).await {
                return;
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
                        () = wake.notified() => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                None => wake.notified().await,
            }
        }
        // The pump is gone: the model is this task's alone; the reports
        // that wait go after the last frame.
        let last = {
            let mut guard = self.lock();
            let inner = &mut *guard;
            let bell = inner.model.bell();
            let (head, body) = inner.sender.last(&inner.model.state(), bell, Instant::now());
            let last = self.encoded(inner, head, &body);
            (last, std::mem::take(&mut inner.parked))
        };
        let Some(mut made) = self.take(epoch) else { return };
        made.push_back(Out::Frame(last.0));
        made.extend(last.1.into_iter().map(Out::Report));
        if !sent(made, &mut out, &mut reports).await {
            return;
        }
        let _ = out.flush().await;
        if let Some(reports) = reports.as_mut() {
            let _ = reports.flush().await;
        }
    }
}

/// Write `made` in its order: each frame on `out`, each report on
/// `reports`. False where the frames' channel is gone; a report that
/// cannot go ends the reports alone.
async fn sent(
    made: VecDeque<Out>,
    out: &mut (impl AsyncWrite + Unpin + Send),
    reports: &mut Option<impl AsyncWrite + Unpin + Send>,
) -> bool {
    for item in made {
        match item {
            Out::Frame(bytes) => {
                if out.write_all(&bytes).await.is_err() {
                    return false;
                }
            }
            Out::Report(bytes) => {
                let failed = match reports.as_mut() {
                    Some(writer) => writer.write_all(&bytes).await.is_err(),
                    None => false,
                };
                if failed {
                    *reports = None;
                }
            }
        }
    }
    true
}

#[cfg(test)]
#[path = "frames_tests.rs"]
mod tests;
