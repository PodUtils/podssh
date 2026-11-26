//! The epochs of a model of the screen (T-303), a part of `frames.rs` in a
//! file of its own so that each stays short, and the writers that its
//! pump and its local echo write into.
//!
//! A channel's own pty has one epoch, from its ask to its end. A kept
//! shell (T-159) outlives its channels, and so does its model: each channel
//! that has the shell with frames starts an epoch ([`Shared::restart`]),
//! whose sender starts with no base, so that its first frame is the whole
//! screen; its leave ends it ([`Shared::release`]), and the model is fed
//! with no frame made until the next. Each epoch has its own queue, its own
//! wake and its own task, and the numbers of its frames go on from the
//! last epoch's, so that an older channel's acknowledgement names no frame
//! of the new one.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::sync::Notify;
use tokio::time::Instant;

use super::{unpoisoned, Made, Out, Shared};
use crate::frames::sender::Sender;
use crate::frames::wire::Version;

impl Shared {
    /// The epoch now: the channel that has the screen, or had it last.
    pub(super) fn epoch(&self) -> u64 {
        unpoisoned(&self.made).epoch
    }

    /// The wake of `epoch`'s task, while it is the epoch now.
    pub(super) fn wake_of(&self, epoch: u64) -> Option<Arc<Notify>> {
        let made = unpoisoned(&self.made);
        (made.epoch == epoch).then(|| made.wake.clone())
    }

    /// The queue of `epoch`, taken; `None` once another epoch started.
    pub(super) fn take(&self, epoch: u64) -> Option<VecDeque<Out>> {
        let mut made = unpoisoned(&self.made);
        (made.epoch == epoch).then(|| std::mem::take(&mut made.queue))
    }

    /// A new epoch whose first frame has the number `first`: the task of
    /// the last one looks once more, and ends.
    fn next_epoch(&self, first: u64) -> u64 {
        let mut made = unpoisoned(&self.made);
        made.wake.notify_one();
        let epoch = made.epoch + 1;
        *made = Made::new(epoch, first);
        epoch
    }

    /// The version that the channel of the epoch now asked for.
    pub(in crate::server) fn version(&self) -> Version {
        self.lock().version
    }

    /// A channel with frames of `version` has the screen from now on: a
    /// new epoch, whose first frame is the whole screen, and whose model
    /// answers the program's questions. Its number, for its task
    /// ([`Shared::run_epoch`]) and its reports ([`Shared::reports`]).
    pub(in crate::server) fn restart(&self, version: Version) -> u64 {
        let now = Instant::now();
        let mut inner = self.lock();
        let first = inner.sender.next_number();
        inner.sender = Sender::from_number(first);
        inner.sender.changed(now);
        inner.parked.clear();
        inner.version = version;
        inner.feeding = true;
        inner.model.set_answering(true);
        unpoisoned(&self.told).acks.clear();
        let epoch = self.next_epoch(first);
        drop(inner);
        epoch
    }

    /// The channel with frames left the screen (`~d`, a close, another
    /// client): its task ends, and the model is fed with no frame made and
    /// no question answered, as a terminal with no one at it, until the
    /// next [`Shared::restart`].
    pub(in crate::server) fn release(&self) {
        let mut inner = self.lock();
        if !inner.feeding {
            return;
        }
        inner.feeding = false;
        inner.parked.clear();
        inner.model.set_answering(false);
        let first = inner.sender.next_number();
        self.next_epoch(first);
    }

    /// Feed the model with `bytes` that it did not see (a kept shell's
    /// ring, for a model made at an attach), with no question answered:
    /// the program asked them long ago.
    pub(in crate::server) fn seed(&self, bytes: &[u8]) {
        let mut inner = self.lock();
        inner.model.set_answering(false);
        inner.model.feed(bytes);
    }

    /// The pty's output ended: the task of the epoch now sends the last
    /// frame, and ends.
    pub(in crate::server) fn end(&self) {
        self.lock().ended = true;
        self.wake();
    }

    /// Where the reporter of local echo of the channel of the epoch now
    /// writes its reports.
    pub(in crate::server) fn reports(self: &Arc<Self>) -> Reports {
        Reports(self.clone(), self.epoch())
    }

    /// Where the pty's pump writes the pty's output.
    pub(in crate::server) fn sink(self: &Arc<Self>) -> Sink {
        Sink(self.clone())
    }
}

/// Local echo's reports of a framed channel, into the queue of the frames
/// of its epoch ([`Shared::reported`]). Each write is one report
/// (`Reporter::tell` writes it whole), and none waits or fails.
pub(in crate::server) struct Reports(Arc<Shared>, u64);

impl AsyncWrite for Reports {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.reported(self.1, buf.to_vec());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The pty's output, into the model ([`Shared::fed`]). It never waits and
/// never fails, so the pump reads the pty to its end whatever the client
/// takes; its drop is the end of the output.
pub(in crate::server) struct Sink(Arc<Shared>);

impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.fed(buf);
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
        self.0.end();
    }
}
