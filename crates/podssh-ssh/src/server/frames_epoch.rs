//! The views of a model of the screen (T-303), a part of `frames.rs` in a
//! file of its own so that each stays short, and the writers that its
//! pump and its local echo write into.
//!
//! A view is one channel that has the screen with frames: its own sender,
//! whose first frame is the whole screen, its queue, its wake and its task.
//! A channel's own pty has one view, from its ask to its end. A kept shell
//! (T-159) outlives its channels, and so does its model: each channel that
//! has the shell with frames is an epoch, a view of its own
//! ([`Shared::restart`]), and its leave ends it ([`Shared::release`]); the
//! model is fed with no frame made until the next. A shell shared by name
//! (T-837) has a view for each seat with frames at once ([`Shared::join`],
//! [`Shared::leave`]). The numbers of a new view's frames go on from the
//! last view's, so that an older channel's acknowledgement names no frame
//! of the new one.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::AsyncWrite;
use tokio::time::Instant;

use super::{unpoisoned, Inner, Lane, Shared, View};
use crate::frames::sender::Sender;
use crate::frames::wire::Version;

impl Shared {
    /// The newest view: the channel that has the screen of a pty with one
    /// view at a time, or had it last.
    pub(super) fn newest(&self) -> u64 {
        let lanes = unpoisoned(&self.lanes);
        lanes.keys().next_back().copied().unwrap_or(super::FIRST_VIEW)
    }

    /// A new view of frames of `version`, whose first frame is the whole
    /// screen where `draw`, and else comes with the next output. Where
    /// `answers`, its task writes the model's answers, and no other's does.
    pub(super) fn open_view(&self, version: Version, answers: bool, draw: bool) -> u64 {
        let mut inner = self.lock();
        self.open_view_in(&mut inner, version, answers, draw)
    }

    fn open_view_in(&self, inner: &mut Inner, version: Version, answers: bool, draw: bool) -> u64 {
        let first = inner.views.values().map(|view| view.sender.next_number()).fold(inner.next_number, u64::max);
        let id = inner.next_view;
        inner.next_view += 1;
        let mut sender = Sender::from_number(first);
        if draw {
            sender.changed(Instant::now());
        }
        // A bell that rang while no view had the screen goes in its first frame.
        let bell = inner.model.bell();
        inner.model.clear_bell();
        if answers {
            inner.views.values_mut().for_each(|view| view.answers = false);
            inner.model.set_answering(true);
        }
        let lane = Arc::new(Lane::new(first));
        let parked = VecDeque::new();
        inner.views.insert(id, View { sender, parked, version, bell, answers, lane: lane.clone() });
        unpoisoned(&self.lanes).insert(id, lane);
        id
    }

    /// Drop the view `id` under the model's lock: its numbers count for the
    /// next view's, its answers stop, and its task looks once more, and ends.
    pub(super) fn drop_view(&self, inner: &mut Inner, id: u64) {
        if let Some(gone) = inner.views.remove(&id) {
            inner.next_number = inner.next_number.max(gone.sender.next_number());
            if gone.answers {
                inner.model.set_answering(false);
            }
            gone.lane.gone.store(true, Ordering::Release);
            gone.lane.wake.notify_one();
        }
        unpoisoned(&self.lanes).remove(&id);
    }

    /// A seat of a shared shell (T-837) has the screen with frames of
    /// `version` from now on, beside the others: a new view, whose first
    /// frame is the whole screen, and which answers nothing.
    pub(in crate::server) fn join(&self, version: Version) -> u64 {
        self.open_view(version, false, true)
    }

    /// The channel of `view` left (a seat went, its channel closed): its
    /// task ends, and the pump drops the view at its next look. It never
    /// waits for the model, as a channel's close runs on the SSH session's
    /// task. A view that left already changes nothing.
    pub(in crate::server) fn leave(&self, view: u64) {
        let Some(lane) = unpoisoned(&self.lanes).remove(&view) else { return };
        lane.gone.store(true, Ordering::Release);
        self.told.store(true, Ordering::Release);
        lane.wake.notify_one();
    }

    /// The version that the model was made for: the channel's, for a
    /// channel's own pty.
    pub(in crate::server) fn version(&self) -> Version {
        self.lock().version
    }

    /// A channel with frames of `version` has the screen of a kept shell
    /// from now on: each other view goes, and a new epoch starts, whose
    /// first frame is the whole screen, and whose task writes the model's
    /// answers. Its number, for its task ([`Shared::run_epoch`]) and its
    /// reports ([`Shared::reports`]).
    pub(in crate::server) fn restart(&self, version: Version) -> u64 {
        let mut inner = self.lock();
        let ids: Vec<u64> = inner.views.keys().copied().collect();
        for id in ids {
            self.drop_view(&mut inner, id);
        }
        self.open_view_in(&mut inner, version, true, true)
    }

    /// The channel with frames left a kept shell (`~d`, a close, another
    /// client): its task ends, and the model is fed with no frame made and
    /// no question answered, as a terminal with no one at it, until the
    /// next [`Shared::restart`].
    pub(in crate::server) fn release(&self) {
        let mut inner = self.lock();
        let ids: Vec<u64> = inner.views.keys().copied().collect();
        for id in ids {
            self.drop_view(&mut inner, id);
        }
        inner.model.set_answering(false);
    }

    /// Feed the model with `bytes` that it did not see (a kept shell's
    /// ring, or a shared shell's, for a model made at an attach), with no
    /// question answered: the program asked them long ago.
    pub(in crate::server) fn seed(&self, bytes: &[u8]) {
        let mut inner = self.lock();
        inner.model.set_answering(false);
        inner.model.feed(bytes);
    }

    /// The pty's output ended: the task of each view sends its last frame,
    /// and ends.
    pub(in crate::server) fn end(&self) {
        self.lock().ended = true;
        self.wake_all();
    }

    /// Where the reporter of local echo of the newest view's channel,
    /// beside the pump, writes its reports.
    pub(in crate::server) fn reports(self: &Arc<Self>) -> Reports {
        Reports(self.clone(), self.newest())
    }

    /// Where a task that is not the pump writes the reports of local echo
    /// of `view` (a seat's at a shared shell, T-896).
    pub(in crate::server) fn aside(self: &Arc<Self>, view: u64) -> Aside {
        Aside(self.clone(), view)
    }

    /// The views open now, by their numbers, and the model's rows and
    /// columns, after the pump's next look: for a test of another module.
    #[cfg(test)]
    pub(in crate::server) fn seen(&self) -> (Vec<u64>, (u16, u16)) {
        let mut inner = self.lock();
        self.heard(&mut inner, Instant::now());
        (inner.views.keys().copied().collect(), inner.model.state().size())
    }

    /// Where the pty's pump writes the pty's output.
    pub(in crate::server) fn sink(self: &Arc<Self>) -> Sink {
        Sink(self.clone())
    }
}

/// Local echo's reports of a framed channel, made by the pump, into the
/// queue of the frames of its view ([`Shared::reported`]). Each write is
/// one report (`Reporter::tell` writes it whole), and none waits or fails.
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

/// Local echo's reports of a seat with frames, made by a task of its own,
/// into its view's inbox ([`Shared::reported_aside`]). Each write is one
/// report (`SeatTold::tell` writes it whole), and none waits or fails.
pub(in crate::server) struct Aside(Arc<Shared>, u64);

impl AsyncWrite for Aside {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.reported_aside(self.1, buf.to_vec());
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
