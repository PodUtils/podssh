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
//! pty: it puts what the client said beside the model (a [`Lane`]). The
//! pump applies it, and makes the frame that is due, at each write; the
//! task that sends only tries the model's lock, and while the pump has it,
//! looks again a moment later.
//!
//! Local echo's reports (T-160), where the client asked for them too, go
//! through the same queue as the frames ([`Shared::reported`]): a report that
//! comes while the screen has a change that no frame holds waits for that
//! frame, and goes right after it. The client then judges its guesses on a
//! screen that holds the echo of each key that the report counts, as it
//! does with bytes, where each report follows the output read before it.
//!
//! One model has a view for each channel that has its screen with frames:
//! the view's own sender (its base, its acknowledgements, its pace), its
//! queue and its task. A channel's own pty has one view. A kept shell
//! (T-159) has one at a time, each channel an epoch of its own, and its
//! model is fed with no view while no channel of frames has it
//! (`frames_epoch.rs`). A shell shared by name (T-837) has one for each
//! seat that asked (`share_frames.rs`), so a seat on a slow road holds no
//! other back. One view at most writes the model's answers to the pty.
//!
//! The model costs a grid for each state kept: the screen now, and for
//! each view its base and at most `HELD` frames that wait, some 60 KiB each
//! at 80 by 24, and the text of one screen of lines that left its top, for
//! a pty of which a channel asked frames, and for no other.

#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::frames::screen::{Model, State};
use crate::frames::sender::Sender;
use crate::frames::wire::{encode, Ack, Head, Version};
use crate::terminal::Size;

// The views of a model: their start and their end, the epochs of a kept
// shell's model, the writers of the pump and of the reports.
#[path = "frames_epoch.rs"]
mod epoch;

// The task that sends the frames of one view.
#[path = "frames_run.rs"]
mod run;

/// The number of the view that [`Shared::new`] opens: the channel whose
/// pty it is.
pub(in crate::server) const FIRST_VIEW: u64 = 0;

/// The most acknowledgements kept for a view; the newest count, so the
/// oldest go past it.
const TOLD_MOST: usize = 8;
/// The most reports of local echo that wait for a frame; past it the
/// oldest goes, as a later report's count covers it.
const PARKED_MOST: usize = 64;

/// One view of the model: the sender of a channel that has the screen with
/// frames, under the model's lock.
struct View {
    sender: Sender,
    /// Reports of local echo made while a change waited for its frame.
    parked: VecDeque<Vec<u8>>,
    /// The version that its channel asked for.
    version: Version,
    /// The bell rang since its last frame.
    bell: bool,
    /// Its task writes the model's answers to the pty: one view at most.
    answers: bool,
    /// Its part apart from the model.
    lane: Arc<Lane>,
}

struct Inner {
    model: Model,
    /// The pty's output ended: the last frame of each view goes.
    ended: bool,
    /// The views open now, by their numbers.
    views: BTreeMap<u64, View>,
    /// The number of the next view.
    next_view: u64,
    /// The least number of a new view's first frame: past each number that
    /// a view gave, so that no acknowledgement of a channel that left
    /// names a frame of the next.
    next_number: u64,
    /// The version that the model was made for: it keeps lines for 2.
    version: Version,
}

/// What the task that sends writes, in this order: a frame, on the frames'
/// code, or a report of local echo, on its own.
enum Out {
    Frame(Vec<u8>),
    Report(Vec<u8>),
}

/// The part of one view apart from the model, so that its client's word
/// never waits for the pump: its acknowledgements with when each came,
/// the reports of a task that is not the pump, its queue and its wake.
struct Lane {
    acks: Mutex<VecDeque<(Ack, Instant)>>,
    /// Reports of local echo that wait for the model's lock
    /// ([`Shared::reported_aside`]).
    inbox: Mutex<VecDeque<Vec<u8>>>,
    /// The frames made and not written yet, in the order of their numbers,
    /// each report of local echo after the frame that it waited for.
    queue: Mutex<VecDeque<Out>>,
    /// A frame was made, output came, its client said something, the size
    /// changed, or the output ended: the view's task looks again.
    wake: Notify,
    /// The number of the view's first frame: an acknowledgement of a lower
    /// one is an older channel's.
    first: u64,
    /// The view left: the pump drops it at its next look.
    gone: AtomicBool,
}

impl Lane {
    fn new(first: u64) -> Lane {
        let (acks, inbox, queue) = (Mutex::default(), Mutex::default(), Mutex::default());
        Lane { acks, inbox, queue, wake: Notify::new(), first, gone: AtomicBool::new(false) }
    }
}

/// The frames of one pty: the model and its views, shared by the pty's
/// pump, each view's task, and the handler.
pub(super) struct Shared {
    inner: Mutex<Inner>,
    /// Each view's lane, for the handler and the tasks, which never wait
    /// for the model.
    lanes: Mutex<BTreeMap<u64, Arc<Lane>>>,
    /// The newest size of the pty, given to the model before the output
    /// that follows it.
    size: Mutex<Option<Size>>,
    /// A client said something since the pump last looked: it looks only
    /// then, so a flood costs no lock of the lanes for each write.
    told: AtomicBool,
}

fn cells(n: u32) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX).max(1)
}

fn unpoisoned<T>(lock: &Mutex<T>) -> MutexGuard<'_, T> {
    lock.lock().unwrap_or_else(|p| p.into_inner())
}

/// The bytes of a frame of `head` and `body` in `version`, with the lines
/// after the line `since` where the version carries them.
fn encoded(model: &Model, version: Version, since: u64, head: Head, body: &[u8]) -> Vec<u8> {
    let lines = match version {
        Version::One => Vec::new(),
        Version::Two => model.lines_after(since),
    };
    encode(version, head, &lines, body)
}

/// The frame of `view` that is due at `now`, made and queued for its task,
/// with the reports that waited for it; under the model's lock. Whether
/// anything was queued. `state` is the screen now, made once for each
/// write however many views are due. The last frame is the task's own.
fn make_view(model: &Model, view: &mut View, state: &mut Option<State>, now: Instant) -> bool {
    if view.sender.due().is_none_or(|at| at > now) {
        return false;
    }
    let state = state.get_or_insert_with(|| model.state());
    let framed = view.sender.frame(state, view.bell, now);
    let mut queue = unpoisoned(&view.lane.queue);
    if let Some((head, body)) = framed.as_ref() {
        view.bell = false;
        queue.push_back(Out::Frame(encoded(model, view.version, view.sender.since(), *head, body)));
    }
    // The change went into a frame, or the client's screen needs none:
    // the reports that waited for it go after it.
    let mut queued = framed.is_some();
    if !view.sender.pending() && !view.parked.is_empty() {
        queue.extend(view.parked.drain(..).map(Out::Report));
        queued = true;
    }
    queued
}

/// A report of local echo for `view`, now that the model holds the output
/// before it: it waits for the frame of a change that no frame holds yet,
/// and else goes after the frames made.
fn place(view: &mut View, report: Vec<u8>) {
    if view.sender.pending() {
        if view.parked.len() >= PARKED_MOST {
            view.parked.pop_front();
        }
        view.parked.push_back(report);
    } else {
        unpoisoned(&view.lane.queue).push_back(Out::Report(report));
    }
}

impl Shared {
    /// For a pty of `size`, whose screen is empty, in frames of `version`,
    /// with the view of the channel whose pty it is ([`FIRST_VIEW`]), which
    /// answers the program's questions. Its first frame comes with the
    /// first output.
    pub(super) fn new(size: Size, version: Version) -> Arc<Shared> {
        let shared = Shared::bare(size, version);
        shared.open_view(version, true, false);
        shared
    }

    /// A model of a pty of `size` with no view, which answers nothing: a
    /// shared shell's, made at the first seat that asks (`share_frames.rs`).
    pub(super) fn bare(size: Size, version: Version) -> Arc<Shared> {
        let model = Model::new(cells(size.rows), cells(size.cols), false);
        // Version 1 carries no line: its model counts none, so a flood that
        // only scrolls makes no frame, as before the lines.
        let model = if version == Version::Two { model } else { model.without_lines() };
        let (views, next_view, next_number) = (BTreeMap::new(), 0, 1);
        let inner = Inner { model, ended: false, views, next_view, next_number, version };
        let (lanes, size, told) = (Mutex::default(), Mutex::default(), AtomicBool::new(false));
        Arc::new(Shared { inner: Mutex::new(inner), lanes, size, told })
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

    /// The lane of `view`, while it is open.
    fn lane(&self, view: u64) -> Option<Arc<Lane>> {
        unpoisoned(&self.lanes).get(&view).cloned()
    }

    /// Each view's task looks again.
    fn wake_all(&self) {
        for lane in unpoisoned(&self.lanes).values() {
            lane.wake.notify_one();
        }
    }

    /// The pty has a new size (`window-change`, or the least of a shared
    /// shell's seats): the model too, before the next output, and the next
    /// frame of each view is the whole screen in that size.
    pub(super) fn resize(&self, size: Size) {
        *unpoisoned(&self.size) = Some(size);
        self.told.store(true, Ordering::Release);
        self.wake_all();
    }

    /// The client's acknowledgement on a pty with one view at a time (a
    /// channel's own, a kept shell's): to the newest view. One of a frame
    /// before that view's first is an older channel's, and goes.
    pub(super) fn acked(&self, ack: Ack) {
        let newest = unpoisoned(&self.lanes).keys().next_back().copied();
        if let Some(view) = newest {
            self.acked_by(view, ack);
        }
    }

    /// The acknowledgement of the client of `view` (`env
    /// frames-ack@podssh`), timed now. A view that left takes none.
    pub(in crate::server) fn acked_by(&self, view: u64, ack: Ack) {
        let Some(lane) = self.lane(view) else { return };
        if ack.number != 0 && ack.number < lane.first {
            return;
        }
        let mut acks = unpoisoned(&lane.acks);
        if acks.len() >= TOLD_MOST {
            acks.pop_front();
        }
        acks.push_back((ack, Instant::now()));
        drop(acks);
        self.told.store(true, Ordering::Release);
        lane.wake.notify_one();
    }

    /// What the clients said, into the model and the views; under the
    /// model's lock. The views that left go first.
    fn heard(&self, inner: &mut Inner, now: Instant) {
        if !self.told.swap(false, Ordering::AcqRel) {
            return;
        }
        let gone: Vec<u64> =
            inner.views.iter().filter(|(_, view)| view.lane.gone.load(Ordering::Acquire)).map(|(id, _)| *id).collect();
        for id in gone {
            self.drop_view(inner, id);
        }
        if let Some(size) = unpoisoned(&self.size).take() {
            inner.model.resize(cells(size.rows), cells(size.cols));
            for view in inner.views.values_mut() {
                view.sender.changed(now);
            }
        }
        for view in inner.views.values_mut() {
            let acks = std::mem::take(&mut *unpoisoned(&view.lane.acks));
            for (ack, at) in acks {
                view.sender.acked(ack, at);
            }
            let reports = std::mem::take(&mut *unpoisoned(&view.lane.inbox));
            for report in reports {
                place(view, report);
            }
        }
    }

    /// The frame of each view that is due at `now`; under the model's lock.
    /// Whether anything was queued. The pump makes them in [`Shared::fed`],
    /// and each view's task its own.
    #[cfg(test)]
    fn make(&self, inner: &mut Inner, now: Instant) -> bool {
        if inner.ended {
            return false;
        }
        let Inner { model, views, .. } = inner;
        let mut state = None;
        let mut queued = false;
        for view in views.values_mut() {
            queued |= make_view(model, view, &mut state, now);
        }
        queued
    }

    /// The pty's output, into the model, and the frame of each view that
    /// is due; it never waits but for the model. The pump of a channel's
    /// own pty writes it through a `Sink`; a kept shell's pump, at each
    /// write that its ring takes; a shared shell's, at each write of the
    /// owner's output (`share.rs`).
    pub(super) fn fed(&self, buf: &[u8]) {
        let now = Instant::now();
        let mut guard = self.lock();
        let inner = &mut *guard;
        // A new size goes before the output that follows it.
        self.heard(inner, now);
        inner.model.feed(buf);
        // No view: the model is fed alone, and keeps its bell for the next.
        if inner.ended || inner.views.is_empty() {
            return;
        }
        if inner.model.bell() {
            inner.model.clear_bell();
            inner.views.values_mut().for_each(|view| view.bell = true);
        }
        let asked = inner.model.answers_wait();
        let Inner { model, views, .. } = inner;
        let mut state = None;
        let mut woken = Vec::new();
        for view in views.values_mut() {
            let first = view.sender.changed(now);
            let made = make_view(model, view, &mut state, now);
            // A view's task looks again at the first change since its last
            // frame, at a frame made here, and when an answer waits for it;
            // the rest of a flood wakes nothing.
            if first || made || (asked && view.answers) {
                woken.push(view.lane.clone());
            }
        }
        drop(guard);
        for lane in woken {
            lane.wake.notify_one();
        }
    }

    /// A report of local echo of `view`, made by the pump after the output
    /// that it read ([`place`]). The pump alone calls it, so it may wait
    /// for the model. A report of a view that left goes nowhere.
    fn reported(&self, view: u64, report: Vec<u8>) {
        let mut inner = self.lock();
        let Some(mine) = inner.views.get_mut(&view) else { return };
        place(mine, report);
        mine.lane.wake.notify_one();
    }

    /// A report of local echo of `view` made by a task that is not the pump
    /// (a seat's at a shared shell, after the model took the output before
    /// it): it never waits for the model, and the pump or the view's task
    /// places it at its next look ([`place`]), where a change that waits
    /// for its frame holds it back as the pump's own would.
    fn reported_aside(&self, view: u64, report: Vec<u8>) {
        let Some(lane) = self.lane(view) else { return };
        let mut inbox = unpoisoned(&lane.inbox);
        if inbox.len() >= PARKED_MOST {
            inbox.pop_front();
        }
        inbox.push_back(report);
        drop(inbox);
        self.told.store(true, Ordering::Release);
        lane.wake.notify_one();
    }
}

#[cfg(test)]
#[path = "frames_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "frames_view_tests.rs"]
mod view_tests;
