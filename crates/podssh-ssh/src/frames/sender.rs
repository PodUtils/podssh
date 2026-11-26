//! When the far end sends a frame, and from which base (T-303); no I/O,
//! and the clock is the caller's.
//!
//! The pace is Mosh's (its paper, section 2.3): a frame at most each half
//! round trip, never sooner than [`SHORTEST`] and never later than
//! [`LONGEST`] after the last, and [`COLLECT`] after the first change, so
//! that a burst of output is one frame. The round trip is measured from a
//! frame to its acknowledgement.
//!
//! A frame's base is the newest state that the client acknowledged, so a
//! frame that a later road loses (T-304) costs only itself. The states kept
//! are the base and the last [`HELD`] that no acknowledgement named yet:
//! past them the oldest goes, and an acknowledgement that names a state
//! that is gone moves no base. A client that says it lost its base gets
//! the whole screen.
//!
//! A frame also carries the lines that left the top of the screen after
//! its base ([`Sender::since`]). Lines alone, under a screen that looks the
//! same (a flood of `yes`), make a frame only while no frame waits for an
//! acknowledgement, and that frame sets no pace: a change of the screen
//! (the prompt after Ctrl-C) then never waits behind lines. Lines that no
//! frame carried are counted at the client as skipped.
//!
//! SSH carries each frame in order, so frames that no one acknowledged wait
//! in the link ahead of the next: while [`WINDOW`] wait, no frame goes,
//! until an acknowledgement comes or [`PATIENCE`] passes. That bound is
//! what lets Ctrl-C show within a round trip under a flood.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use super::screen::{diff, State};
use super::wire::{Ack, Head};

/// How long output is gathered after the first change, before its frame.
pub const COLLECT: Duration = Duration::from_millis(8);
/// The shortest time from one frame to the next.
pub const SHORTEST: Duration = Duration::from_millis(20);
/// The longest half round trip that paces the frames; also the pace before
/// the first acknowledgement measured one.
pub const LONGEST: Duration = Duration::from_millis(250);
/// The most frames that wait for an acknowledgement before the next goes.
pub const WINDOW: usize = 2;
/// The most states kept for acknowledgements that did not come yet.
pub const HELD: usize = 3;
/// With [`WINDOW`] frames not acknowledged, how long after the last frame
/// the next one goes all the same: a client whose acknowledgements stopped
/// still gets the screen, at this pace.
pub const PATIENCE: Duration = Duration::from_secs(2);

struct Sent {
    number: u64,
    state: State,
    at: Instant,
}

/// The sender of one channel's frames.
pub struct Sender {
    /// The newest state that the client acknowledged, with its number.
    base: Option<(u64, State)>,
    /// The frames sent after it, the oldest first.
    sent: VecDeque<Sent>,
    /// The number of the next frame.
    next: u64,
    /// The smoothed round trip, once an acknowledgement measured one.
    round_trip: Option<Duration>,
    /// When the last frame went.
    last: Option<Instant>,
    /// When the screen first changed since the last frame.
    changed: Option<Instant>,
    /// Lines alone waited for the frames on their way: the acknowledgement
    /// that empties the window looks again.
    lines_wait: bool,
}

impl Default for Sender {
    fn default() -> Self {
        let (round_trip, last, changed) = (None, None, None);
        Sender { base: None, sent: VecDeque::new(), next: 1, round_trip, last, changed, lines_wait: false }
    }
}

impl Sender {
    /// The screen may differ from the last frame, since `now`: output came,
    /// the size changed, or the client lost its base. True for the first
    /// such word since the last frame: the caller then looks at
    /// [`Sender::due`] again.
    pub fn changed(&mut self, now: Instant) -> bool {
        let first = self.changed.is_none();
        self.changed.get_or_insert(now);
        first
    }

    /// The time from one frame to the next: half the round trip, within
    /// [`SHORTEST`] and [`LONGEST`].
    pub fn interval(&self) -> Duration {
        self.round_trip.map_or(LONGEST, |trip| (trip / 2).clamp(SHORTEST, LONGEST))
    }

    /// The smoothed round trip, once one was measured.
    pub fn round_trip(&self) -> Option<Duration> {
        self.round_trip
    }

    /// When the next frame may go; `None` while nothing changed.
    pub fn due(&self) -> Option<Instant> {
        let mut at = self.changed? + COLLECT;
        if let Some(last) = self.last {
            at = at.max(last + self.interval());
            if self.sent.len() >= WINDOW {
                at = at.max(last + PATIENCE);
            }
        }
        Some(at)
    }

    /// The frame of `state` at `now`, where one is due and the client's
    /// screen would differ: its header and its body. `bell`: the far end
    /// rang since the last frame, which goes with no change of the screen
    /// too.
    pub fn frame(&mut self, state: &State, bell: bool, now: Instant) -> Option<(Head, Vec<u8>)> {
        if self.due().is_none_or(|at| at > now) {
            return None;
        }
        self.changed = None;
        // What the client shows once each frame sent has come: the last
        // one sent, else the base.
        let newest = self.sent.back().map(|sent| &sent.state).or(self.base.as_ref().map(|(_, state)| state));
        let alone = !bell && newest.is_some_and(|newest| newest.same(state));
        if alone && newest.is_some_and(|newest| newest.total == state.total) {
            return None;
        }
        // Lines alone go only into an empty window, so that the next change
        // of the screen never waits behind them.
        if alone && !self.sent.is_empty() {
            self.lines_wait = true;
            return None;
        }
        let (body, full) = diff(self.base.as_ref().map(|(_, base)| base), state);
        Some((self.numbered(state, full, bell, now, !alone), body))
    }

    /// The last frame, after the program's output ended: the whole screen,
    /// so that it shows whatever the client holds.
    pub fn last(&mut self, state: &State, bell: bool, now: Instant) -> (Head, Vec<u8>) {
        let (body, _) = diff(None, state);
        let head = Head { last: true, ..self.numbered(state, true, bell, now, true) };
        (head, body)
    }

    /// The header of the next frame, and its state kept for its
    /// acknowledgement; past [`HELD`], the oldest kept goes. A `paced` frame
    /// starts the time to the next one; a frame of lines alone does not.
    fn numbered(&mut self, state: &State, full: bool, bell: bool, now: Instant, paced: bool) -> Head {
        let number = self.next;
        self.next += 1;
        let base = match (&self.base, full) {
            (Some((base, _)), false) => *base,
            _ => 0,
        };
        if self.sent.len() >= HELD {
            self.sent.pop_front();
        }
        self.sent.push_back(Sent { number, state: state.clone(), at: now });
        if paced || self.last.is_none() {
            self.last = Some(now);
        }
        self.lines_wait = false;
        let (rows, cols) = state.size();
        Head { full, bell, last: false, number, base, rows, cols, total: state.total }
    }

    /// The count of lines at the base of the frames: a frame carries the
    /// lines after it. 0 with no base: then the newest lines kept go, and
    /// the client passes over those that its scrollback has.
    pub fn since(&self) -> u64 {
        self.base.as_ref().map_or(0, |(_, base)| base.total)
    }

    /// The client's acknowledgement, at `now`. A state that is kept
    /// becomes the base, and its frame's age a sample of the round trip. A
    /// client that lost its base and holds a state that is not kept gets
    /// the whole screen next.
    pub fn acked(&mut self, ack: Ack, now: Instant) {
        if let Some(at) = self.sent.iter().position(|sent| sent.number == ack.number) {
            // Each older one goes with it: no later acknowledgement can
            // name a state before the client's newest.
            if let Some(sent) = self.sent.drain(..=at).next_back() {
                let sample = now.saturating_duration_since(sent.at);
                self.round_trip = Some(match self.round_trip {
                    Some(smooth) => (smooth * 7 + sample) / 8,
                    None => sample,
                });
                self.base = Some((sent.number, sent.state));
            }
        } else if ack.lost && self.base.as_ref().is_none_or(|(base, _)| *base != ack.number) {
            self.base = None;
        }
        if ack.lost {
            // The frames after the state that the client holds drew nothing
            // there: they are forgotten, and one goes again from that state.
            self.sent.clear();
            self.changed(now);
        }
        if self.lines_wait && self.sent.is_empty() {
            self.lines_wait = false;
            self.changed(now);
        }
    }

    /// How many frames wait for an acknowledgement.
    pub fn waiting(&self) -> usize {
        self.sent.len()
    }
}

#[cfg(test)]
#[path = "sender_tests.rs"]
mod tests;
