//! The client's half of the frames (T-303); no I/O. It reads the frames of
//! the far end's screen, keeps the states that a later frame may start
//! from, and gives what its terminal needs to show the newest one, and the
//! acknowledgement that is due.
//!
//! The rules of the acknowledgement are the donor study's (gedigi/noissh,
//! in the entry): one is due once any frame came, also a frame that was
//! refused, and at most one goes for each pass of the caller's loop. A
//! frame whose base is not held is refused, and the acknowledgement says
//! so; a frame that is not newer than the state held is passed over, also
//! a whole screen, so that a late one never moves the screen back.

use std::collections::VecDeque;

use super::screen::{apply, draw, leave, State};
use super::wire::{Ack, Decoder, Frame};

/// The most states kept as bases of later frames: more than the far end
/// keeps ([`super::sender::HELD`]) and its base, so each base that it can
/// name is held unless frames were lost.
pub const KEPT: usize = 8;

/// What became of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Taken {
    /// It gave a new state.
    Applied,
    /// It is not newer than the state held.
    Old,
    /// Its base is not held, or has another size.
    Lost,
}

/// The receiver of one session's frames.
#[derive(Default)]
pub struct Receiver {
    decoder: Decoder,
    /// The states held, the newest last, each with its number.
    held: VecDeque<(u64, State)>,
    /// What the terminal shows, once a frame was drawn.
    shown: Option<State>,
    /// The terminal's cursor or content may be another than `shown`'s.
    repaint: bool,
    /// An acknowledgement is due, and whether the last frame was refused.
    due: Option<bool>,
    /// The last frame came: the far end's output ended.
    ended: bool,
}

impl Receiver {
    /// The bytes of the far end's extended data: what the terminal needs
    /// to show the newest state, empty when nothing new came. `Err` for
    /// bytes that are no frame of this version: no later frame can be
    /// read.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let frames = self.decoder.feed(bytes)?;
        let (mut fresh, mut bell) = (false, false);
        for frame in &frames {
            // Due before any check, so that a refused frame is answered too.
            let taken = self.take(frame);
            self.due = Some(match taken {
                Taken::Lost => true,
                Taken::Applied => false,
                // A frame passed over changes nothing of what is owed.
                Taken::Old => self.due.unwrap_or(false),
            });
            if taken == Taken::Applied {
                fresh = true;
                bell |= frame.head.bell;
                self.ended |= frame.head.last;
            }
        }
        if !fresh {
            return Ok(Vec::new());
        }
        // One draw for the frames of one read: only the newest shows.
        let Some((_, new)) = self.held.back() else { return Ok(Vec::new()) };
        let mut out = match self.shown.as_ref() {
            Some(_) => Vec::new(),
            None => first(new),
        };
        out.extend_from_slice(&draw(self.shown.as_ref(), new, self.repaint));
        if bell {
            out.push(0x07);
        }
        self.shown = Some(new.clone());
        self.repaint = false;
        Ok(out)
    }

    fn take(&mut self, frame: &Frame) -> Taken {
        let head = frame.head;
        if head.number <= self.newest() {
            return Taken::Old;
        }
        let base = if head.full {
            None
        } else {
            match self.held.iter().find(|(number, _)| *number == head.base) {
                Some((_, state)) if state.size() == (head.rows, head.cols) => Some(state),
                _ => return Taken::Lost,
            }
        };
        let state = apply(base, head.rows, head.cols, &frame.body);
        if self.held.len() >= KEPT {
            self.held.pop_front();
        }
        self.held.push_back((head.number, state));
        Taken::Applied
    }

    /// The number of the newest state held; 0 with none.
    pub fn newest(&self) -> u64 {
        self.held.back().map_or(0, |(number, _)| *number)
    }

    /// The newest state held.
    pub fn state(&self) -> Option<&State> {
        self.held.back().map(|(_, state)| state)
    }

    /// The acknowledgement that is due, taken: at most one for each call,
    /// whatever number of frames came since the last.
    pub fn take_ack(&mut self) -> Option<Ack> {
        let lost = self.due.take()?;
        Some(Ack { number: self.newest(), lost })
    }

    /// The terminal's cursor or content moved under the frames (a line of
    /// podssh's own, a new size of the window): the next frame draws the
    /// whole screen again.
    pub fn disturbed(&mut self) {
        self.repaint = true;
    }

    /// Whether the far end's last frame came.
    pub fn ended(&self) -> bool {
        self.ended
    }

    /// What gives the terminal back to its user, as it shows now; empty
    /// while no frame was drawn.
    pub fn leave(&self) -> Vec<u8> {
        self.shown.as_ref().map(leave).unwrap_or_default()
    }
}

/// Before the first frame: the lines that the terminal shows go up into
/// its scrollback, one line feed for each row from its last row, so that
/// the first frame's clear of the screen erases nothing of the user's.
fn first(new: &State) -> Vec<u8> {
    let (rows, _) = new.size();
    let mut out = b"\x1b[999;1H".to_vec();
    out.extend(std::iter::repeat_n(b'\n', usize::from(rows)));
    out
}

#[cfg(test)]
#[path = "receiver_tests.rs"]
mod tests;
