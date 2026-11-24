//! The guesses of local echo (T-160), sans I/O: the keys sent, the far end's
//! reports, and the row of the cursor as the client's model of the screen
//! has it, in; the cells and the cursor to draw over that screen, out.
//!
//! Each guess is judged against the screen once the far end reports that
//! its key reached the pty, never against a clock (mosh's way, read in
//! report 07 of PodUtils/podssh#317). A guess shows only in an epoch whose
//! first guess the far end confirmed; Enter, each other key that is not
//! guessed, a change of the pty's flags or of the cursor's row, and a wrong
//! guess start a new epoch, and nothing is guessed until the far end has
//! read each key before it. Nothing shows while the pty reads a line with
//! no echo, as for a password.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::keys::{keys, Key};
use super::report::{Flags, Report, ECHO_WAIT};

/// Guesses show from this smoothed round trip up (the Approach's step 5)...
pub const SHOW_FROM: Duration = Duration::from_millis(120);
/// ...and stop showing below this one, so that a round trip near the line
/// does not make them come and go.
pub const HIDE_BELOW: Duration = Duration::from_millis(80);
/// A read of more bytes than this is a paste, which is not guessed (mosh's
/// 100).
pub const PASTE: usize = 100;
/// The sends kept for a round trip's sample.
const SAMPLES: usize = 64;

/// What the client's model shows on the cursor's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Line {
    pub(super) row: u16,
    /// The cursor's column; the width of the screen while a character
    /// written in the last column waits for the next to wrap.
    pub(super) cursor: u16,
    pub(super) cols: u16,
    /// Each cell's text, "" for an empty one; `None` for each half of a
    /// wide character, which no guess moves.
    pub(super) cells: Vec<Option<String>>,
    pub(super) hidden_cursor: bool,
}

/// One guessed cell of the cursor's row: what its key makes it show.
#[derive(Debug, Clone)]
struct Guess {
    col: u16,
    text: String,
    /// The count of bytes sent with its key, which a report must reach.
    offset: u64,
    epoch: u64,
}

/// The guesses of one session.
#[derive(Debug)]
pub(super) struct Engine {
    sent: u64,
    acked: u64,
    flags: Option<Flags>,
    epoch: u64,
    confirmed: u64,
    row: Option<u16>,
    guesses: Vec<Guess>,
    /// The guessed column of the cursor, with the offset and epoch of its key.
    cursor: Option<(u16, u64, u64)>,
    /// No guess until a report reaches this count.
    blind_until: u64,
    srtt: Duration,
    showing: bool,
    sends: VecDeque<(u64, Instant)>,
    stopped: bool,
}

/// Two cells' texts are the same: an empty cell and a space are one.
fn same(a: &str, b: &str) -> bool {
    let blank = |s: &str| s.is_empty() || s == " ";
    a == b || (blank(a) && blank(b))
}

/// The screen shows `guess` already: its echo came, and it needs no
/// drawing; it is judged when its report comes.
fn echoed(guess: &Guess, line: &Line) -> bool {
    line.cells.get(usize::from(guess.col)).and_then(Option::as_deref).is_some_and(|c| same(c, &guess.text))
}

impl Engine {
    /// The engine of a session whose round trip measured `rtt` at its start.
    pub(super) fn new(rtt: Duration) -> Engine {
        Engine {
            sent: 0,
            acked: 0,
            flags: None,
            epoch: 1,
            confirmed: 0,
            row: None,
            guesses: Vec::new(),
            cursor: None,
            blind_until: 0,
            srtt: rtt,
            showing: rtt >= SHOW_FROM,
            sends: VecDeque::new(),
            stopped: false,
        }
    }

    /// No guess any more in this session.
    pub(super) fn stop(&mut self) {
        self.stopped = true;
        self.guesses.clear();
        self.cursor = None;
    }

    pub(super) fn stopped(&self) -> bool {
        self.stopped
    }

    /// Each guess goes, a new epoch starts, and nothing is guessed until
    /// the far end has read each key sent.
    pub(super) fn reset(&mut self) {
        self.guesses.clear();
        self.cursor = None;
        self.epoch += 1;
        self.blind_until = self.sent;
    }

    /// `data` went to the far end at `now`: guess what its keys do to `line`.
    pub(super) fn keys(&mut self, data: &[u8], line: &Line, now: Instant) {
        let start = self.sent;
        self.sent += data.len() as u64;
        if self.stopped || data.is_empty() {
            return;
        }
        if self.sends.len() == SAMPLES {
            self.sends.pop_front();
        }
        self.sends.push_back((self.sent, now));
        let blind = self.acked < self.blind_until || self.flags.is_none_or(Flags::hidden);
        if blind || data.len() > PASTE || line.cursor.saturating_add(1) >= line.cols {
            self.reset();
            return;
        }
        // A new row is a new line, or a new question: a new epoch.
        if self.row != Some(line.row) {
            self.guesses.clear();
            self.cursor = None;
            self.row = Some(line.row);
            self.epoch += 1;
        }
        let mut view = self.view(line);
        let mut col = self.cursor.map_or(line.cursor, |c| c.0);
        let mut at = start;
        for (key, len) in keys(data) {
            at += len as u64;
            let guessed = match key {
                Key::Text(c) => self.insert(&mut view, line, &mut col, c, at),
                Key::Erase => self.erase(&mut view, line, &mut col, at),
                Key::Left => match col.checked_sub(1) {
                    Some(left) => {
                        col = left;
                        true
                    }
                    None => false,
                },
                // Over text the cursor moves on; past the line's end it stays.
                Key::Right => {
                    let over = view.get(usize::from(col)).and_then(Option::as_deref).is_some_and(|t| !same(t, ""));
                    if over && col.saturating_add(2) < line.cols {
                        col += 1;
                    }
                    true
                }
                Key::Other => false,
            };
            if !guessed {
                self.reset();
                return;
            }
            self.cursor = Some((col, at, self.epoch));
        }
    }

    /// The row as the screen and the guesses make it.
    fn view(&self, line: &Line) -> Vec<Option<String>> {
        let mut view = line.cells.clone();
        for g in &self.guesses {
            if let Some(cell) = view.get_mut(usize::from(g.col)) {
                *cell = Some(g.text.clone());
            }
        }
        view
    }

    /// The last cell at or after `from` that shows text, if any; `Err` when
    /// a wide character lies there.
    fn end(view: &[Option<String>], from: usize) -> Result<Option<usize>, ()> {
        let mut end = None;
        for (i, cell) in view.iter().enumerate().skip(from) {
            match cell {
                None => return Err(()),
                Some(t) if !same(t, "") => end = Some(i),
                Some(_) => {}
            }
        }
        Ok(end)
    }

    /// A character at the cursor: the text from there on moves right, as a
    /// line editor inserts. Never into the last column, whose wrap waits.
    fn insert(&mut self, view: &mut [Option<String>], line: &Line, col: &mut u16, c: char, at: u64) -> bool {
        let from = usize::from(*col);
        let last = usize::from(line.cols).saturating_sub(1);
        let Ok(end) = Self::end(view, from) else { return false };
        let reach = end.map_or(from, |e| e.max(from) + 1);
        if from >= last || reach >= last {
            return false;
        }
        view[from..=reach].rotate_right(1);
        view[from] = Some(c.to_string());
        self.note(view, line, from..=reach, at);
        *col += 1;
        true
    }

    /// The character before the cursor goes: the text after it moves left.
    fn erase(&mut self, view: &mut [Option<String>], line: &Line, col: &mut u16, at: u64) -> bool {
        let Some(to) = col.checked_sub(1).map(usize::from) else { return false };
        let last = usize::from(line.cols).saturating_sub(1);
        let Ok(end) = Self::end(view, to) else { return false };
        if view.get(to).is_none() || end.is_some_and(|e| e >= last) {
            return false;
        }
        let reach = end.map_or(to, |e| e.max(to));
        view[to..=reach].rotate_left(1);
        view[reach] = Some(String::new());
        self.note(view, line, to..=reach, at);
        *col -= 1;
        true
    }

    /// The cells of `range` as the guesses now make them: a guess where the
    /// view differs from the screen, none where it shows the same.
    fn note(&mut self, view: &[Option<String>], line: &Line, range: std::ops::RangeInclusive<usize>, at: u64) {
        for i in range {
            let col = i as u16;
            self.guesses.retain(|g| g.col != col);
            let (Some(Some(text)), Some(Some(shown))) = (view.get(i), line.cells.get(i)) else { continue };
            if !same(text, shown) {
                self.guesses.push(Guess { col, text: text.clone(), offset: at, epoch: self.epoch });
            }
        }
    }

    /// The far end's report, with `line` as the screen shows it after each
    /// byte that came before the report.
    pub(super) fn report(&mut self, report: Report, line: &Line, now: Instant) {
        if self.stopped {
            return;
        }
        // A far end that counts bytes never sent counts wrong: no guess of
        // this session can be judged any more.
        if report.offset > self.sent || report.offset < self.acked {
            self.stop();
            return;
        }
        let changed = self.flags.is_some_and(|f| f != report.flags);
        self.flags = Some(report.flags);
        self.acked = report.offset;
        self.sample(now);
        let guessing = !self.guesses.is_empty() || self.cursor.is_some();
        if changed || report.flags.hidden() || (guessing && self.row != Some(line.row)) {
            self.reset();
            return;
        }
        let mut wrong = false;
        let (acked, mut confirmed) = (self.acked, self.confirmed);
        self.guesses.retain(|g| {
            if g.offset > acked {
                return true;
            }
            match line.cells.get(usize::from(g.col)) {
                Some(Some(shown)) if same(shown, &g.text) => confirmed = confirmed.max(g.epoch),
                _ => wrong = true,
            }
            false
        });
        if let Some((col, _, epoch)) = self.cursor.filter(|c| c.1 <= acked) {
            if col == line.cursor {
                confirmed = confirmed.max(epoch);
            } else {
                wrong = true;
            }
            self.cursor = None;
        }
        self.confirmed = confirmed;
        if wrong {
            self.reset();
        }
    }

    /// The far end's output moved the cursor to `line`: guesses on another
    /// row are void.
    pub(super) fn output(&mut self, line: &Line) {
        let guessing = !self.guesses.is_empty() || self.cursor.is_some();
        if guessing && self.row != Some(line.row) {
            self.reset();
        }
    }

    /// A round trip's sample: the newest send that the report reaches,
    /// less the far end's wait for the echo.
    fn sample(&mut self, now: Instant) {
        let mut newest = None;
        while let Some(&(end, at)) = self.sends.front() {
            if end > self.acked {
                break;
            }
            newest = Some(at);
            self.sends.pop_front();
        }
        let Some(at) = newest else { return };
        let rtt = now.saturating_duration_since(at).saturating_sub(ECHO_WAIT);
        self.srtt = (self.srtt * 7 + rtt) / 8;
        self.showing = if self.showing { self.srtt >= HIDE_BELOW } else { self.srtt >= SHOW_FROM };
    }

    /// What to draw over `line`: the guessed cells, and the cursor's
    /// column; `None` when nothing differs from the screen, or nothing may
    /// show.
    pub(super) fn shown(&self, line: &Line) -> Option<(Vec<(u16, String)>, u16)> {
        let may = !self.stopped
            && self.showing
            && self.flags.is_some_and(|f| !f.hidden())
            && !line.hidden_cursor
            && self.row == Some(line.row)
            && line.cursor.saturating_add(1) < line.cols;
        if !may {
            return None;
        }
        let mut cells: Vec<(u16, String)> = self
            .guesses
            .iter()
            .filter(|g| g.epoch <= self.confirmed && !echoed(g, line))
            .map(|g| (g.col, g.text.clone()))
            .collect();
        cells.sort_by_key(|c| c.0);
        let cursor = self.cursor.filter(|c| c.2 <= self.confirmed).map_or(line.cursor, |c| c.0);
        if cells.is_empty() && cursor == line.cursor {
            return None;
        }
        Some((cells, cursor))
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
