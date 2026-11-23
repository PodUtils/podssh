//! The state word of each forward (T-840), beside its counts: `bound` (its
//! listener bound or its request made, with no link yet), `waiting` (the
//! link was lost, and `--persist` connects again), `up`, and `refused`
//! (with the server's reason when it gave one). The word is one atomic, so
//! a read of it or a write of the same word takes no lock; only a refusal
//! keeps its reason under a lock, off the data path. With `--persist`, each
//! change is one line on stderr ([`announce`]), as nothing else says that a
//! forward waits through a lost link.

use std::sync::atomic::{AtomicU8, Ordering::Relaxed};
use std::sync::{Arc, Mutex};

use crate::log::Log;

/// The longest reason that a line keeps: a reason is a few words.
const REASON_MAX: usize = 200;

/// Where a forward stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Bound = 0,
    Waiting = 1,
    Up = 2,
    Refused = 3,
}

impl State {
    /// Each state, in the order of its number.
    pub const ALL: [State; 4] = [State::Bound, State::Waiting, State::Up, State::Refused];

    /// Its word, in `~#`, in the lines of `-v` and in `--result-file`.
    pub fn word(self) -> &'static str {
        match self {
            State::Bound => "bound",
            State::Waiting => "waiting",
            State::Up => "up",
            State::Refused => "refused",
        }
    }

    /// An unknown number reads as `bound`, the state that claims least.
    fn of(n: u8) -> State {
        State::ALL.get(usize::from(n)).copied().unwrap_or(State::Bound)
    }
}

/// The state of one forward, and the reason of its refusal.
#[derive(Debug, Default)]
pub struct Word {
    state: AtomicU8,
    reason: Mutex<Option<String>>,
}

impl Word {
    pub fn get(&self) -> State {
        State::of(self.state.load(Relaxed))
    }

    /// The server's reason of a refusal; none in another state.
    pub fn reason(&self) -> Option<String> {
        if self.get() != State::Refused {
            return None;
        }
        self.reason.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Set the state: whether it changed. The same word again takes no
    /// lock, as each connection of `-L` says `up`; a refusal with another
    /// reason is a change.
    pub fn set(&self, state: State, reason: Option<&str>) -> bool {
        if state != State::Refused && self.get() == state {
            return false;
        }
        let reason = reason.map(clean).filter(|r| !r.is_empty() && state == State::Refused);
        let mut kept = self.reason.lock().unwrap_or_else(|e| e.into_inner());
        let before = State::of(self.state.swap(state as u8, Relaxed));
        let changed = before != state || *kept != reason;
        *kept = reason;
        changed
    }

    /// The word as shown: `refused (REASON)` when the server gave one.
    pub fn shown(&self) -> String {
        match (self.get(), self.reason()) {
            (State::Refused, Some(reason)) => format!("refused ({reason})"),
            (state, _) => state.word().to_string(),
        }
    }
}

/// A reason as a line may hold it: one line of printable text, bounded, so
/// that no peer's words can forge a second line or fill the log.
fn clean(reason: &str) -> String {
    let one: String = reason.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let one = one.trim();
    match one.char_indices().nth(REASON_MAX) {
        Some((at, _)) => format!("{}...", &one[..at]),
        None => one.to_string(),
    }
}

/// The line of a change of `name` to `word` (as [`Word::shown`] gives it),
/// with `why` after it: the loss that names the hop that broke.
pub fn line(name: &str, word: &str, why: Option<&str>) -> String {
    match why {
        Some(why) => format!("{name}: {word}: {why}"),
        None => format!("{name}: {word}"),
    }
}

static ANNOUNCE: Mutex<Option<Arc<Log>>> = Mutex::new(None);

/// Say each change of a forward's state on `log` from now on (`--persist`),
/// or no longer, with `None`.
pub fn announce(log: Option<Arc<Log>>) {
    *ANNOUNCE.lock().unwrap_or_else(|e| e.into_inner()) = log;
}

/// Say `line`, when changes are said.
pub(crate) fn said(line: &str) {
    let log = ANNOUNCE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    if let Some(log) = log {
        log.info(line);
    }
}

#[cfg(test)]
#[path = "tally_state_tests.rs"]
mod tests;
