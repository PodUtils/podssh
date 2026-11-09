//! The node's journal line for a session that the relay closed with a reason
//! (T-701): without it, an operator learns that a cut was the byte cap only
//! by reproducing it on the relay.

use std::time::Instant;

use crate::session::budget::SAY_EVERY;

/// The reason's longest part that the line keeps; the relay cuts its own to
/// 123 bytes, and a journal line wants less.
const KEPT: usize = 80;
/// The characters of a session's id that the line names, no more.
const ID_CHARS: usize = 8;

/// When the node last said such a line, so that a burst of cuts says one.
#[derive(Debug, Default)]
pub struct CloseSay {
    last: Option<Instant>,
}

impl CloseSay {
    /// The line for a close of session `id` with `reason` at `now`, or `None`
    /// for a close with no reason (a normal end) or one said less than
    /// [`SAY_EVERY`] ago.
    pub fn line(&mut self, now: Instant, id: &str, reason: Option<&str>) -> Option<String> {
        let reason = reason.map(str::trim).filter(|r| !r.is_empty())?;
        if self.last.is_some_and(|at| now.saturating_duration_since(at) < SAY_EVERY) {
            return None;
        }
        self.last = Some(now);
        // The relay's text is data: no control character reaches the journal.
        let reason: String = reason.chars().filter(|c| !c.is_control()).take(KEPT).collect();
        let id: String = id.chars().take(ID_CHARS).collect();
        Some(format!("the relay closed session {id}...: {reason}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn a_burst_of_cuts_says_the_reason_once() {
        let (mut say, t0) = (CloseSay::default(), Instant::now());
        let first = say.line(t0, "0123456789abcdef", Some("session byte cap"));
        assert_eq!(first.as_deref(), Some("the relay closed session 01234567...: session byte cap"));
        for i in 1..20 {
            assert_eq!(say.line(t0 + Duration::from_millis(i), "ffff", Some("session byte cap")), None);
        }
        assert!(say.line(t0 + SAY_EVERY, "ffff", Some("session byte cap")).is_some(), "the next minute says it again");
    }

    #[test]
    fn a_normal_close_says_nothing_and_takes_no_turn() {
        let (mut say, t0) = (CloseSay::default(), Instant::now());
        assert_eq!(say.line(t0, "abcd", None), None);
        assert_eq!(say.line(t0, "abcd", Some("  ")), None);
        assert!(say.line(t0, "abcd", Some("session byte cap")).is_some(), "a silent close keeps the turn");
    }

    #[test]
    fn the_reason_is_clean_and_short() {
        let mut say = CloseSay::default();
        let line = say.line(Instant::now(), "abcd", Some(&format!("a\x1b[31mb{}", "x".repeat(500)))).unwrap();
        assert!(!line.contains('\x1b') && line.len() < 140, "{line}");
    }
}
