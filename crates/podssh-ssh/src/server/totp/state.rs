//! What a one-time code is judged by (T-115), apart from its file: the
//! last step that let a login in, so that a code is never taken twice
//! (RFC 6238, section 5.2), and each key's failures, so that each one
//! waits longer before the next try. Pure: the caller reads and writes the
//! state under the lock, and gives the time.

use std::fmt::Write as _;

use super::code::{self, DIGITS};

/// The first line of the state file.
const HEADER: &str = "podssh totp state 1";

/// The steps around now that a code may come from: one each way, for a
/// clock that is off by up to 30 s (RFC 6238, section 5.2).
pub const SKEW: u64 = 1;

/// The longest wait after failures.
pub const MOST_WAIT: u64 = 60;

/// Failures this old are forgotten.
pub const FORGET: u64 = 3600;

/// The most keys whose failures are kept; the oldest go first.
pub const MOST_KEYS: usize = 64;

/// One key's failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    /// The key's fingerprint.
    pub key: String,
    pub count: u32,
    /// The last failure, in Unix seconds.
    pub at: u64,
}

/// The state of one secret.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct State {
    /// The last step whose code let a login in; no code of it or before it
    /// is taken again.
    pub step: u64,
    pub failed: Vec<Failed>,
}

/// What a code met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    Accepted,
    /// Not the code of a step around now.
    Wrong,
    /// The code of a step that already let a login in.
    Replayed,
    /// The key failed lately: no code is judged for these seconds.
    Wait(u64),
}

impl Checked {
    /// The words of a refusal for serve's stderr and the audit log.
    pub fn says(&self) -> String {
        match self {
            Checked::Accepted => "accepted".into(),
            Checked::Wrong => "a wrong one-time code".into(),
            Checked::Replayed => "a one-time code that was used already".into(),
            Checked::Wait(secs) => format!("{secs} s to wait after the failures before it"),
        }
    }
}

/// The wait after `count` failures: 1 s, then twice as long each time, at
/// most [`MOST_WAIT`].
pub fn delay(count: u32) -> u64 {
    match count {
        0 => 0,
        n => 1u64.checked_shl(n - 1).unwrap_or(MOST_WAIT).min(MOST_WAIT),
    }
}

/// Judge `answer`, given for `key` at `now`, against `secret`, and change
/// `state` to match: the step taken, or the failure counted.
pub fn judge(state: &mut State, secret: &[u8], key: &str, answer: &[u8], now: u64) -> Checked {
    state.failed.retain(|f| now.saturating_sub(f.at) < FORGET);
    let count = state.failed.iter().find(|f| f.key == key).map_or(0, |f| f.count);
    let last = state.failed.iter().find(|f| f.key == key).map_or(0, |f| f.at);
    let until = last.saturating_add(delay(count));
    if now < until {
        return Checked::Wait(until - now);
    }
    let checked = match given(answer) {
        Some(digits) => match_step(secret, &digits, code::step_of(now)).map_or(Checked::Wrong, |step| {
            if step <= state.step {
                Checked::Replayed
            } else {
                state.step = step;
                Checked::Accepted
            }
        }),
        None => Checked::Wrong,
    };
    if checked == Checked::Accepted {
        state.failed.retain(|f| f.key != key);
    } else {
        fail(state, key, now);
    }
    checked
}

/// The answer as its digits: spaces around it are passed over; anything
/// but six ASCII digits is no code.
fn given(answer: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(answer).ok()?.trim();
    (text.len() == DIGITS as usize && text.bytes().all(|b| b.is_ascii_digit())).then(|| text.to_string())
}

/// The step around `now` whose code is `digits`, compared in a time that
/// does not depend on where they differ; each step is compared.
fn match_step(secret: &[u8], digits: &str, now: u64) -> Option<u64> {
    let mut found = None;
    for step in now.saturating_sub(SKEW)..=now.saturating_add(SKEW) {
        let Some(code) = code::code_of(secret, step) else { continue };
        if pod_core::entropy::same_secret(code.as_bytes(), digits.as_bytes()) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

fn fail(state: &mut State, key: &str, now: u64) {
    match state.failed.iter_mut().find(|f| f.key == key) {
        Some(f) => {
            f.count = f.count.saturating_add(1);
            f.at = now;
        }
        None => state.failed.push(Failed { key: key.to_string(), count: 1, at: now }),
    }
    if state.failed.len() > MOST_KEYS {
        state.failed.sort_by_key(|f| std::cmp::Reverse(f.at));
        state.failed.truncate(MOST_KEYS);
    }
}

/// The state file's text.
pub fn render(state: &State) -> String {
    let mut text = format!("{HEADER}\nstep {}\n", state.step);
    for f in &state.failed {
        let _ = writeln!(text, "failed {} {} {}", f.key, f.count, f.at);
    }
    text
}

/// The state of a file's text; Err names the line that is wrong. A state
/// that does not read is never taken as empty: that would take a code
/// again.
pub fn parse(text: &str) -> Result<State, String> {
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(format!("its first line is not {HEADER:?}"));
    }
    let mut state = State::default();
    for (n, line) in lines.enumerate().map(|(i, l)| (i + 2, l)) {
        let words: Vec<&str> = line.split(' ').collect();
        match words.as_slice() {
            ["step", step] => state.step = step.parse().map_err(|_| format!("line {n}: not a step"))?,
            ["failed", key, count, at] if !key.is_empty() && state.failed.len() < MOST_KEYS => {
                let count = count.parse().map_err(|_| format!("line {n}: not a count"))?;
                let at = at.parse().map_err(|_| format!("line {n}: not a time"))?;
                state.failed.push(Failed { key: key.to_string(), count, at });
            }
            [""] => {}
            _ => return Err(format!("line {n}: not a line of the state")),
        }
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"12345678901234567890";

    fn code_at(unix: u64) -> String {
        code::code_of(SECRET, code::step_of(unix)).unwrap().to_string()
    }

    /// The window: a code of the step before and after now is taken, two
    /// steps off is not.
    #[test]
    fn a_code_one_step_off_is_taken_and_two_are_not() {
        let now = 1_800_000_015;
        for (off, taken) in [(-60i64, false), (-30, true), (0, true), (30, true), (60, false)] {
            let mut state = State::default();
            let answer = code_at(now.saturating_add_signed(off));
            let checked = judge(&mut state, SECRET, "k", answer.as_bytes(), now);
            assert_eq!(checked == Checked::Accepted, taken, "{off} s: {checked:?}");
        }
    }

    /// A code is taken once: again, or an older one after it, is a replay;
    /// the next step's code is taken.
    #[test]
    fn a_code_is_never_taken_twice() {
        let now = 1_800_000_015;
        let mut state = State::default();
        assert_eq!(judge(&mut state, SECRET, "k", code_at(now).as_bytes(), now), Checked::Accepted);
        assert_eq!(judge(&mut state, SECRET, "k", code_at(now).as_bytes(), now + 2), Checked::Replayed);
        // The replay counts as a failure: one second to wait.
        assert_eq!(judge(&mut state, SECRET, "k", code_at(now - 30).as_bytes(), now + 2), Checked::Wait(1));
        assert_eq!(judge(&mut state, SECRET, "k", code_at(now - 30).as_bytes(), now + 3), Checked::Replayed);
        let later = now + 30;
        assert_eq!(judge(&mut state, SECRET, "k", code_at(later).as_bytes(), later), Checked::Accepted);
    }

    /// Each failure doubles the wait, up to its bound, for that key alone;
    /// a code that is no code is a failure too.
    #[test]
    fn each_failure_makes_the_key_wait_longer() {
        assert_eq!((0..9).map(delay).collect::<Vec<_>>(), vec![0, 1, 2, 4, 8, 16, 32, 60, 60]);
        let mut state = State::default();
        let mut now = 1_800_000_000;
        for answer in ["000000", "12345", "abcdef", "1234567"] {
            now += 120;
            let wrong = if code_at(now) == answer { "999999" } else { answer };
            assert_eq!(judge(&mut state, SECRET, "k", wrong.as_bytes(), now), Checked::Wrong, "{answer}");
            assert!(matches!(judge(&mut state, SECRET, "k", b"000000", now), Checked::Wait(_)));
        }
        assert_eq!(judge(&mut state, SECRET, "other", code_at(now).as_bytes(), now), Checked::Accepted);
        assert_eq!(state.failed.len(), 1, "{state:?}");
    }

    /// The file's text both ways; a text that does not read is refused.
    #[test]
    fn the_state_reads_back_and_a_broken_one_is_refused() {
        let state = State { step: 7, failed: vec![Failed { key: "SHA256:x".into(), count: 3, at: 9 }] };
        assert_eq!(parse(&render(&state)), Ok(state));
        for bad in ["", "podssh totp state 2\n", "podssh totp state 1\nstep x\n", "podssh totp state 1\nmore\n"] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }
}
