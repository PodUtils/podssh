//! The count of local echo (T-160), apart from `predict.rs` so that a
//! shell shared by name (T-896, `share_told.rs`), which builds on each
//! system, counts each seat's bytes the same way: how many of a client's
//! bytes reached the tty, and when each write falls due for a report.

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// count is unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::sync::Notify;
use tokio::time::Instant;

use crate::predict::report::ECHO_WAIT;

/// The writes not yet reported, kept at most: past them the oldest goes,
/// and a later write's count covers it.
const KEPT: usize = 1024;

#[derive(Debug, Default)]
struct State {
    offset: u64,
    writes: VecDeque<(u64, Instant)>,
}

#[derive(Debug, Default)]
struct Shared {
    state: Mutex<State>,
    /// Wakes the task of the output at a write: a key that makes no output
    /// (a line with no echo) must still get its report.
    wake: Notify,
}

/// The count of the client's bytes written to the tty, shared by the
/// writer of the input and the task of the output.
#[derive(Debug, Clone, Default)]
pub(super) struct Applied(Arc<Shared>);

impl Applied {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn wrote(&self, n: usize, now: Instant) {
        let mut state = self.state();
        state.offset += n as u64;
        let end = state.offset;
        if state.writes.len() == KEPT {
            state.writes.pop_front();
        }
        state.writes.push_back((end, now));
        drop(state);
        // A permit is kept where no task waits, so no write is missed.
        self.0.wake.notify_one();
    }

    /// Until the oldest write not reported falls due, waiting for a write
    /// where none waits.
    pub(super) async fn fall_due(&self) {
        loop {
            match self.due() {
                Some(at) => return tokio::time::sleep_until(at).await,
                None => self.0.wake.notified().await,
            }
        }
    }

    /// The count of the writes that are [`ECHO_WAIT`] old at `now`, if any
    /// is new; they are reported once.
    pub(super) fn ripe(&self, now: Instant) -> Option<u64> {
        let mut state = self.state();
        let mut ripe = None;
        while let Some(&(end, at)) = state.writes.front() {
            if at + ECHO_WAIT > now {
                break;
            }
            ripe = Some(end);
            state.writes.pop_front();
        }
        ripe
    }

    /// When the oldest write not reported falls due.
    pub(super) fn due(&self) -> Option<Instant> {
        self.state().writes.front().map(|&(_, at)| at + ECHO_WAIT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A count is reported once it is ECHO_WAIT old, and once only; the
    /// next write's time is the next report's.
    #[test]
    fn a_count_ripens_after_the_echo_wait_and_is_reported_once() {
        let applied = Applied::default();
        let start = Instant::now();
        applied.wrote(3, start);
        applied.wrote(2, start + Duration::from_millis(30));
        assert_eq!(applied.due(), Some(start + ECHO_WAIT));
        assert_eq!(applied.ripe(start + ECHO_WAIT - Duration::from_millis(1)), None);
        assert_eq!(applied.ripe(start + ECHO_WAIT), Some(3));
        assert_eq!(applied.ripe(start + ECHO_WAIT), None, "once");
        assert_eq!(applied.due(), Some(start + Duration::from_millis(30) + ECHO_WAIT));
        assert_eq!(applied.ripe(start + Duration::from_secs(1)), Some(5));
        assert_eq!(applied.due(), None);
    }

    /// A write while the task waits with nothing due wakes it, and it
    /// ends once that write's count is ECHO_WAIT old; with no write it
    /// never ends.
    #[tokio::test(start_paused = true)]
    async fn a_write_while_nothing_is_due_wakes_the_wait() {
        let applied = Applied::default();
        let waiting = applied.clone();
        let wait = tokio::spawn(async move { waiting.fall_due().await });
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert!(!wait.is_finished(), "nothing written, nothing due");
        let start = Instant::now();
        applied.wrote(1, start);
        wait.await.unwrap();
        assert!(Instant::now() >= start + ECHO_WAIT, "after the echo wait");
        assert_eq!(applied.ripe(Instant::now()), Some(1));
    }
}
