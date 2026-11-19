//! The pump, watched (T-780): one step of it that holds 20 s, in place of
//! taking the channel's next message, is said at `-v` with its name. Where SSH
//! reads nothing of its stream and this says nothing, the pump waits in its
//! select, ready for a message, and the hold is in russh's own loop.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

use crate::log::Log;

/// How long a step may hold before it is said.
const HOLD: Duration = Duration::from_secs(20);

/// The step that the pump is in, and since when; none while it waits in its
/// select.
#[derive(Clone, Default)]
pub(super) struct Busy(Arc<Mutex<Option<(Instant, &'static str)>>>);

impl Busy {
    /// The pump is in `what` from now.
    pub(super) fn at(&self, what: &'static str) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), what));
    }

    /// The pump waits in its select, and takes the next message.
    pub(super) fn idle(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The line of a step that held [`HOLD`] at `now`, once for each step.
    fn line(&self, now: Instant, said: &mut Option<Instant>) -> Option<String> {
        let (since, what) = (*self.0.lock().unwrap_or_else(|e| e.into_inner()))?;
        if now.duration_since(since) < HOLD || *said == Some(since) {
            return None;
        }
        *said = Some(since);
        Some(format!(
            "the session took no message of its channel for {} s, held in {what}",
            now.duration_since(since).as_secs()
        ))
    }

    /// A task that says each step that holds, until the pump drops its watch.
    pub(super) fn watch(&self, log: &Arc<Log>) -> tokio::task::JoinHandle<()> {
        let (busy, log) = (self.clone(), log.clone());
        tokio::spawn(async move {
            let mut said = None;
            while Arc::strong_count(&busy.0) > 1 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(line) = busy.line(Instant::now(), &mut said) {
                    log.verbose(&line);
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A step that holds 20 s is said once, with its name; a pump in its
    /// select says nothing.
    #[tokio::test(start_paused = true)]
    async fn a_step_that_holds_is_said_once_with_its_name() {
        let busy = Busy::default();
        let mut said = None;
        busy.idle();
        tokio::time::advance(HOLD).await;
        assert_eq!(busy.line(Instant::now(), &mut said), None, "waiting in the select is no hold");
        busy.at("the output to stdout");
        assert_eq!(busy.line(Instant::now(), &mut said), None, "not before 20 s");
        tokio::time::advance(HOLD).await;
        let line = busy.line(Instant::now(), &mut said).expect("said after 20 s");
        assert_eq!(line, "the session took no message of its channel for 20 s, held in the output to stdout");
        assert_eq!(busy.line(Instant::now(), &mut said), None, "once for each step");
    }
}
