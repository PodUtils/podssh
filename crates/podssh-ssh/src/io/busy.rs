//! The pump, watched (T-780): one step of it that holds 20 s, in place of
//! taking the channel's next message, is said at `-v` with its name. Where SSH
//! reads nothing of its stream and this says nothing, the pump waits in its
//! select, ready for a message, and the hold is in russh's own loop: its step
//! that holds 20 s is said too (podssh's patch of russh, `Step`).

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

    /// A task that says each step that holds, of the pump and of russh's
    /// loop, until the pump drops its watch.
    pub(super) fn watch(&self, log: &Arc<Log>, russh: russh::client::Step) -> tokio::task::JoinHandle<()> {
        let (busy, log) = (self.clone(), log.clone());
        tokio::spawn(async move {
            let (mut said, mut said_russh) = (None, None);
            while Arc::strong_count(&busy.0) > 1 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(line) = busy.line(Instant::now(), &mut said) {
                    log.verbose(&line);
                }
                if let Some(line) = loop_line(russh.now(), std::time::Instant::now(), &mut said_russh) {
                    log.verbose(&line);
                }
            }
        })
    }
}

/// The line of a step of russh's loop that held [`HOLD`] at `now`, once for
/// each step: the loop reads nothing of its stream meanwhile.
fn loop_line(
    step: Option<(std::time::Instant, &'static str)>,
    now: std::time::Instant,
    said: &mut Option<std::time::Instant>,
) -> Option<String> {
    let (since, what) = step?;
    let held = now.saturating_duration_since(since);
    if held < HOLD || *said == Some(since) {
        return None;
    }
    *said = Some(since);
    Some(format!("the SSH session's loop read nothing of its stream for {} s, held in {what}", held.as_secs()))
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

    /// A step of russh's loop that holds 20 s is said once, with its name;
    /// a loop in its select, or a shorter step, says nothing.
    #[test]
    fn a_step_of_the_loop_that_holds_is_said_once_with_its_name() {
        let since = std::time::Instant::now();
        let mut said = None;
        assert_eq!(loop_line(None, since + HOLD, &mut said), None, "the select is no hold");
        let step = Some((since, "the queue of a channel, with its CHANNEL_DATA"));
        assert_eq!(loop_line(step, since + HOLD / 2, &mut said), None, "not before 20 s");
        let line = loop_line(step, since + HOLD, &mut said).expect("said after 20 s");
        assert_eq!(
            line,
            "the SSH session's loop read nothing of its stream for 20 s, held in the queue of a channel, with its CHANNEL_DATA"
        );
        assert_eq!(loop_line(step, since + 2 * HOLD, &mut said), None, "once for each step");
        let next = Some((since + HOLD, "the handler's data"));
        assert!(loop_line(next, since + 2 * HOLD, &mut said).is_some(), "a new step is said again");
    }
}
