//! The pump, watched (T-780): one step of it that holds 20 s, in place of
//! taking the channel's next message, is said at `-v` with its name. Where SSH
//! reads nothing of its stream and this says nothing, the pump waits in its
//! select, ready for a message, and the hold is in russh's own loop: its step
//! that holds 20 s is said too (podssh's patch of russh, `Step`), with the
//! channel that it waits on beside the session's own. An idle pump whose wait
//! of its channel was not polled for 20 s is said too: its task holds
//! elsewhere, and nothing drains the channel's queue. A step that waits on
//! the session drains the channel beside it (`beside.rs`), and says so.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh::ChannelId;

use tokio::time::Instant;

use crate::log::Log;

/// How long a step may hold before it is said.
const HOLD: Duration = Duration::from_secs(20);

/// The step that the pump is in, and since when (none while it waits in its
/// select); and when its wait of the channel was last polled.
#[derive(Clone, Default)]
pub(super) struct Busy {
    step: Arc<Mutex<Option<(Instant, &'static str)>>>,
    polled: Arc<Mutex<Option<Instant>>>,
}

impl Busy {
    /// The pump is in `what` from now.
    pub(super) fn at(&self, what: &'static str) {
        *self.step.lock().unwrap_or_else(|e| e.into_inner()) = Some((Instant::now(), what));
    }

    /// The pump waits in its select, and takes the next message.
    pub(super) fn idle(&self) {
        *self.step.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// The pump's wait of its channel was polled now, beside a wait on the
    /// session (`beside.rs`).
    pub(super) fn mark(&self) {
        *self.polled.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
    }

    /// `wait`, the pump's wait of its channel, with the time of each poll kept.
    pub(super) fn polled<F: Future>(&self, wait: F) -> impl Future<Output = F::Output> {
        let polled = self.polled.clone();
        let mut wait = Box::pin(wait);
        std::future::poll_fn(move |cx| {
            *polled.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            wait.as_mut().poll(cx)
        })
    }

    /// The line of a step that held [`HOLD`] at `now`, once for each step;
    /// or of an idle pump whose wait was not polled for [`HOLD`], once for
    /// each last poll.
    fn line(&self, now: Instant, said: &mut Option<Instant>) -> Option<String> {
        let step = *self.step.lock().unwrap_or_else(|e| e.into_inner());
        let Some((since, what)) = step else {
            let last = (*self.polled.lock().unwrap_or_else(|e| e.into_inner()))?;
            if now.duration_since(last) < HOLD || *said == Some(last) {
                return None;
            }
            *said = Some(last);
            return Some(format!(
                "the session waits for its channel, and its wait was not polled for {} s: the task that runs it holds elsewhere",
                now.duration_since(last).as_secs()
            ));
        };
        if now.duration_since(since) < HOLD || *said == Some(since) {
            return None;
        }
        *said = Some(since);
        // A step beside the channel takes its messages meanwhile: the wait
        // is the session's, and no queue fills behind it.
        let last = *self.polled.lock().unwrap_or_else(|e| e.into_inner());
        if last.is_some_and(|last| last >= since && now.duration_since(last) < HOLD) {
            return Some(format!(
                "the session has waited {} s in {what}, and takes its channel's messages meanwhile",
                now.duration_since(since).as_secs()
            ));
        }
        Some(format!(
            "the session took no message of its channel for {} s, held in {what}",
            now.duration_since(since).as_secs()
        ))
    }

    /// A task that says each step that holds, of the pump and of russh's
    /// loop, until the pump drops its watch.
    pub(super) fn watch(
        &self,
        log: &Arc<Log>,
        russh: russh::client::Step,
        own: ChannelId,
    ) -> tokio::task::JoinHandle<()> {
        let (busy, log) = (self.clone(), log.clone());
        tokio::spawn(async move {
            let (mut said, mut said_russh) = (None, None);
            while Arc::strong_count(&busy.step) > 1 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some(line) = busy.line(Instant::now(), &mut said) {
                    log.verbose(&line);
                }
                let step = russh.now().map(|s| (s.since, s.what, s.channel.map(u32::from)));
                if let Some(line) = loop_line(step, u32::from(own), std::time::Instant::now(), &mut said_russh) {
                    log.verbose(&line);
                }
            }
        })
    }
}

/// The line of a step of russh's loop that held [`HOLD`] at `now`, once for
/// each step: the loop reads nothing of its stream meanwhile. A step on a
/// channel's queue names that channel and the session's own (`own`).
fn loop_line(
    step: Option<(std::time::Instant, &'static str, Option<u32>)>,
    own: u32,
    now: std::time::Instant,
    said: &mut Option<std::time::Instant>,
) -> Option<String> {
    let (since, what, channel) = step?;
    let held = now.saturating_duration_since(since);
    if held < HOLD || *said == Some(since) {
        return None;
    }
    *said = Some(since);
    let which = match channel {
        Some(channel) => format!(" {channel}; this session's channel is {own}"),
        None => String::new(),
    };
    Some(format!("the SSH session's loop read nothing of its stream for {} s, held in {what}{which}", held.as_secs()))
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

    /// A step that waits on the session beside the channel says so: its wait
    /// of the channel was polled meanwhile.
    #[tokio::test(start_paused = true)]
    async fn a_step_beside_the_channel_says_that_it_takes_the_messages() {
        let busy = Busy::default();
        let mut said = None;
        busy.at("the end of the input");
        tokio::time::advance(HOLD - Duration::from_secs(1)).await;
        busy.mark();
        tokio::time::advance(Duration::from_secs(1)).await;
        let line = busy.line(Instant::now(), &mut said).expect("said after 20 s");
        assert_eq!(
            line,
            "the session has waited 20 s in the end of the input, and takes its channel's messages meanwhile"
        );
        busy.at("the end of the input");
        tokio::time::advance(HOLD).await;
        let line = busy.line(Instant::now(), &mut said).expect("a new step is said");
        assert!(line.starts_with("the session took no message of its channel for 20 s"), "{line}");
    }

    /// A step of russh's loop that holds 20 s is said once, with its name;
    /// a loop in its select, or a shorter step, says nothing.
    #[test]
    fn a_step_of_the_loop_that_holds_is_said_once_with_its_name() {
        let since = std::time::Instant::now();
        let mut said = None;
        assert_eq!(loop_line(None, 2, since + HOLD, &mut said), None, "the select is no hold");
        let step = Some((since, "the queue of a channel, with its CHANNEL_DATA", Some(5)));
        assert_eq!(loop_line(step, 2, since + HOLD / 2, &mut said), None, "not before 20 s");
        let line = loop_line(step, 2, since + HOLD, &mut said).expect("said after 20 s");
        assert_eq!(
            line,
            "the SSH session's loop read nothing of its stream for 20 s, held in the queue of a channel, with its \
             CHANNEL_DATA 5; this session's channel is 2"
        );
        assert_eq!(loop_line(step, 2, since + 2 * HOLD, &mut said), None, "once for each step");
        let next = Some((since + HOLD, "the handler's data", None));
        let line = loop_line(next, 2, since + 2 * HOLD, &mut said).expect("a new step is said again");
        assert!(line.ends_with("held in the handler's data"), "{line}");
    }

    /// An idle pump whose wait was not polled for 20 s is said once; one
    /// polled since says nothing.
    #[tokio::test(start_paused = true)]
    async fn an_idle_pump_whose_wait_is_not_polled_is_said_once() {
        let busy = Busy::default();
        let mut said = None;
        busy.idle();
        assert_eq!(busy.line(Instant::now(), &mut said), None, "never polled: nothing to say");
        let mut wait = std::pin::pin!(busy.polled(std::future::pending::<()>()));
        assert!(futures_poll_once(wait.as_mut()).await.is_pending());
        tokio::time::advance(HOLD / 2).await;
        assert_eq!(busy.line(Instant::now(), &mut said), None, "polled 10 s ago");
        tokio::time::advance(HOLD).await;
        let line = busy.line(Instant::now(), &mut said).expect("said after 20 s with no poll");
        assert!(line.starts_with("the session waits for its channel, and its wait was not polled for 30 s"), "{line}");
        assert_eq!(busy.line(Instant::now(), &mut said), None, "once for each last poll");
        assert!(futures_poll_once(wait.as_mut()).await.is_pending());
        assert_eq!(busy.line(Instant::now(), &mut said), None, "polled again: nothing");
    }

    /// One poll of `fut`.
    async fn futures_poll_once<F: Future + ?Sized>(fut: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let mut fut = Some(fut);
        std::future::poll_fn(|cx| std::task::Poll::Ready(fut.take().unwrap().poll(cx))).await
    }
}
