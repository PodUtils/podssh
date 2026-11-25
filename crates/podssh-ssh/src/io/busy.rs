//! The pump, watched (T-780): one step of it that holds 20 s, in place of
//! taking the channel's next message, is said at `-v` with its name. Where SSH
//! reads nothing of its stream and this says nothing, the pump waits in its
//! select, ready for a message, and the hold is in russh's own loop: its step
//! that holds 20 s is said too (podssh's patch of russh, `Step`), with the
//! channel that it waits on beside the session's own. An idle pump whose wait
//! of its channel was woken and not polled for 20 s is said too: its task holds
//! elsewhere, and nothing drains the channel's queue. A step that waits on
//! the session drains the channel beside it (`beside.rs`), and says so.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Wake, Waker};
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
    /// When the wait of the channel was woken and not polled since: a wait
    /// that nothing woke is idle, not held, however long it lasts.
    woken: Arc<Mutex<Option<Instant>>>,
}

/// The waker of the channel's wait, which keeps the time of its first wake
/// since the last poll, then wakes the task as the runtime's would.
struct Noted {
    inner: Waker,
    woken: Arc<Mutex<Option<Instant>>>,
}

impl Wake for Noted {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.lock().unwrap_or_else(|e| e.into_inner()).get_or_insert_with(Instant::now);
        self.inner.wake_by_ref();
    }
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
        *self.woken.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    /// `wait`, the pump's wait of its channel, with the time of each poll
    /// kept, and the time of a wake that no poll followed.
    pub(super) fn polled<F: Future>(&self, wait: F) -> impl Future<Output = F::Output> {
        let (polled, woken) = (self.polled.clone(), self.woken.clone());
        let mut wait = Box::pin(wait);
        // The task's waker, and ours over it, made again only when the task's
        // changes.
        let mut ours: Option<(Waker, Waker)> = None;
        std::future::poll_fn(move |cx| {
            *polled.lock().unwrap_or_else(|e| e.into_inner()) = Some(Instant::now());
            *woken.lock().unwrap_or_else(|e| e.into_inner()) = None;
            let waker = match &ours {
                Some((task, noted)) if task.will_wake(cx.waker()) => noted.clone(),
                _ => {
                    let noted = Waker::from(Arc::new(Noted { inner: cx.waker().clone(), woken: woken.clone() }));
                    ours = Some((cx.waker().clone(), noted.clone()));
                    noted
                }
            };
            wait.as_mut().poll(&mut Context::from_waker(&waker))
        })
    }

    /// The line of a step that held [`HOLD`] at `now`, once for each step;
    /// or of an idle pump whose wait was woken and not polled for [`HOLD`],
    /// once for each wake. A wait that nothing woke is a quiet session (a
    /// remote `sleep`), and says nothing.
    fn line(&self, now: Instant, said: &mut Option<Instant>) -> Option<String> {
        let step = *self.step.lock().unwrap_or_else(|e| e.into_inner());
        let Some((since, what)) = step else {
            let woken = (*self.woken.lock().unwrap_or_else(|e| e.into_inner()))?;
            if now.duration_since(woken) < HOLD || *said == Some(woken) {
                return None;
            }
            *said = Some(woken);
            return Some(format!(
                "the session's channel has a message, and its wait was not polled for {} s since: the task that runs \
                 it holds elsewhere",
                now.duration_since(woken).as_secs()
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

    /// A quiet session, whose wait nothing woke, says nothing however long it
    /// waits; a wait that was woken and not polled for 20 s is said once, and
    /// a poll ends it.
    #[tokio::test(start_paused = true)]
    async fn only_a_woken_wait_that_is_not_polled_is_said() {
        let busy = Busy::default();
        let mut said = None;
        busy.idle();
        assert_eq!(busy.line(Instant::now(), &mut said), None, "never polled: nothing to say");
        // The channel's wait keeps its waker, as a channel's receiver does.
        let kept: Arc<Mutex<Option<Waker>>> = Arc::default();
        let slot = kept.clone();
        let channel = std::future::poll_fn(move |cx| {
            *slot.lock().unwrap() = Some(cx.waker().clone());
            std::task::Poll::<()>::Pending
        });
        let mut wait = std::pin::pin!(busy.polled(channel));
        assert!(futures_poll_once(wait.as_mut()).await.is_pending());
        tokio::time::advance(3 * HOLD).await;
        assert_eq!(busy.line(Instant::now(), &mut said), None, "a quiet session is idle, not held");
        kept.lock().unwrap().take().expect("a waker").wake();
        tokio::time::advance(HOLD / 2).await;
        assert_eq!(busy.line(Instant::now(), &mut said), None, "woken 10 s ago");
        tokio::time::advance(HOLD).await;
        let line = busy.line(Instant::now(), &mut said).expect("said 20 s after a wake with no poll");
        let starts = "the session's channel has a message, and its wait was not polled for 30 s";
        assert!(line.starts_with(starts), "{line}");
        assert_eq!(busy.line(Instant::now(), &mut said), None, "once for each wake");
        assert!(futures_poll_once(wait.as_mut()).await.is_pending());
        tokio::time::advance(3 * HOLD).await;
        assert_eq!(busy.line(Instant::now(), &mut said), None, "polled again, and quiet: nothing");
    }

    /// One poll of `fut`.
    async fn futures_poll_once<F: Future + ?Sized>(fut: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let mut fut = Some(fut);
        std::future::poll_fn(|cx| std::task::Poll::Ready(fut.take().unwrap().poll(cx))).await
    }
}
