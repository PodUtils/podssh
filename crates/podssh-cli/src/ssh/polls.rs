//! The parts of one task, watched (T-780): SSH, the layer and the end-to-end
//! channel of a road run in one task (`tokio::join!`), so a part whose poll
//! does not return holds the others, the pump of SSH's channel among them.
//! Each part keeps when its poll entered and when it last returned; a poll
//! that has not returned for 20 s is said at `-v` with the part's name, and so
//! is a task none of whose parts was polled for 20 s while one waits on a
//! channel's full queue. A part parked on a wait that is never woken (the
//! pump's write that waited on russh's loop, which waited on the pump)
//! returns at once from each poll and is not named here: the pump's watch
//! (`podssh-ssh`'s `io/busy.rs`) names its step.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

/// How long a poll may stay in before it is said.
pub(crate) const HOLD: Duration = Duration::from_secs(20);

/// What one part's polls did.
#[derive(Default, Clone, Copy)]
struct Part {
    /// Since when its poll is in, while it is.
    inside: Option<Instant>,
    /// When its poll last returned.
    out: Option<Instant>,
}

/// The parts of one task, by name.
#[derive(Default)]
pub(crate) struct Polls(Mutex<Vec<(&'static str, Part)>>);

impl Polls {
    fn set(&self, at: usize, part: Part) {
        let mut parts = self.0.lock().unwrap_or_else(|e| e.into_inner());
        parts[at].1 = part;
    }

    fn get(&self, at: usize) -> Part {
        self.0.lock().unwrap_or_else(|e| e.into_inner())[at].1
    }

    /// `part` of the task, with each poll kept under `name`.
    pub(crate) fn watched<F: Future>(self: &Arc<Self>, name: &'static str, part: F) -> impl Future<Output = F::Output> {
        let at = {
            let mut parts = self.0.lock().unwrap_or_else(|e| e.into_inner());
            parts.push((name, Part::default()));
            parts.len() - 1
        };
        let (polls, mut part) = (self.clone(), Box::pin(part));
        std::future::poll_fn(move |cx| {
            let before = polls.get(at);
            polls.set(at, Part { inside: Some(Instant::now()), ..before });
            let polled = part.as_mut().poll(cx);
            polls.set(at, Part { inside: None, out: Some(Instant::now()) });
            polled
        })
    }

    /// The lines at `now`: a part whose poll has not returned for [`HOLD`],
    /// once for each poll; and, where no poll is in, none returned for
    /// [`HOLD`] (said once for each last return), which tells something
    /// only beside a channel whose queue is full.
    fn lines(&self, now: Instant, said: &mut Vec<Instant>) -> Vec<String> {
        let parts = self.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut lines = Vec::new();
        for (name, part) in &parts {
            if let Some(since) = part.inside
                && now.duration_since(since) >= HOLD
                && !said.contains(&since)
            {
                said.push(since);
                lines.push(format!(
                    "the poll of {name} has not returned for {} s: it holds its task",
                    now.duration_since(since).as_secs()
                ));
            }
        }
        let any_in = parts.iter().any(|(_, p)| p.inside.is_some());
        let last = parts.iter().filter_map(|(_, p)| p.out).max();
        if let Some(last) = last
            && !any_in
            && now.duration_since(last) >= HOLD
            && !said.contains(&last)
        {
            said.push(last);
            let names: Vec<&str> = parts.iter().map(|(name, _)| *name).collect();
            lines.push(format!(
                "no part of the task of {} was polled for {} s",
                names.join(", "),
                now.duration_since(last).as_secs()
            ));
        }
        lines
    }
}

/// Say each line of `polls` each second, while a part holds `polls` beside
/// this task.
pub(crate) async fn watch(polls: Arc<Polls>, say: impl Fn(String)) {
    let mut said = Vec::new();
    while Arc::strong_count(&polls) > 1 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        for line in polls.lines(Instant::now(), &mut said) {
            say(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A part whose poll does not return is named once after 20 s; a task
    /// whose parts all returned and were not polled again is said once.
    #[tokio::test(start_paused = true)]
    async fn a_poll_that_does_not_return_is_named() {
        let polls = Arc::new(Polls::default());
        let quiet = polls.watched("the layer", std::future::pending::<()>());
        let mut quiet = std::pin::pin!(quiet);
        let mut said = Vec::new();
        assert!(futures_poll_once(quiet.as_mut()).await.is_pending());
        assert!(polls.lines(Instant::now(), &mut said).is_empty(), "polled now");
        tokio::time::advance(HOLD).await;
        let lines = polls.lines(Instant::now(), &mut said);
        assert_eq!(lines, ["no part of the task of the layer was polled for 20 s"]);
        assert!(polls.lines(Instant::now(), &mut said).is_empty(), "once for each last return");
        // A poll that stays in: set by hand, as a poll that blocks the thread
        // would leave it.
        polls.set(0, Part { inside: Some(Instant::now()), out: None });
        tokio::time::advance(HOLD).await;
        let lines = polls.lines(Instant::now(), &mut said);
        assert_eq!(lines, ["the poll of the layer has not returned for 20 s: it holds its task"]);
        assert!(polls.lines(Instant::now(), &mut said).is_empty(), "once for each poll");
    }

    /// One poll of `fut`.
    async fn futures_poll_once<F: Future + ?Sized>(fut: std::pin::Pin<&mut F>) -> std::task::Poll<F::Output> {
        let mut fut = Some(fut);
        std::future::poll_fn(|cx| std::task::Poll::Ready(fut.take().unwrap().poll(cx))).await
    }
}
