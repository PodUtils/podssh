//! The task that sends the frames of one view (T-303), a part of
//! `frames.rs` in a file of its own so that each stays short. It never
//! waits for the model; it writes the frames and the reports of its view's
//! queue in their order, the model's answers where its view writes them,
//! and at the end of the output the last frame, before the program's
//! status.

use std::collections::VecDeque;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use super::{encoded, make_view, unpoisoned, Inner, Out, Shared};
use crate::frames::sender::COLLECT;

/// How long an answer to a program's question may wait on a pty whose
/// program reads nothing; past it the answer is dropped, not the frames.
const ANSWER_WAIT: Duration = Duration::from_millis(200);
/// While the pump holds the model, how soon the task that sends tries it
/// again: the pump makes the frames that fall due meanwhile itself.
const BUSY: Duration = COLLECT;

impl Shared {
    /// [`Shared::run_told`] with no reports of local echo.
    #[cfg(test)]
    pub(in crate::server) async fn run(
        self: Arc<Self>,
        out: impl AsyncWrite + Unpin + Send,
        answers: impl AsyncWrite + Unpin + Send,
    ) {
        self.run_told(out, answers, None::<tokio::io::Sink>).await;
    }

    /// Send the frames of the newest view on `out` (the channel's extended
    /// data of `crate::frames::EXT`) until the pty's output ends, then the
    /// last one; `answers` is the pty's master, for the model's answers. A
    /// channel that is gone ends it. Local echo's reports go on `reports`
    /// (the extended data of `crate::predict::EXT`), each after the frame
    /// that it waited for.
    pub(in crate::server) async fn run_told(
        self: Arc<Self>,
        out: impl AsyncWrite + Unpin + Send,
        answers: impl AsyncWrite + Unpin + Send,
        reports: Option<impl AsyncWrite + Unpin + Send>,
    ) {
        let view = self.newest();
        self.run_epoch(view, out, answers, reports).await;
    }

    /// [`Shared::run_told`] for the channel of the view `view`: it ends with
    /// no last frame once the view left (another channel has the kept
    /// shell, a seat went), and leaves the view where its channel is gone.
    pub(in crate::server) async fn run_epoch(
        self: Arc<Self>,
        view: u64,
        mut out: impl AsyncWrite + Unpin + Send,
        mut answers: impl AsyncWrite + Unpin + Send,
        mut reports: Option<impl AsyncWrite + Unpin + Send>,
    ) {
        let Some(lane) = self.lane(view) else { return };
        loop {
            let now = Instant::now();
            // Never a wait for the model: while the pump has it, it makes
            // the frames itself, and this task looks again a moment later.
            let looked = match self.try_lock() {
                Some(mut guard) => {
                    let inner = &mut *guard;
                    self.heard(inner, now);
                    let ended = inner.ended;
                    let Inner { model, views, .. } = inner;
                    // The answers and what the client said are another
                    // channel's once this view left.
                    let Some(mine) = views.get_mut(&view) else { return };
                    if !ended {
                        make_view(model, mine, &mut None, now);
                    }
                    let answer = if mine.answers { model.take_answers() } else { Vec::new() };
                    Some((ended, mine.sender.due(), answer))
                }
                None => None,
            };
            if lane.gone.load(Ordering::Acquire) {
                return;
            }
            let made = std::mem::take(&mut *unpoisoned(&lane.queue));
            if !sent(made, &mut out, &mut reports).await {
                self.leave(view);
                return;
            }
            let (ended, due) = match looked {
                Some((ended, due, answer)) => {
                    if !answer.is_empty() {
                        // One write: an answer is never cut by the client's keys.
                        let _ = tokio::time::timeout(ANSWER_WAIT, answers.write_all(&answer)).await;
                    }
                    (ended, due)
                }
                None => (false, Some(now + BUSY)),
            };
            if ended {
                break;
            }
            match due {
                Some(at) => {
                    tokio::select! {
                        () = lane.wake.notified() => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
                None => lane.wake.notified().await,
            }
        }
        // The pump is gone: the model is fed no more; the reports that wait
        // go after the last frame.
        let last = {
            let mut guard = self.lock();
            let Inner { model, views, .. } = &mut *guard;
            let Some(mine) = views.get_mut(&view) else { return };
            let state = model.state();
            let (head, body) = mine.sender.last(&state, mine.bell, Instant::now());
            mine.bell = false;
            let frame = encoded(model, mine.version, mine.sender.since(), head, &body);
            (frame, std::mem::take(&mut mine.parked))
        };
        let mut made = std::mem::take(&mut *unpoisoned(&lane.queue));
        made.push_back(Out::Frame(last.0));
        made.extend(last.1.into_iter().map(Out::Report));
        if sent(made, &mut out, &mut reports).await {
            let _ = out.flush().await;
            if let Some(reports) = reports.as_mut() {
                let _ = reports.flush().await;
            }
        }
        self.leave(view);
    }
}

/// Write `made` in its order: each frame on `out`, each report on
/// `reports`. False where the frames' channel is gone; a report that
/// cannot go ends the reports alone.
async fn sent(
    made: VecDeque<Out>,
    out: &mut (impl AsyncWrite + Unpin + Send),
    reports: &mut Option<impl AsyncWrite + Unpin + Send>,
) -> bool {
    for item in made {
        match item {
            Out::Frame(bytes) => {
                if out.write_all(&bytes).await.is_err() {
                    return false;
                }
            }
            Out::Report(bytes) => {
                let failed = match reports.as_mut() {
                    Some(writer) => writer.write_all(&bytes).await.is_err(),
                    None => false,
                };
                if failed {
                    *reports = None;
                }
            }
        }
    }
    true
}
