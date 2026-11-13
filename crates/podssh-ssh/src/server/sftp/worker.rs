//! The thread on which the file-system calls of one SFTP session run, each
//! within a time limit.
//!
//! A FIFO with no writer, or a dead mount, holds a call in the kernel, and
//! nothing can stop that thread: so a call past its limit is left on it, the
//! session answers with the failure, and its next call runs on a new thread.
//! A session that left [`MAX_STUCK`] threads ends, so a client cannot make
//! threads without bound. The threads are the session's own, never tokio's
//! blocking pool: a call that never returns would hold the runtime's end.

use std::sync::mpsc;
use std::time::Duration;

use tokio::sync::oneshot;

/// The most calls that a session may leave stuck before it ends.
pub const MAX_STUCK: usize = 8;

type Job = Box<dyn FnOnce() + Send>;

/// Why a call gave no result.
#[derive(Debug)]
pub(super) enum Failed {
    /// No answer within the limit: the call was left on its thread.
    Stuck(Duration),
    /// The call panicked, or no thread could run it.
    Lost(String),
}

/// One session's thread, made when a call needs it.
pub(super) struct Worker {
    jobs: Option<mpsc::Sender<Job>>,
    limit: Duration,
    /// The calls left stuck so far.
    pub(super) stuck: usize,
}

impl Worker {
    pub(super) fn new(limit: Duration) -> Worker {
        Worker { jobs: None, limit, stuck: 0 }
    }

    /// The thread's queue, with a new thread when there is none.
    fn sender(&mut self) -> std::io::Result<mpsc::Sender<Job>> {
        if let Some(jobs) = &self.jobs {
            return Ok(jobs.clone());
        }
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new().name("podssh-sftp".into()).spawn(move || {
            while let Ok(job) = rx.recv() {
                // A call that panics fails alone; the thread serves the next.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
            }
        })?;
        self.jobs = Some(tx.clone());
        Ok(tx)
    }

    /// Run `call` on the session's thread, and wait for it within the limit.
    pub(super) async fn call<T: Send + 'static>(
        &mut self,
        call: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, Failed> {
        let (tx, rx) = oneshot::channel();
        let job: Job = Box::new(move || {
            let _ = tx.send(call());
        });
        let unsent = match self.sender() {
            Ok(jobs) => match jobs.send(job) {
                Ok(()) => None,
                Err(mpsc::SendError(job)) => {
                    self.jobs = None;
                    Some(job)
                }
            },
            Err(_) => Some(job),
        };
        // No thread of its own (a cage that limits threads): tokio's pool
        // runs it, which is better than no answer.
        if let Some(job) = unsent {
            tokio::task::spawn_blocking(job);
        }
        match tokio::time::timeout(self.limit, rx).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(Failed::Lost("the call failed on its thread".into())),
            Err(_) => {
                // The stuck thread ends once its call returns, as its queue
                // is gone.
                self.jobs = None;
                self.stuck += 1;
                Err(Failed::Stuck(self.limit))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_call_past_its_limit_is_left_and_the_next_runs_on_a_new_thread() {
        let mut worker = Worker::new(Duration::from_millis(200));
        assert_eq!(worker.call(|| 7).await.unwrap(), 7);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let stuck = worker.call(move || held.recv().is_ok()).await;
        assert!(matches!(stuck, Err(Failed::Stuck(_))), "{stuck:?}");
        assert_eq!(worker.stuck, 1);
        // The session goes on while the first thread still waits.
        assert_eq!(worker.call(|| "next").await.unwrap(), "next");
        drop(release);
    }

    #[tokio::test]
    async fn a_call_that_panics_fails_alone() {
        let mut worker = Worker::new(Duration::from_secs(5));
        let lost = worker.call(|| -> u8 { panic!("planted") }).await;
        assert!(matches!(lost, Err(Failed::Lost(_))), "{lost:?}");
        assert_eq!(worker.call(|| 1).await.unwrap(), 1);
    }
}
