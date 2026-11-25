//! The one thread, and its one runtime, on which each session of the layer's
//! road runs (T-811). A runtime for each session ended the connections of
//! HTTP/2 that the process's pool shares: their tasks run on the runtime
//! that opened them, so the end of the first session of `podssh each` broke
//! the streams of the others ("broken pipe"). One runtime for the life of
//! the process keeps each shared connection as long as a session holds it.
//! Its sessions are tasks of a `LocalSet`: the opener's future holds the
//! lines that it says, which no other thread may take.

use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};

/// A session of the road: made on the thread, from what is sent to it.
pub(super) type Job = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()>>> + Send>;

/// The stack of the command's own thread (`main.rs`): the opener's futures
/// are deep (a debug build overflowed 2 MiB once QUIC's race joined, T-667).
const STACK: usize = 16 << 20;

static JOBS: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();

/// Run `job` on the road's thread; `Err` with why when the thread or its
/// runtime could not start, so that the caller takes the contract's road.
pub(super) fn submit(job: Job) -> Result<(), String> {
    let jobs = match JOBS.get() {
        Some(jobs) => jobs,
        None => {
            let (send, receive) = mpsc::channel::<Job>();
            let (started, ready) = mpsc::channel::<Result<(), String>>();
            std::thread::Builder::new()
                .name("podssh-relay-layer".into())
                .stack_size(STACK)
                .spawn(move || serve(receive, started))
                .map_err(|e| format!("the resumable layer's thread did not start ({})", podssh_ws::text::said(&e)))?;
            ready.recv().map_err(|_| "the resumable layer's thread ended at its start".to_string())??;
            JOBS.get_or_init(|| Mutex::new(send))
        }
    };
    let sent = jobs.lock().unwrap_or_else(|e| e.into_inner()).send(job);
    sent.map_err(|_| "the resumable layer's thread has ended".to_string())
}

/// The thread: its runtime, then each job as a local task, for the life of
/// the process.
fn serve(jobs: mpsc::Receiver<Job>, started: mpsc::Sender<Result<(), String>>) {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = started
                .send(Err(format!("the resumable layer could not start its runtime ({})", podssh_ws::text::said(&e))));
            return;
        }
    };
    let _ = started.send(Ok(()));
    let local = tokio::task::LocalSet::new();
    local.block_on(&runtime, async move {
        // The blocking receive goes to a thread of the runtime's pool, so
        // that the sessions' tasks run while it waits.
        let jobs = std::sync::Arc::new(Mutex::new(jobs));
        loop {
            let next = jobs.clone();
            let job = tokio::task::spawn_blocking(move || next.lock().unwrap_or_else(|e| e.into_inner()).recv()).await;
            match job {
                Ok(Ok(job)) => {
                    tokio::task::spawn_local(job());
                }
                _ => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_job_runs_on_one_thread_and_runtime_and_both_outlive_a_job() {
        let (said, heard) = mpsc::channel();
        for n in 0..3 {
            let said = said.clone();
            submit(Box::new(move || {
                Box::pin(async move {
                    let id = tokio::runtime::Handle::current().id();
                    let _ = said.send((n, std::thread::current().id(), id));
                })
            }))
            .unwrap();
        }
        let got: Vec<_> = (0..3).map(|_| heard.recv_timeout(std::time::Duration::from_secs(10)).unwrap()).collect();
        assert!(got.windows(2).all(|w| w[0].1 == w[1].1 && w[0].2 == w[1].2), "{got:?}");
        assert_ne!(got[0].1, std::thread::current().id(), "not the caller's thread");
    }
}
