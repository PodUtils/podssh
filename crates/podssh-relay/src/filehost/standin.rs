//! In-process stand-ins of a file host and of a board, for the tests: each
//! keeps what it was given in memory, answers as a host or a board of
//! `pod-services` would, and counts its calls. A shared [`Counter`] sees how
//! many calls of the road are open at once, which the road's gate keeps at
//! one.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use super::board::{Board, Posting};
use super::host::{Doing, Host, Refusal, Stored};
use super::keys::OVERHEAD;
use super::PIECE_MOST;

/// The calls of a road that are open now, and the most that ever were.
#[derive(Clone, Default)]
pub struct Counter {
    open: Arc<AtomicUsize>,
    most: Arc<AtomicUsize>,
}

impl Counter {
    /// One call: counted while it runs, with a yield in it, so that a call
    /// made beside it would be seen.
    async fn call<T>(&self, done: impl FnOnce() -> T) -> T {
        let now = self.open.fetch_add(1, Ordering::SeqCst) + 1;
        self.most.fetch_max(now, Ordering::SeqCst);
        tokio::task::yield_now().await;
        let out = done();
        self.open.fetch_sub(1, Ordering::SeqCst);
        out
    }

    pub fn most(&self) -> usize {
        self.most.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct Files {
    stored: HashMap<String, Vec<u8>>,
    uploads: usize,
    deleted: Vec<String>,
    next: u64,
}

/// A file host in memory, at `https://NAME/ID/piece.bin`.
pub struct StandInHost {
    name: String,
    per_hour: Option<u32>,
    most: usize,
    /// Answers busy from this upload on.
    busy_from: Option<usize>,
    deletes: bool,
    files: Mutex<Files>,
    counter: Counter,
}

impl StandInHost {
    pub fn new(name: &str, per_hour: Option<u32>, counter: Counter) -> StandInHost {
        StandInHost {
            name: name.into(),
            per_hour,
            most: PIECE_MOST + OVERHEAD,
            busy_from: None,
            deletes: true,
            files: Mutex::new(Files::default()),
            counter,
        }
    }

    pub fn with_most(mut self, most: usize) -> StandInHost {
        self.most = most;
        self
    }

    /// Busy (429) from the `n`th upload on, counted from 0.
    pub fn busy_from(mut self, n: usize) -> StandInHost {
        self.busy_from = Some(n);
        self
    }

    /// A host that cannot delete, as one whose form has no delete.
    pub fn never_deletes(mut self) -> StandInHost {
        self.deletes = false;
        self
    }

    fn files(&self) -> std::sync::MutexGuard<'_, Files> {
        self.files.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The uploads that it took.
    pub fn uploads(&self) -> usize {
        self.files().uploads
    }

    /// The bytes that it keeps now, each upload's.
    pub fn kept(&self) -> Vec<Vec<u8>> {
        self.files().stored.values().cloned().collect()
    }

    /// Change a byte of each upload that it keeps, as a host that is not
    /// to be trusted would.
    pub fn spoil(&self) {
        for bytes in self.files().stored.values_mut() {
            if let Some(last) = bytes.last_mut() {
                *last ^= 1;
            }
        }
    }

    /// The URLs deleted.
    pub fn deleted(&self) -> Vec<String> {
        self.files().deleted.clone()
    }
}

impl Host for StandInHost {
    fn name(&self) -> &str {
        &self.name
    }

    fn most(&self) -> usize {
        self.most
    }

    fn per_hour(&self) -> Option<u32> {
        self.per_hour
    }

    fn one_person(&self) -> bool {
        true
    }

    fn owns(&self, url: &str) -> bool {
        let rest = url.strip_prefix("https://").and_then(|rest| rest.strip_prefix(self.name.as_str()));
        rest.is_some_and(|path| path.starts_with('/'))
    }

    fn upload(&self, sealed: Vec<u8>) -> Doing<'_, Stored> {
        Box::pin(self.counter.call(move || {
            let mut files = self.files();
            if self.busy_from.is_some_and(|from| files.uploads >= from) {
                return Err(Refusal::Busy(None));
            }
            if sealed.len() > self.most {
                return Err(Refusal::Failed(format!("{} bytes is over {}", sealed.len(), self.most)));
            }
            files.uploads += 1;
            files.next += 1;
            let url = format!("https://{}/{}/piece.bin", self.name, files.next);
            files.stored.insert(url.clone(), sealed);
            let token = self.deletes.then(|| format!("token-{}", files.next));
            Ok(Stored { url, token })
        }))
    }

    fn fetch<'a>(&'a self, url: &'a str, most: usize) -> Doing<'a, Vec<u8>> {
        Box::pin(self.counter.call(move || match self.files().stored.get(url) {
            Some(bytes) if bytes.len() <= most => Ok(bytes.clone()),
            Some(_) => Err(Refusal::Failed("over the most bytes".into())),
            None => Err(Refusal::Failed("404".into())),
        }))
    }

    fn delete<'a>(&'a self, stored: &'a Stored) -> Doing<'a, ()> {
        Box::pin(self.counter.call(move || {
            let mut files = self.files();
            if self.deletes && stored.token.is_some() {
                files.stored.remove(&stored.url);
                files.deleted.push(stored.url.clone());
            }
            Ok(())
        }))
    }
}

/// A board in memory that keeps the last message of each topic.
pub struct StandInBoard {
    topics: Mutex<HashMap<String, Vec<u8>>>,
    puts: AtomicUsize,
    counter: Counter,
}

impl StandInBoard {
    pub fn new(counter: Counter) -> StandInBoard {
        StandInBoard { topics: Mutex::new(HashMap::new()), puts: AtomicUsize::new(0), counter }
    }

    fn topics(&self) -> std::sync::MutexGuard<'_, HashMap<String, Vec<u8>>> {
        self.topics.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Each message that it keeps now, as a stranger on the board reads it.
    pub fn kept(&self) -> Vec<(String, Vec<u8>)> {
        self.topics().iter().map(|(t, m)| (t.clone(), m.clone())).collect()
    }

    /// Put a message as a stranger would.
    pub fn plant(&self, topic: &str, payload: &[u8]) {
        self.topics().insert(topic.to_string(), payload.to_vec());
    }

    pub fn puts(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }
}

impl Board for StandInBoard {
    fn name(&self) -> &str {
        "board.stand-in.test"
    }

    fn most(&self) -> usize {
        64_000
    }

    fn put<'a>(&'a self, topic: &'a str, payload: Vec<u8>) -> Posting<'a, ()> {
        Box::pin(self.counter.call(move || {
            if payload.len() > self.most() {
                return Err(format!("a message of {} bytes", payload.len()));
            }
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.topics().insert(topic.to_string(), payload);
            Ok(())
        }))
    }

    fn take<'a>(&'a self, topic: &'a str) -> Posting<'a, Option<Vec<u8>>> {
        Box::pin(self.counter.call(move || Ok(self.topics().get(topic).cloned())))
    }

    fn clear<'a>(&'a self, topic: &'a str) -> Posting<'a, ()> {
        Box::pin(self.counter.call(move || {
            self.topics().remove(topic);
            Ok(())
        }))
    }
}
