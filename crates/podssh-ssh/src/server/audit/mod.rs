//! The audit log of `podssh serve` (T-116): `--audit-log FILE`, one JSON
//! object on each line, appended, mode 0600. Each line has the keys of
//! PodUtils' log schema (`schema`, `time`, `level`, `event`, `fields`), and
//! its `fields.prev` is the SHA-256 of the line before it (`chain.rs`), so
//! that `--audit-verify FILE` finds a line that was changed.
//!
//! What a line never holds: key material, a token, a value of the
//! environment, the bytes of a session, a name of `--share` (a name is the
//! right to the shell), and a command line unless `--audit-commands` asked
//! for it, as one can hold a password. Each run's first line says so in
//! its coverage map.
//!
//! The lines go to a thread of their own: an append takes the file's lock,
//! which another serve process may hold, and no session waits on it. A
//! write that fails (a full disk) is said once on stderr, and the sessions
//! go on.

pub mod chain;
mod marks;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value};

pub use marks::{Asked, Counted, Exit, Forward, Place, Session, Tally, Trail, Verdict};

use super::Say;

/// How long an append waits for another process's lock: a line is short,
/// so a lock held longer is a writer that hangs.
pub const LOCK_WAIT: Duration = Duration::from_secs(2);

/// How long [`Audit::flush`] waits for the thread.
pub const FLUSH_WAIT: Duration = Duration::from_secs(5);

/// The longest text of a peer kept in a field (a login name, a target):
/// the line stays short, and the tail of the file is read in one piece.
pub const MOST_TEXT: usize = 256;

/// The longest command line kept with `--audit-commands`.
pub const MOST_COMMAND: usize = 4096;

/// What a run records of each class of the session, after report 24 of
/// the donor study: `recorded`, `metadata` (that it happened, not what it
/// said), or `declined` (seen, and kept out on purpose).
pub fn coverage(commands: bool) -> Value {
    let pairs = [
        ("auth", "recorded"),
        ("channel", "recorded"),
        ("exec", if commands { "recorded" } else { "metadata" }),
        ("pty.in", "declined"),
        ("pty.out", "declined"),
        ("sftp.meta", "declined"),
        ("sftp.content", "declined"),
        ("forward.meta", "recorded"),
        ("forward.payload", "declined"),
    ];
    Value::Object(pairs.iter().map(|(k, v)| (k.to_string(), Value::from(*v))).collect())
}

/// The level of a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warn,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Info => "info",
            Level::Warn => "warn",
        }
    }
}

enum Job {
    Line(String, Level, Map<String, Value>),
    Flush(mpsc::SyncSender<()>),
}

/// The sink of one serve process.
pub struct Audit {
    path: PathBuf,
    commands: bool,
    /// This run's id: random, as a pid is not unique across PID namespaces,
    /// and two serve processes may append to one file.
    run: String,
    jobs: mpsc::Sender<Job>,
    next_conn: AtomicU64,
}

impl std::fmt::Debug for Audit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Audit").field("path", &self.path).field("commands", &self.commands).finish()
    }
}

impl Audit {
    /// The log at `path`, made with mode 0600 where it is missing. One that
    /// another user owns, that others may read, or that is not a regular
    /// file is refused with the reason: the caller refuses the start (78).
    /// `say` is where the one line of a failed write goes.
    pub fn open(path: &Path, commands: bool, say: Option<Say>) -> Result<Arc<Audit>, String> {
        let shown = path.display();
        // The log is its own lock: an error of the lock is said of the log,
        // never of a "lock file" the user did not name.
        let lock = pod_core::lock::FileLock::lock_within(path, pod_core::lock::Mode::Exclusive, LOCK_WAIT)
            .map_err(|e| format!("--audit-log {shown}: {}", opening_words(path, &e)))?;
        let meta = lock.file().metadata().map_err(|e| format!("--audit-log {shown}: {}", podssh_ws::text::said(&e)))?;
        if !meta.is_file() {
            return Err(format!("--audit-log {shown}: not a regular file"));
        }
        pod_core::files::closed(path, lock.file(), pod_core::files::Others::NoAccess)
            .map_err(|why| format!("--audit-log {why}"))?;
        drop(lock);
        let run = random_id().ok_or("--audit-log: the system gave no random bytes for the run's id")?;
        let (jobs, rx) = mpsc::channel();
        let owned = path.to_path_buf();
        std::thread::Builder::new()
            .name("podssh-audit".into())
            .spawn(move || write_each(&owned, &rx, say.as_ref()))
            .map_err(|e| format!("--audit-log: no thread for its writes: {e}"))?;
        Ok(Arc::new(Audit { path: path.to_path_buf(), commands, run, jobs, next_conn: AtomicU64::new(1) }))
    }

    /// Whether command lines are recorded (`--audit-commands`).
    pub fn commands(&self) -> bool {
        self.commands
    }

    /// The file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The id of a new connection: this run's, then its number.
    pub(super) fn conn_id(&self) -> String {
        format!("{}-{}", self.run, self.next_conn.fetch_add(1, Ordering::Relaxed))
    }

    /// Queue the line of `event` with `fields`; `run` is added. It never
    /// waits, and never fails: the thread says a failed write.
    pub fn line(&self, event: &str, level: Level, mut fields: Map<String, Value>) {
        fields.insert("run".into(), Value::from(self.run.as_str()));
        let _ = self.jobs.send(Job::Line(event.to_string(), level, fields));
    }

    /// `serve.start`: the run's first line, with its coverage map.
    pub fn started(&self, mode: &str) {
        let mut fields = Map::new();
        fields.insert("version".into(), Value::from(env!("CARGO_PKG_VERSION")));
        fields.insert("mode".into(), Value::from(mode));
        fields.insert("coverage".into(), coverage(self.commands));
        self.line("serve.start", Level::Info, fields);
    }

    /// `serve.stop`, then the wait for each line to be written.
    pub fn stopped(&self, outcome: &str) {
        let mut fields = Map::new();
        fields.insert("outcome".into(), Value::from(outcome));
        self.line("serve.stop", Level::Info, fields);
        self.flush();
    }

    /// Wait, at most [`FLUSH_WAIT`], until each line queued before is
    /// written or given up.
    pub fn flush(&self) {
        let (tx, rx) = mpsc::sync_channel(1);
        if self.jobs.send(Job::Flush(tx)).is_ok() {
            let _ = rx.recv_timeout(FLUSH_WAIT);
        }
    }
}

/// What a failed open of the log says: the missing directory, "no such
/// file", the system's words; or the lock's own words (a writer that held
/// it past [`LOCK_WAIT`]), with no "(os error N)".
fn opening_words(path: &Path, e: &pod_core::failure::Failure) -> String {
    match e.io_cause() {
        Some(io) => podssh_ws::text::file_said(path, io),
        None => podssh_ws::text::said(e),
    }
}

/// The thread: each line appended under the file's lock, chained to the
/// line before it, whoever wrote that one.
fn write_each(path: &Path, jobs: &mpsc::Receiver<Job>, say: Option<&Say>) {
    let mut told = false;
    while let Ok(job) = jobs.recv() {
        match job {
            Job::Line(event, level, fields) => {
                if let Err(e) = append(path, &event, level, fields)
                    && !told
                {
                    told = true;
                    if let Some(Say(say)) = say {
                        say(&format!(
                            "the audit log {} could not be written ({e}); the sessions go on, and each later line \
                             is tried again",
                            path.display()
                        ));
                    }
                }
            }
            Job::Flush(done) => {
                let _ = done.send(());
            }
        }
    }
}

/// One line of `event` at the end of the file at `path`.
fn append(path: &Path, event: &str, level: Level, mut fields: Map<String, Value>) -> Result<(), String> {
    use std::io::{Seek, SeekFrom, Write};
    let lock = pod_core::lock::FileLock::lock_within(path, pod_core::lock::Mode::Exclusive, LOCK_WAIT)
        .map_err(|e| podssh_ws::text::said(&e))?;
    let mut file = lock.file();
    let (prev, cut) = chain::tail(file).map_err(|e| podssh_ws::text::said(&e))?;
    fields.insert("prev".into(), Value::from(prev));
    let mut bytes = Vec::new();
    // A write that a crash cut short ends its own line: the chain covers
    // it, and the check names it.
    if cut {
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(render(SystemTime::now(), event, level, &fields).as_bytes());
    bytes.push(b'\n');
    file.seek(SeekFrom::End(0)).map_err(|e| podssh_ws::text::said(&e))?;
    // One write of the whole line, so that a reader without the lock sees
    // whole lines, or the cut that the check names.
    file.write_all(&bytes).map_err(|e| podssh_ws::text::said(&e))?;
    Ok(())
}

/// The text of one line, its keys in the schema's order (`schema` first).
pub fn render(at: SystemTime, event: &str, level: Level, fields: &Map<String, Value>) -> String {
    let text = |s: &str| Value::from(s).to_string();
    format!(
        "{{\"schema\":{},\"time\":{},\"level\":{},\"event\":{},\"fields\":{}}}",
        pod_core::LOG_SCHEMA,
        text(&pod_core::clock::rfc3339(at)),
        text(level.name()),
        text(event),
        Value::Object(fields.clone())
    )
}

/// `text` of a peer cut at `most` bytes on a character's edge; true when
/// it was cut.
pub fn bounded(text: &str, most: usize) -> (String, bool) {
    if text.len() <= most {
        return (text.to_string(), false);
    }
    let mut end = most;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_string(), true)
}

/// 64 random bits in hex; None where the system gives none.
fn random_id() -> Option<String> {
    use std::fmt::Write as _;
    let mut bits = [0u8; 8];
    aws_lc_rs::rand::fill(&mut bits).ok()?;
    let mut id = String::with_capacity(16);
    for b in bits {
        let _ = write!(id, "{b:02x}");
    }
    Some(id)
}

#[cfg(test)]
mod tests;
