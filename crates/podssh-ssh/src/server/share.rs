//! A live shell shared by name (T-837): with `--share`, the login shell of
//! each pty (the kernel's, or serve's own tty, T-861) is offered under two names, minted from 128 random bits each
//! and told once to its owner: one that types in it, one that watches it.
//!
//! A name is the SSH user of a later login: `ssh NAME@HOST`, by the same
//! road that reached serve. The name alone lets the client in, with any
//! key; a name that the table lacks falls back to the authorized keys, so
//! a miss reads as a wrong key. The table is part of the server's table of
//! live connections (`live.rs`), and a name dies with its shell.
//!
//! The right of a name is kept at one gate: the channel of a watcher gets a
//! sink for its input, never the pty (`share_view.rs`). Each writer, the
//! owner among them, writes through one lease: the bytes of one writer
//! reach the pty at a time, and the lease passes after [`LEASE_IDLE`] of
//! silence. The pty's size is the least of each seat's.

// Windows refuses each program (`podssh serve` is a Unix host's), so the
// parts that share one are unused there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use bytes::Bytes;
use pod_term::grammar::Ring;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tokio::time::Instant;

use super::channel::Input;
use super::share_told::{Said, Tells};
use crate::terminal::Size;

/// How long a writer's silence holds the lease: then another writer's
/// bytes may claim it. Measured with two people typing (T-862,
/// `docs/terminal.md`): the least span that broke no word, as it outlasts
/// the gaps between a person's keys; a shorter one breaks most words.
pub const LEASE_IDLE: Duration = Duration::from_millis(400);

/// The chunks of output that a watcher may fall behind before it skips to
/// the present: with chunks of 32 KiB at most, 2 MiB for each shell.
pub const BACKLOG: usize = 64;

/// A writer's bytes that wait for the lease in serve, past which its
/// channel's window holds the client.
const PASTE: usize = 32 * 1024;
/// The owner's output that a hub keeps for a seat that joins: more than a
/// screen's worth of a full-screen program's repaint.
const SCREEN_RING: usize = 64 * 1024;

/// The prefix of each name, which tells a person its right; the table, not
/// the prefix, decides it.
const WRITE_PREFIX: &str = "rw-";
const READ_PREFIX: &str = "ro-";

/// The right of a name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Its bytes reach the pty, under the lease.
    Write,
    /// It reads the output and sends its window size; nothing else.
    Read,
}

impl Mode {
    /// The words of serve's line for a login under a name of this right.
    pub fn says(self) -> &'static str {
        match self {
            Mode::Write => "to type in it",
            Mode::Read => "to watch it",
        }
    }
}

/// A name's shell, held weakly so that the name dies with it, and its right.
type Named = HashMap<String, (Weak<Hub>, Mode)>;

/// The names of the server, shared by each of its connections: name to
/// shell and right.
#[derive(Clone, Default)]
pub(super) struct Shares(Arc<Mutex<Named>>);

impl std::fmt::Debug for Shares {
    // The names are credentials: never in a debug line.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shares")
    }
}

/// What a login under a name holds: the shell and the right.
#[derive(Clone)]
pub(super) struct Pass {
    pub(super) hub: Arc<Hub>,
    pub(super) mode: Mode,
}

/// The two names of one shell, for the owner's line.
pub(super) struct Names {
    pub(super) write: String,
    pub(super) read: String,
}

impl Names {
    /// The words that the owner reads on the channel's stderr, once.
    pub(super) fn told(&self) -> String {
        format!(
            "podssh serve: this shell is shared until it ends; log in by the same road, as one of these users:\r\n  \
             {}  types in it\r\n  {}  watches it\r\n",
            self.write, self.read
        )
    }
}

/// A new name of `mode`: its prefix and 128 random bits in hex. None where
/// the system gives no random bytes: the shell then runs unshared.
fn fresh_name(mode: Mode) -> Option<String> {
    use std::fmt::Write as _;
    let mut bits = [0u8; 16];
    aws_lc_rs::rand::fill(&mut bits).ok()?;
    let mut name = String::from(if mode == Mode::Write { WRITE_PREFIX } else { READ_PREFIX });
    for b in bits {
        let _ = write!(name, "{b:02x}");
    }
    Some(name)
}

impl Shares {
    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<String, (Weak<Hub>, Mode)>> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The shell and right of `name`, while its shell runs.
    pub(super) fn find(&self, name: &str) -> Option<Pass> {
        let (hub, mode) = self.table().get(name).map(|(hub, mode)| (hub.upgrade(), *mode))?;
        let hub = hub.filter(|hub| !hub.ended.load(Ordering::SeqCst))?;
        Some(Pass { hub, mode })
    }

    /// Mint the two names of `hub`; None where no random bytes came.
    pub(super) fn mint(&self, hub: &Arc<Hub>) -> Option<Names> {
        let names = Names { write: fresh_name(Mode::Write)?, read: fresh_name(Mode::Read)? };
        let mut table = self.table();
        table.insert(names.write.clone(), (Arc::downgrade(hub), Mode::Write));
        table.insert(names.read.clone(), (Arc::downgrade(hub), Mode::Read));
        hub.names.lock().unwrap_or_else(|p| p.into_inner()).extend([names.write.clone(), names.read.clone()]);
        Some(names)
    }

    /// Delete `name`: no new login under it; a seat that it opened stays.
    pub(super) fn unshare(&self, name: &str) -> bool {
        self.table().remove(name).is_some()
    }

    /// Put a new name of the same right in the place of `name`; the other
    /// name of its shell stays.
    pub(super) fn reshare(&self, name: &str) -> Option<String> {
        let mut table = self.table();
        let (weak, mode) = table.get(name).cloned()?;
        // A name whose shell ended goes, and gets no heir.
        let Some(hub) = weak.upgrade().filter(|hub| !hub.ended.load(Ordering::SeqCst)) else {
            table.remove(name);
            return None;
        };
        let fresh = fresh_name(mode)?;
        table.remove(name);
        table.insert(fresh.clone(), (weak, mode));
        let mut names = hub.names.lock().unwrap_or_else(|p| p.into_inner());
        names.retain(|n| n != name);
        names.push(fresh.clone());
        Some(fresh)
    }

    /// The names that let in to `hub` now, with their rights: none once
    /// its shell ended.
    pub(super) fn names_of(&self, hub: &Arc<Hub>) -> Vec<(String, Mode)> {
        if hub.ended.load(Ordering::SeqCst) {
            return Vec::new();
        }
        let shell = Arc::as_ptr(hub);
        let table = self.table();
        let mine = table.iter().filter(|(_, (weak, _))| std::ptr::eq(weak.as_ptr(), shell));
        mine.map(|(name, (_, mode))| (name.clone(), *mode)).collect()
    }

    /// How many names let in now.
    pub(super) fn len(&self) -> usize {
        self.table().values().filter(|(hub, _)| hub.strong_count() > 0).count()
    }
}

/// Who may write now (T-837's lease): one seat, until its silence passes
/// [`LEASE_IDLE`]. Each change of holder is a new generation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Lease {
    pub(super) holder: Option<u64>,
    pub(super) until: Option<Instant>,
    pub(super) generation: u64,
}

impl Lease {
    /// Until when `seat` must wait at `now`; None when it may write.
    pub(super) fn busy(&self, seat: u64, now: Instant) -> Option<Instant> {
        match (self.holder, self.until) {
            (Some(holder), Some(until)) if holder != seat && now < until => Some(until),
            _ => None,
        }
    }

    /// `seat` writes at `now`: it holds the lease for [`LEASE_IDLE`] more
    /// (another span only under T-862's measure).
    pub(super) fn take(&mut self, seat: u64, now: Instant) {
        if self.holder != Some(seat) {
            self.holder = Some(seat);
            self.generation += 1;
        }
        self.until = Some(now + super::share_measure::lease_idle());
    }
}

/// One shared shell: its output to each watcher, its pty's input under the
/// lease, and its size as the least of each seat's.
pub(super) struct Hub {
    output: Mutex<Option<broadcast::Sender<Said>>>,
    /// The owner's recent output, from which a seat that joins gets the
    /// screen so far (T-901); fed under the output's lock.
    screen: Mutex<Ring>,
    input: tokio::sync::Mutex<(Lease, Input)>,
    sizes: Mutex<BTreeMap<u64, Size>>,
    resize: Box<dyn Fn(Size) + Send + Sync>,
    next: AtomicU64,
    names: Mutex<Vec<String>>,
    table: Shares,
    ended: AtomicBool,
    /// Local echo's reports of the seats that asked (T-896).
    pub(super) tells: Tells,
}

/// One seat at a shell: the owner's, or a login's under a name. Its size
/// counts while it lives.
pub(super) struct Seat {
    pub(super) hub: Arc<Hub>,
    id: u64,
}

impl Hub {
    /// A shell to share: `pty` takes its input, `resize` sets its size, and
    /// the owner's seat starts at `size`.
    pub(super) fn open(table: &Shares, pty: Input, resize: Box<dyn Fn(Size) + Send + Sync>, size: Size) -> Arc<Seat> {
        let (output, _) = broadcast::channel(BACKLOG);
        let hub = Arc::new(Hub {
            output: Mutex::new(Some(output)),
            screen: Mutex::new(Ring::new(SCREEN_RING)),
            input: tokio::sync::Mutex::new((Lease::default(), pty)),
            sizes: Mutex::new(BTreeMap::new()),
            resize,
            next: AtomicU64::new(0),
            names: Mutex::new(Vec::new()),
            table: table.clone(),
            ended: AtomicBool::new(false),
            tells: Tells::default(),
        });
        hub.seat(Some(size))
    }

    /// A new seat, of `size` where it asked for a pty.
    pub(super) fn seat(self: &Arc<Self>, size: Option<Size>) -> Arc<Seat> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let seat = Arc::new(Seat { hub: self.clone(), id });
        if let Some(size) = size {
            seat.resize(size);
        }
        seat
    }

    /// The output from now on, or None once the shell ended.
    pub(super) fn subscribe(&self) -> Option<broadcast::Receiver<Said>> {
        self.output.lock().unwrap_or_else(|p| p.into_inner()).as_ref().map(broadcast::Sender::subscribe)
    }

    /// The output from now on, after the screen so far: the modes before
    /// the ring's last `rows` lines and those lines, or the ring from its
    /// first boundary where the program is on the alternate screen (T-901).
    /// Both are taken under the output's lock, so that no byte is in the
    /// screen and in the receiver, nor in neither. None once the shell ended.
    pub(super) fn subscribe_with_screen(&self, rows: u32) -> Option<(Vec<u8>, broadcast::Receiver<Said>)> {
        let output = self.output.lock().unwrap_or_else(|p| p.into_inner());
        let from = output.as_ref()?.subscribe();
        let ring = self.screen.lock().unwrap_or_else(|p| p.into_inner());
        let start = super::kept_screen::tail_from(&ring, ring.end() + 1, rows).or_else(|| ring.start());
        let mut screen = Vec::new();
        if let Some(start) = start {
            screen = super::kept_screen::modes_before(&ring, start);
            screen.extend(super::kept_replay::since(&ring, start).0);
        }
        Some((screen, from))
    }

    /// A copy of the owner's output for each watcher, and after it each
    /// asking seat's report (T-896); a watcher that lags skips, and none
    /// holds the owner. The reports are made under the output's lock, so
    /// that no item goes ahead of one made before it.
    pub(super) fn said(&self, bytes: &[u8]) {
        if let Some(output) = self.output.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
            self.screen.lock().unwrap_or_else(|p| p.into_inner()).push(bytes, std::time::Instant::now());
            let told = self.tells.reports(true);
            let _ = output.send(Said { bytes: Bytes::copy_from_slice(bytes), told });
        }
    }

    /// A count fell due with no output: the reports that changed, as an
    /// item with no bytes, from the task that reads the tty (T-896).
    pub(super) fn tick(&self) {
        if let Some(output) = self.output.lock().unwrap_or_else(|p| p.into_inner()).as_ref()
            && let Some(told) = self.tells.reports(false)
        {
            let _ = output.send(Said { bytes: Bytes::new(), told: Some(told) });
        }
    }

    /// The shell's output ended: its names let nobody in, and each watcher
    /// reads to the end of what was sent.
    pub(super) fn end(&self) {
        self.ended.store(true, Ordering::SeqCst);
        self.output.lock().unwrap_or_else(|p| p.into_inner()).take();
        let names: Vec<String> = self.names.lock().unwrap_or_else(|p| p.into_inner()).drain(..).collect();
        for name in names {
            self.table.unshare(&name);
        }
    }

    fn set_size(&self, seat: u64, size: Option<Size>) {
        let mut sizes = self.sizes.lock().unwrap_or_else(|p| p.into_inner());
        match size {
            Some(size) => sizes.insert(seat, size),
            None => sizes.remove(&seat),
        };
        if let Some(least) = least(sizes.values()) {
            (self.resize)(least);
        }
    }

    /// Write `bytes` to the pty as `seat`, once it holds the lease; false
    /// once the shell ended or the pty refused them.
    async fn write_leased(&self, seat: u64, bytes: &[u8]) -> bool {
        let mut held_since = None;
        loop {
            if self.ended.load(Ordering::SeqCst) {
                return false;
            }
            let mut held = self.input.lock().await;
            if let Some(until) = held.0.busy(seat, Instant::now()) {
                drop(held);
                held_since.get_or_insert_with(Instant::now);
                tokio::time::sleep_until(until).await;
                continue;
            }
            if let Some(since) = held_since {
                super::share_measure::waited(since.elapsed());
            }
            held.0.take(seat, Instant::now());
            // Local echo counts each seat's bytes that reached the tty (T-896).
            self.tells.before(seat, bytes.len());
            let written = held.1.write_all(bytes).await.is_ok();
            if written {
                self.tells.wrote(seat, bytes.len());
            }
            // The silence counts from the end of the write.
            held.0.take(seat, Instant::now());
            return written;
        }
    }

    #[cfg(test)]
    pub(super) async fn lease(&self) -> Lease {
        self.input.lock().await.0
    }
}

impl Seat {
    /// This seat's number at its shell, which its reports carry (T-896).
    pub(super) fn id(&self) -> u64 {
        self.id
    }

    /// A new size of this seat's window.
    pub(super) fn resize(&self, size: Size) {
        self.hub.set_size(self.id, Some(size));
    }

    /// Where this seat's bytes go: through the lease to the pty. Only a
    /// seat of the right to write is ever given one.
    pub(super) fn writer(self: &Arc<Self>) -> Input {
        let (near, far) = tokio::io::duplex(PASTE);
        tokio::spawn(lease_pump(self.clone(), far));
        Box::new(near)
    }
}

impl Drop for Seat {
    // A seat that leaves no longer holds the size down, nor gets reports.
    fn drop(&mut self) {
        self.hub.set_size(self.id, None);
        self.hub.tells.leave(self.id);
    }
}

/// The least of `sizes`, field by field; None for no seat.
pub(super) fn least<'a>(sizes: impl Iterator<Item = &'a Size>) -> Option<Size> {
    sizes.copied().reduce(|a, b| Size {
        cols: a.cols.min(b.cols),
        rows: a.rows.min(b.rows),
        px_width: a.px_width.min(b.px_width),
        px_height: a.px_height.min(b.px_height),
    })
}

/// Copy a seat's bytes to the pty under the lease, until the seat's input
/// ends or the shell does; then the dropped pipe tells the channel's feeder,
/// which drops and grants the rest.
async fn lease_pump(seat: Arc<Seat>, mut from: tokio::io::DuplexStream) {
    let mut buf = vec![0u8; PASTE];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if !seat.hub.write_leased(seat.id, &buf[..n]).await {
            return;
        }
    }
}

impl super::stop::Control {
    /// Delete the shared shell's name `name`: no new login under it, and a
    /// seat that it opened stays. False when no shell has that name.
    pub fn unshare(&self, name: &str) -> bool {
        self.live.shares.unshare(name)
    }

    /// Put a new name in the place of `name`, with its right; the other
    /// name of its shell stays. None when no running shell has that name.
    pub fn reshare(&self, name: &str) -> Option<String> {
        self.live.shares.reshare(name)
    }

    /// How many names of shared shells let in now.
    pub fn shared(&self) -> usize {
        self.live.shares.len()
    }
}

#[cfg(test)]
#[path = "share_tests.rs"]
mod tests;
