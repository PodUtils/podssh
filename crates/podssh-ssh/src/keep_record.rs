//! The offsets that this client has of kept shells, kept across runs
//! (T-895): the next `--attach` of a shell gives its offset to the far end,
//! which replays what this client did not get.
//!
//! A far end is known by its host key with the user, through a hash
//! ([`crate::accepted::host_id`]), so the file names no host and no user; a
//! shell by its name. Neither is a secret, and an offset is a count of
//! bytes. The caller keeps the file in the private cache (podssh-cli, mode
//! 0600), as a [`KeptFile`]; with none, nothing is kept, and each attach
//! starts where the far end counted.
//!
//! The file is text: the line [`HEADER`], then one line for each shell,
//! `HOST NAME OFFSET AT_MS`. A file that does not read is set aside whole,
//! said at `-v`, and made again by the next offset kept.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use crate::accepted::{now_ms, valid_host, KeptFile};
use crate::keep::check_name;

/// The file's name in the cache.
pub const FILE: &str = "kept-offsets.txt";
/// The first line of the file: its format.
pub const HEADER: &str = "podssh kept offsets 1";
/// The shells kept; past it, the one kept longest ago goes.
pub const MOST: usize = 64;
/// An offset kept longer ago than this is forgotten: the longest lease that
/// a far end grants (`podssh serve --keep-lease`, 30 days).
pub const MAX_AGE_MS: i64 = 30 * 24 * 3600 * 1000;

/// Each shell's offset, by the far end's id and the shell's name, with when
/// it was kept, in milliseconds since the epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Offsets {
    pub shells: BTreeMap<(String, String), (u64, i64)>,
}

impl Offsets {
    /// The offsets of `text` kept within [`MAX_AGE_MS`] of `now_ms`, at
    /// most [`MOST`]. A text that does not read is refused whole, with why.
    pub fn read(text: &str, now_ms: i64) -> Result<Offsets, String> {
        let mut lines = text.lines();
        if lines.next() != Some(HEADER) {
            return Err("its first line is not podssh's".into());
        }
        let mut offsets = Offsets::default();
        for (at, line) in lines.enumerate() {
            let number = at + 2;
            let fields: Vec<&str> = line.split(' ').collect();
            let [host, name, offset, kept] = fields[..] else {
                return Err(format!("line {number} does not hold a host, a name, an offset and a time"));
            };
            let offset: u64 = offset.parse().map_err(|_| format!("line {number} holds no offset"))?;
            let kept: i64 = kept.parse().map_err(|_| format!("line {number} holds no time"))?;
            if !valid_host(host) || check_name(name).is_err() {
                return Err(format!("line {number} holds no host's id or no name of a kept shell"));
            }
            if now_ms.saturating_sub(kept) < MAX_AGE_MS {
                offsets.shells.insert((host.to_string(), name.to_string()), (offset, kept));
            }
        }
        offsets.bound();
        Ok(offsets)
    }

    /// The file's text.
    pub fn text(&self) -> String {
        let mut text = format!("{HEADER}\n");
        for ((host, name), (offset, kept)) in &self.shells {
            text.push_str(&format!("{host} {name} {offset} {kept}\n"));
        }
        text
    }

    /// The offset of the shell `name` of the far end `host`.
    pub fn get(&self, host: &str, name: &str) -> Option<u64> {
        self.shells.get(&(host.to_string(), name.to_string())).map(|(offset, _)| *offset)
    }

    /// Keep `offset` for `name` of `host`, at `now_ms`. Whether the record
    /// changed: an id or a name that is not one changes nothing.
    pub fn put(&mut self, host: &str, name: &str, offset: u64, now_ms: i64) -> bool {
        if !valid_host(host) || check_name(name).is_err() {
            return false;
        }
        self.shells.insert((host.to_string(), name.to_string()), (offset, now_ms));
        self.bound();
        true
    }

    /// Forget the offset of `name` of `host`. Whether the record changed.
    pub fn forget(&mut self, host: &str, name: &str) -> bool {
        self.shells.remove(&(host.to_string(), name.to_string())).is_some()
    }

    /// At most [`MOST`]: the shell kept longest ago goes.
    fn bound(&mut self) {
        while self.shells.len() > MOST {
            let Some(oldest) = self.shells.iter().min_by_key(|(_, (_, kept))| *kept).map(|(key, _)| key.clone()) else {
                break;
            };
            self.shells.remove(&oldest);
        }
    }
}

static KEPT: OnceLock<Box<dyn KeptFile>> = OnceLock::new();

/// Keep the offsets in `file`, once a run. `false` when a file was given
/// before, which stays.
pub fn keep_in(file: Box<dyn KeptFile>) -> bool {
    KEPT.set(file).is_ok()
}

/// The file's record now: empty with no file; `Err` with why a file that
/// did not read was set aside.
fn record() -> Result<Offsets, String> {
    let Some(text) = KEPT.get().and_then(|file| file.load()) else { return Ok(Offsets::default()) };
    Offsets::read(&text, now_ms()).map_err(|why| format!("the record of the kept shells' offsets was set aside: {why}"))
}

/// The offset that this client kept of the shell `name` of `host`; `Err`
/// says at `-v` why the file was set aside.
pub fn saved(host: &str, name: &str) -> Result<Option<u64>, String> {
    Ok(record()?.get(host, name))
}

/// One change of the file at a time in this process: each change reads the
/// whole file and writes it whole. Two processes can still race; the loser
/// costs a later attach its replay of the bytes that it missed, nothing
/// else.
static CHANGE: Mutex<()> = Mutex::new(());

/// Read the record, apply `edit`, and write it when `edit` says it changed.
/// A file set aside is made again.
fn change(edit: impl FnOnce(&mut Offsets) -> bool) {
    let Some(file) = KEPT.get() else { return };
    let _one = CHANGE.lock().unwrap_or_else(PoisonError::into_inner);
    let mut kept = record().unwrap_or_default();
    if edit(&mut kept) {
        file.store(kept.text().as_bytes());
    }
}

/// This client has the output of `name` of `host` up to `offset`.
pub fn save(host: &str, name: &str, offset: u64) {
    change(|kept| kept.put(host, name, offset, now_ms()));
}

/// No offset of `name` of `host` is worth keeping.
pub fn forget(host: &str, name: &str) {
    change(|kept| kept.forget(host, name));
}
