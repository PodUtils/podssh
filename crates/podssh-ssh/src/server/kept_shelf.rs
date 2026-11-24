//! The kept shells of one server (T-159): each named shell with its key,
//! the limits, and the record of their names in a state file, so that the
//! next start says which shells a restart ended.
//!
//! A shell is found by its key and its name alone: another key's shell of
//! the same name is no shell of this key, and its name is not told. The
//! shelf's lock is taken before a shell's own, never after it.

// Windows refuses each program (`podssh serve` is a Unix host's), so no
// shell is ever kept there.
#![cfg_attr(not(unix), allow(dead_code))]

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use super::kept::{Shell, PER_KEY, TOTAL};
use super::kept_record;

/// The kept shells of a server, shared by each of its connections.
#[derive(Clone, Default)]
pub(super) struct Shelf(Arc<Mutex<Shelved>>);

#[derive(Default)]
struct Shelved {
    shells: Vec<Arc<Shell>>,
    /// Where the names are written at each change.
    record: Option<PathBuf>,
    /// The server stops: the record keeps the names that the stop ends.
    frozen: bool,
    /// The last run's names, which ended with it: the key and the name.
    lost: Vec<(String, String)>,
}

impl std::fmt::Debug for Shelf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Shelf")
    }
}

impl Shelf {
    fn lock(&self) -> MutexGuard<'_, Shelved> {
        self.0.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Keep `shell` as `name`: Err with the words where another shell of
    /// its key has the name, or a limit is reached.
    pub(super) fn put(&self, shell: &Arc<Shell>, name: &str) -> Result<(), String> {
        let mut shelved = self.lock();
        shelved.shells.retain(|s| !s.ended());
        let mine: Vec<&Arc<Shell>> = shelved.shells.iter().filter(|s| s.owner == shell.owner).collect();
        if mine.iter().any(|s| !Arc::ptr_eq(s, shell) && s.name().as_deref() == Some(name)) {
            return Err(format!("another kept shell of this key is named {name}"));
        }
        if !mine.iter().any(|s| Arc::ptr_eq(s, shell)) {
            if mine.len() >= PER_KEY {
                return Err(format!("this key keeps {PER_KEY} shells already, the most for one key"));
            }
            if shelved.shells.len() >= TOTAL {
                return Err(format!("podssh serve keeps {TOTAL} shells already, the most that it keeps"));
            }
            shelved.shells.push(shell.clone());
        }
        shell.set_name(name);
        shelved.lost.retain(|(owner, lost)| !(owner == &shell.owner && lost == name));
        write_record(&shelved);
        Ok(())
    }

    /// The shell of `owner` kept as `name`, or the words of a refusal.
    pub(super) fn find(&self, owner: &str, name: &str) -> Result<Arc<Shell>, String> {
        let shelved = self.lock();
        let found = shelved.shells.iter().find(|s| s.owner == owner && !s.ended() && s.name().as_deref() == Some(name));
        if let Some(shell) = found {
            return Ok(shell.clone());
        }
        if shelved.lost.iter().any(|(o, n)| o == owner && n == name) {
            return Err(format!("the kept shell {name} ended with the last run of podssh serve"));
        }
        Err(format!("no kept shell named {name}"))
    }

    /// `shell` ended: off the shelf.
    pub(super) fn remove(&self, shell: &Shell) {
        let mut shelved = self.lock();
        let before = shelved.shells.len();
        shelved.shells.retain(|s| !std::ptr::eq(Arc::as_ptr(s), shell));
        if shelved.shells.len() != before {
            write_record(&shelved);
        }
    }

    /// The lines of `shells@podssh` for `owner`: each kept shell's name,
    /// `attached` or `detached` and its offset (T-833), then each name of
    /// the last run, `lost`.
    pub(super) fn lines(&self, owner: &str) -> String {
        let shelved = self.lock();
        let mut out = String::new();
        for shell in shelved.shells.iter().filter(|s| s.owner == owner && !s.ended()) {
            if let Some(name) = shell.name() {
                let (state, offset) = shell.listed();
                out.push_str(&format!("{name} {state} {offset}\n"));
            }
        }
        for (_, name) in shelved.lost.iter().filter(|(o, _)| o == owner) {
            out.push_str(&format!("{name} lost\n"));
        }
        out
    }

    /// How many shells are kept now.
    pub(super) fn count(&self) -> usize {
        self.lock().shells.iter().filter(|s| !s.ended() && s.name().is_some()).count()
    }

    /// The server stops: the record is no longer written, so that it names
    /// the shells that the stop ends.
    pub(super) fn freeze(&self) {
        self.lock().frozen = true;
    }

    /// Write the names to `path` from now on, after reading the names that
    /// it holds from the last run, which ended with it: those, returned.
    pub(super) fn record_at(&self, path: PathBuf) -> Result<Vec<(String, String)>, String> {
        let lost = kept_record::read(&path)?;
        let mut shelved = self.lock();
        shelved.lost = lost.clone();
        shelved.record = Some(path);
        write_record(&shelved);
        Ok(lost)
    }
}

/// The names of the kept shells to the record, where there is one; a
/// write that fails leaves the record as it was, and serve goes on.
fn write_record(shelved: &Shelved) {
    let Some(path) = shelved.record.as_ref().filter(|_| !shelved.frozen) else { return };
    let names: Vec<(String, String)> = shelved
        .shells
        .iter()
        .filter(|s| !s.ended())
        .filter_map(|s| s.name().map(|name| (s.owner.clone(), name)))
        .collect();
    let _ = kept_record::write(path, &names);
}

impl super::stop::Control {
    /// Keep the names of the kept shells in `path` (T-159), and give the
    /// names that it held from the last run, which ended with it.
    pub fn keep_record(&self, path: PathBuf) -> Result<Vec<String>, String> {
        let lost = self.shelf.record_at(path)?;
        Ok(lost.into_iter().map(|(_, name)| name).collect())
    }

    /// How many shells are kept now (T-159).
    pub fn kept(&self) -> usize {
        self.shelf.count()
    }
}
