//! One run of a service at a time (T-393): a run with `--env-file FILE`
//! holds a lock on `FILE.lock` for its life, and writes its pid there. A
//! second start of the same service while the first serves (cron's
//! watchdog each 5 minutes, a person, the way of an earlier install) ends
//! at once with 0, where it would run a second node of the same pair, which
//! the relay refuses, or ask the server again for a port that the first
//! holds. The kernel lets the lock go when its process ends, however it
//! ends, so no stale file can keep a service down, as a file of a pid can.
//! A lock that cannot be taken at all lets the run go on: a service with no
//! lock serves, and one that never starts locks its server out.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use pod_core::lock::{FileLock, Mode};

/// The lock that this process holds, kept open until it ends.
static HELD: OnceLock<FileLock> = OnceLock::new();

/// The lock's file beside the file of variables `name`.
pub(super) fn file_name(name: &str) -> String {
    format!("{name}.lock")
}

/// The lock's path beside `env_file`.
pub(crate) fn path_of(env_file: &Path) -> PathBuf {
    let mut name = env_file.as_os_str().to_owned();
    name.push(".lock");
    PathBuf::from(name)
}

/// What a try of the lock came to.
#[derive(Debug)]
pub(crate) enum Tried {
    /// This process holds it now.
    Held(FileLock),
    /// Another run holds it: its pid, when its file says one.
    Taken(Option<u32>),
}

/// One try of the lock at `path`, made when missing, with no wait; `Err`
/// when no lock can be had here, as on a file system that takes none. The
/// open and the try are pod-core's (a link at `path` is refused, 0600).
pub(crate) fn try_hold(path: &Path) -> Result<Tried, String> {
    match FileLock::try_lock(path, Mode::Exclusive).map_err(|e| e.to_string())? {
        Some(lock) => {
            // The pid is for a person who reads the file; the lock is the
            // kernel's, and needs none. A file of another user is read only,
            // and then no pid is written.
            let mut file = lock.file();
            let _ = file.set_len(0).and_then(|()| writeln!(file, "{}", std::process::id()));
            Ok(Tried::Held(lock))
        }
        None => {
            let pid = std::fs::read_to_string(path).ok().and_then(|text| text.trim().parse().ok());
            Ok(Tried::Taken(pid))
        }
    }
}

/// Before a run of `verb` with `--env-file FILE`: hold the lock beside FILE
/// for the life of this process. `Some(0)` when another run holds it, and
/// this one must end; a line says so to a person at a terminal, and nothing
/// to a service manager or to cron, which would mail it each 5 minutes.
pub(crate) fn enter(verb: &str, env_file: Option<&str>, err: &mut dyn Write) -> Option<i32> {
    let path = path_of(Path::new(env_file?));
    match try_hold(&path) {
        Ok(Tried::Held(file)) => {
            let _ = HELD.set(file);
            None
        }
        Ok(Tried::Taken(pid)) => {
            if std::io::stderr().is_terminal() {
                let by = pid.map_or_else(String::new, |pid| format!(" (pid {pid})"));
                let _ = writeln!(
                    err,
                    "podssh {verb}: another run of this service serves{by}, as it holds {}: this one ends",
                    path.display()
                );
            }
            Some(0)
        }
        Err(why) => {
            let _ = writeln!(
                err,
                "podssh {verb}: no lock of this service ({why}): a second start of it would run beside this one"
            );
            None
        }
    }
}
