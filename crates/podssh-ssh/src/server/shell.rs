//! The shell of `podssh serve` (T-222, GitHub #32): found with no passwd
//! entry and no `/etc/shells`, which a cage often lacks, and never by
//! `getpwuid`. Each candidate that fails is named with its reason, so that
//! a login never ends at once with no word, and no probe changes what runs
//! in silence.
//!
//! The order: the shell that the operator names (`--shell`), alone and
//! strict; else `SHELL`, then [`FALLBACKS`]. A candidate passes when it is an
//! absolute path to a regular file that this user may execute
//! (`faccessat(X_OK, AT_EACCESS)`; `exists()` takes a directory), and when a
//! real run of `-c 'exit 0'` ends with 0: a noexec mount, a data file with
//! its mode bits set, or a missing loader pass the first checks, and only a
//! real attempt tells them apart. glibc's `execvp` hands a file that the
//! kernel refuses with ENOEXEC to `/bin/sh` as a script, so a start alone
//! can succeed for a file that is no shell; the run's status cannot. The
//! search runs again at each session's start, with no cache: what runs can
//! change in the same image.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// The shells tried after `SHELL`, in order.
pub const FALLBACKS: &[&str] = &["/bin/sh", "/usr/bin/sh", "/bin/bash", "/usr/bin/bash", "/bin/ash", "/bin/dash"];

/// The longest that a candidate may take to run `-c 'exit 0'`.
pub const PROBE_WAIT: Duration = Duration::from_secs(5);

/// The command of the probe: any shell runs it, and it reads nothing.
const PROBE: &str = "exit 0";

/// One shell to try, and how the line of a failure names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub label: String,
    pub path: PathBuf,
}

/// A candidate that failed, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    pub label: String,
    pub why: String,
}

/// The shell that runs, and the candidates passed over before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub path: PathBuf,
    pub failed: Vec<Failed>,
}

/// No candidate runs: each one with its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoShell {
    pub failed: Vec<Failed>,
}

/// `label: why; label: why`, the words of a list of failures.
pub fn said(failed: &[Failed]) -> String {
    failed.iter().map(|f| format!("{}: {}", f.label, f.why)).collect::<Vec<_>>().join("; ")
}

impl fmt::Display for NoShell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no shell runs here: {}", said(&self.failed))
    }
}

impl Found {
    /// The line that names the candidates passed over, when there were any.
    pub fn passed_over(&self) -> Option<String> {
        (!self.failed.is_empty()).then(|| format!("{} (passed over: {})", self.path.display(), said(&self.failed)))
    }
}

/// The candidates in order. A named shell is the only one: the operator
/// chose it, and another one in its place would be a change that nobody
/// asked for. Else `SHELL` (empty is unset), then each of [`FALLBACKS`]
/// that is not the same path.
pub fn candidates(named: Option<&Path>, shell_var: Option<&OsStr>) -> Vec<Candidate> {
    if let Some(named) = named {
        return vec![Candidate { label: format!("--shell {}", named.display()), path: named.to_path_buf() }];
    }
    let mut out = Vec::new();
    if let Some(var) = shell_var.filter(|v| !v.is_empty()) {
        out.push(Candidate { label: format!("SHELL={}", Path::new(var).display()), path: PathBuf::from(var) });
    }
    for path in FALLBACKS {
        if !out.iter().any(|c| c.path == Path::new(path)) {
            out.push(Candidate { label: (*path).to_string(), path: PathBuf::from(path) });
        }
    }
    out
}

/// The first candidate that passes [`check`] and a run of `-c 'exit 0'`
/// in `env` (the child's environment, so a library path that the cage
/// needs is there).
pub fn find(candidates: &[Candidate], env: &[(OsString, OsString)]) -> Result<Found, NoShell> {
    find_with(candidates, |path| probe(path, env))
}

/// [`find`] with the run given, for the tests and for a caller that runs
/// otherwise: the order and the words stay the same.
pub fn find_with(candidates: &[Candidate], mut run: impl FnMut(&Path) -> Result<(), String>) -> Result<Found, NoShell> {
    let mut failed = Vec::new();
    for candidate in candidates {
        let why = match check(&candidate.path).and_then(|()| run(&candidate.path)) {
            Ok(()) => return Ok(Found { path: candidate.path.clone(), failed }),
            Err(why) => why,
        };
        failed.push(Failed { label: candidate.label.clone(), why });
    }
    Err(NoShell { failed })
}

/// The checks that need no run: an absolute path, a regular file once its
/// links are followed, and executable for this user. Read access is not
/// needed: a shell of mode 0711 runs.
pub fn check(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("not an absolute path".into());
    }
    let link = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err("no such file".into()),
        Err(e) => return Err(format!("cannot be looked at: {e}")),
    };
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound && link.file_type().is_symlink() => {
            return Err("a link to a missing file".into())
        }
        Err(e) => return Err(format!("cannot be looked at: {e}")),
    };
    if meta.is_dir() {
        return Err("a directory".into());
    }
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if executable(path) {
        return Ok(());
    }
    let mode = meta.permissions().mode() & 0o7777;
    Err(if mode & 0o111 == 0 {
        format!("not executable (mode {mode:04o})")
    } else if noexec_mount(path) {
        "not executable (noexec mount)".into()
    } else {
        format!("not executable by this user (mode {mode:04o})")
    })
}

/// `faccessat(X_OK, AT_EACCESS)`: the effective ids, as an exec uses them.
fn executable(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: a valid C string, alive for the call; nothing is kept.
    unsafe { libc::faccessat(libc::AT_FDCWD, c_path.as_ptr(), libc::X_OK, libc::AT_EACCESS) == 0 }
}

/// Whether the file system of `path` is mounted noexec: the reason that a
/// file with its mode bits set is still refused.
#[cfg(target_os = "linux")]
fn noexec_mount(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(c_path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return false };
    // SAFETY: statvfs fills the struct that it is given; zeroed is a valid
    // value of it.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a valid C string and a struct of the right type.
    let read = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } == 0;
    read && stat.f_flag & libc::ST_NOEXEC != 0
}

#[cfg(not(target_os = "linux"))]
fn noexec_mount(_path: &Path) -> bool {
    false
}

/// A real run of `PATH -c 'exit 0'` in `env`, at `/`, within
/// [`PROBE_WAIT`]. Its standard files are pipes, kept open until it ends,
/// as a cage may have no `/dev/null`.
pub fn probe(path: &Path, env: &[(OsString, OsString)]) -> Result<(), String> {
    let mut cmd = Command::new(path);
    cmd.args(["-c", PROBE]).env_clear().envs(env.iter().map(|(k, v)| (k, v))).current_dir("/");
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| not_started(&e))?;
    // Its stdin ends at once: a shell that reads it gets its end.
    drop(child.stdin.take());
    let deadline = Instant::now() + PROBE_WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return judged(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("ran -c '{PROBE}' and did not end within {} s", PROBE_WAIT.as_secs()));
            }
            Err(e) => {
                let _ = child.kill();
                return Err(format!("could not be waited for: {e}"));
            }
        }
    }
}

/// The words of a start that failed, by its errno.
pub fn not_started(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(libc::ENOEXEC) => "not a program that this host runs (exec format error)".into(),
        // The file itself was there at the check: what is missing is its
        // loader, or the interpreter of its `#!` line.
        Some(libc::ENOENT) => "its loader or interpreter is missing".into(),
        Some(libc::EACCES) => "refused at its start (a noexec mount, or a security policy)".into(),
        _ => format!("does not start: {e}"),
    }
}

/// Whether the probe's run passed.
fn judged(status: ExitStatus) -> Result<(), String> {
    if status.success() {
        return Ok(());
    }
    if let Some(signal) = status.signal() {
        return Err(format!("ran -c '{PROBE}' and was killed by signal {signal}"));
    }
    Err(format!("ran -c '{PROBE}' and ended with status {}: no shell", status.code().unwrap_or(-1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_shell_is_the_only_candidate() {
        let named = candidates(Some(Path::new("/opt/zsh")), Some(OsStr::new("/bin/bash")));
        assert_eq!(named.len(), 1);
        assert_eq!(named[0].label, "--shell /opt/zsh");
    }

    #[test]
    fn shell_comes_first_and_no_path_twice() {
        let list = candidates(None, Some(OsStr::new("/bin/bash")));
        assert_eq!(list[0].label, "SHELL=/bin/bash");
        assert_eq!(list.iter().filter(|c| c.path == Path::new("/bin/bash")).count(), 1);
        assert_eq!(list.len(), FALLBACKS.len());
        let empty = candidates(None, Some(OsStr::new("")));
        assert_eq!(empty[0].label, "/bin/sh", "an empty SHELL is no candidate");
    }

    #[test]
    fn the_line_names_each_failure_in_order() {
        let list = candidates(None, Some(OsStr::new("relative/sh")));
        let found = find_with(&list[..2], |_| Err("no".into())).expect_err("none passes");
        let line = found.to_string();
        assert!(line.starts_with("no shell runs here: SHELL=relative/sh: not an absolute path; /bin/sh: "), "{line}");
    }
}
