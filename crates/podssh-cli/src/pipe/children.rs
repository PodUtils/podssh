//! The programs of a pipe's `exec:` sides that podssh has not waited for
//! yet, by pid (T-913). A signal that ends a pipe that does not listen goes
//! on to each of them, as a shell's job gets it, and a program that is still
//! there after [`CHILD_WAIT`] is killed: else the pipe's end would leave it
//! running with no parent, or podssh would wait for it with no bound.
//!
//! A pid is forgotten before its program is waited for, so that a signal
//! never reaches a pid that the system gave to another process since. The
//! loop of datagrams waits beside its other work; it forgets its pid as it
//! stops, which leaves a window of one reap, far shorter than the reuse of
//! a pid.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

pub use super::datagram::CHILD_WAIT;

/// How long the pipe waits for its ends after a program was killed: the
/// kill is sure, and only the reads and the waits remain.
pub const AFTER_KILL: Duration = Duration::from_secs(2);

static STARTED: Mutex<Vec<u32>> = Mutex::new(Vec::new());

fn with<T>(f: impl FnOnce(&mut Vec<u32>) -> T) -> T {
    f(&mut STARTED.lock().unwrap_or_else(PoisonError::into_inner))
}

/// A program was started; `None` (no pid) is skipped.
pub fn started(pid: Option<u32>) {
    if let Some(pid) = pid.filter(|pid| killable(*pid)) {
        with(|pids| pids.push(pid));
    }
}

/// The program of `pid` is about to be waited for, or was killed.
pub fn reaped(pid: Option<u32>) {
    if let Some(pid) = pid {
        with(|pids| pids.retain(|p| *p != pid));
    }
}

/// Whether a program of this pipe has not been waited for.
pub fn any() -> bool {
    with(|pids| !pids.is_empty())
}

/// A pid that may get a signal: never 0, 1 or this process.
fn killable(pid: u32) -> bool {
    pid > 1 && pid != std::process::id() && i32::try_from(pid).is_ok()
}

/// Send `signal` to each program. On Windows a console's Ctrl-C and
/// Ctrl-Break reach each program of the console by themselves; nothing is
/// sent.
pub fn signal_all(signal: i32) {
    #[cfg(unix)]
    for pid in with(|pids| pids.clone()) {
        // SAFETY: kill only sends a signal, to a program that this pipe
        // started and has not waited for, so its pid is still its own.
        unsafe { libc::kill(pid as libc::pid_t, signal) };
    }
    #[cfg(not(unix))]
    let _ = signal;
}

/// Kill each program that is still there: SIGKILL, or TerminateProcess on
/// Windows. Each is forgotten, as the pipe's wait reaps it next.
pub fn kill_all() {
    for pid in with(std::mem::take) {
        kill(pid);
    }
}

#[cfg(unix)]
fn kill(pid: u32) {
    // SAFETY: as in [`signal_all`].
    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
}

#[cfg(windows)]
fn kill(pid: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
    // SAFETY: the handle is checked, used once and closed once.
    unsafe {
        let process = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !process.is_null() {
            TerminateProcess(process, 1);
            CloseHandle(process);
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn kill(_pid: u32) {}

/// The name of a signal by the exit code that it gives, for the line.
pub fn named(code: i32) -> &'static str {
    match code {
        129 => "SIGHUP",
        130 => "SIGINT",
        143 => "SIGTERM",
        _ => "a signal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pid_that_is_no_program_of_the_pipe_is_never_kept() {
        for pid in [0, 1, std::process::id(), u32::MAX] {
            started(Some(pid));
            assert!(with(|pids| !pids.contains(&pid)), "{pid}");
        }
    }

    #[test]
    fn each_code_of_a_signal_has_its_name() {
        let table = [(129, "SIGHUP"), (130, "SIGINT"), (143, "SIGTERM"), (1, "a signal")];
        for (code, name) in table {
            assert_eq!(named(code), name, "{code}");
        }
    }
}
