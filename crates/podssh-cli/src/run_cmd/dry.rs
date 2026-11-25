//! The answer of `podssh run --dry-run` (T-475): what the copy would change
//! and the command it would run, on stdout, with nothing changed on either
//! side and nothing run. The copy's looks only read, so the plan holds only
//! what changed, as the run would send it: a second dry run after a run and
//! one change names that file alone.

use std::io::Write;

use podssh_ssh::{Log, EXIT_FAILURE};

use super::Plan;
use crate::cp::sync::Synced;
use crate::exitmap::sysexits::EX_IOERR;

/// The plan of a dry run on `out`: each far directory above the project's
/// that the run would make, the actions of the copy as `cp -r --dry-run`
/// says them, then `run cd DIR && COMMAND`. The paths that the excludes left
/// out are counted on stderr, as the summary of a run counts them. The
/// exit: 0, 255 when the far side could not be read, with no plan, or 74
/// when the plan could not be written, as for each output (T-965).
pub(super) fn answer(plan: &Plan, parents: &[String], synced: &Synced, log: &Log, out: &mut dyn Write) -> i32 {
    if synced.failed.is_some() {
        // Each failure was said as it came; half a plan would read as all of it.
        log.error(&format!("the dry run could not read {}, so it gives no plan", plan.far.path));
        return EXIT_FAILURE;
    }
    let text = lines(plan, parents, &synced.plan);
    // The standard library takes a write to a closed stdout for done: the
    // descriptor is asked as well (T-983).
    if let Err(e) = out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        log.error(&format!("the plan could not be written to stdout: {}", podssh_ws::text::said(&e)));
        return EX_IOERR;
    }
    if stdout_closed() {
        log.error("the plan could not be written: stdout is closed");
        return EX_IOERR;
    }
    if let Some(line) = left_out(synced.counts.left_out) {
        log.info(&line);
    }
    0
}

/// The text of the plan: a line for each action, the command last.
pub(super) fn lines(plan: &Plan, parents: &[String], actions: &[String]) -> String {
    let mut text = String::new();
    for dir in parents {
        text.push_str(&format!("mkdir {dir}\n"));
    }
    for line in actions {
        text.push_str(line);
        text.push('\n');
    }
    text.push_str(&format!("run {}\n", plan.command));
    text
}

/// The line on stderr when the excludes left paths out, which `-v` names
/// each with its pattern; none when they left nothing out.
pub(super) fn left_out(count: usize) -> Option<String> {
    match count {
        0 => None,
        1 => Some("1 path left out by the excludes; -v names it".into()),
        n => Some(format!("{n} paths left out by the excludes; -v names each")),
    }
}

/// Whether this process has no stdout: its descriptor closed (`>&-`), or no
/// handle on Windows. Rust's stdout takes each write there for done, so a
/// plan would be lost with exit 0 (T-983).
pub(super) fn stdout_closed() -> bool {
    // SAFETY: F_GETFD only reads the table of descriptors; a closed one
    // fails with EBADF.
    #[cfg(unix)]
    let closed = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFD) } == -1;
    #[cfg(windows)]
    let closed = {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::System::Console::{GetStdHandle, STD_OUTPUT_HANDLE};
        // SAFETY: a read of this process's standard handle.
        let handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
        handle.is_null() || handle == INVALID_HANDLE_VALUE
    };
    #[cfg(not(any(unix, windows)))]
    let closed = false;
    closed
}
