//! The lines that tell a user the way back after an update (T-396, T-507):
//! `pod-release` keeps the binary before it beside the new one and puts it
//! back; what a line says of it is podssh's own, as it names podssh's
//! command.
//!
//! The way back that a line names is the kept file itself, moved over the
//! binary, which needs no podssh; `podssh update --rollback` beside it only
//! where the binary then in place has it: a release before
//! [`ROLLBACK_SINCE`] says "unknown flag". The version decides, as the
//! trial runs the new binary with `--version` alone.

use std::path::Path;

use pod_release::keep::{self, RolledBack};
use pod_release::replace::shown;
use pod_release::Version;

pub use crate::flags::ROLLBACK_SINCE;

/// Whether the binary of `version` has `podssh update --rollback`.
pub fn has_rollback(version: &Version) -> bool {
    Version::parse(ROLLBACK_SINCE).is_some_and(|first| *version >= first)
}

/// The command that moves `prev` over `exe` with no podssh: `mv`, its paths
/// quoted for a POSIX shell; on Windows `move /Y` of cmd, through `cmd /c`,
/// which PowerShell runs as cmd does.
pub fn moved_back(prev: &Path, exe: &Path) -> String {
    if cfg!(windows) {
        format!("cmd /c move /Y \"{}\" \"{}\"", shown(prev), shown(exe))
    } else {
        format!("mv {} {}", crate::snippets::quote(&shown(prev)), crate::snippets::quote(&shown(exe)))
    }
}

/// The line of an update to `version` that kept `prev` beside `exe`.
pub fn way_back(prev: &Path, exe: &Path, version: &Version) -> String {
    let mv = moved_back(prev, exe);
    if has_rollback(version) {
        format!("the binary before it is {}: podssh update --rollback puts it back, and so does {mv}", shown(prev))
    } else {
        format!("the binary before it is {}: {mv} puts it back; podssh {version} has no update --rollback", shown(prev))
    }
}

/// The version of a line that a binary said to `--version`, as
/// `podssh 1.0.0 (35a0d19d)`.
fn version_said(said: &str) -> Option<Version> {
    let mut words = said.split_whitespace();
    if words.next()? != super::PROGRAM {
        return None;
    }
    words.next().and_then(Version::parse)
}

/// The lines of `podssh update --rollback` that `done` on `exe` gives.
pub fn rolled_back(exe: &Path, done: &RolledBack) -> Vec<String> {
    let prev = keep::prev_of(exe);
    let said = &done.said;
    let mut lines = vec![format!("{}: rolled back; it is the binary of before, and said {said}", shown(exe))];
    // The binary now in place runs a next --rollback: it may be older.
    let mv = moved_back(&prev, exe);
    let replaced = format!("the binary that it replaced is {} now", shown(&prev));
    lines.push(match (&done.kept, version_said(said)) {
        (Ok(_), Some(now)) if has_rollback(&now) => {
            format!("{replaced}: podssh update --rollback goes back to it, and so does {mv}")
        }
        (Ok(_), Some(now)) => format!("{replaced}: {mv} goes back to it; podssh {now} has no update --rollback"),
        (Ok(_), None) => format!("{replaced}: {mv} goes back to it"),
        (Err(why), _) => format!("the binary that it replaced is not kept ({why})"),
    });
    lines.push("a run that started before goes on with its own binary until it starts again".into());
    lines
}
