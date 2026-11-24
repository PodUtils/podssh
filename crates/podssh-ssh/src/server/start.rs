//! What the start of a login shell adds to the child, apart from the child
//! itself, so that each path of a tty (a pty, serve's line discipline, a tty
//! that serve answers) takes the same: the message of the day (T-119) and
//! the shell integration marks (T-120).
//! Each part is read at the start of each session, with no cache, on the
//! blocking thread of the search for the shell.

// Windows runs no program (`podssh serve` is a Unix host's).
#![cfg_attr(not(unix), allow(dead_code))]

use std::ffi::OsString;
use std::path::Path;

use super::{env, marks, motd, Settings};

/// The parts of one start, kept on the channel until its child runs.
#[derive(Debug, Default)]
pub(super) struct Extras {
    /// The message of the day, as bytes for the client's terminal: the tty
    /// path writes it before the child's first byte.
    pub(super) motd: Option<Vec<u8>>,
    /// The start files of the marks on a pty or a tty that serve answers
    /// (T-120); dropped, they are removed, at the session's end.
    pub(super) marks: Option<marks::Files>,
    /// Whether serve's line discipline writes the marks itself (T-120).
    pub(super) line_marks: bool,
}

/// What a start is: a login shell on a tty, or anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Kind {
    /// A shell request, not a command (a key's `command=` makes a command).
    pub(super) login: bool,
    /// A tty of any of serve's kinds, granted by a `pty-req`.
    pub(super) tty: bool,
    /// The tty is serve's line discipline on pipes (T-111), where serve
    /// draws the prompt; else a pty or a tty that serve answers.
    pub(super) line: bool,
}

/// The parts for a start of `kind` with the child's environment `env`, and
/// the lines for serve's log. Only a login shell on a tty gets any, as sshd
/// gives them.
pub(super) fn extras(
    settings: &Settings,
    kind: Kind,
    shell: &Path,
    env: &[(OsString, OsString)],
) -> (Extras, Vec<String>) {
    let mut extras = Extras::default();
    let mut said = Vec::new();
    if !(kind.login && kind.tty) {
        return (extras, said);
    }
    if let Some(file) = settings.motd.as_ref() {
        let shown = motd::shown(file, env::lookup(env, "HOME"));
        extras.motd = shown.screen;
        said.extend(shown.said);
    }
    if settings.shell_integration {
        if kind.line {
            extras.line_marks = true;
        } else {
            match start_files(shell, env) {
                Ok(files) => extras.marks = Some(files),
                // The shell starts without marks: no session fails for them.
                Err(why) => said.push(format!("--shell-integration: {why}: this shell has no marks")),
            }
        }
    }
    (extras, said)
}

/// The start files of the marks for `shell`, where it is bash or zsh.
fn start_files(shell: &Path, env: &[(OsString, OsString)]) -> Result<marks::Files, String> {
    let Some(kind) = marks::Shell::of(shell) else {
        return Err(format!("{} is neither bash nor zsh", shell.display()));
    };
    let tmp = marks::tmp_of(env::lookup(env, "TMPDIR"));
    marks::files(kind, &tmp, env::lookup(env, "ZDOTDIR"))
}
