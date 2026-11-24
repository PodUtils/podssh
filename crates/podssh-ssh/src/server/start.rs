//! What the start of a login shell adds to the child, apart from the child
//! itself, so that each path of a tty (a pty, serve's line discipline, a tty
//! that serve answers) takes the same: the message of the day (T-119).
//! Each part is read at the start of each session, with no cache, on the
//! blocking thread of the search for the shell.

// Windows runs no program (`podssh serve` is a Unix host's).
#![cfg_attr(not(unix), allow(dead_code))]

use std::ffi::OsString;

use super::{env, motd, Settings};

/// The parts of one start, kept on the channel until its child runs.
#[derive(Debug, Default)]
pub(super) struct Extras {
    /// The message of the day, as bytes for the client's terminal: the tty
    /// path writes it before the child's first byte.
    pub(super) motd: Option<Vec<u8>>,
}

/// What a start is: a login shell on a tty, or anything else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Kind {
    /// A shell request, not a command (a key's `command=` makes a command).
    pub(super) login: bool,
    /// A tty of any of serve's kinds, granted by a `pty-req`.
    pub(super) tty: bool,
}

/// The parts for a start of `kind` with the child's environment `env`, and
/// the lines for serve's log. Only a login shell on a tty gets any, as sshd
/// gives them.
pub(super) fn extras(settings: &Settings, kind: Kind, env: &[(OsString, OsString)]) -> (Extras, Vec<String>) {
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
    (extras, said)
}
