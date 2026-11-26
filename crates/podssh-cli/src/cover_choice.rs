//! `--cover-credential` (T-765): the delegated credential of a cover relay
//! on the live connection, chosen once before any road is built.
//!
//! The flag sets this process's switch; [`crate::h2_road`] reads it where it
//! opens a session, because the credential must be asked for on the very
//! TLS connection that then upgrades, and only a client that builds that
//! connection itself can put the request between the handshake and the
//! upgrade.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::exit_codes::EXIT_USAGE;
use crate::tree::Parsed;

static ON: AtomicBool = AtomicBool::new(false);

/// Apply the flag to this process, or return the exit code of a run that
/// asks for two roads at once.
pub fn apply(p: &Parsed, err: &mut dyn Write) -> Option<i32> {
    if !p.cover_credential() {
        return None;
    }
    if crate::h2_choice::on() {
        let _ = writeln!(
            err,
            "{}: --cover-credential asks for a credential on the TLS connection, which --h2-shape's road does \
             not offer; name one or the other",
            p.head()
        );
        return Some(EXIT_USAGE);
    }
    ON.store(true, Ordering::SeqCst);
    None
}

/// Whether this run asks the relay for a delegated credential before its
/// upgrade.
pub fn on() -> bool {
    ON.load(Ordering::SeqCst)
}
