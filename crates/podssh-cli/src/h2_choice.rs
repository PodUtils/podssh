//! `--h2-shape WORD` (T-763): the shape of the HTTP/2 road that podssh
//! builds, chosen once before any road is built. A word that is not a shape
//! refuses the run (64) rather than silently sending the default; `doctor`
//! then names the shape that was chosen.
//!
//! The shape reaches no road where no road of podssh's own is built:
//! `pod-relay`'s opener takes `pod_ws::h2_road` directly and that road has no
//! shape. [`crate::h2_road`] is the opener that sends it, and
//! [`selected`] is what tells it to.

use std::io::Write;

use crate::exit_codes::EXIT_USAGE;
use crate::exitmap::sysexits::EX_CONFIG;
use crate::tree::Parsed;

/// Apply the flag's shape to this process, or return the exit code of a
/// word that is not one.
pub fn apply(p: &Parsed, err: &mut dyn Write) -> Option<i32> {
    let word = p.h2_shape();
    if let Some(word) = word {
        match podssh_ws::h2_road::choose(word) {
            Ok(()) => {}
            Err(why) => {
                // The word came from the flag, so the line names the flag,
                // never the variable (T-972).
                let why = why.replacen(podssh_ws::h2_road::SHAPE_ENV, "--h2-shape", 1);
                let _ = writeln!(err, "{}: {why}", p.head());
                return Some(EXIT_USAGE);
            }
        }
    }
    // The variable is read here too, and once: a run with a word that this
    // program cannot send is refused before it connects, whether the word
    // came from the flag (above) or from `PODSSH_H2_SHAPE`. The flag wins
    // over the variable, so a chosen shape makes the variable no concern.
    if podssh_ws::h2_road::chosen().is_some() {
        return None;
    }
    // A word of the variable is a fault of the environment: 78, as for
    // each other variable that cannot be used (T-972).
    match podssh_ws::h2_road::shape_from_env() {
        Ok(_) => None,
        Err(why) => {
            let _ = writeln!(err, "{}: {why}", p.head());
            Some(EX_CONFIG)
        }
    }
}

/// Whether this run sends a shape: `--h2-shape` chose one, or
/// `PODSSH_H2_SHAPE` names one that is not empty. An absent or empty
/// variable sends the road's own shape on podssh's own road, as before
/// T-763, and [`crate::h2_road`] stays out of the way.
pub fn on() -> bool {
    podssh_ws::h2_road::chosen().is_some()
        || std::env::var_os(podssh_ws::h2_road::SHAPE_ENV).is_some_and(|value| !value.is_empty())
}

/// The shape that this run sends, or `None` where no shape was chosen. A
/// word that is not a shape came back as a refusal of [`apply`]; this never
/// invents one.
pub fn selected() -> Option<podssh_ws::h2_road::Shape> {
    if !on() {
        return None;
    }
    podssh_ws::h2_road::chosen().or_else(|| podssh_ws::h2_road::shape_from_env().ok())
}
