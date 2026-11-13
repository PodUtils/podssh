//! Whether each verb works in this binary, apart from the flag table so
//! that `flags.rs` stays one file of 500 lines or fewer.

use super::Verb;

/// Every verb that dispatch refuses as "not implemented yet", with the roadmap
/// milestone (docs/ROADMAP.md) that builds it. The milestone is for
/// maintainers; users only see that the verb is not implemented.
///
/// A verb with its own dispatch arm (`ssh`, `proxy`, `doctor`, `keygen`,
/// `man`, `ts`) is handled before this table is consulted. When a verb gets
/// its own arm, remove its row here and add it to `DISPATCHED` in
/// `tests/flag_table.rs`; dispatch treats a verb with neither an arm nor a row
/// as an internal error, never as success. Each verb has its arm now; the
/// table stays for a verb that parses before it works.
pub const VERB_OWNER: &[(&str, &str)] = &[];

/// Whether a verb does something in this binary. `--help` and the manual
/// both show it, so neither can offer a command that only refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    Works,
    /// Parses, and refuses with exit 70 (a row of [`VERB_OWNER`]).
    NotYet,
    /// Needs a cargo feature this binary was built without (`ts`).
    NotInBuild,
}

pub fn availability(verb: &Verb) -> Availability {
    if verb.name == "ts" && !cfg!(feature = "ts") {
        Availability::NotInBuild
    } else if VERB_OWNER.iter().any(|(name, _)| *name == verb.name) {
        Availability::NotYet
    } else {
        Availability::Works
    }
}
