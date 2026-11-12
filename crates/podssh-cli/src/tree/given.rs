//! Whether a flag of a verb was given, as `clap`'s matches hold it.

use clap::ArgMatches;

/// Whether an argument id was actually supplied, under either spelling.
///
/// A boolean flag that was not given is still present in `ArgMatches` with
/// the value `false`, so "contains the id" is not enough — the value has to be
/// read, or the flag has to be true.
pub(super) fn was_given(m: &ArgMatches, id: &str) -> bool {
    if let Ok(Some(v)) = m.try_get_one::<bool>(id) {
        return *v;
    }
    if let Ok(Some(_)) = m.try_get_one::<String>(id) {
        return true;
    }
    if let Ok(Some(v)) = m.try_get_one::<u8>(id) {
        return *v > 0;
    }
    m.try_contains_id(id).unwrap_or(false)
}
