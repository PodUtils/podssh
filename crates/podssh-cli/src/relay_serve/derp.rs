//! `--derp-keys FILE` of `podssh relay serve` (T-106): DERP at `/derp` for
//! the node keys of FILE, `podssh_relay::serve::derp`'s, so that a node of
//! `podssh ts --ts-mode relay` pins this relay in the place of the
//! operator's Tailscale relay. The file is read here once, so that a file
//! that cannot be read, or a line that is no key, stops the start.

use crate::relay_settings::Refusal;

/// DERP turned on for the file of `keys`, when given: the words of the
/// start's line, empty with none.
pub(super) fn of(keys: Option<&str>) -> Result<String, Refusal> {
    let Some(file) = keys else { return Ok(String::new()) };
    let listed = podssh_relay::serve::derp::enable(std::path::Path::new(file))
        .map_err(|why| Refusal::usage(format!("--derp-keys {why}")))?;
    Ok(format!(", DERP at /derp for the node keys of {file} ({listed} now, read again at each login)"))
}
