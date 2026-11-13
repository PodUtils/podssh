//! WARP's road over HTTP/3 (T-582, the operator's ruling Q82), in a build
//! with the feature `warp`: where UDP passes, the same tunnel with each IP
//! packet in a QUIC datagram (pod-warp's `Way::h3`). [`H3_ENV`] says when:
//! `auto`, the default, tries it after the road over HTTP/2 failed to reach
//! the endpoint (a proxy that refused, a network that carried nothing), as
//! the roads over UDP go after those over TCP; `first` tries it before; `no`
//! never. [`SERVER_ENV`] names a server of connect-ip over HTTP/3 that the
//! user runs, in place of WARP's endpoint: pod-warp does not speak to one
//! (PodUtils/podcrates T-481), so a run that sets it is refused.

use super::Failed;
use crate::exitmap::sysexits::EX_CONFIG;

/// When the road takes HTTP/3: `auto`, `first` or `no`.
pub const H3_ENV: &str = "PODSSH_WARP_H3";
/// A server of connect-ip over HTTP/3, `https://HOST[:PORT][/PATH]`.
pub const SERVER_ENV: &str = "PODSSH_WARP_SERVER";
/// The SHA-256 of that server's certificate, 64 hex digits.
pub const SERVER_PIN_ENV: &str = "PODSSH_WARP_SERVER_PIN";

/// When the road takes HTTP/3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// After the road over HTTP/2 failed to reach the endpoint.
    Auto,
    /// Before the road over HTTP/2.
    First,
    /// Never.
    No,
}

/// The mode of `value` of [`H3_ENV`]: unset or empty is `auto`.
pub fn mode_of(value: Option<&str>) -> Result<Mode, String> {
    let Some(value) = value else { return Ok(Mode::Auto) };
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "auto" | "yes" | "on" => Ok(Mode::Auto),
        "first" => Ok(Mode::First),
        "no" | "off" | "false" | "0" => Ok(Mode::No),
        _ => Err(format!("{H3_ENV}={value}: auto, first or no")),
    }
}

/// The mode of this run.
pub fn mode() -> Result<Mode, Failed> {
    mode_of(std::env::var(H3_ENV).ok().as_deref()).map_err(|why| (why, EX_CONFIG))
}

/// The refusal of a user's server of [`SERVER_ENV`] (or its pin alone).
pub fn server_refused(server: Option<&str>, pin: Option<&str>) -> Result<(), String> {
    let set = |v: Option<&str>| v.is_some_and(|v| !v.trim().is_empty());
    if !set(server) && !set(pin) {
        return Ok(());
    }
    Err(format!(
        "{SERVER_ENV} and {SERVER_PIN_ENV}: this build takes WARP's endpoint alone, as pod-warp does not speak \
         connect-ip over HTTP/3 to a server of the user's own (PodUtils/podcrates T-481); unset both"
    ))
}

/// [`server_refused`] for this run's environment, with the code of a part
/// that this build lacks.
pub fn no_server() -> Result<(), Failed> {
    let var = |name: &str| std::env::var(name).ok();
    server_refused(var(SERVER_ENV).as_deref(), var(SERVER_PIN_ENV).as_deref())
        .map_err(|why| (why, crate::exit_codes::EXIT_NOT_IMPLEMENTED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mode_reads_its_words() {
        assert_eq!(mode_of(None), Ok(Mode::Auto));
        assert_eq!(mode_of(Some("")), Ok(Mode::Auto));
        assert_eq!(mode_of(Some("FIRST")), Ok(Mode::First));
        assert_eq!(mode_of(Some("no")), Ok(Mode::No));
        assert!(mode_of(Some("maybe")).unwrap_err().contains("auto, first or no"));
    }

    /// A server of the user's own is refused with the entry that brings it
    /// back; none set is no refusal.
    #[test]
    fn a_server_of_the_user_s_own_is_refused() {
        assert_eq!(server_refused(None, Some(" ")), Ok(()));
        let why = server_refused(Some("https://masque.example:443"), None).unwrap_err();
        assert!(why.contains("PodUtils/podcrates T-481"), "{why}");
        assert!(server_refused(None, Some("ab")).is_err());
    }
}
