//! WARP's road over HTTP/3 (T-582, the operator's ruling Q82), in a build
//! with the feature `warp`: where a probe found that UDP passes, the same
//! tunnel with each IP packet in a QUIC datagram. [`H3_ENV`] says when:
//! `auto`, the default, tries it after the road over HTTP/2 failed to reach
//! the endpoint (a proxy that refused, a network that carried nothing), as
//! the roads over UDP go after those over TCP; `first` tries it before; `no`
//! never. [`SERVER_ENV`] names a server of connect-ip over HTTP/3 that the
//! user runs, in place of WARP's endpoint, which needs no device.

use std::time::Duration;

use podssh_warp::h3::server::Server;
use podssh_warp::{Device, Fault, Warp};
use podssh_ws::Trust;

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
pub fn mode() -> Result<Mode, (String, i32)> {
    mode_of(std::env::var(H3_ENV).ok().as_deref()).map_err(|why| (why, EX_CONFIG))
}

/// Whether a fault of the road over HTTP/2 leaves HTTP/3 worth a try: the
/// endpoint not reached, cut, or silent. A refused device or this host's
/// part is the same over QUIC.
pub fn worth(fault: &Fault) -> bool {
    matches!(fault, Fault::Unreachable(_) | Fault::Intercepted(_) | Fault::Edge(_) | Fault::Silent(_))
}

/// The tunnel of `device` over HTTP/3, said in `verbose`.
pub async fn open(device: &Device, limit: Duration, verbose: &(dyn Fn(&str) + Sync)) -> Result<Warp, Fault> {
    verbose("trying WARP's road over HTTP/3, where a probe finds that UDP passes");
    let opened = Warp::open_h3(device, limit).await;
    match &opened {
        Ok(warp) => verbose(&format!("WARP's tunnel opened over HTTP/3 at {}", warp.endpoint)),
        Err(fault) => verbose(&format!("WARP's road over HTTP/3: {fault}")),
    }
    opened
}

/// A fault of HTTP/2, and HTTP/3's after it, as one line of the first's kind.
pub fn both(h2: Fault, h3: &Fault) -> Fault {
    let line = format!("{h2}; over HTTP/3: {h3}");
    match h2 {
        Fault::Unreachable(_) => Fault::Unreachable(line),
        Fault::Intercepted(_) => Fault::Intercepted(line),
        Fault::Device(_) => Fault::Device(line),
        Fault::Edge(_) => Fault::Edge(line),
        Fault::Silent(_) => Fault::Silent(line),
        Fault::Local(_) => Fault::Local(line),
    }
}

/// The user's server of [`SERVER_ENV`], or `None` when it is not set.
pub fn server() -> Result<Option<Server>, (String, i32)> {
    let Some(url) = std::env::var(SERVER_ENV).ok().filter(|v| !v.trim().is_empty()) else { return Ok(None) };
    let pin = std::env::var(SERVER_PIN_ENV).ok().filter(|v| !v.trim().is_empty());
    Server::parse(&url, pin.as_deref()).map(Some).map_err(|why| (format!("{SERVER_ENV}: {why}"), EX_CONFIG))
}

/// The tunnel to the user's `server`, with the probe inside it of
/// `PODSSH_WARP_PROBE` (T-560).
pub async fn to_server(
    server: &Server,
    trust: &Trust,
    probe: bool,
    limit: Duration,
    verbose: &(dyn Fn(&str) + Sync),
) -> Result<Warp, Fault> {
    verbose(&format!("{SERVER_ENV}: connect-ip over HTTP/3 to {}", server.shown()));
    let target = probe.then(podssh_warp::probe::target_v4);
    Warp::open_server(server, trust, target, limit).await
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

    /// A refused device is not tried again over QUIC; a silent tunnel is,
    /// and the line keeps the first fault's kind.
    #[test]
    fn http3_follows_a_fault_of_the_way_alone() {
        assert!(!worth(&Fault::Device("refused".into())));
        assert!(!worth(&Fault::Local("key".into())));
        assert!(worth(&Fault::Unreachable("the proxy refused CONNECT".into())));
        let line = both(Fault::Silent("carried nothing".into()), &Fault::Unreachable("UDP does not pass".into()));
        assert!(matches!(&line, Fault::Silent(l) if l == "carried nothing; over HTTP/3: UDP does not pass"));
    }
}
