//! The Pinggy road (T-548): a last fallback of the reverse road through
//! Pinggy's free TLS tunnels, which need no account. The operator's ruling
//! Q78 makes each public service that carries bytes a last fallback,
//! whatever its terms: tried after podssh's own roads and after the
//! services that allow the use, with a line that names the third party.
//!
//! A node's leg is SSH to Pinggy's server on port 443, through
//! `HTTPS_PROXY`: raw first, and inside TLS that the host's trust verifies
//! where a proxy passes TLS alone (the binary's); the user is `tls`, with a
//! remote forward of port 0. Pinggy gives the tunnel a name of its own,
//! routes each visitor's TLS by its SNI and never ends it, and opens a
//! `forwarded-tcpip` channel for each visitor
//! (<https://pinggy.io/docs/usages/>, read 2026-11-09). The node ends that
//! TLS itself with a certificate of its own key, self-signed ([`far`]), and
//! learns the tunnel's name from Pinggy's list at port 4300 of its end, or
//! from the session's own text ([`urls`]). A client's leg is TLS by the name
//! on port 443, with no upgrade ([`client`]), which pins the node's key as
//! the node says it beside the name ([`tls`]). The SSH host key of Pinggy's
//! server is pinned where `pod-services` names it, and the end-to-end channel
//! above the resumable layer checks the node's key on each link, so Pinggy
//! carries bytes it cannot read.
//!
//! A free tunnel ends at 60 minutes, and its next one has a new name
//! (<https://pinggy.io/>, read 2026-11-09): the node opens it again, and a
//! client's layer moves its session to the new name.

pub mod client;
pub mod far;
pub mod tls;
pub mod trace;
pub mod urls;

use std::sync::Arc;

pub use client::{carry, Address, Dialer, Link, Name};
pub use tls::Pin;

/// `no` turns the road off; `HOST[:PORT]` names another server of the same
/// protocol, such as a stand-in.
pub const ENV: &str = "PODSSH_PINGGY";
/// `no` turns off each last fallback of Q78 at once (T-548's Decision).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The port of a server where a value names none, and of each tunnel's name.
pub const PORT: u16 = 443;
/// The keyword of a TLS tunnel, sent as the SSH user: Pinggy routes by SNI
/// and forwards the TLS as it is (<https://pinggy.io/docs/tls_tunnels/>).
pub const TLS_USER: &str = "tls";
/// The address of the remote forward, as OpenSSH sends `-R0:...` with no
/// bind address: Pinggy's default forwarding, which takes no domain.
pub const FORWARD_ADDRESS: &str = "localhost";
/// The port of Pinggy's web debugger at its own end of the session, whose
/// `GET /urls` lists the tunnel's addresses
/// (<https://pinggy.io/docs/api/web_debugger_api/>, read 2026-11-09).
pub const URLS_PORT: u32 = 4300;

/// Where the lines of the road go, for the user.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The service of `pod-services`: Pinggy's free tier.
fn catalog() -> &'static pod_services::Service {
    pod_services::get("pinggy").expect("pod-services holds the service pinggy")
}

/// What Pinggy's text names beside a tunnel's address and is never a
/// tunnel's name, as its dashboard's host: `url-skip` of `pod-services`.
pub fn skips() -> Vec<String> {
    pod_services::forward::Relay::of(catalog()).map(|relay| relay.url_rule().skips).unwrap_or_default()
}

/// A server of Pinggy's protocol: SSH on `host`:`port`, raw or inside TLS,
/// and the SHA256 fingerprint of its host key when one is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub host_key: Option<String>,
}

impl Service {
    /// Pinggy's own: the endpoint `ssh` of `pod-services`, raw SSH on port
    /// 443, which takes SSH inside TLS too
    /// (<https://pinggy.io/docs/client_behind_proxy/>, read 2026-11-09); its
    /// host key where the fact `host-key-sha256` names it.
    pub fn hosted() -> Service {
        let service = catalog();
        let endpoint = service.endpoint("ssh").expect("pinggy of pod-services has the endpoint ssh");
        let host_key = service.text("host-key-sha256").map(str::to_string);
        Service { host: endpoint.host().to_ascii_lowercase(), port: endpoint.port(), host_key }
    }

    /// `HOST[:PORT]` or `[IPV6]:PORT`, with no scheme, path or user: another
    /// server, whose host key nobody named. A value that holds more is
    /// refused, and the refusal does not echo it.
    pub fn parse(text: &str) -> Result<Service, String> {
        let (host, port) = host_port(text, "the Pinggy road")?;
        Ok(Service { host, port: port.unwrap_or(PORT), host_key: None })
    }

    /// The server as a line names it.
    pub fn shown(&self) -> String {
        if self.port == PORT {
            self.host.clone()
        } else {
            podssh_ws::dial::authority(&self.host, self.port)
        }
    }
}

/// `HOST[:PORT]` or `[IPV6]:PORT` of a server of `road`'s protocol, with no
/// scheme, path or user: the host in lower case, and the port when the text
/// names one. Each road of an SSH service reads its variable so (T-548,
/// T-549); a refusal does not echo the text.
pub fn host_port(text: &str, road: &str) -> Result<(String, Option<u16>), String> {
    let text = text.trim();
    let bad = |c: char| matches!(c, '/' | '?' | '#' | '@') || c.is_whitespace();
    if text.is_empty() || text.contains(bad) {
        return Err(format!("a server of {road} is HOST[:PORT], with no scheme, path or user"));
    }
    let port_of = |text: &str| -> Result<u16, String> {
        let port = text.parse::<u16>().ok().filter(|p| *p != 0);
        port.ok_or_else(|| "the server's port is not a number from 1 to 65535".to_string())
    };
    // An IPv6 address in brackets, whose colons are not the port's.
    let (host, port) = if let Some(inner) = text.strip_prefix('[') {
        let (host, after) = inner.split_once(']').ok_or("an IPv6 address of the server has no closing ]")?;
        match after.strip_prefix(':') {
            Some(port) => (host, Some(port_of(port)?)),
            None if after.is_empty() => (host, None),
            None => return Err("the server's address is not [IPv6]:PORT".into()),
        }
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) => (host, Some(port_of(port)?)),
            None => (text, None),
        }
    };
    if host.is_empty() {
        return Err(format!("a server of {road} names no host"));
    }
    Ok((host.to_ascii_lowercase(), port))
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown())
    }
}

/// What [`ENV`] and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No Pinggy road, as the variable of this name says.
    Off(&'static str),
    /// The road, through this server.
    On(Service),
}

/// Whether a switch's value says no: unset, empty or yes is on.
fn says_no(name: &str, value: Option<&str>) -> Result<bool, String> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Ok(false),
        "no" | "off" | "false" | "0" => Ok(true),
        _ => Err(format!("{name}: yes or no")),
    }
}

/// Whether [`LAST_RESORT`]'s `value` turns the last fallbacks off. A word
/// that is neither yes nor no is no, as the proxy nodes read it (T-574):
/// the switch of the third parties fails closed.
pub fn last_resort_off(value: Option<&str>) -> Result<bool, String> {
    Ok(says_no(LAST_RESORT, value).unwrap_or(true))
}

/// [`ENV`]'s `value`, and [`LAST_RESORT`]'s `last`: either no turns the
/// road off; else Pinggy's own server, or the one that [`ENV`] names.
pub fn setting(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    if last_resort_off(last)? {
        return Ok(Setting::Off(LAST_RESORT));
    }
    let text = value.map(str::trim).unwrap_or_default();
    match says_no(ENV, Some(text)) {
        Ok(true) => Ok(Setting::Off(ENV)),
        Ok(false) => Ok(Setting::On(Service::hosted())),
        Err(_) => Service::parse(text).map(Setting::On).map_err(|why| format!("{ENV}: yes, no, or HOST[:PORT]: {why}")),
    }
}

/// The line that a run says before Pinggy carries a session of its own (Q78).
pub fn third_party_line(service: &Service) -> String {
    format!(
        "the Pinggy road, a last fallback: {service}, a third party that nobody vouches for, carries this session \
         (the operator's ruling Q78); SSH and the end-to-end channel keep its bytes private; {ENV}=no or \
         {LAST_RESORT}=no turns it off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinggy_s_own_server_is_the_one_of_pod_services_on_443() {
        let hosted = Service::hosted();
        assert_eq!(hosted.port, 443);
        assert!(!hosted.host.is_empty() && !hosted.host.contains('/'), "{hosted:?}");
        assert_eq!(hosted.shown(), hosted.host);
    }

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_are_refused_without_their_text() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting(on, None), Ok(Setting::On(Service::hosted())), "{on:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting(Some(off), None), Ok(Setting::Off(ENV)), "{off}");
            assert_eq!(setting(None, Some(off)), Ok(Setting::Off(LAST_RESORT)), "{off}");
            assert_eq!(setting(Some("127.0.0.1:8443"), Some(off)), Ok(Setting::Off(LAST_RESORT)), "{off}");
        }
        let own = setting(Some("Stand-In.Example.test:8443"), Some("yes")).unwrap();
        let wanted = Service { host: "stand-in.example.test".into(), port: 8443, host_key: None };
        assert_eq!(own, Setting::On(wanted));
        assert_eq!(Service::parse("[::1]:2222").unwrap().host, "::1");
        for refused in ["ssh://h?SECRET", "u:SECRET@h", "h/SECRET", "h:0", ":443"] {
            let why = setting(Some(refused), None).unwrap_err();
            assert!(why.starts_with("PODSSH_PINGGY: ") && !why.contains("SECRET"), "{why}");
        }
        assert_eq!(setting(None, Some("maybe")), Ok(Setting::Off(LAST_RESORT)), "another word is no");
    }

    /// The dashboard's host is never a tunnel's name: `url-skip` of
    /// `pod-services` (its `dashboard-host` before podcrates v0.26.0).
    #[test]
    fn the_dashboard_s_host_is_skipped() {
        let skips = skips();
        assert!(skips.iter().any(|s| s.contains("dashboard.pinggy.io")), "{skips:?}");
    }

    #[test]
    fn the_line_of_the_third_party_names_it_and_both_switches() {
        let line = third_party_line(&Service::parse("relay.example.test").unwrap());
        for word in ["relay.example.test", "nobody vouches for", "Q78", "PODSSH_PINGGY=no", "PODSSH_LAST_RESORT=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
    }
}
