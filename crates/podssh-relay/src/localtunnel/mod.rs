//! The localtunnel road (T-568): a last fallback of the operator's ruling
//! Q78 through localtunnel's public server, which gives a node an HTTPS name
//! with no account. What the road speaks was read on 2026-11-10 in
//! localtunnel's client (localtunnel/localtunnel 2.0.2: `lib/Tunnel.js`,
//! `lib/TunnelCluster.js`) and its server (localtunnel/server 0.0.8:
//! `server.js`, `lib/ClientManager.js`, `lib/Client.js`,
//! `lib/TunnelAgent.js`), both MIT:
//!
//! - the node asks `GET /?new`, or `GET /NAME` for a name of its own, and
//!   the server answers `{id, port, max_conn_count, url}`, with `ip` where
//!   it names one ([`api`]); a name that another holds gives a random one;
//! - the node opens `max_conn_count` TCP connections (10) to that port,
//!   which the server's OS chose, and the server sends each visitor's
//!   request down one: written again by Node's HTTP client on a connection
//!   that it keeps for the next, or for an upgrade the head as it came and
//!   then each byte both ways ([`keep`]);
//! - nothing proves who connects to the port, and the server forgets a
//!   tunnel 1 s after its last connection closed.
//!
//! Each connection is served by [`route`]: the relay role's paths go to the
//! role (`crate::serve`), as behind the quick tunnel (T-428), and a
//! WebSocket to any other path is one link of the node's resumable layer,
//! with the end-to-end channel above it. A client's link ([`link`]) is TLS to
//! the tunnel's name on port 443 and that WebSocket, with the header
//! `Bypass-Tunnel-Reminder`, which passes the hosted server's page for
//! browsers. The node asks for a name that its key gives ([`name_of`]), so a
//! client that holds the key finds it with no record; a stranger at the
//! name, or at the port, meets the end-to-end channel, which refuses it.

pub mod api;
pub mod keep;
pub mod link;
pub mod route;

use std::net::IpAddr;

use sha2::{Digest, Sha256};

/// `no` turns the road off; an `https://` URL names another server of the
/// same protocol, or `http://` one on this host's loopback, such as a
/// stand-in.
pub const ENV: &str = "PODSSH_LOCALTUNNEL";
/// The id of the hosted server in `pod-services`; the road has no server of
/// its own until that list names one (`AGENTS.md`: no host of another party
/// in podssh's code).
pub const SERVICE_ID: &str = "localtunnel";
/// The header that passes the hosted server's page for browsers, with any
/// value that is not false (its operator, localtunnel/localtunnel#663).
pub const HEADER: &str = "Bypass-Tunnel-Reminder";
/// The status of that page, as its operator names it there.
pub const REMINDER: u16 = 511;
/// The port of the API and of each tunnel's name, where a URL names none.
pub const PORT: u16 = 443;

/// The label of the name's derivation, so that the name is this road's alone.
const NAME_LABEL: &[u8] = b"podssh localtunnel name v1\0";
/// What a derived name begins with, so that a line or a log shows whose it is.
const NAME_PREFIX: &str = "podssh-";

/// A server of localtunnel's protocol: its API at `host`:`port`, over TLS
/// unless `tls` is false (the loopback alone), and the domain of its
/// tunnels' names, `ID.zone`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub zone: String,
}

impl Service {
    /// The hosted server, as `pod-services` names it (the endpoint `api` and
    /// the fact `tunnel-zone`); none while that list does not hold it.
    pub fn hosted() -> Option<Service> {
        let service = pod_services::get(SERVICE_ID)?;
        let api = service.endpoint("api")?;
        let zone = service.text("tunnel-zone")?.to_ascii_lowercase();
        Some(Service { host: api.host().to_ascii_lowercase(), port: api.port(), tls: true, zone })
    }

    /// `https://HOST[:PORT][/]`, or `http://` with a host of the loopback:
    /// another server, whose tunnels are names under the API's own, as
    /// localtunnel/server makes them. The refusal does not echo the text.
    pub fn parse(text: &str) -> Result<Service, String> {
        let text = text.trim();
        let scheme = |n: usize| text.get(..n).map(str::to_ascii_lowercase);
        let (tls, rest) = match (scheme(8).as_deref(), scheme(7).as_deref()) {
            (Some("https://"), _) => (true, &text[8..]),
            (_, Some("http://")) => (false, &text[7..]),
            _ => return Err("a localtunnel server is an https:// URL, or http:// on this host's loopback".into()),
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = crate::pinggy::host_port(rest, "the localtunnel road")?;
        if !tls && !loopback(&host) {
            return Err("a localtunnel server over http:// must be on this host's loopback: use https://".into());
        }
        let port = port.unwrap_or(if tls { PORT } else { 80 });
        let mut service = Service { host, port, tls, zone: String::new() };
        service.zone = service.authority();
        Ok(service)
    }

    /// The value of a request's `Host`: the host alone on its scheme's port.
    pub fn authority(&self) -> String {
        let default = if self.tls { PORT } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            podssh_ws::dial::authority(&self.host, self.port)
        }
    }

    /// The server as a line names it.
    pub fn shown(&self) -> String {
        format!("{}://{}", if self.tls { "https" } else { "http" }, self.authority())
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown())
    }
}

/// Whether `host` is this host's loopback.
fn loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// What [`ENV`] and `PODSSH_LAST_RESORT` ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No localtunnel road, as the variable of this name says.
    Off(&'static str),
    /// The road, through this server.
    On(Service),
    /// The road is on, but no server is known: `pod-services` names none,
    /// and [`ENV`] names none.
    Unnamed,
}

/// [`ENV`]'s `value`, and `PODSSH_LAST_RESORT`'s `last`: either no turns
/// the road off, as each last fallback reads them (T-548's Decision); else
/// the server that [`ENV`] names, or the hosted one where `pod-services`
/// names it.
pub fn setting(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    setting_with(value, last, Service::hosted())
}

/// [`setting`] with `hosted` as the list's server, for the tests.
pub fn setting_with(value: Option<&str>, last: Option<&str>, hosted: Option<Service>) -> Result<Setting, String> {
    if crate::pinggy::last_resort_off(last)? {
        return Ok(Setting::Off(crate::pinggy::LAST_RESORT));
    }
    let text = value.map(str::trim).unwrap_or_default();
    match text.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(Setting::Off(ENV)),
        "" | "yes" | "on" | "true" | "1" => Ok(hosted.map_or(Setting::Unnamed, Setting::On)),
        _ => Service::parse(text).map(Setting::On).map_err(|why| format!("{ENV}: yes, no, or a server's URL: {why}")),
    }
}

/// The setting of this process's variables.
pub fn from_env() -> Result<Setting, String> {
    let value = std::env::var(ENV).ok();
    let last = std::env::var(crate::pinggy::LAST_RESORT).ok();
    setting(value.as_deref(), last.as_deref())
}

/// Why the road has no server, for a line or a refusal.
pub fn unnamed_words() -> String {
    format!(
        "the localtunnel road has no server: podssh's list of services (pod-services) does not name localtunnel's \
         in this build, and {ENV} names none; {ENV}=https://HOST names one"
    )
}

/// The name that a node of the key `fingerprint` (`SHA256:...`) asks for:
/// SHA-256 over this road's label and the fingerprint, 64 bits of it in hex,
/// a word that the server's check of a name takes (4 to 63 lower-case
/// letters, digits and `-`). A stranger may take it from the key, which is
/// public, so the hash hides nothing; the end-to-end channel refuses that
/// stranger.
pub fn name_of(fingerprint: &str) -> String {
    let digest: [u8; 32] =
        Sha256::new().chain_update(NAME_LABEL).chain_update(fingerprint.as_bytes()).finalize().into();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{NAME_PREFIX}{hex}")
}

/// Whether `text` is one label of a name, as a tunnel's id must be: 1 to
/// 63 lower-case letters, digits and `-`, with no `-` at either end.
pub fn is_label(text: &str) -> bool {
    let ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    (1..=63).contains(&text.len())
        && text.bytes().all(ok)
        && !text.starts_with('-')
        && !text.ends_with('-')
}

/// The line that a run says before the road carries a session of its own
/// (Q78), as the other last fallbacks say theirs.
pub fn third_party_line(service: &Service) -> String {
    format!(
        "the localtunnel road, a last fallback: {service}, a third party that nobody vouches for, carries this \
         session (the operator's ruling Q78); it ends the visitors' TLS and sees the times, the sizes and the \
         layer's bytes, which the end-to-end channel keeps private; {ENV}=no or {}=no turns it off",
        crate::pinggy::LAST_RESORT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand_in() -> Service {
        Service { host: "lt.stand-in.test".into(), port: 443, tls: true, zone: "lt.stand-in.test".into() }
    }

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_leave_it_with_none() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting_with(on, None, Some(stand_in())), Ok(Setting::On(stand_in())), "{on:?}");
            assert_eq!(setting_with(on, None, None), Ok(Setting::Unnamed), "{on:?}: no server of the list");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting_with(Some(off), None, Some(stand_in())), Ok(Setting::Off(ENV)), "{off}");
            let last = setting_with(Some("https://lt.example.test"), Some(off), Some(stand_in()));
            assert_eq!(last, Ok(Setting::Off("PODSSH_LAST_RESORT")), "{off}");
        }
        let own = setting_with(Some("https://Tunnels.Example.test:8443/"), None, None).unwrap();
        let zone = "tunnels.example.test:8443".to_string();
        assert_eq!(own, Setting::On(Service { host: "tunnels.example.test".into(), port: 8443, tls: true, zone }));
        let local = Service::parse("http://127.0.0.1:3000").unwrap();
        assert_eq!((local.tls, local.port, local.authority()), (false, 3000, "127.0.0.1:3000".to_string()));
        for refused in
            ["maybe?SECRET", "http://lt.example.test", "https://lt.example.test/x?SECRET", "https://u:SECRET@h"]
        {
            let why = setting_with(Some(refused), None, None).unwrap_err();
            assert!(why.starts_with("PODSSH_LOCALTUNNEL: ") && !why.contains("SECRET"), "{why}");
        }
    }

    #[test]
    fn the_name_is_the_key_s_and_a_word_that_the_server_takes() {
        let name = name_of("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
        assert_eq!(name.len(), NAME_PREFIX.len() + 16, "{name}");
        assert!(is_label(&name), "{name}");
        // localtunnel/server's check of a name: 4 to 63, lower case, digits, `-` inside.
        assert!(name.len() >= 6 && !name.ends_with('-'));
        assert_ne!(name, name_of("SHA256:another"), "another key, another name");
        // The derivation is fixed: a node and a client of other versions meet.
        assert_eq!(name, name_of("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"));
        for bad in ["", "-a", "a-", "A", "a.b", &"a".repeat(64)] {
            assert!(!is_label(bad), "{bad}");
        }
    }

    #[test]
    fn the_line_of_the_third_party_names_it_and_both_switches() {
        let line = third_party_line(&stand_in());
        for word in ["lt.stand-in.test", "nobody vouches for", "Q78", "PODSSH_LOCALTUNNEL=no", "PODSSH_LAST_RESORT=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
        assert!(unnamed_words().contains("PODSSH_LOCALTUNNEL=https://HOST"));
    }
}
