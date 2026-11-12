//! The hostc road (T-742): a last fallback of the operator's ruling Q78
//! through hostc's public server, which gives a node a public HTTPS name
//! with no account. What the road speaks is version 5 of hostc's protocol,
//! read on 2026-11-12 in `akazwz/hostc` at `c19ff67` (Apache-2.0):
//! `docs/protocol.md`, `packages/protocol/src/` (its constants, frames and
//! messages), `packages/client/src/` (`api.ts`, `connection.ts`,
//! `streams.ts`) and `apps/server/src/index.ts`:
//!
//! - the node asks `POST /api/tunnels` with the header `hostc-protocol: 5`
//!   and gets `201 {id, url, connectUrl, token}` ([`api`]); a version that
//!   the server does not speak is `426`, with no fallback;
//! - the node keeps one WebSocket to `connectUrl` with `Authorization:
//!   Bearer TOKEN`, offering no extension, and sends the text `hostc:ping`
//!   each 15 s; nothing within 10 s of a ping is a dead socket ([`link`]);
//! - each visitor's request or WebSocket is a stream of binary frames
//!   (`u8` type, `u32` stream id) on it ([`wire`]): HTTP bodies keep windows
//!   of 256 KiB, a WebSocket's messages pass whole below 1 MiB;
//! - a dropped socket keeps the tunnel's name for 10 minutes, but no stream
//!   survives it: the resumable layer carries a session over ([`keep`]).
//!
//! Each stream is written again as plain HTTP/1.1 on a pipe in this process
//! ([`bridge`]), so the node serves it as it serves a visitor of a tunnel of
//! `ssh -R` (`crate::ssh_http::visit`): a WebSocket at `/` is one link of the
//! node's layer, with the end-to-end channel above it; a path of the relay
//! role goes to the role. A client reaches the name as it reaches such a
//! tunnel's: TLS by name on 443 and a WebSocket at `/`. Nothing listens.

pub mod api;
pub mod bridge;
mod bridge_http;
mod bridge_ws;
pub mod keep;
pub mod link;
pub mod wire;

use std::net::IpAddr;
use std::time::Duration;

pub use crate::pinggy::LAST_RESORT;

/// `no` turns the road off; an `https://` URL names another server of the
/// same protocol, or `http://` one on this host's loopback, such as hostc's
/// own server under its local runtime in a test.
pub const ENV: &str = "PODSSH_HOSTC";
/// The id of the hosted server in `pod-services`; the road has no server of
/// its own until that list names one (`AGENTS.md`: no host of another party
/// in podssh's code).
pub const SERVICE_ID: &str = "hostc";
/// The version of the protocol, which must match the server's exactly.
pub const PROTOCOL_VERSION: u32 = 5;
/// The header of the version, on each call of the API and the socket.
pub const PROTOCOL_HEADER: &str = "hostc-protocol";
/// The heartbeat, as text; the runtime answers [`PONG`]. Every other
/// message is a binary frame.
pub const PING: &str = "hostc:ping";
pub const PONG: &str = "hostc:pong";
/// How often the node pings.
pub const HEARTBEAT: Duration = Duration::from_secs(15);
/// How long after a ping a socket that brought nothing is dead.
pub const HEARTBEAT_WAIT: Duration = Duration::from_secs(10);
/// The largest `DATA` of an HTTP body.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Each stream's first window, each way.
pub const STREAM_WINDOW: usize = 256 * 1024;
/// The largest WebSocket message that passes whole; a larger one closes
/// the visitor's socket with `1009` at the server.
pub const MAX_MESSAGE: usize = 1024 * 1024 - 64;
/// The streams of one tunnel at once, at the server.
pub const MAX_STREAMS: usize = 256;
/// What a WebSocket stream may hold for the role, which the server cannot
/// hold back: past it, the stream closes with `1013`, as hostc's client does.
pub const MAX_QUEUED: usize = 4 * 1024 * 1024;
/// How long a dropped tunnel keeps its name.
pub const RECONNECT_GRACE: Duration = Duration::from_secs(10 * 60);
/// The tunnels that one address may ask for in a minute (`CREATE_LIMIT`).
pub const CREATE_LIMIT: u32 = 20;
/// The port of the API and of each tunnel's name, where a URL names none.
pub const PORT: u16 = 443;

/// A server of hostc's protocol: its API at `host`:`port`, over TLS unless
/// `tls` is false (the loopback alone), and the domain of its tunnels'
/// names where it is known (the hosted server's, of `pod-services`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub zone: Option<String>,
}

impl Service {
    /// The hosted server, as `pod-services` names it (the endpoint `api` and
    /// the fact `tunnel-zone`); none while that list does not hold it.
    pub fn hosted() -> Option<Service> {
        let service = pod_services::get(SERVICE_ID)?;
        let api = service.endpoint("api")?;
        let zone = service.text("tunnel-zone").map(str::to_ascii_lowercase);
        Some(Service { host: api.host().to_ascii_lowercase(), port: api.port(), tls: true, zone })
    }

    /// `https://HOST[:PORT][/]`, or `http://` with a host of the loopback.
    /// The refusal does not echo the text.
    pub fn parse(text: &str) -> Result<Service, String> {
        let text = text.trim();
        let scheme = |n: usize| text.get(..n).map(str::to_ascii_lowercase);
        let (tls, rest) = match (scheme(8).as_deref(), scheme(7).as_deref()) {
            (Some("https://"), _) => (true, &text[8..]),
            (_, Some("http://")) => (false, &text[7..]),
            _ => return Err("a hostc server is an https:// URL, or http:// on this host's loopback".into()),
        };
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let (host, port) = crate::pinggy::host_port(rest, "the hostc road")?;
        if !tls && !loopback(&host) {
            return Err("a hostc server over http:// must be on this host's loopback: use https://".into());
        }
        Ok(Service { port: port.unwrap_or(if tls { PORT } else { 80 }), host, tls, zone: None })
    }

    /// The value of a request's `Host`: the host alone on its scheme's port.
    pub fn authority(&self) -> String {
        match self.port == if self.tls { PORT } else { 80 } {
            true => self.host.clone(),
            false => podssh_ws::dial::authority(&self.host, self.port),
        }
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", if self.tls { "https" } else { "http" }, self.authority())
    }
}

/// Whether `host` is this host's loopback.
pub(crate) fn loopback(host: &str) -> bool {
    host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// What [`ENV`] and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No hostc road, as the variable of this name says.
    Off(&'static str),
    /// The road, through this server.
    On(Service),
    /// The road is on, but no server is known: `pod-services` names none,
    /// and [`ENV`] names none.
    Unnamed,
}

/// [`ENV`]'s `value`, and [`LAST_RESORT`]'s `last`: either no turns the
/// road off, as each last fallback reads them (T-548's Decision); else the
/// server that [`ENV`] names, or the hosted one where `pod-services` names it.
pub fn setting(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    setting_with(value, last, Service::hosted())
}

/// [`setting`] with `hosted` as the list's server, for the tests.
pub fn setting_with(value: Option<&str>, last: Option<&str>, hosted: Option<Service>) -> Result<Setting, String> {
    if crate::pinggy::last_resort_off(last)? {
        return Ok(Setting::Off(LAST_RESORT));
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
    let last = std::env::var(LAST_RESORT).ok();
    setting(value.as_deref(), last.as_deref())
}

/// Whether `name` is a tunnel's name of the hosted server: one label under
/// its zone. A client takes the road's switch and line for it.
pub fn owns(name: &str) -> bool {
    let zone = Service::hosted().and_then(|service| service.zone);
    zone.is_some_and(|zone| under(name, &zone))
}

/// Whether `name` is one label under `zone`.
pub fn under(name: &str, zone: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    name.strip_suffix(&format!(".{}", zone.to_ascii_lowercase()))
        .is_some_and(|label| !label.is_empty() && !label.contains('.'))
}

/// Why the road has no server, for a line or a refusal.
pub fn unnamed_words() -> String {
    format!(
        "the hostc road has no server: podssh's list of services (pod-services) does not name hostc's in this \
         build, and {ENV} names none; {ENV}=https://HOST names one"
    )
}

/// The line that a node says before the road carries a session (Q78).
pub fn third_party_line(service: &Service) -> String {
    format!(
        "the hostc road, a last fallback: {service}, a third party that nobody vouches for, carries this session \
         (the operator's ruling Q78); it ends the visitors' TLS and sees the times, the sizes and the layer's \
         bytes, which the end-to-end channel keeps private; {ENV}=no or {LAST_RESORT}=no turns it off"
    )
}

/// The line that a client says before its first link to `host`, a
/// tunnel's name at hostc (Q78).
pub fn client_line(host: &str) -> String {
    format!(
        "the hostc road, a last fallback: {host}, a tunnel's name at hostc, a third party that nobody vouches for, \
         carries this session over HTTPS that it ends (the operator's ruling Q78); the end-to-end channel keeps \
         its bytes private; {ENV}=no or {LAST_RESORT}=no turns it off"
    )
}

/// The words of a `426`: the server speaks another version, which only a
/// newer podssh speaks. No failure of the session: it goes to the next road.
pub fn refused_version(service: &Service, said: &str) -> String {
    format!(
        "{service} answered 426: it no longer speaks version {PROTOCOL_VERSION} of hostc's protocol, which this \
         podssh {} speaks ({}); a newer release of podssh speaks the server's (podssh update), and the session \
         goes on to its next road",
        env!("CARGO_PKG_VERSION"),
        podssh_ws::text::one_line(said).chars().take(160).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand_in() -> Service {
        Service { host: "hostc.stand-in.test".into(), port: 443, tls: true, zone: Some("tunnels.test".into()) }
    }

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_leave_it_with_none() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting_with(on, None, Some(stand_in())), Ok(Setting::On(stand_in())), "{on:?}");
            assert_eq!(setting_with(on, None, None), Ok(Setting::Unnamed), "{on:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting_with(Some(off), None, Some(stand_in())), Ok(Setting::Off(ENV)), "{off}");
            let last = setting_with(Some("https://h.example.test"), Some(off), Some(stand_in()));
            assert_eq!(last, Ok(Setting::Off(LAST_RESORT)), "{off}");
        }
        let local = Service::parse("http://127.0.0.1:8787").unwrap();
        assert_eq!((local.tls, local.port, local.authority()), (false, 8787, "127.0.0.1:8787".to_string()));
        assert_eq!(Service::parse("https://H.example.test/").unwrap().to_string(), "https://h.example.test");
        for refused in
            ["maybe?SECRET", "http://h.example.test", "https://h.example.test/x?SECRET", "https://u:SECRET@h"]
        {
            let why = setting_with(Some(refused), None, None).unwrap_err();
            assert!(why.starts_with("PODSSH_HOSTC: ") && !why.contains("SECRET"), "{why}");
        }
    }

    #[test]
    fn a_tunnel_s_name_is_one_label_under_the_zone() {
        assert!(under("abcdefghijkm.tunnels.test", "tunnels.test"));
        assert!(under("codex-abcdefghijkm.Tunnels.Test.", "tunnels.test"));
        for not in ["tunnels.test", "a.b.tunnels.test", "abc.other.test", ".tunnels.test"] {
            assert!(!under(not, "tunnels.test"), "{not}");
        }
    }

    #[test]
    fn each_line_names_the_third_party_both_switches_and_a_refused_version_the_way_on() {
        let line = third_party_line(&stand_in());
        for word in ["hostc.stand-in.test", "nobody vouches for", "Q78", "PODSSH_HOSTC=no", "PODSSH_LAST_RESORT=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
        assert!(client_line("abc.tunnels.test").contains("PODSSH_HOSTC=no"));
        let refused = refused_version(&stand_in(), "{\"error\":\"This hostc version is not supported\"}");
        assert!(refused.contains("426") && refused.contains("version 5") && refused.contains("next road"), "{refused}");
        assert!(unnamed_words().contains("PODSSH_HOSTC=https://HOST"));
    }
}
