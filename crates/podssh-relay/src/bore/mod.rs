//! The bore road (T-569): a last fallback of the operator's ruling Q78
//! through bore.pub, the public server of bore (`ekzhang/bore`), which
//! gives a node a public TCP port with no account. Its protocol, read in its
//! source at commit `00a735a89917` (2026-11-10; `src/shared.rs`,
//! `src/client.rs`, `src/server.rs`, `src/auth.rs`), is [`wire`]'s: JSON
//! messages, each ended by a zero byte, on the control port 7835; the
//! node's `Hello` names a port (0 for any), the server's `Hello` gives it,
//! and its `Heartbeat` comes each 500 ms; for each visitor of that port a
//! `Connection` with a UUID comes, which the node takes on a new connection
//! to the control port with `Accept` and that UUID, within 10 s; a server
//! with a secret sends a `Challenge` first, which an HMAC of the secret
//! answers.
//!
//! Both ports are raw TCP: no TLS and no HTTP. A node reaches 7835 directly
//! or by a CONNECT that `HTTPS_PROXY` allows; a client reaches the public
//! port directly, by such a CONNECT, or through the caller's other roads (the
//! forwarders of the operator's ruling Q56, whose URL names the target),
//! where a proxy that allows 443 alone refuses it ([`Dial`] is the caller's).
//!
//! The node asks the ports of its key ([`ports`]), in their order, so that a
//! client that holds the key (`--node-key`, the net, or the pins) derives
//! them and needs no record or word; each visitor first gets a hello of the
//! key, so that a client passes over a port that another tunnel holds. The
//! port and the hello prove nothing: anyone may take a port, and the key is
//! public. The end-to-end channel above the resumable layer checks the
//! node's key on each link, and bore.pub carries only ciphertext.
//!
//! bore.pub restarts on purpose, "isn't meant for long-lived connections",
//! and ends a tunnel at 24 hours (its issues 170 and 150, read 2026-11-10):
//! the node registers again ([`far`]), and the layer moves its sessions.

pub mod client;
pub mod control;
pub mod far;
pub mod ports;
pub mod wire;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::ProxyChoice;

pub use crate::pinggy::{Say, LAST_RESORT};
pub use client::{carry, Dialer};
pub use far::Node;

/// `no` turns the road off; `HOST[:PORT]` names a server of bore's
/// protocol, such as a stand-in, at its control port.
pub const ENV: &str = "PODSSH_BORE";
/// The id of the service in `pod-services`; the road has no server of its
/// own until that list names one (`AGENTS.md`: no host of another party in
/// podssh's code).
pub const SERVICE_ID: &str = "bore";
/// bore's control port (`CONTROL_PORT` of its `src/shared.rs`), where a
/// value names none.
pub const CONTROL_PORT: u16 = 7835;
/// The bound of each TCP connection to the server, and of each answer of a
/// handshake: bore's own is 3 s (`NETWORK_TIMEOUT`), which a proxy's CONNECT
/// can pass.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(10);

/// A byte stream to the server.
pub type BoxIo = crate::opentunnel::dial::BoxIo;
/// A dial in progress.
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// How a node reaches the control port, and a client a node's public port:
/// [`tcp`], the caller's road with its fallbacks, or a test's pipe.
pub type Dial = Arc<dyn Fn(&str, u16) -> Dialing + Send + Sync>;

/// TCP to each host and port, through `proxy`'s CONNECT where it is set.
pub fn tcp(proxy: ProxyChoice) -> Dial {
    Arc::new(move |host: &str, port: u16| -> Dialing {
        let (host, proxy) = (host.to_string(), proxy.clone());
        Box::pin(async move {
            let tcp = podssh_ws::dial::dial(&host, port, &proxy, CONNECT_LIMIT)
                .await
                .map_err(|e| format!("{}: {e}", podssh_ws::dial::authority(&host, port)))?;
            Ok(Box::new(tcp) as BoxIo)
        })
    })
}

/// A server's secret, as `bore server --secret` takes it; never shown.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(zeroize::Zeroizing<String>);

impl Secret {
    pub fn new(text: &str) -> Secret {
        Secret(zeroize::Zeroizing::new(text.to_string()))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A server of bore's protocol: its host, its control port, and its secret
/// where it has one (a test's stand-in; bore.pub has none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub secret: Option<Secret>,
}

impl Service {
    /// bore.pub, as `pod-services` names it (the endpoint `control`); none
    /// while that list does not hold it.
    pub fn hosted() -> Option<Service> {
        let endpoint = pod_services::get(SERVICE_ID)?.endpoint("control")?;
        Some(Service { host: endpoint.host().to_ascii_lowercase(), port: endpoint.port(), secret: None })
    }

    /// `HOST[:PORT]` or `[IPV6]:PORT`, with no scheme, path or user, as
    /// each road of a server reads its variable; the refusal does not echo it.
    pub fn parse(text: &str) -> Result<Service, String> {
        let (host, port) = crate::pinggy::host_port(text, "the bore road")?;
        Ok(Service { host, port: port.unwrap_or(CONTROL_PORT), secret: None })
    }

    /// The server as a line names it: its host, and its port where it is
    /// not bore's.
    pub fn shown(&self) -> String {
        match self.port {
            CONTROL_PORT => self.host.clone(),
            port => podssh_ws::dial::authority(&self.host, port),
        }
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown())
    }
}

/// What [`ENV`] and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No bore road, as the variable of this name says.
    Off(&'static str),
    /// The road, through this server.
    On(Service),
    /// The road is on, but no server is known: `pod-services` names none,
    /// and [`ENV`] names none.
    Unnamed,
}

/// [`ENV`]'s `value`, and [`LAST_RESORT`]'s `last`: either no turns the road
/// off, as each last fallback reads them (T-548's Decision); else the server
/// that [`ENV`] names, or bore.pub where `pod-services` names it.
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
        _ => Service::parse(text).map(Setting::On).map_err(|why| format!("{ENV}: yes, no, or HOST[:PORT]: {why}")),
    }
}

/// The setting of this process's variables.
pub fn from_env() -> Result<Setting, String> {
    let value = std::env::var(ENV).ok();
    let last = std::env::var(LAST_RESORT).ok();
    setting(value.as_deref(), last.as_deref())
}

/// Why the road has no server, for a line or a refusal.
pub fn unnamed_words() -> String {
    format!(
        "the bore road has no server: podssh's list of services (pod-services) does not name bore.pub in this \
         build, and {ENV} names none; {ENV}=HOST[:PORT] names one"
    )
}

/// The line that a run says before the road carries a session of its own
/// (Q78), as each last fallback says its own.
pub fn third_party_line(service: &Service) -> String {
    format!(
        "the bore road, a last fallback: {service}, a third party that nobody vouches for, carries this session \
         over raw TCP, its control port {} and a public port of the node's key (the operator's ruling Q78); it sees \
         the times and the sizes, and the end-to-end channel keeps the bytes private; {ENV}=no or {LAST_RESORT}=no \
         turns it off",
        service.port
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand_in() -> Service {
        Service { host: "bore.stand-in.test".into(), port: CONTROL_PORT, secret: None }
    }

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_leave_it_with_none() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting_with(on, None, Some(stand_in())), Ok(Setting::On(stand_in())), "{on:?}");
            assert_eq!(setting_with(on, None, None), Ok(Setting::Unnamed), "{on:?}: no server of the list");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting_with(Some(off), None, Some(stand_in())), Ok(Setting::Off(ENV)), "{off}");
            let last = setting_with(Some("127.0.0.1:7835"), Some(off), Some(stand_in()));
            assert_eq!(last, Ok(Setting::Off("PODSSH_LAST_RESORT")), "{off}");
        }
        let named = setting_with(Some("Stand-In.Example.test:17835"), None, None).unwrap();
        assert_eq!(named, Setting::On(Service { host: "stand-in.example.test".into(), port: 17835, secret: None }));
        assert_eq!(Service::parse("h").unwrap().port, 7835, "bore's control port where none is named");
        assert_eq!(Service::parse("[::1]:7836").unwrap().host, "::1");
        for refused in ["tcp://h?SECRET", "u:SECRET@h", "h/SECRET", "h:0", ":7835"] {
            let why = setting_with(Some(refused), None, None).unwrap_err();
            assert!(why.starts_with("PODSSH_BORE: ") && !why.contains("SECRET"), "{why}");
        }
        let maybe = setting_with(None, Some("maybe"), Some(stand_in()));
        assert_eq!(maybe, Ok(Setting::Off("PODSSH_LAST_RESORT")), "another word of the switch is no");
    }

    #[test]
    fn the_line_of_the_third_party_names_it_both_switches_and_raw_tcp() {
        let line = third_party_line(&stand_in());
        for word in ["bore.stand-in.test", "nobody vouches for", "Q78", "PODSSH_BORE=no", "PODSSH_LAST_RESORT=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
        assert!(line.contains("raw TCP") && line.contains("control port 7835"), "{line}");
        assert!(unnamed_words().contains("PODSSH_BORE=HOST[:PORT]"));
        assert_eq!(format!("{:?}", Secret::new("hidden")), "Secret(..)", "a secret is never shown");
        let other = Service { port: 17835, ..stand_in() };
        assert_eq!(other.shown(), "bore.stand-in.test:17835");
    }
}
