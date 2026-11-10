//! The Serveo road (T-549): a last fallback of the reverse road through
//! Serveo's private aliases, which need no account. The operator's ruling
//! Q78 makes each public service that carries bytes a last fallback,
//! whatever its terms: tried after podssh's own roads and after the
//! services that allow the use, with a line that names the third party.
//!
//! A node's leg is SSH to Serveo's server, raw, on port 443 then 22, through
//! `HTTPS_PROXY`, with no account; it asks the remote forward of a private
//! alias, as `ssh -R ALIAS:22:localhost:22 serveo.net` does, and Serveo opens
//! a `forwarded-tcpip` channel for each client that jumps to the alias, as
//! `ssh -J serveo.net user@ALIAS` does: a `direct-tcpip` channel of the
//! client's own SSH session to Serveo (<https://serveo.net/docs/>, read
//! 2026-11-10). The alias is derived from the node's key ([`alias`]), so a
//! client that holds the key (its pins, `--node-key`, the net) computes it,
//! and no name passes between them. The channel carries the resumable layer
//! with no TLS: SSH keeps its bytes from the network, and the end-to-end
//! channel above the layer, which checks the node's key, keeps them from
//! Serveo; a stranger at the alias is refused there. Serveo's documents call
//! an alias "a routing name rather than an authentication secret".
//!
//! Serveo's server is the one of `pod-services` where it names one, else
//! the one of `PODSSH_SERVEO`: podssh names no host of a third party in its
//! own code. The SSH client of both legs is the caller's.

pub mod alias;

pub use alias::{alias, pinned};
pub use crate::pinggy::LAST_RESORT;

/// `no` turns the road off; `HOST[:PORT]` names a server of the same
/// protocol, such as a stand-in.
pub const ENV: &str = "PODSSH_SERVEO";
/// Serveo's SSH ports, in the order tried: 443 passes a cage that keeps 22
/// shut, and 22 is its default (<https://serveo.net/docs/>, "Connect on
/// port 443").
pub const PORTS: [u16; 2] = [443, 22];
/// The port of the alias's forward, as Serveo's documents forward SSH by an
/// alias: a host name before the port makes a private TCP forward, and port
/// 80 alone would make an HTTP tunnel.
pub const ALIAS_PORT: u32 = 22;
/// The aliases of a node's series: the first that nobody holds is the
/// node's. Serveo can hold an alias for a while after an abrupt end of its
/// tunnel, so the node's next tunnel may take the next one.
pub const SERIES: u8 = 4;
/// The user of the login with no account: Serveo reads the user to choose a
/// public subdomain alone, and an alias needs none; a fixed word, so that the
/// local user's name never goes to the third party.
pub const USER: &str = "anonymous";

/// The service of `pod-services`, where it holds Serveo's.
fn catalog() -> Option<&'static pod_services::Service> {
    pod_services::get("serveo")
}

/// A server of Serveo's protocol: SSH on `host`, at each of `ports` in turn,
/// and the SHA256 fingerprint of its host key when one is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub ports: Vec<u16>,
    pub host_key: Option<String>,
}

impl Service {
    /// Serveo's own, where `pod-services` names it: its endpoints `ssh-443`
    /// and `ssh`, in that order, and its host key where the fact
    /// `host-key-sha256` names it. None where the catalog holds no Serveo.
    pub fn hosted() -> Option<Service> {
        let service = catalog()?;
        let (mut host, mut ports) = (None, Vec::new());
        for endpoint in ["ssh-443", "ssh"].into_iter().filter_map(|name| service.endpoint(name)) {
            host.get_or_insert_with(|| endpoint.host().to_ascii_lowercase());
            if !ports.contains(&endpoint.port()) {
                ports.push(endpoint.port());
            }
        }
        let host_key = service.text("host-key-sha256").map(str::to_string);
        Some(Service { host: host?, ports, host_key })
    }

    /// `HOST[:PORT]`: another server, whose host key nobody named; with no
    /// port, Serveo's two. The refusal does not echo the text.
    pub fn parse(text: &str) -> Result<Service, String> {
        let (host, port) = crate::pinggy::host_port(text, "the Serveo road")?;
        Ok(Service { host, ports: port.map_or_else(|| PORTS.to_vec(), |port| vec![port]), host_key: None })
    }

    /// The server on one of its ports, as the SSH leg of the Pinggy road
    /// takes a server, whose handshake the Serveo road shares.
    pub fn at(&self, port: u16) -> crate::pinggy::Service {
        crate::pinggy::Service { host: self.host.clone(), port, host_key: self.host_key.clone() }
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ports.as_slice() {
            [port] if !PORTS.contains(port) => f.write_str(&podssh_ws::dial::authority(&self.host, *port)),
            _ => f.write_str(&self.host),
        }
    }
}

/// What [`ENV`] and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No Serveo road, as the variable of this name says.
    Off(&'static str),
    /// The road is on, and no server is named: `pod-services` holds no
    /// Serveo, and [`ENV`] names none.
    Unnamed,
    /// The road, through this server.
    On(Service),
}

/// Why the road has no server, for a refusal or a line.
pub const UNNAMED: &str = "podssh's list of services names no Serveo server; PODSSH_SERVEO=HOST[:PORT] names one";

/// [`ENV`]'s `value`, and [`LAST_RESORT`]'s `last`: either no turns the
/// road off; else Serveo's own server, or the one that [`ENV`] names.
pub fn setting(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    if crate::pinggy::last_resort_off(last)? {
        return Ok(Setting::Off(LAST_RESORT));
    }
    let text = value.map(str::trim).unwrap_or_default();
    match text.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(Setting::Off(ENV)),
        "" | "yes" | "on" | "true" | "1" => Ok(Service::hosted().map_or(Setting::Unnamed, Setting::On)),
        _ => Service::parse(text).map(Setting::On).map_err(|why| format!("{ENV}: yes, no, or HOST[:PORT]: {why}")),
    }
}

/// The line that a run says before Serveo carries a session of its own (Q78).
pub fn third_party_line(service: &Service) -> String {
    format!(
        "the Serveo road, a last fallback: {service}, a third party that nobody vouches for, carries this session \
         (the operator's ruling Q78); SSH and the end-to-end channel keep its bytes private; {ENV}=no or \
         {LAST_RESORT}=no turns it off"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_are_refused_without_their_text() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            let hosted = Service::hosted().map_or(Setting::Unnamed, Setting::On);
            assert_eq!(setting(on, None), Ok(hosted), "{on:?}");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting(Some(off), None), Ok(Setting::Off(ENV)), "{off}");
            assert_eq!(setting(None, Some(off)), Ok(Setting::Off(LAST_RESORT)), "{off}");
            assert_eq!(setting(Some("127.0.0.1:2222"), Some(off)), Ok(Setting::Off(LAST_RESORT)), "{off}");
        }
        let own = setting(Some("Stand-In.Example.test:2222"), Some("yes")).unwrap();
        let wanted = Service { host: "stand-in.example.test".into(), ports: vec![2222], host_key: None };
        assert_eq!(own, Setting::On(wanted.clone()));
        assert_eq!(wanted.to_string(), "stand-in.example.test:2222");
        let both = Service::parse("relay.example.test").unwrap();
        assert_eq!((both.ports.as_slice(), both.to_string().as_str()), (&[443, 22][..], "relay.example.test"));
        assert_eq!(both.at(22).port, 22);
        for refused in ["ssh://h?SECRET", "u:SECRET@h", "h/SECRET", "h:0", ":22"] {
            let why = setting(Some(refused), None).unwrap_err();
            assert!(why.starts_with("PODSSH_SERVEO: ") && !why.contains("SECRET"), "{why}");
        }
        assert_eq!(setting(None, Some("maybe")), Ok(Setting::Off(LAST_RESORT)), "another word is no");
    }

    #[test]
    fn the_line_of_the_third_party_names_it_and_both_switches() {
        let line = third_party_line(&Service::parse("relay.example.test").unwrap());
        for word in ["Serveo", "relay.example.test", "nobody vouches for", "Q78", "PODSSH_SERVEO=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
        assert!(line.contains("PODSSH_LAST_RESORT=no"), "{line}");
    }
}
