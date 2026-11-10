//! A tunnel of HTTP made by `ssh -R` (T-565): a last fallback of the
//! operator's ruling Q78 through a public service that gives a node an
//! HTTPS name for a remote forward of port 80, with no account, as
//! localhost.run does. Its documents (<https://localhost.run/docs/>, which
//! now serves <https://lhr-landing.lovable.app/docs>, read 2026-11-10) give
//! the shape that the module speaks:
//!
//! - a node asks `ssh -R 80:localhost:8080 localhost.run`, or `nokey@` for
//!   a free tunnel with no key, and "The command prints your public URL",
//!   as `NAME.lhr.life tunneled with tls termination, https://NAME.lhr.life`
//!   on the session (its landing page's sample);
//! - "localhost.run unwraps the encryption and sends plain HTTP requests to
//!   your app", with `X-Forwarded-For`, `X-Forwarded-Host`,
//!   `X-Forwarded-Proto` and `Forwarded` added;
//! - "Free domains change after a few hours", and "There is a speed limit"
//!   ("Forever Free").
//!
//! Each visitor's connection comes down the forward as a `forwarded-tcpip`
//! channel of plain HTTP/1.1 ([`visit`]): a WebSocket at `/` is one link of
//! the resumable layer, with the end-to-end channel above it, as a quick
//! tunnel's visitor is (T-300); a path of the relay role goes to the role
//! where the node serves it, as T-428's origin does behind a quick tunnel;
//! each other request gets 404. The edge ends TLS with its own certificate,
//! which a CA vouches for, so a client's TLS checks that, and the end-to-end
//! channel checks the node's key: the service sees the times, the sizes and
//! the layer's bytes, which the channel keeps from it.
//!
//! A service of the shape is a [`Word`]: its user, its forward, its ports
//! and the word of its line that names a tunnel. localhost.run is the first
//! (T-565); srv.us (T-566), tunnl.gg (T-567) and Sandhole's public server
//! (T-743) are more words of the same module. Each server comes from
//! `pod-services` alone, or from the word's variable: podssh names no host
//! of a third party in its own code. The SSH client of the node's leg is the
//! binary's.

pub mod name;
pub mod visit;

pub use crate::pinggy::LAST_RESORT;

/// A service of the shape: what differs between hosts that speak it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Word {
    /// Its id in `pod-services`.
    pub id: &'static str,
    /// Its name in lines.
    pub name: &'static str,
    /// `no` turns it off; `HOST[:PORT]` names a server of the same shape.
    pub env: &'static str,
    /// The flag of `podssh node` that asks for it.
    pub flag: &'static str,
    /// The SSH user of a login with no account.
    pub user: &'static str,
    /// The remote forward that the service reads: its address and its port.
    pub forward: (&'static str, u32),
    /// The SSH ports where a value names none, in the order tried.
    pub ports: &'static [u16],
    /// The word of the service's line that names a tunnel.
    pub marker: &'static str,
}

/// localhost.run's word. The user `nokey`: "For free tunnels, skip the key
/// check with the `nokey` user" (its FAQ), so no key of the node's goes to
/// it and no local user's name either. The forward is the one that OpenSSH
/// asks for `-R 80:localhost:PORT`: with no bind address, `localhost`
/// (`channel_rfwd_bind_host` of its `channels.c`), port 80, "80 or 443",
/// where 80 makes the edge end TLS ("CLI Reference"). Port 22: the command
/// names none (Inferred; `docs/carriers.md`).
pub const LOCALHOST_RUN: Word = Word {
    id: "localhost-run",
    name: "localhost.run",
    env: "PODSSH_LOCALHOST_RUN",
    flag: "--localhost-run",
    user: "nokey",
    forward: ("localhost", 80),
    ports: &[22],
    marker: "tunneled",
};

/// A server of a word's shape: SSH on `host`, at each of `ports` in turn,
/// and the SHA256 fingerprint of its host key when one is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub word: Word,
    pub host: String,
    pub ports: Vec<u16>,
    pub host_key: Option<String>,
}

impl Service {
    /// The word's own server, where `pod-services` names it: its endpoints
    /// `ssh-443` and `ssh`, in that order, and its host key where the fact
    /// `host-key-sha256` names it. None while that list holds no such entry.
    pub fn hosted(word: Word) -> Option<Service> {
        let service = pod_services::get(word.id)?;
        let (mut host, mut ports) = (None, Vec::new());
        for endpoint in ["ssh-443", "ssh"].into_iter().filter_map(|name| service.endpoint(name)) {
            host.get_or_insert_with(|| endpoint.host().to_ascii_lowercase());
            if !ports.contains(&endpoint.port()) {
                ports.push(endpoint.port());
            }
        }
        let host_key = service.text("host-key-sha256").map(str::to_string);
        Some(Service { word, host: host?, ports, host_key })
    }

    /// `HOST[:PORT]`: another server of the shape, such as a stand-in, whose
    /// host key nobody named; with no port, the word's. The refusal does not
    /// echo the text.
    pub fn parse(word: Word, text: &str) -> Result<Service, String> {
        let (host, port) = crate::pinggy::host_port(text, &format!("the {} road", word.name))?;
        let ports = port.map_or_else(|| word.ports.to_vec(), |port| vec![port]);
        Ok(Service { word, host, ports, host_key: None })
    }

    /// The server on one of its ports, as the SSH leg of the Pinggy road
    /// takes a server, whose handshake this road shares.
    pub fn at(&self, port: u16) -> crate::pinggy::Service {
        crate::pinggy::Service { host: self.host.clone(), port, host_key: self.host_key.clone() }
    }

    /// Whether `host` is the service's own (its server, a name under it),
    /// which its text names beside a tunnel's, as `admin.localhost.run`.
    pub fn own(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        host == self.host || host.ends_with(&format!(".{}", self.host))
    }
}

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ports.as_slice() {
            [port] if !self.word.ports.contains(port) => f.write_str(&podssh_ws::dial::authority(&self.host, *port)),
            _ => f.write_str(&self.host),
        }
    }
}

/// What a word's variable and [`LAST_RESORT`] ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road of the word, as the variable of this name says.
    Off(&'static str),
    /// The road is on, and no server is named: `pod-services` holds none of
    /// the word's, and its variable names none.
    Unnamed,
    /// The road, through this server.
    On(Service),
}

/// The word's variable's `value`, and [`LAST_RESORT`]'s `last`: either no
/// turns the road off (one switch for each last fallback, T-548's
/// Decision); else the server that the variable names, or `hosted`.
pub fn setting_with(
    word: Word,
    value: Option<&str>,
    last: Option<&str>,
    hosted: Option<Service>,
) -> Result<Setting, String> {
    if crate::pinggy::last_resort_off(last)? {
        return Ok(Setting::Off(LAST_RESORT));
    }
    let text = value.map(str::trim).unwrap_or_default();
    match text.to_ascii_lowercase().as_str() {
        "no" | "off" | "false" | "0" => Ok(Setting::Off(word.env)),
        "" | "yes" | "on" | "true" | "1" => Ok(hosted.map_or(Setting::Unnamed, Setting::On)),
        _ => Service::parse(word, text)
            .map(Setting::On)
            .map_err(|why| format!("{}: yes, no, or HOST[:PORT]: {why}", word.env)),
    }
}

/// [`setting_with`] with the word's server of `pod-services`.
pub fn setting(word: Word, value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    setting_with(word, value, last, Service::hosted(word))
}

/// The setting of this process's variables for `word`.
pub fn from_env(word: Word) -> Result<Setting, String> {
    let value = std::env::var(word.env).ok();
    let last = std::env::var(LAST_RESORT).ok();
    setting(word, value.as_deref(), last.as_deref())
}

/// Why the word's road has no server, for a line or a refusal.
pub fn unnamed_words(word: Word) -> String {
    format!(
        "the {} road has no server: podssh's list of services (pod-services) names none in this build, and {} \
         names none; {}=HOST[:PORT] names one",
        word.name, word.env, word.env
    )
}

/// The line that a run says before the service carries a session of its
/// own (Q78), as the Pinggy road says its own.
pub fn third_party_line(service: &Service) -> String {
    let word = service.word;
    format!(
        "the {} road, a last fallback: {service}, a third party that nobody vouches for, carries this session \
         over HTTPS that it ends (the operator's ruling Q78); it sees the times and the sizes, and the end-to-end \
         channel keeps the bytes private; {}=no or {LAST_RESORT}=no turns it off",
        word.name, word.env
    )
}

/// The line that a client says before its first link to `host`, a
/// tunnel's name of `word`'s service (Q78): the client has no server of its
/// own to name, only the name that the node gave.
pub fn client_line(word: Word, host: &str) -> String {
    format!(
        "the {} road, a last fallback: {host}, a tunnel's name at {}, a third party that nobody vouches for, \
         carries this session over HTTPS that it ends (the operator's ruling Q78); the end-to-end channel keeps \
         its bytes private; {}=no or {LAST_RESORT}=no turns it off",
        word.name, word.name, word.env
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand_in() -> Service {
        Service { word: LOCALHOST_RUN, host: "lhr.stand-in.test".into(), ports: vec![22], host_key: None }
    }

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_leave_it_with_none() {
        let word = LOCALHOST_RUN;
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting_with(word, on, None, Some(stand_in())), Ok(Setting::On(stand_in())), "{on:?}");
            assert_eq!(setting_with(word, on, None, None), Ok(Setting::Unnamed), "{on:?}: no server of the list");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting_with(word, Some(off), None, Some(stand_in())), Ok(Setting::Off(word.env)), "{off}");
            let last = setting_with(word, Some("127.0.0.1:2222"), Some(off), Some(stand_in()));
            assert_eq!(last, Ok(Setting::Off(LAST_RESORT)), "{off}");
        }
        let named = setting_with(word, Some("Stand-In.Example.test:2222"), None, None).unwrap();
        let wanted = Service { word, host: "stand-in.example.test".into(), ports: vec![2222], host_key: None };
        assert_eq!(named, Setting::On(wanted.clone()));
        assert_eq!(wanted.to_string(), "stand-in.example.test:2222");
        let bare = Service::parse(word, "lhr.example.test").unwrap();
        assert_eq!((bare.ports.as_slice(), bare.to_string().as_str()), (&[22][..], "lhr.example.test"));
        assert_eq!(bare.at(22).port, 22);
        for refused in ["ssh://h?SECRET", "u:SECRET@h", "h/SECRET", "h:0", ":22"] {
            let why = setting_with(word, Some(refused), None, None).unwrap_err();
            assert!(why.starts_with("PODSSH_LOCALHOST_RUN: ") && !why.contains("SECRET"), "{why}");
        }
        let maybe = setting_with(word, None, Some("maybe"), Some(stand_in()));
        assert_eq!(maybe, Ok(Setting::Off(LAST_RESORT)), "another word of the switch is no");
    }

    #[test]
    fn the_service_s_own_hosts_are_its_server_and_the_names_under_it() {
        let service = Service { host: "localhost.run".into(), ..stand_in() };
        for own in ["localhost.run", "admin.localhost.run", "Admin.Localhost.Run."] {
            assert!(service.own(own), "{own}");
        }
        for other in ["a1b2c3d4e5f6.lhr.life", "notlocalhost.run", "twitter.com"] {
            assert!(!service.own(other), "{other}");
        }
    }

    #[test]
    fn the_line_of_the_third_party_names_it_both_switches_and_what_it_sees() {
        let line = third_party_line(&stand_in());
        for word in ["localhost.run", "lhr.stand-in.test", "nobody vouches for", "Q78", "PODSSH_LOCALHOST_RUN=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
        assert!(line.contains("PODSSH_LAST_RESORT=no") && line.contains("end-to-end channel"), "{line}");
        assert!(unnamed_words(LOCALHOST_RUN).contains("PODSSH_LOCALHOST_RUN=HOST[:PORT]"));
        let client = client_line(LOCALHOST_RUN, "a1.lhr.life");
        for word in ["a1.lhr.life", "localhost.run", "nobody vouches for", "Q78", "PODSSH_LAST_RESORT=no"] {
            assert!(client.contains(word), "{word}: {client}");
        }
    }
}
