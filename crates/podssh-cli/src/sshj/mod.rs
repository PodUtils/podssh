//! The ssh-j road (T-570): a last fallback of the operator's ruling Q78
//! through `ssh-j.com`, a public SSH jump and forwarding server with no
//! account, on port 22. Its page (<https://ssh-j.com/>, read 2026-11-10)
//! gives the two commands that the road speaks:
//!
//! - a host publishes a port by name: `ssh any-username@ssh-j.com -N -R
//!   laptop-behind-nat:22:localhost:22`, where the user is "a unique
//!   namespace for your hosts" and the forward's address "device name";
//! - a client reaches it: `ssh -J any-username@ssh-j.com laptop-behind-nat`;
//!   "Published hosts are bound to the username. Other usernames can't
//!   access them", with "50 exposed services (ports) per username".
//!
//! Its server is Dropbear with a table of names (ValdikSS/dropbear-sshj on
//! Bitbucket, commit `d622b1e8fe35`, read 2026-11-10): a remote forward
//! keeps the user, the address (64 bytes at most) and the port it asked;
//! a `direct-tcpip` channel of the same user to that address and port goes
//! down it, as a `forwarded-tcpip` channel that names them; a name that a
//! user holds already is refused to a second forward; any login passes.
//!
//! The node and the client derive the user and the address from the node's
//! key ([`name`]), so a client that holds the key (`--node-key`, the net, or
//! the pins of NAME) needs no other word, and no record. Anyone may take any
//! user there, so the name proves nothing: the end-to-end channel above the
//! resumable layer checks the node's key on each link, and ssh-j.com, which
//! ends SSH and sees the forward's bytes, carries only ciphertext.

pub mod client;
pub mod leg;
pub mod name;

pub use name::JumpName;

/// `no` turns the road off; `HOST[:PORT]` names a server of the same
/// protocol, such as a stand-in.
pub const ENV: &str = "PODSSH_SSH_J";
/// The id of the service in `pod-services`; the road has no server of its
/// own until that list names one (`AGENTS.md`: no host of another party in
/// podssh's code).
pub const SERVICE_ID: &str = "ssh-j";
/// The server's port where a value names none: SSH's, as the page's
/// commands use it.
pub const PORT: u16 = 22;
/// The port of each name, as the page's `-R laptop-behind-nat:22:...` asks.
pub const NAME_PORT: u32 = 22;
/// The longest forward address that the server keeps (`MAX_HOST_LEN` of
/// dropbear-sshj's `sysoptions.h`).
pub const MOST_ADDRESS: usize = 64;

/// A server of the road's protocol: SSH on `host`:`port`, and the SHA256
/// fingerprint of its host key when one is known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub host: String,
    pub port: u16,
    pub host_key: Option<String>,
}

impl Service {
    /// ssh-j.com, as `pod-services` names it (the endpoint `ssh`, and the
    /// fact `host-key-sha256`); none while that list does not hold it.
    pub fn hosted() -> Option<Service> {
        let service = pod_services::get(SERVICE_ID)?;
        let endpoint = service.endpoint("ssh")?;
        let host_key = service.text("host-key-sha256").map(str::to_string);
        Some(Service { host: endpoint.host().to_ascii_lowercase(), port: endpoint.port(), host_key })
    }

    /// `HOST[:PORT]` or `[IPV6]:PORT`, with no scheme, path or user: another
    /// server, whose host key nobody named. The refusal does not echo it.
    pub fn parse(text: &str) -> Result<Service, String> {
        let text = text.trim();
        let bad = |c: char| matches!(c, '/' | '?' | '#' | '@') || c.is_whitespace();
        if text.is_empty() || text.contains(bad) {
            return Err("a server of the ssh-j road is HOST[:PORT], with no scheme, path or user".into());
        }
        let port_of = |text: &str| -> Result<u16, String> {
            let port = text.parse::<u16>().ok().filter(|p| *p != 0);
            port.ok_or_else(|| "the server's port is not a number from 1 to 65535".to_string())
        };
        // An IPv6 address in brackets, whose colons are not the port's.
        let (host, port) = if let Some(inner) = text.strip_prefix('[') {
            let (host, after) = inner.split_once(']').ok_or("an IPv6 address of the server has no closing ]")?;
            match after.strip_prefix(':') {
                Some(port) => (host, port_of(port)?),
                None if after.is_empty() => (host, PORT),
                None => return Err("the server's address is not [IPv6]:PORT".into()),
            }
        } else {
            match text.rsplit_once(':') {
                Some((host, port)) => (host, port_of(port)?),
                None => (text, PORT),
            }
        };
        if host.is_empty() {
            return Err("a server of the ssh-j road names no host".into());
        }
        Ok(Service { host: host.to_ascii_lowercase(), port, host_key: None })
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

impl std::fmt::Display for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.shown())
    }
}

/// What [`ENV`] and `PODSSH_LAST_RESORT` ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No ssh-j road, as the variable of this name says.
    Off(&'static str),
    /// The road, through this server.
    On(Service),
    /// The road is on, but no server is known: `pod-services` names none,
    /// and [`ENV`] names none.
    Unnamed,
}

/// [`ENV`]'s `value`, and `PODSSH_LAST_RESORT`'s `last`: either no turns
/// the road off, as the Pinggy road reads them (one switch for each last
/// fallback, T-548's Decision); else the server that [`ENV`] names, or
/// ssh-j.com where `pod-services` names it.
pub fn setting(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    setting_with(value, last, Service::hosted())
}

/// [`setting`] with `hosted` as the list's server, for the tests.
pub fn setting_with(value: Option<&str>, last: Option<&str>, hosted: Option<Service>) -> Result<Setting, String> {
    if podssh_relay::pinggy::last_resort_off(last)? {
        return Ok(Setting::Off(podssh_relay::pinggy::LAST_RESORT));
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
    let last = std::env::var(podssh_relay::pinggy::LAST_RESORT).ok();
    setting(value.as_deref(), last.as_deref())
}

/// Why the road has no server, for a line or a refusal.
pub fn unnamed_words() -> String {
    format!(
        "the ssh-j road has no server: podssh's list of services (pod-services) does not name ssh-j.com in this \
         build, and {ENV} names none; {ENV}=HOST[:PORT] names one"
    )
}

/// The line that a run says before the road carries a session of its own
/// (Q78), as the Pinggy road says its own.
pub fn third_party_line(service: &Service) -> String {
    format!(
        "the ssh-j road, a last fallback: {service}, a third party that nobody vouches for, carries this session \
         over SSH on port {} (the operator's ruling Q78); it ends that SSH and sees the times and the sizes, and \
         the end-to-end channel keeps the bytes private; {ENV}=no or {}=no turns it off",
        service.port,
        podssh_relay::pinggy::LAST_RESORT
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand_in() -> Service {
        Service { host: "ssh-j.stand-in.test".into(), port: 22, host_key: None }
    }

    #[test]
    fn the_variables_turn_the_road_off_name_a_server_or_leave_it_with_none() {
        for on in [None, Some(""), Some(" yes "), Some("On"), Some("1")] {
            assert_eq!(setting_with(on, None, Some(stand_in())), Ok(Setting::On(stand_in())), "{on:?}");
            assert_eq!(setting_with(on, None, None), Ok(Setting::Unnamed), "{on:?}: no server of the list");
        }
        for off in ["no", "OFF", "0", "false"] {
            assert_eq!(setting_with(Some(off), None, Some(stand_in())), Ok(Setting::Off(ENV)), "{off}");
            let last = setting_with(Some("127.0.0.1:2222"), Some(off), Some(stand_in()));
            assert_eq!(last, Ok(Setting::Off("PODSSH_LAST_RESORT")), "{off}");
        }
        let named = setting_with(Some("Stand-In.Example.test:2222"), None, None).unwrap();
        assert_eq!(named, Setting::On(Service { host: "stand-in.example.test".into(), port: 2222, host_key: None }));
        assert_eq!(Service::parse("[::1]:2222").unwrap().host, "::1");
        assert_eq!(Service::parse("h").unwrap().port, 22, "SSH's port where none is named");
        for refused in ["ssh://h?SECRET", "u:SECRET@h", "h/SECRET", "h:0", ":22"] {
            let why = setting_with(Some(refused), None, None).unwrap_err();
            assert!(why.starts_with("PODSSH_SSH_J: ") && !why.contains("SECRET"), "{why}");
        }
        let maybe = setting_with(None, Some("maybe"), Some(stand_in()));
        assert_eq!(maybe, Ok(Setting::Off("PODSSH_LAST_RESORT")), "another word of the switch is no");
    }

    #[test]
    fn the_line_of_the_third_party_names_it_both_switches_and_what_it_sees() {
        let line = third_party_line(&stand_in());
        for word in ["ssh-j.stand-in.test", "nobody vouches for", "Q78", "PODSSH_SSH_J=no", "PODSSH_LAST_RESORT=no"] {
            assert!(line.contains(word), "{word}: {line}");
        }
        assert!(line.contains("port 22") && line.contains("end-to-end channel"), "{line}");
        assert!(unnamed_words().contains("PODSSH_SSH_J=HOST[:PORT]"));
    }
}
