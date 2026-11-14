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
//! A service of the shape is a [`Word`]: its user, its login, its forward,
//! its ports, its command and the word of its line that names a tunnel.
//! localhost.run is the first (T-565); Sandhole's public server (T-743),
//! srv.us (T-566, whose name is a function of the login's key, [`srv_us`])
//! and tunnl.gg (T-567) are more words of the same module. Each server comes from
//! `pod-services` alone, or from the word's variable: podssh names no host
//! of a third party in its own code. The SSH client of the node's leg is the
//! binary's.

pub mod name;
pub mod srv_us;
pub mod visit;

pub use crate::pinggy::LAST_RESORT;

/// How a word's leg logs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Login {
    /// With no account: none, an empty password, keyboard-interactive, then
    /// a key made for the login alone, never the node's.
    NoAccount,
    /// With the node's own key: the service derives the tunnel's name from
    /// the key of the login, so a client that holds the node's key knows the
    /// name with no meeting point (srv.us, T-566).
    NodeKey,
}

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
    /// The SSH user of the login.
    pub user: &'static str,
    /// How the login proves itself.
    pub login: Login,
    /// The remote forward that the service reads: its address and its port.
    pub forward: (&'static str, u32),
    /// The SSH ports where a value names none, in the order tried.
    pub ports: &'static [u16],
    /// The words of the service's line that name a tunnel, in lower case.
    pub marker: &'static str,
    /// Whether its tunnels are names under its own server, as Sandhole's
    /// `NAME.demo.sandhole.com.br`: only the server's own name is then its
    /// own, else each name under it is (`admin.localhost.run`).
    pub tunnels_under_host: bool,
    /// Whether the session opens before the forward is asked: srv.us
    /// answers a forward only once a session can carry its line.
    pub session_first: bool,
    /// The session's command where the service reads one (tunnl.gg's
    /// `output=json`); none asks for a shell.
    pub command: Option<&'static str>,
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
    login: Login::NoAccount,
    forward: ("localhost", 80),
    ports: &[22],
    marker: "tunneled",
    tunnels_under_host: false,
    session_first: false,
    command: None,
};

/// Sandhole's public server (T-743): it lets any key in as a user and
/// serves a remote forward of port 80 at a random name under its own,
/// `NAME.demo.sandhole.com.br`, new at each connection; its line is
/// `Starting HTTPS on https://NAME... for address localhost` (measured on
/// 2026-11-11, `docs/carriers.md`). The user is a fixed word, so that no
/// local user's name goes to it; it asks for a key, which the leg's login
/// makes for the login alone. Its ports are its endpoints' (443, then 22).
pub const SANDHOLE: Word = Word {
    id: "sandhole",
    name: "Sandhole",
    env: "PODSSH_SANDHOLE",
    flag: "--sandhole",
    user: "tunnel",
    login: Login::NoAccount,
    forward: ("localhost", 80),
    ports: &[443, 22],
    marker: "starting https",
    tunnels_under_host: true,
    session_first: false,
    command: None,
};

/// srv.us (T-566; its Go server, `backend/main.go` of xmit-dev/srv.us at
/// c153c354, 0BSD, read 2026-11-13): it lets in any key that signs, and
/// names the tunnel of a forward of port P `NAME.srv.us`, NAME a function
/// of the key and P alone ([`srv_us`]), so the node logs in with its own
/// key and a client derives the name from the key it pins. The user
/// `nomatch` keeps the server from asking GitHub and GitLab whether a login
/// of that name holds the key (its README); no local user's name goes to
/// it. The forward is port 1, as its README's `ssh srv.us -R
/// 1:localhost:3000`; its line is `1: https://NAME.srv.us/`. Its server
/// answers a forward only after a session is open (the forward's reply
/// waits on the line it writes there), and closes a session that asked
/// for no forward within a second, so the session opens first and the
/// forward follows at once. SSH on port 22 alone: its port 443 reads TLS.
pub const SRV_US: Word = Word {
    id: "srv-us",
    name: "srv.us",
    env: "PODSSH_SRV_US",
    flag: "--srv-us",
    user: "nomatch",
    login: Login::NodeKey,
    forward: ("localhost", srv_us::FORWARD_PORT),
    ports: &[22],
    marker: "1: https://",
    tunnels_under_host: true,
    session_first: true,
    command: None,
};

/// tunnl.gg (T-567; its Go server, klipitkas/tunnl.gg at ea47661c, MIT,
/// read 2026-11-13): a login with no key is let in as any user but
/// `stable` and `pro`, and gets a random name `ADJ-NOUN-HEX.tunnl.gg`
/// (`pkg/subdomain`); the name of `stable@` is an HMAC of the key under a
/// secret of the server's, which no client can compute, so the record
/// carries the name either way and no key of the node's goes to it. The
/// command `output=json` makes the session's first line
/// `{"event":"tunnel","url":"https://NAME.tunnl.gg",...}`: with a shell
/// and no terminal its banner is drawn for a person. The forward is the
/// README's `-R 80:localhost:PORT`; the server reads its port nowhere.
pub const TUNNL_GG: Word = Word {
    id: "tunnl-gg",
    name: "tunnl.gg",
    env: "PODSSH_TUNNL_GG",
    flag: "--tunnl-gg",
    user: "tunnel",
    login: Login::NoAccount,
    forward: ("localhost", 80),
    ports: &[22],
    marker: "\"event\":\"tunnel\"",
    tunnels_under_host: false,
    session_first: false,
    command: Some("output=json"),
};

/// Each word of the module, in the order that a node tries them unasked:
/// the ones measured live first (T-565, T-743), then srv.us and tunnl.gg.
pub const WORDS: &[Word] = &[LOCALHOST_RUN, SANDHOLE, SRV_US, TUNNL_GG];

/// The word whose service holds `name` under its tunnels' zone (the fact
/// `tunnel-zone` of `pod-services`), else localhost.run's, whose zone
/// moves (`lhr.life` now) and is the module's first.
pub fn word_of_name(name: &str) -> Word {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let zone_of = |word: &Word| pod_services::get(word.id)?.text("tunnel-zone").map(|zone| zone.to_ascii_lowercase());
    WORDS
        .iter()
        .find(|word| zone_of(word).is_some_and(|zone| name.ends_with(&format!(".{zone}"))))
        .copied()
        .unwrap_or(LOCALHOST_RUN)
}

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
        host == self.host || (!self.word.tunnels_under_host && host.ends_with(&format!(".{}", self.host)))
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

/// What a word's variable and [`LAST_RESORT`] ask for. One is made for each
/// road of a run, never in a loop of bytes, so the size of `On` costs
/// nothing worth a box.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
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
        // Sandhole's tunnels are names under its server: only the server is its own.
        let sandhole =
            Service { word: SANDHOLE, host: "demo.sandhole.com.br".into(), ports: vec![443], host_key: None };
        assert!(sandhole.own("demo.sandhole.com.br") && !sandhole.own("ke97cq.demo.sandhole.com.br"));
    }

    #[test]
    fn a_tunnel_s_name_belongs_to_the_word_whose_zone_holds_it() {
        assert_eq!(word_of_name("ke97cq.demo.sandhole.com.br").id, "sandhole", "pod-services' tunnel-zone");
        assert_eq!(word_of_name("KE97CQ.Demo.Sandhole.com.br.").id, "sandhole");
        assert_eq!(word_of_name("a1b2c3.lhr.life").id, "localhost-run");
        assert_eq!(word_of_name("demo.sandhole.com.br").id, "localhost-run", "the server itself is no tunnel");
        let sandhole = Service::hosted(SANDHOLE).expect("pod-services names Sandhole");
        assert_eq!((sandhole.host.as_str(), sandhole.ports.as_slice()), ("demo.sandhole.com.br", &[443, 22][..]));
        assert!(sandhole.host_key.as_deref().is_some_and(|key| key.starts_with("SHA256:")), "pinned");
    }

    #[test]
    fn the_words_go_in_their_order_and_tunnl_gg_s_json_line_names_its_tunnel() {
        let ids: Vec<&str> = WORDS.iter().map(|word| word.id).collect();
        assert_eq!(ids, ["localhost-run", "sandhole", "srv-us", "tunnl-gg"], "srv.us and tunnl.gg last (Q78)");
        assert_eq!((SRV_US.login, SRV_US.session_first, SRV_US.forward.1), (Login::NodeKey, true, 1));
        assert_eq!((TUNNL_GG.login, TUNNL_GG.command), (Login::NoAccount, Some("output=json")));
        // The first line of `output=json`, as tunnl.gg's README shows it.
        let line = "{\"event\":\"tunnel\",\"url\":\"https://brave-fox-7c41e09b.tunnl.gg\",\"subdomain\":\
                    \"brave-fox-7c41e09b\",\"stable\":false,\"idle_timeout_seconds\":7200}";
        let tunnl = Service { word: TUNNL_GG, host: "proxy.tunnl.gg".into(), ports: vec![22], host_key: None };
        let found = name::of_line(line, &TUNNL_GG, &|host| tunnl.own(host));
        assert_eq!(found.as_deref(), Some("brave-fox-7c41e09b.tunnl.gg"));
        let request = "{\"event\":\"request\",\"method\":\"GET\",\"path\":\"https://x.tunnl.gg/\"}";
        assert_eq!(name::of_line(request, &TUNNL_GG, &|host| tunnl.own(host)), None, "a request's line");
        for word in [SRV_US, TUNNL_GG] {
            let off = setting_with(word, Some("no"), None, None);
            assert_eq!(off, Ok(Setting::Off(word.env)), "{}", word.env);
        }
        assert_eq!((SRV_US.env, TUNNL_GG.env), ("PODSSH_SRV_US", "PODSSH_TUNNL_GG"));
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
