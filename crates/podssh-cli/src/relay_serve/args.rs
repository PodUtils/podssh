//! The flags of `podssh relay serve`, read from the command line once: each
//! value unparsed, as each module of the role parses its own.

use super::publish;
use crate::relay_settings::Refusal;

/// The flags of `serve`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeArgs {
    pub listen: Option<String>,
    pub cert: Option<String>,
    pub key: Option<String>,
    pub port_file: Option<String>,
    pub mint: Option<String>,
    pub allow_private: bool,
    /// The private ranges that it dials too, unparsed (T-635).
    pub routes: Option<String>,
    /// The limits that it moves, unparsed (T-704; `limits.rs`).
    pub keepalive: Option<String>,
    pub idle: Option<String>,
    pub session_hours: Option<String>,
    pub max_session_mib: Option<String>,
    pub connect: Option<String>,
    /// The caps of the open connections, unparsed (T-748; `limits.rs`).
    pub max_connections_per_address: Option<String>,
    pub max_connections: Option<String>,
    /// The file that keeps the pairs of the reverse road across a restart.
    pub pairs: Option<String>,
    /// The name of a certificate from ACME, in place of `cert` and `key`.
    pub acme: Option<String>,
    /// The CA's directory, else Let's Encrypt's.
    pub acme_directory: Option<String>,
    /// yes or no: the cleartext road beside TLS on the listener (T-326).
    pub cleartext: Option<String>,
    /// The deployments of the list that `/relays.json` signs, and its key
    /// file (T-346).
    pub deployment: Vec<String>,
    pub list_key: Option<String>,
    /// The resumable sessions of the forward road (T-173): how long one
    /// whose link is lost is kept, the MiB of their replay buffers in all,
    /// and this process's own name for each link of one.
    pub resume_deadline: Option<String>,
    pub resume_budget: Option<String>,
    pub resume_host: Option<String>,
    /// yes or no: HTTP/2 with extended CONNECT on the listener (T-321).
    pub http2: Option<String>,
    /// yes or no: QUIC on the listener's port of UDP (T-667).
    pub quic: Option<String>,
    /// A key's MiB for a day, and the file of each key's counts (T-636).
    pub quota: Option<String>,
    pub usage: Option<String>,
    /// How often a list of keys at a URL is fetched, and how long past
    /// that its copy is read while its server fails (T-646).
    pub list_ttl: Option<String>,
    pub list_stale: Option<String>,
    /// The owner's sshd, for an SSH client of the listener (T-644).
    pub sshd: Option<String>,
    /// The owner's balancers, whose PROXY header names the client (T-807).
    pub proxy_protocol: Option<String>,
    /// Each name published to a pair's node, `NAME=PAIR` (T-649).
    pub publish: Vec<String>,
    /// The tree of a static cover site, for the name of the certificate
    /// (T-764).
    pub cover: Option<String>,
    /// The `Server` value of the cover site, else `nginx`.
    pub cover_server: Option<String>,
    /// Each name that the role terminates itself for the cover site, and
    /// whose requests it answers locally, forwarded names aside (T-764).
    pub cover_name: Vec<String>,
    /// The cover script of the role's records (podnet#491).
    pub cover_script: Option<String>,
    /// The operator's Ed25519 secret that signs cover credentials, in a file
    /// of 64 hexadecimal digits (T-765).
    pub cover_issuer_key: Option<String>,
    /// The operator's Ed25519 public key that the role pins, in hexadecimal
    /// (T-765), for a role that holds no secret and issues no credential.
    pub cover_issuer_public: Option<String>,
    /// The owner's socket of the documents that a cover moves off the
    /// public listener (T-767).
    pub control_socket: Option<String>,
    /// The file of the node keys that DERP at `/derp` admits (T-106).
    pub derp_keys: Option<String>,
    /// The meeting points that it serves, `iroh` and `derp` (T-720).
    pub relay_roads: Option<String>,
}

impl ServeArgs {
    pub fn from_matches(matches: &clap::ArgMatches) -> ServeArgs {
        let get = |id: &str| matches.try_get_one::<String>(id).ok().flatten().cloned();
        ServeArgs {
            listen: get("listen"),
            cert: get("cert"),
            key: get("key"),
            port_file: get("port-file"),
            mint: get("mint"),
            allow_private: matches.try_get_one::<bool>("allow-private").ok().flatten().copied().unwrap_or(false),
            routes: get("routes"),
            keepalive: get("keepalive"),
            idle: get("idle"),
            session_hours: get("session-hours"),
            max_session_mib: get("max-session-mib"),
            connect: get("connect"),
            max_connections_per_address: get("max-connections-per-address"),
            max_connections: get("max-connections"),
            pairs: get("pairs"),
            acme: get("acme"),
            acme_directory: get("acme-directory"),
            cleartext: get("cleartext"),
            deployment: matches
                .try_get_many::<String>("deployment")
                .ok()
                .flatten()
                .map(|v| v.cloned().collect())
                .unwrap_or_default(),
            list_key: get("list-key"),
            resume_deadline: get("resume-deadline"),
            resume_budget: get("resume-budget"),
            resume_host: get("resume-host"),
            http2: get("http2"),
            quic: get("quic"),
            quota: get("quota"),
            usage: get("usage"),
            list_ttl: get("list-ttl"),
            list_stale: get("list-stale"),
            sshd: get("sshd"),
            proxy_protocol: get("proxy-protocol"),
            publish: publish::args(matches),
            cover: get("cover"),
            cover_server: get("cover-server"),
            cover_name: matches
                .try_get_many::<String>("cover-name")
                .ok()
                .flatten()
                .map(|v| v.cloned().collect())
                .unwrap_or_default(),
            cover_script: get("cover-script"),
            cover_issuer_key: get("cover-issuer-key"),
            cover_issuer_public: get("cover-issuer-public"),
            control_socket: get("control-socket"),
            derp_keys: get("derp-keys"),
            relay_roads: get("relay-roads"),
        }
    }

    /// Whether a flag of `serve` was given, which another subcommand refuses.
    pub fn any(&self) -> bool {
        self != &ServeArgs::default()
    }
}

/// `--listen ADDR:PORT` in its form, before anything is read (T-943): a word
/// that is no address is a usage error (64); a name that does not resolve,
/// or a port that is taken, is the host's answer at the bind (69).
pub(super) fn listen_of(text: &str) -> Result<&str, Refusal> {
    let bad = || {
        Refusal::usage(format!(
            "--listen {text:?}: not ADDR:PORT; give an address and a port, as 127.0.0.1:443, [::]:443 or \
             127.0.0.1:0 (a free port)"
        ))
    };
    if text.parse::<std::net::SocketAddr>().is_ok() {
        return Ok(text);
    }
    let (host, port) = text.rsplit_once(':').ok_or_else(bad)?;
    port.parse::<u16>().map_err(|_| bad())?;
    // A name of the host: letters, digits, '-' and '.'; an IPv6 address goes
    // in brackets, which SocketAddr read above.
    let named = !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    named.then_some(text).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    use super::listen_of;

    /// A word that is no address is 64, before a bind; an address or a name
    /// with a port goes on to the bind. One table, one rule.
    #[test]
    fn listen_is_an_address_and_a_port() {
        for good in ["127.0.0.1:0", "[::]:443", "0.0.0.0:8443", "localhost:8080", "relay.example:443"] {
            assert_eq!(listen_of(good).map_err(|r| r.message), Ok(good), "{good}");
        }
        for bad in ["nonsense", "", ":443", "127.0.0.1", "127.0.0.1:", "127.0.0.1:99999", "::1:443", "a b:1", "h:-1"] {
            let refused = listen_of(bad).unwrap_err();
            assert_eq!(refused.code, crate::exit_codes::EXIT_USAGE, "{bad}");
            assert!(refused.message.starts_with(&format!("--listen {bad:?}: not ADDR:PORT")), "{}", refused.message);
        }
    }
}
