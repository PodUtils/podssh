//! The flags of `podssh relay serve`, read from the command line once: each
//! value unparsed, as each module of the role parses its own.

use super::publish;

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
    /// Each name published to a pair's node, `NAME=PAIR` (T-649).
    pub publish: Vec<String>,
    /// The file of the node keys that DERP at `/derp` admits (T-106).
    pub derp_keys: Option<String>,
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
            publish: publish::args(matches),
            derp_keys: get("derp-keys"),
        }
    }

    /// Whether a flag of `serve` was given, which another subcommand refuses.
    pub fn any(&self) -> bool {
        self != &ServeArgs::default()
    }
}
