//! What `podssh doctor` was given, and the parse of its flags: kept apart
//! from `mod.rs`, which runs the checks.

use super::ExitFlags;

/// What `podssh doctor` was given: the relay settings `ssh` and `proxy` take,
/// so the doctor checks the path they would use.
#[derive(Debug, Clone, Default)]
pub struct DoctorArgs {
    pub relay_host: Option<String>,
    /// `--relay-failover`: how the relay check tries the hosts (T-220).
    pub relay_failover: Option<String>,
    pub relay_addr: Option<String>,
    pub ca_file: Option<String>,
    /// `--json`: one JSON object on stdout when every check has run.
    pub json: bool,
    /// `--full`: also log in to GitHub through the relay with a key made
    /// for the check (`login`).
    pub full: bool,
    /// `--hop`: this host and a first hop of `-J` alone (T-371).
    pub hop: Option<String>,
    /// `--policy FILE`, with `--hop`: the algorithm policy that judges the
    /// hop's KEXINIT (T-838).
    pub policy: Option<String>,
    /// `--forwarder`: forwarders to check after the relay (T-369).
    pub forwarder: Option<String>,
    /// `--shadowsocks`: the file whose first server is checked (T-373).
    pub shadowsocks: Option<String>,
    /// `--via`: the second proxy that is checked (T-439).
    pub via: crate::via::Flags,
    /// `--vless`: the file whose servers are checked (T-440).
    pub vless: Option<String>,
    /// `--early-data WORD`: the early data that the VLESS check offers
    /// (T-758).
    pub early_data: Option<String>,
    /// `--h2-shape WORD`: the shape of the HTTP/2 road that podssh builds
    /// (T-763).
    pub h2_shape: Option<String>,
    /// `--trojan`: state what the Trojan road carries, with no connection (T-761).
    pub trojan: bool,
    /// `--hysteria`: the file whose servers are checked (T-580).
    pub hysteria: Option<String>,
    /// `--tuic`: the file whose servers are checked (T-581).
    pub tuic: Option<String>,
    /// `--turn` and `--turn-auth-file`: the TURN server checked (T-621).
    pub turn: crate::turn::Flags,
    /// `--devtunnel TUNNEL[:PORT]`: the Dev Tunnels tunnel checked (T-755).
    pub devtunnel: Option<String>,
    /// `--cover NAME`: the delegated credential of a cover relay (T-766).
    pub cover: Option<String>,
    /// `--quick`: this host, the egress and the relay, with the roads that
    /// the run names, and none of the others (T-511).
    pub quick: bool,
    /// `--tier`: this host's lines and one verdict of its capabilities, alone (T-706).
    pub tier: bool,
    /// `--jobs N`: at most N sections at once, as typed (T-511).
    pub jobs: Option<String>,
    /// `--stream URL` and `--stream-idle SECONDS`, as typed (T-325).
    pub stream: Option<String>,
    pub stream_idle: Option<String>,
    /// `--exit NAME`, `--exit-target` and `--client-key` (T-458).
    pub exit: ExitFlags,
}

/// The parse of `doctor`, kept here so that `tree` stays a dispatcher of
/// verbs rather than a list of each verb's fields.
pub fn parsed(m: &clap::ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> crate::tree::Parsed {
    let get = |id: &str| m.get_one::<String>(id).cloned();
    crate::tree::Parsed::Doctor {
        relay_host: get("relay-host"),
        relay_failover: get("relay-failover"),
        relay_addr: get("relay-addr"),
        ca_file: get("ca-file"),
        json: m.get_flag("json"),
        full: m.get_flag("full"),
        hop: get("hop"),
        policy: get("policy"),
        forwarder: get("forwarder"),
        shadowsocks: get("shadowsocks"),
        via: crate::via::Flags { url: get("via"), auth_file: get("via-auth-file") },
        vless: get("vless"),
        early_data: get("early-data"),
        h2_shape: get("h2-shape"),
        trojan: m.get_flag("trojan"),
        hysteria: get("hysteria"),
        tuic: get("tuic"),
        turn: crate::turn::Flags { url: get("turn"), auth_file: get("turn-auth-file") },
        devtunnel: get("devtunnel"),
        cover: get("cover"),
        quick: m.get_flag("quick"),
        tier: m.get_flag("tier"),
        jobs: get("jobs"),
        stream: get("stream"),
        stream_idle: get("stream-idle"),
        exit: ExitFlags { name: get("exit"), target: get("exit-target"), client_key: get("client-key") },
        refused,
    }
}
