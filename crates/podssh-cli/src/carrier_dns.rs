//! `--carrier dns:FILE` (T-877): the stream of a carrier in the questions
//! and answers of DNS, for a host that reaches a recursive resolver and
//! nothing else. The road is pod-link's (PodUtils/podcrates, feature `dns`):
//! the client's bytes go up in base32 labels of names under a zone of the
//! user's own, and come down in TXT records, under a selective-repeat ARQ
//! and TLS 1.3 with each end's Ed25519 key pinned by the other. podssh keeps
//! the glue: FILE, the probe of UDP, the bound of the owner's ruling Q107
//! (at most 20 queries a second and 8 in flight), and the node's listener,
//! which the user asks for with `listen`.
//!
//! FILE holds `NAME = VALUE` lines, `#` for a comment, as a bucket's does:
//!
//! - `zone`: the zone whose names carry the stream, delegated to the node;
//! - `resolver` (the client's): `system` (the first nameserver of
//!   `/etc/resolv.conf`, the default) or `IP[:PORT]`;
//! - `listen` (the node's): `IP:PORT` of UDP, as `0.0.0.0:53`;
//! - `key-file`: this end's key, made when it is missing (private);
//! - `peer`: the other end's key: on a client, the node's; on a node, each
//!   client's that it takes, by spaces or commas;
//! - `queries-per-second` (20 at most), `in-flight` (8 at most),
//!   `query-timeout` and `poll-max` in seconds, and `answer` in bytes.
//!
//! A relative path is read from FILE's directory. No key is on the command
//! line; a key's public half alone is in FILE.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pod_link::dns::{Dns, DnsSettings};
use pod_link::CarrierErrorKind;
use podssh_relay::identity::file::{self, Place};
use podssh_relay::identity::{Identity, KeyName};
use podssh_relay::serve::reverse::carrier::Link;
use podssh_relay::session::OsEntropy;

use crate::carrier_bucket::Side;
use crate::dns_road::{self, Resolver};
use crate::exitmap::Fault;
use crate::relay_settings::Refusal;

/// The kind's word in `--carrier`.
pub(crate) const SCHEME: &str = "dns:";
/// The most bytes of FILE.
const FILE_MOST: u64 = 64 * 1024;
/// Each direction of the pipe between the role and the road.
const PIPE: usize = 256 * 1024;
/// The bounds of the settings of FILE beside Q107's.
const TIMEOUT_MOST: f64 = 60.0;
const POLL_MOST: f64 = 60.0;
const ANSWER_MOST: u16 = 4096;
/// How many failed handshakes a node says one by one; then each 100th.
const SAID_FAILURES: u64 = 10;

/// The names that FILE may hold.
const KNOWN: &[&str] = &[
    "zone",
    "resolver",
    "listen",
    "key-file",
    "peer",
    "queries-per-second",
    "in-flight",
    "query-timeout",
    "poll-max",
    "answer",
];

/// FILE, read and checked.
#[derive(Debug)]
pub(crate) struct Spec {
    /// FILE, in the user's words.
    pub file: String,
    /// The zone, in lower case with no final dot.
    pub zone: String,
    pub resolver: Resolver,
    pub listen: Option<SocketAddr>,
    /// This end's key file, read or made when the road starts.
    pub key_file: PathBuf,
    /// The other end's keys.
    pub peers: Vec<KeyName>,
    pub settings: DnsSettings,
}

fn config(file: &str, why: impl std::fmt::Display) -> Refusal {
    Refusal::config(format!("--carrier dns:{file}: {why}"))
}

/// A number of FILE, or why it is none.
fn number<T: std::str::FromStr>(name: &str, value: &str) -> Result<T, String> {
    value.trim().parse::<T>().map_err(|_| format!("{name} {}: not a number", podssh_ws::text::one_line(value)))
}

/// Seconds of FILE within `(0, most]`.
fn seconds(name: &str, value: &str, most: f64) -> Result<Duration, String> {
    let secs: f64 = number(name, value)?;
    if !secs.is_finite() || secs <= 0.0 || secs > most {
        return Err(format!("{name} {secs}: give more than 0 and at most {most} seconds"));
    }
    Duration::try_from_secs_f64(secs).map_err(|e| format!("{name} {secs}: {e}"))
}

/// The settings of FILE over pod-link's, each within Q107's bound and its
/// own.
fn settings_of(get: &dyn Fn(&str) -> Option<String>) -> Result<DnsSettings, String> {
    let mut settings = DnsSettings::default();
    if let Some(value) = get("queries-per-second") {
        let rate: f64 = number("queries-per-second", &value)?;
        if !rate.is_finite() || rate <= 0.0 || rate > dns_road::MOST_RATE {
            return Err(format!("queries-per-second {rate}: more than 0 and at most {} (Q107)", dns_road::MOST_RATE));
        }
        settings.queries_per_second = rate;
    }
    if let Some(value) = get("in-flight") {
        let count: usize = number("in-flight", &value)?;
        if !(1..=dns_road::MOST_IN_FLIGHT).contains(&count) {
            return Err(format!("in-flight {count}: 1 to {} (Q107)", dns_road::MOST_IN_FLIGHT));
        }
        settings.in_flight = count;
    }
    if let Some(value) = get("query-timeout") {
        settings.query_timeout = seconds("query-timeout", &value, TIMEOUT_MOST)?;
    }
    if let Some(value) = get("poll-max") {
        settings.poll_max = seconds("poll-max", &value, POLL_MOST)?.max(settings.poll_min);
    }
    if let Some(value) = get("answer") {
        let size: u16 = number("answer", &value)?;
        if !(512..=ANSWER_MOST).contains(&size) {
            return Err(format!("answer {size}: 512 to {ANSWER_MOST} bytes"));
        }
        settings.answer = size;
    }
    // Q107's bound holds whatever pod-link's defaults become.
    settings.queries_per_second = settings.queries_per_second.min(dns_road::MOST_RATE);
    settings.in_flight = settings.in_flight.min(dns_road::MOST_IN_FLIGHT);
    settings.check().map_err(|e| e.to_string())?;
    Ok(settings)
}

/// The keys of `peer`, by spaces or commas; each a key, its fingerprint, or
/// the display form of it.
fn peers_of(text: &str) -> Result<Vec<KeyName>, String> {
    let words: Vec<&str> = text.split([',', ' ', '\t']).filter(|w| !w.is_empty()).collect();
    if words.is_empty() {
        return Err("peer names no key".into());
    }
    words
        .iter()
        .enumerate()
        .map(|(at, word)| {
            KeyName::parse(word).ok_or_else(|| format!("peer: its key {} is no key or fingerprint", at + 1))
        })
        .collect()
}

/// FILE read and checked, before anything connects: each name known, the
/// zone one that a name of the road fits under, each value in its bound.
pub(crate) fn read(file: &str) -> Result<Spec, Refusal> {
    use std::io::Read as _;
    let path = PathBuf::from(file);
    let opened = std::fs::File::open(&path).map_err(|e| config(file, format!("the file: {e}")))?;
    let mut bytes = Vec::new();
    opened.take(FILE_MOST + 1).read_to_end(&mut bytes).map_err(|e| config(file, format!("the file: {e}")))?;
    if bytes.len() as u64 > FILE_MOST {
        return Err(config(file, format!("the file is over {FILE_MOST} bytes")));
    }
    let text = String::from_utf8(bytes).map_err(|_| config(file, "not UTF-8 text"))?;
    let found = crate::carrier_bucket::lines(&text).map_err(|why| config(file, why))?;
    if let Some((name, _)) = found.iter().find(|(n, _)| !KNOWN.contains(&n.as_str())) {
        let name = podssh_ws::text::one_line(&name.chars().take(40).collect::<String>());
        return Err(config(file, format!("{name} is no name of the DNS road's file; a private key goes in key-file")));
    }
    let get = |name: &str| found.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone()).filter(|v| !v.is_empty());
    let zone = get("zone").ok_or_else(|| config(file, "no zone"))?.trim_end_matches('.').to_ascii_lowercase();
    // A name that a resolver passes on: pod-link checks the labels' lengths.
    if !zone.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)) {
        let shown = podssh_ws::text::one_line(&zone.chars().take(64).collect::<String>());
        return Err(config(file, format!("zone: {shown}: letters, digits, - and _ in labels")));
    }
    // pod-link's own check of a dial address: the zone leaves room for a
    // datagram in a name. Any key stands in for the peer's here.
    Dns::address(&format!("{}@{zone}", "0".repeat(64))).map_err(|e| config(file, format!("zone: {e}")))?;
    let resolver = match get("resolver") {
        Some(text) => Resolver::parse(&text).map_err(|why| config(file, format!("resolver: {why}")))?,
        None => Resolver::System,
    };
    let listen = match get("listen") {
        Some(text) => Some(text.trim().parse::<SocketAddr>().map_err(|_| {
            config(file, format!("listen {}: give IP:PORT, as 0.0.0.0:53", podssh_ws::text::one_line(&text)))
        })?),
        None => None,
    };
    let near = |name: &str| -> PathBuf {
        let given = PathBuf::from(name);
        match path.parent() {
            Some(dir) if given.is_relative() => dir.join(given),
            _ => given,
        }
    };
    let key_file = get("key-file").ok_or_else(|| config(file, "no key-file: this end's key, made when missing"))?;
    let key_file = near(&key_file);
    let peers = peers_of(&get("peer").ok_or_else(|| config(file, "no peer: the other end's key"))?)
        .map_err(|why| config(file, why))?;
    let settings = settings_of(&get).map_err(|why| config(file, why))?;
    Ok(Spec { file: file.to_string(), zone, resolver, listen, key_file, peers, settings })
}

/// This end's key, read or made; a line names a key that was made, for the
/// other end's `peer`.
fn key_of(spec: &Spec, say: &podssh_relay::filehost::Say) -> Result<Identity, Refusal> {
    let key = file::load(&Place::File(spec.key_file.clone()), &mut OsEntropy)
        .map_err(|why| config(&spec.file, format!("key-file: {why}")))?;
    if key.made {
        let shown = spec.key_file.display();
        let public = key.identity.public();
        say(format!("{}: made this end's key in {shown}: give {public} to the other end's peer", spec.file));
    }
    Ok(key.identity)
}

/// The carrier of this end: podssh's TLS provider, `identity`, and FILE's
/// settings.
fn carrier(spec: &Spec, identity: Identity) -> Dns {
    let mut dns = Dns::new(podssh_ws::tls::context().provider().clone(), Arc::new(identity));
    dns.dns = spec.settings;
    dns
}

/// Where the road's lines go: stderr, as each line of the carrier.
fn say() -> podssh_relay::filehost::Say {
    Arc::new(|line: String| {
        podssh_ssh::err_line!("podssh: the DNS carrier: {line}");
    })
}

/// The client's checks before any datagram: one peer, the resolver, and the
/// probe of UDP toward it (Q107). A host that refuses UDP is 69, with
/// nothing sent.
fn client_ready(spec: &Spec) -> Result<(SocketAddr, KeyName), Refusal> {
    let peer = match spec.peers.as_slice() {
        [one] => one.clone(),
        _ => return Err(config(&spec.file, "peer: one key on a client's side, the node's, which it pins")),
    };
    let (server, _) = spec.resolver.resolve("resolver").map_err(|why| config(&spec.file, why))?;
    let unavailable = Fault::RelayUnreachable.code();
    dns_road::udp_out(server)
        .map_err(|why| Refusal { message: format!("the carrier dns:{}: {why}", spec.file), code: unavailable })?;
    Ok((server, peer))
}

/// The stream of `side`, in a tokio runtime: a pipe at once, whose far end
/// a task carries over the road once its link opens; the role's Pings wait
/// in it meanwhile. A road that fails says why and ends the pipe, which ends
/// the stream for the role (69). The checks that need no datagram come
/// first, as refusals.
pub(crate) fn open(spec: Arc<Spec>, side: Side) -> Result<Link, Refusal> {
    let say = say();
    let (ours, mut far) = tokio::io::duplex(PIPE);
    match side {
        Side::Client => {
            let (server, peer) = client_ready(&spec)?;
            let identity = key_of(&spec, &say)?;
            let dns = carrier(&spec, identity).to(server);
            tokio::spawn(async move {
                match dns.connect(&spec.zone, &peer).await {
                    Ok((mut link, _)) => {
                        let _ = tokio::io::copy_bidirectional(&mut far, &mut link).await;
                    }
                    Err(e) => say(format!("{}: {e}", spec.file)),
                }
            });
        }
        Side::Node => {
            tokio::spawn(async move {
                match accept(&spec).await {
                    Ok(mut link) => {
                        let _ = tokio::io::copy_bidirectional(&mut far, &mut link).await;
                    }
                    Err(refusal) => say(refusal.message),
                }
            });
        }
    }
    Ok(Box::new(ours))
}

/// The node's stream, once a client whose key is a `peer` of FILE finished
/// its handshake: the listener of `listen`, which the user asked for, its
/// bind the probe (69 where it fails), after `PODSSH_LISTEN` (78). A
/// handshake that fails leaves the listener open for the next.
pub(crate) async fn accept(spec: &Spec) -> Result<Link, Refusal> {
    let say = say();
    let listen = spec.listen.ok_or_else(|| config(&spec.file, "no listen: the node's IP:PORT of UDP, as 0.0.0.0:53"))?;
    crate::pipe::listen::allowed()?;
    let identity = key_of(spec, &say)?;
    let me = identity.public();
    let clients = pod_tls::peer::Keys::new(spec.peers.clone());
    let dns = carrier(spec, identity).zone(spec.zone.clone()).with_clients(clients);
    let unavailable = Fault::RelayUnreachable.code();
    let mut listener = dns.bind(listen).await.map_err(|e| Refusal {
        message: format!("the carrier dns:{}: cannot listen on {listen} (UDP): {e}", spec.file),
        code: unavailable,
    })?;
    say(format!("{}: answers for {} at {} (UDP), as the key {me}", spec.file, spec.zone, listener.local_addr()));
    let mut failed: u64 = 0;
    loop {
        match listener.accept_key().await {
            Ok((io, key)) => {
                say(format!("{}: the client of the key {key} took the stream", spec.file));
                return Ok(Box::new(io));
            }
            // The listener's own task ended: no client can come.
            Err(e) if e.kind == CarrierErrorKind::Io(std::io::ErrorKind::BrokenPipe) => {
                return Err(Refusal { message: format!("the carrier dns:{}: {e}", spec.file), code: unavailable });
            }
            // One peer's handshake: a stranger's name costs a line, not the
            // node; a flood of them is said each 100th.
            Err(e) => {
                failed += 1;
                if failed <= SAID_FAILURES || failed % 100 == 0 {
                    say(format!("{}: a handshake failed ({failed} so far): {e}", spec.file));
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "carrier_dns_tests.rs"]
mod tests;
