//! FILE of `--carrier dns:FILE` (T-877), read and checked before anything
//! connects or binds: each name known and on its own line, each value in
//! its bound and shown as the file holds it, the zone one that a resolver
//! passes on, `key-file` a path and not a pasted key, and FILE itself one
//! that only its owner can change, as it lists the node's allowlist (`peer`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use pod_link::dns::{Dns, DnsSettings};
use podssh_relay::identity::KeyName;

use crate::carrier_bucket::{numbered, visible, Line, Side};
use crate::carrier_dns_https::{self as https, Https};
use crate::dns_road::{self, Resolver};
use crate::relay_settings::Refusal;

/// The most bytes of FILE.
const FILE_MOST: u64 = 64 * 1024;
/// The bounds of the settings of FILE beside the bound of the DNS road.
const TIMEOUT_MOST: f64 = 60.0;
const POLL_MOST: f64 = 60.0;
const ANSWER_MOST: u64 = 4096;
/// The most bytes of a label of a name.
const LABEL_MOST: usize = 63;
/// The most characters of a value that a line shows.
const SHOWN: usize = 40;

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
    /// The line of `resolver`, where FILE gives one: a client's setting.
    pub resolver_at: Option<usize>,
    /// A resolver of DNS over HTTPS in the place of `resolver`.
    pub https: Option<Https>,
    pub listen: Option<SocketAddr>,
    /// The line of `listen`, where FILE gives one: a node's setting.
    pub listen_at: Option<usize>,
    /// This end's key file, read or made when the road starts.
    pub key_file: PathBuf,
    /// The other end's keys.
    pub peers: Vec<KeyName>,
    pub settings: DnsSettings,
}

pub(super) fn config(file: &str, why: impl std::fmt::Display) -> Refusal {
    Refusal::config(format!("--carrier dns:{file}: {why}"))
}

/// A number of FILE, or why it is none; the user's own text is shown.
fn number<T: std::str::FromStr>(name: &str, value: &str) -> Result<T, String> {
    value.trim().parse::<T>().map_err(|_| format!("{name} {}: not a number", visible(value, SHOWN)))
}

/// A whole number of FILE within `[least, most]`: digits past the bound of
/// the type are out of the bound, not "not a number".
fn whole(name: &str, value: &str, least: u64, most: u64, unit: &str) -> Result<u64, String> {
    let digits = value.trim();
    let out = || format!("{name} {}: give {least} to {most}{unit}", visible(value, SHOWN));
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        let count = digits.parse::<u64>().map_err(|_| out())?;
        return if (least..=most).contains(&count) { Ok(count) } else { Err(out()) };
    }
    Err(format!("{name} {}: not a whole number", visible(value, SHOWN)))
}

/// A number of FILE within `(0, most]`, a fraction allowed.
fn fraction(name: &str, value: &str, most: f64, unit: &str) -> Result<f64, String> {
    let got: f64 = number(name, value)?;
    if !got.is_finite() || got <= 0.0 || got > most {
        return Err(format!("{name} {}: give more than 0 and at most {most}{unit}", visible(value, SHOWN)));
    }
    Ok(got)
}

/// Seconds of FILE within `(0, most]`.
fn seconds(name: &str, value: &str, most: f64) -> Result<Duration, String> {
    let secs = fraction(name, value, most, " seconds")?;
    Duration::try_from_secs_f64(secs).map_err(|e| format!("{name} {}: {e}", visible(value, SHOWN)))
}

/// The settings of FILE over pod-link's, each within the DNS road's bound
/// (20 queries a second, 8 in flight) and its own.
pub(super) fn settings_of(get: &dyn Fn(&str) -> Option<String>) -> Result<DnsSettings, String> {
    let mut settings = DnsSettings::default();
    if let Some(value) = get("queries-per-second") {
        // A fraction is a slower road, as 0.5 for one query each 2 s.
        settings.queries_per_second = fraction("queries-per-second", &value, dns_road::MOST_RATE, "")?;
    }
    if let Some(value) = get("in-flight") {
        let most = dns_road::MOST_IN_FLIGHT as u64;
        settings.in_flight = whole("in-flight", &value, 1, most, "")? as usize;
    }
    if let Some(value) = get("query-timeout") {
        settings.query_timeout = seconds("query-timeout", &value, TIMEOUT_MOST)?;
        // pod-link's held poll must end before a query's wait does: a short
        // timeout takes a hold of half of it, not a refusal.
        settings.hold = settings.hold.min(settings.query_timeout / 2);
    }
    if let Some(value) = get("poll-max") {
        settings.poll_max = seconds("poll-max", &value, POLL_MOST)?.max(settings.poll_min);
    }
    if let Some(value) = get("answer") {
        settings.answer = whole("answer", &value, 512, ANSWER_MOST, " bytes")? as u16;
    }
    // The road's bound holds whatever pod-link's defaults become.
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

/// The zone in the file's words: labels of letters, digits, `-` and `_`,
/// none empty, none that starts or ends with `-`, at most 63 bytes each, at
/// least two of them (a zone delegated to the node is under a domain), and
/// room under it for the road's data.
pub(super) fn zone_of(text: &str) -> Result<String, String> {
    let zone = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let shown = visible(&zone, 64);
    let labels: Vec<&str> = zone.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err(format!("zone {shown}: an empty label: no dot at its start, and no two dots together"));
        }
        if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)) {
            return Err(format!("zone {shown}: give letters, digits, - and _ in labels"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("zone {shown}: a label starts or ends with -, which a resolver may refuse"));
        }
        if label.len() > LABEL_MOST {
            return Err(format!("zone {shown}: a label of {} bytes; at most {LABEL_MOST}", label.len()));
        }
    }
    if labels.len() < 2 {
        return Err(format!("zone {shown}: one label; give the zone delegated to the node, as t.example"));
    }
    // pod-link's own check of a dial address: the zone leaves room for a
    // datagram in a name. Any key stands in for the peer's here.
    Dns::address(&format!("{}@{zone}", "0".repeat(64)))
        .map_err(|_| format!("zone {shown}: too long to leave room for the road's data in a name"))?;
    Ok(zone)
}

/// Whether `value` reads as a pasted key rather than a path: hex digits of
/// a seed or a whole key pair.
fn looks_like_a_key(value: &str) -> bool {
    matches!(value.len(), 64 | 128) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// FILE's metadata, refused when others can change it (Unix): its `peer`
/// is the node's allowlist. The rule is the settings file's.
#[cfg(unix)]
fn owner_alone(path: &std::path::Path, opened: &std::fs::File) -> Result<(), String> {
    let meta = opened.metadata().map_err(|e| format!("the file: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    crate::ssh::config::owner_alone_writes(path, opened, &meta).map_err(|why| {
        // Its line names the path, which the refusal already names.
        why.strip_prefix(&format!("{}: ", path.display())).map(str::to_string).unwrap_or(why)
    })
}

/// Windows keeps the writers in an access list; the rule is Unix's alone.
#[cfg(not(unix))]
fn owner_alone(_path: &std::path::Path, opened: &std::fs::File) -> Result<(), String> {
    let meta = opened.metadata().map_err(|e| format!("the file: {e}"))?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    Ok(())
}

/// FILE read and checked, before anything connects: each name known, the
/// zone one that a name of the road fits under, each value in its bound.
pub(crate) fn read(file: &str) -> Result<Spec, Refusal> {
    use std::io::Read as _;
    let path = PathBuf::from(file);
    let opened = std::fs::File::open(&path).map_err(|e| config(file, format!("the file: {e}")))?;
    owner_alone(&path, &opened).map_err(|why| config(file, why))?;
    let mut bytes = Vec::new();
    opened.take(FILE_MOST + 1).read_to_end(&mut bytes).map_err(|e| config(file, format!("the file: {e}")))?;
    if bytes.len() as u64 > FILE_MOST {
        return Err(config(file, format!("the file is over {FILE_MOST} bytes")));
    }
    let text = String::from_utf8(bytes).map_err(|_| config(file, "not UTF-8 text"))?;
    let found = numbered(&text).map_err(|why| config(file, why))?;
    for Line { at, name, value } in &found {
        if !KNOWN.contains(&name.as_str()) {
            let name = visible(name, SHOWN);
            return Err(config(
                file,
                format!("line {at}: {name} is no name of the DNS road's file; a private key goes in key-file"),
            ));
        }
        // No value of the file holds ` #`: a comment there would else be
        // read as a key or a path.
        if value.char_indices().any(|(i, c)| c == '#' && value[..i].ends_with(char::is_whitespace)) {
            return Err(config(file, format!("line {at}: {name}: a comment takes a line of its own, # first")));
        }
    }
    let line_of = |name: &str| found.iter().find(|l| l.name == name);
    let get = |name: &str| line_of(name).map(|l| l.value.clone()).filter(|v| !v.is_empty());
    let zone = zone_of(&get("zone").ok_or_else(|| config(file, "no zone"))?).map_err(|why| config(file, why))?;
    let (resolver, https) = match get("resolver") {
        Some(text) => match https::parse(&text) {
            Some(url) => (Resolver::System, Some(url.map_err(|why| config(file, format!("resolver: {why}")))?)),
            None => (Resolver::parse(&text).map_err(|why| config(file, format!("resolver: {why}")))?, None),
        },
        None => (Resolver::System, None),
    };
    let listen = match get("listen") {
        Some(text) => Some(
            text.trim()
                .parse::<SocketAddr>()
                .map_err(|_| config(file, format!("listen {}: give IP:PORT, as 0.0.0.0:53", visible(&text, SHOWN))))?,
        ),
        None => None,
    };
    let near = |name: &str| -> PathBuf {
        let given = PathBuf::from(name);
        match path.parent() {
            Some(dir) if given.is_relative() => dir.join(given),
            _ => given,
        }
    };
    let key_file = get("key-file").ok_or_else(|| {
        config(file, "no key-file: give the path of this end's key; podssh makes the file where it does not exist")
    })?;
    let key_file_at = line_of("key-file").map_or(0, |l| l.at);
    // A pasted key would become the name of a new key file: never shown.
    if looks_like_a_key(&key_file) && !near(&key_file).exists() {
        let why = "key-file is the path of this end's key file, not a key; no file has that name";
        return Err(config(file, format!("line {key_file_at}: {why}")));
    }
    let key_file = near(&key_file);
    let peers = peers_of(&get("peer").ok_or_else(|| config(file, "no peer: the other end's key"))?)
        .map_err(|why| config(file, why))?;
    let settings = settings_of(&get).map_err(|why| config(file, why))?;
    let resolver_at = line_of("resolver").map(|l| l.at);
    let listen_at = line_of("listen").map(|l| l.at);
    Ok(Spec {
        file: file.to_string(),
        zone,
        resolver,
        resolver_at,
        https,
        listen,
        listen_at,
        key_file,
        peers,
        settings,
    })
}

/// The settings of the other end are refused (78), not ignored: a client's
/// file with `listen`, or a node's with `resolver`, is the wrong file, or a
/// setting that would do nothing.
pub(super) fn for_side(spec: &Spec, side: Side) -> Result<(), Refusal> {
    let (at, name, whose, here) = match side {
        Side::Client => (spec.listen_at, "listen", "the node's", "a client's"),
        Side::Node => (spec.resolver_at, "resolver", "the client's", "a node's"),
    };
    match at {
        Some(at) => Err(config(
            &spec.file,
            format!("line {at}: {name} is {whose} setting, which {here} file does not take; remove it"),
        )),
        None => Ok(()),
    }
}
