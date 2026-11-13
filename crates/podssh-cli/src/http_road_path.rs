//! What `podssh doctor --stream` measured of the path to a server (T-325),
//! kept for the HTTP road (T-319): the largest body that passed and how long
//! a quiet answer lived, so that a later session's batches and waits come
//! from the path's probe, as invariant 5 of GitHub #55 asks, through
//! `pod-relay`'s `Tuning::measured`. The probes take minutes, so a session
//! never runs them: it reads what the last `doctor` run kept for its relay
//! host, and the compiled defaults where none was kept.
//!
//! One private file of the cache (`podssh_relay::cache`), a JSON object by
//! `HOST:PORT`, each entry with the time it was measured. An entry older
//! than [`MAX_AGE`] is not used, as the path of a host that moved is
//! another; the file keeps the newest [`MOST`] entries.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use podssh_relay::http_road::Tuning;
use podssh_relay::relay::Relay;
use serde_json::{json, Map, Value};

/// The file of the cache that holds the measurements.
pub const FILE: &str = "http-road-paths.json";
/// How long a measurement is used: a week, past which the host may be on
/// another network, behind another proxy.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 24 * 3600);
/// The most servers that the file keeps.
pub const MOST: usize = 32;
/// The statuses with which a hop ends a quiet answer in the server's place
/// (as `doctor`'s verdict on the quiet probe reads them).
const QUIET_ENDERS: [u64; 4] = [408, 502, 503, 504];

/// What the probes measured of one path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Measured {
    /// The first body that did not pass, when one did not.
    pub body_cap: Option<u64>,
    /// When a quiet answer ended, when something on the path ended it.
    pub quiet: Option<Duration>,
}

impl Measured {
    /// From the `samples` of `doctor --json`'s lines "body cap" and "quiet
    /// stream": a cap is the first size refused or cut, as the size before
    /// it passed and the batch is half the cap; a quiet limit is the time
    /// the stream was cut, or a hop's answer in the server's place.
    pub fn of_samples(cap: Option<&Value>, quiet: Option<&Value>) -> Measured {
        let body_cap = cap.and_then(|c| c["refused_bytes"].as_u64());
        let quiet = quiet.and_then(|q| {
            let ender = q["status"].as_u64().is_some_and(|s| QUIET_ENDERS.contains(&s) || (520..=524).contains(&s));
            let at = q["ended_ms"].as_u64().or_else(|| q["answered_ms"].as_u64().filter(|_| ender));
            at.map(Duration::from_millis)
        });
        Measured { body_cap, quiet }
    }

    /// Whether the probes found nothing to shrink.
    pub fn is_empty(&self) -> bool {
        self.body_cap.is_none() && self.quiet.is_none()
    }

    pub fn tuning(&self) -> Tuning {
        Tuning::measured(self.body_cap, self.quiet)
    }
}

/// The key of a server: `HOST:PORT`, as the road's relay host names it.
pub fn key(host: &str, port: u16) -> String {
    format!("{}:{port}", host.to_ascii_lowercase())
}

fn now_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// `text`, the file as it was, with `measured` at `key` as of `now_s`:
/// the newest [`MOST`] entries, and a file that does not read made anew.
pub fn with(text: Option<&str>, key: &str, measured: Measured, now_s: u64) -> String {
    let parsed = text.and_then(|t| serde_json::from_str::<Value>(t).ok());
    let mut all: Map<String, Value> = parsed.and_then(|v| v.as_object().cloned()).unwrap_or_default();
    all.insert(
        key.to_string(),
        json!({
            "at_s": now_s,
            "body_cap_bytes": measured.body_cap,
            "quiet_ms": measured.quiet.map(|q| q.as_millis() as u64),
        }),
    );
    while all.len() > MOST {
        let oldest = all.iter().min_by_key(|(_, e)| e["at_s"].as_u64().unwrap_or(0)).map(|(k, _)| k.clone());
        match oldest {
            Some(oldest) => all.remove(&oldest),
            None => break,
        };
    }
    Value::Object(all).to_string()
}

/// The measurement at `key` in `text`, when it is younger than
/// [`MAX_AGE`] at `now_s`, with its age.
pub fn read(text: &str, key: &str, now_s: u64) -> Option<(Measured, Duration)> {
    let doc: Value = serde_json::from_str(text).ok()?;
    let entry = doc.get(key)?;
    let at = entry["at_s"].as_u64()?;
    let age = Duration::from_secs(now_s.checked_sub(at)?);
    if age > MAX_AGE {
        return None;
    }
    let measured = Measured {
        body_cap: entry["body_cap_bytes"].as_u64().filter(|c| *c > 0),
        quiet: entry["quiet_ms"].as_u64().map(Duration::from_millis),
    };
    Some((measured, age))
}

/// Keep what `doctor --stream` measured at `host:port`. A cache that keeps
/// no file (`PODSSH_CACHE_DIR=none`) keeps none, and the road then takes
/// its defaults.
pub fn record(host: &str, port: u16, measured: Measured) -> Result<(), String> {
    let text = podssh_relay::cache::load_file(FILE);
    let body = with(text.as_deref(), &key(host, port), measured, now_s());
    podssh_relay::cache::store_file(FILE, body.as_bytes()).map(|_| ())
}

/// The tuning of the road at `relay`: what the last `doctor --stream` there
/// measured, else the defaults; and a line that says which, for `-v`.
pub fn tuning_for(relay: &Relay) -> (Tuning, Option<String>) {
    let kept = podssh_relay::cache::load_file(FILE);
    tuning_from(kept.as_deref(), relay, now_s())
}

/// [`tuning_for`] over the file's text (for tests).
pub fn tuning_from(text: Option<&str>, relay: &Relay, now_s: u64) -> (Tuning, Option<String>) {
    let Some((measured, age)) = text.and_then(|t| read(t, &key(&relay.host, relay.port), now_s)) else {
        return (Tuning::default(), None);
    };
    let tuning = measured.tuning();
    let hours = age.as_secs() / 3600;
    let line = format!(
        "the HTTP road at {} sizes its requests by what podssh doctor --stream measured there {hours} h ago: \
         batches of {} bytes at most, an answer down waits {} s at most",
        relay.host,
        tuning.batch,
        tuning.wait.as_secs()
    );
    (tuning, Some(line))
}

#[cfg(test)]
#[path = "http_road_path_tests.rs"]
mod tests;
