//! The measurements of `doctor --stream` kept for the HTTP road: what the
//! samples give, the file's entries and their age, and the tuning that a
//! session takes from them.

use super::*;

fn relay(host: &str, port: u16) -> Relay {
    Relay { host: host.into(), port }
}

/// A cap is the first size that did not pass; a quiet limit is the cut,
/// or a hop's answer in the server's place, never the server's own `200`.
#[test]
fn the_samples_give_the_cap_and_the_quiet_limit() {
    let cap = json!({ "passed_bytes": 1 << 20, "refused_bytes": 2 << 20, "status": 413 });
    let cut = json!({ "hold_ms": 130_000, "ended_ms": 60_010, "status": 200 });
    let m = Measured::of_samples(Some(&cap), Some(&cut));
    assert_eq!(m, Measured { body_cap: Some(2 << 20), quiet: Some(Duration::from_millis(60_010)) });
    let whole = json!({ "passed_bytes": 8 << 20, "refused_bytes": null, "status": null });
    let held = json!({ "hold_ms": 130_000, "ended_ms": null, "status": 200, "answered_ms": 3 });
    assert!(Measured::of_samples(Some(&whole), Some(&held)).is_empty(), "nothing on the path to shrink for");
    let hop = json!({ "hold_ms": 130_000, "ended_ms": null, "status": 524, "answered_ms": 100_200 });
    assert_eq!(Measured::of_samples(None, Some(&hop)).quiet, Some(Duration::from_millis(100_200)));
    let own = json!({ "hold_ms": 130_000, "ended_ms": null, "status": 404, "answered_ms": 5 });
    assert_eq!(Measured::of_samples(None, Some(&own)).quiet, None, "a 404 is no quiet limit");
    assert!(Measured::of_samples(None, None).is_empty());
}

/// The tuning of a measured path is `pod-relay`'s, which halves the cap
/// and takes two thirds of the quiet limit.
#[test]
fn a_measured_path_tunes_the_road_by_pod_relay_s_rule() {
    let m = Measured { body_cap: Some(64 * 1024), quiet: Some(Duration::from_secs(9)) };
    let tuning = m.tuning();
    assert_eq!((tuning.batch, tuning.wait), (32 * 1024, Duration::from_secs(6)));
    assert_eq!(Measured::default().tuning(), Tuning::default());
}

/// An entry is read back at its key, and not once it is a week old or
/// written in the future.
#[test]
fn an_entry_is_read_at_its_key_while_it_is_young() {
    let m = Measured { body_cap: Some(1 << 20), quiet: None };
    let text = with(None, &key("Relay.Example", 443), m, 1_000);
    assert_eq!(read(&text, "relay.example:443", 1_000 + 3600), Some((m, Duration::from_secs(3600))));
    assert_eq!(read(&text, "relay.example:8443", 1_000), None, "another port is another path");
    assert_eq!(read(&text, "relay.example:443", 1_000 + MAX_AGE.as_secs() + 1), None);
    assert_eq!(read(&text, "relay.example:443", 999), None);
    assert_eq!(read("not json", "relay.example:443", 1_000), None);
}

/// The file keeps the newest entries, and a file that does not read is
/// made anew.
#[test]
fn the_file_keeps_the_newest_entries() {
    let mut text = with(Some("[broken"), "a:443", Measured::default(), 1);
    for i in 0..MOST as u64 {
        text = with(Some(&text), &format!("h{i}:443"), Measured::default(), 10 + i);
    }
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc.as_object().unwrap().len(), MOST);
    assert!(doc.get("a:443").is_none(), "the oldest went first");
    assert!(doc.get(format!("h{}:443", MOST - 1)).is_some());
}

/// With no measurement the road takes its defaults and says nothing; with
/// one, its tuning and a line that names where it came from.
#[test]
fn a_session_takes_the_kept_measurement_or_the_defaults() {
    let r = relay("relay.example", 443);
    assert_eq!(tuning_from(None, &r, 10_000), (Tuning::default(), None));
    let m = Measured { body_cap: Some(64 * 1024), quiet: Some(Duration::from_secs(30)) };
    let text = with(None, &key("relay.example", 443), m, 10_000 - 7200);
    let (tuning, line) = tuning_from(Some(&text), &r, 10_000);
    assert_eq!((tuning.batch, tuning.wait), (32 * 1024, Duration::from_secs(20)));
    let line = line.expect("a line");
    assert!(line.contains("relay.example") && line.contains("2 h ago") && line.contains("32768 bytes"), "{line}");
    assert_eq!(tuning_from(Some(&text), &relay("other.example", 443), 10_000).0, Tuning::default());
}
