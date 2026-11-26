//! `podssh play FILE` (T-033): a recording of `podssh ssh --record`, or
//! another asciicast v2 file, played again on stdout with its timing. The
//! output of a session reaches the terminal again, its control sequences
//! too: play only a file that you trust.

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::exit_codes::EXIT_USAGE;

/// The exit when the file cannot be played: missing, or not asciicast v2.
pub const EXIT_FAILED: i32 = 1;

/// Every value `podssh play` accepts, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayArgs {
    pub file: Option<String>,
    pub speed: Option<String>,
    pub idle_limit: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

pub fn run(args: &PlayArgs, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let Some(path) = args.file.as_deref() else {
        let _ = writeln!(err, "podssh play: give the recording: podssh play FILE");
        return EXIT_USAGE;
    };
    let number = |flag: &str, value: &Option<String>| match value.as_deref() {
        None => Ok(None),
        Some(text) => positive(text).map(Some).ok_or(format!("{flag} {text}: a number above 0")),
    };
    // A speed so small that one second of the recording is a wait that no
    // clock keeps is refused here, not met as a panic at a wait (T-1057).
    let slow = |speed: Option<f64>| match (speed, args.speed.as_deref()) {
        (Some(v), Some(text)) if Duration::try_from_secs_f64(1.0 / v).is_err() => {
            Err(format!("--speed {text}: so small that one second would be a wait past any clock"))
        }
        _ => Ok(speed),
    };
    let speed = number("--speed", &args.speed).and_then(slow);
    let (speed, idle) = match (speed, number("--idle-limit", &args.idle_limit)) {
        (Ok(speed), Ok(idle)) => (speed.unwrap_or(1.0), idle),
        (Err(why), _) | (_, Err(why)) => {
            let _ = writeln!(err, "podssh play: {why}");
            return EXIT_USAGE;
        }
    };
    match play(path, speed, idle, out) {
        Ok(()) => 0,
        Err(why) => {
            let _ = writeln!(err, "podssh play: {path}{why}");
            EXIT_FAILED
        }
    }
}

/// Each output event of the file at its time, each wait cut to `idle` and
/// divided by `speed`; an event of another kind is passed over. `Err` is
/// the end of a message after the file's name.
fn play(path: &str, speed: f64, idle: Option<f64>, out: &mut dyn Write) -> Result<(), String> {
    // A directory opens on Unix and fails at the first read, and Windows
    // refuses its open: either is said as what it is (T-1042).
    if std::fs::metadata(path).is_ok_and(|meta| meta.is_dir()) {
        return Err(": a directory, not a recording".into());
    }
    let file = std::fs::File::open(path).map_err(|e| format!(": {}", podssh_ws::text::said(&e)))?;
    let mut lines = std::io::BufReader::new(file).lines();
    let first = lines.next().transpose().map_err(|e| format!(": {}", podssh_ws::text::said(&e)))?;
    let header: Option<Value> = first.and_then(|line| serde_json::from_str(&line).ok());
    let header = header.filter(|h| h.get("version").and_then(Value::as_u64) == Some(2));
    let Some(header) = header else { return Err(": not an asciicast v2 recording".into()) };
    let idle = idle.or_else(|| header.get("idle_time_limit").and_then(Value::as_f64).filter(|v| *v > 0.0));
    let (start, mut last, mut clock) = (Instant::now(), 0.0_f64, 0.0_f64);
    for (n, line) in lines.enumerate() {
        let line = line.map_err(|e| format!(": {}", podssh_ws::text::said(&e)))?;
        if line.trim().is_empty() {
            continue;
        }
        let event: Option<Value> = serde_json::from_str(&line).ok();
        let event = event.as_ref().and_then(|e| Some((e.get(0)?.as_f64()?, e.get(1)?.as_str()?, e.get(2)?.as_str()?)));
        let Some((at, kind, data)) = event else { return Err(format!(":{}: not an event", n + 2)) };
        // A time below 0 is no time of a recording (T-984). One before the
        // latest plays at once, as asciinema's player waits only for a later
        // time, and the clock goes on from the latest.
        if at < 0.0 || !at.is_finite() {
            return Err(format!(":{}: a time below 0 ({at})", n + 2));
        }
        let gap = (at - last).max(0.0);
        last = last.max(at);
        clock += idle.map_or(gap, |limit| gap.min(limit)) / speed;
        // The sum of the waits at this speed can pass what a Duration or this
        // host's clock holds, each time being good: said, not a panic.
        let Some(due) = deadline(start, clock) else {
            let why = format!("a wait too long for any clock ({clock:e} s); a larger --speed or an --idle-limit plays it");
            return Err(format!(":{}: {why}", n + 2));
        };
        if kind != "o" {
            continue;
        }
        std::thread::sleep(due.saturating_duration_since(Instant::now()));
        // Whoever read the output went: nothing more to play.
        if out.write_all(data.as_bytes()).and_then(|()| out.flush()).is_err() {
            return Ok(());
        }
    }
    Ok(())
}

/// The instant `clock` seconds after `start`, or `None` where no Duration or
/// no `Instant` of this host holds it: `Instant + Duration` panics on overflow.
fn deadline(start: Instant, clock: f64) -> Option<Instant> {
    Duration::try_from_secs_f64(clock).ok().and_then(|wait| start.checked_add(wait))
}

fn positive(text: &str) -> Option<f64> {
    text.parse::<f64>().ok().filter(|v| v.is_finite() && *v > 0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recording of `events` after a header, in a file of its own.
    fn recording(name: &str, events: &[&str]) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("podssh-play-{name}-{}.cast", std::process::id()));
        let mut text = String::from("{\"version\":2,\"width\":80,\"height\":24}\n");
        for event in events {
            text.push_str(event);
            text.push('\n');
        }
        std::fs::write(&path, text).unwrap();
        path
    }

    /// What is no recording, each in its own words (T-1042): a directory,
    /// an empty file, and a header of another version.
    #[test]
    fn what_is_no_recording_is_said_for_what_it_is() {
        let empty = std::env::temp_dir().join(format!("podssh-play-empty-{}.cast", std::process::id()));
        std::fs::write(&empty, b"").unwrap();
        let other = std::env::temp_dir().join(format!("podssh-play-v1-{}.cast", std::process::id()));
        std::fs::write(&other, b"{\"version\":1}\n").unwrap();
        let dir = std::env::temp_dir();
        for (path, want) in [
            (dir.as_path(), ": a directory, not a recording"),
            (empty.as_path(), ": not an asciicast v2 recording"),
            (other.as_path(), ": not an asciicast v2 recording"),
        ] {
            let got = play(path.to_str().unwrap(), 1.0, None, &mut Vec::new());
            assert_eq!(got, Err(want.to_string()), "{}", path.display());
        }
        let _ = std::fs::remove_file(&empty);
        let _ = std::fs::remove_file(&other);
    }

    /// Each time an event may have (T-984): a time below 0 is a bad line,
    /// named by its number; one before the latest plays at once, and its
    /// output is kept.
    #[test]
    fn a_time_below_0_is_refused_and_one_out_of_order_plays_at_once() {
        for (name, events, want) in [
            ("order", &["[0.0,\"o\",\"a\"]", "[0.2,\"o\",\"b\"]", "[0.1,\"o\",\"c\"]"][..], Ok("abc")),
            ("negative", &["[0.0,\"o\",\"a\"]", "[-1,\"o\",\"b\"]"][..], Err(":3: a time below 0")),
            ("first", &["[-0.5,\"o\",\"a\"]"][..], Err(":2: a time below 0")),
        ] {
            let path = recording(name, events);
            let mut out = Vec::new();
            let started = Instant::now();
            let got = play(path.to_str().unwrap(), 1.0, None, &mut out);
            let _ = std::fs::remove_file(&path);
            match (want, got) {
                (Ok(text), Ok(())) => assert_eq!(String::from_utf8_lossy(&out), text, "{name}"),
                (Err(part), Err(why)) => assert!(why.starts_with(part), "{name}: {why}"),
                (want, got) => panic!("{name}: {want:?} {got:?}"),
            }
            // 0.2 s at most: the event out of order adds no wait.
            assert!(started.elapsed() < Duration::from_secs(2), "{name}");
        }
    }

    /// Each speed against the waits it makes (T-1057): one so small that a
    /// second overflows is a usage error, and a sum of waits past any clock
    /// is a bad line, exit 1. None of them panics, and none waits.
    #[test]
    fn a_wait_past_any_clock_is_refused_not_a_panic() {
        let path = recording("clock", &["[0.0,\"o\",\"a\"]", "[2.0,\"o\",\"b\"]"]);
        let file = Some(path.to_str().unwrap().to_string());
        for (speed, idle, want, line) in [
            ("1e-320", None, EXIT_USAGE, "--speed 1e-320: so small"),
            ("5e-324", None, EXIT_USAGE, "--speed 5e-324: so small"),
            ("1e-310", Some("1"), EXIT_USAGE, "--speed 1e-310: so small"),
            ("1e-25", None, EXIT_USAGE, "--speed 1e-25: so small"),
            // 1e19 s a second holds; 2 s of the recording, 2e19 s, does not.
            ("1e-19", None, EXIT_FAILED, ":3: a wait too long for any clock"),
            ("1000", None, 0, ""),
        ] {
            let args = PlayArgs {
                file: file.clone(),
                speed: Some(speed.into()),
                idle_limit: idle.map(str::to_string),
                refused: Vec::new(),
            };
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let started = Instant::now();
            let code = run(&args, &mut out, &mut err);
            let err = String::from_utf8_lossy(&err);
            assert_eq!(code, want, "{speed}: {err}");
            assert!(err.contains(line), "{speed}: {err}");
            assert!(err.lines().count() <= 1, "{speed}: one line: {err}");
            assert!(started.elapsed() < Duration::from_secs(2), "{speed}");
        }
        let _ = std::fs::remove_file(&path);
        assert!(deadline(Instant::now(), f64::INFINITY).is_none());
        assert!(deadline(Instant::now(), 1e20).is_none());
        assert!(deadline(Instant::now(), 1.5).is_some());
    }
}
