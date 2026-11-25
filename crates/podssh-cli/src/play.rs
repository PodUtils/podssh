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
    let (speed, idle) = match (number("--speed", &args.speed), number("--idle-limit", &args.idle_limit)) {
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
    let file = std::fs::File::open(path).map_err(|e| format!(": {}", podssh_ws::text::said(&e)))?;
    let mut lines = std::io::BufReader::new(file).lines();
    let header: Option<Value> = lines.next().and_then(Result::ok).and_then(|line| serde_json::from_str(&line).ok());
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
        if kind != "o" {
            continue;
        }
        std::thread::sleep((start + Duration::from_secs_f64(clock)).saturating_duration_since(Instant::now()));
        // Whoever read the output went: nothing more to play.
        if out.write_all(data.as_bytes()).and_then(|()| out.flush()).is_err() {
            return Ok(());
        }
    }
    Ok(())
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
}
