//! The line of `podssh sftp` before the relay session's byte budget is spent
//! (T-700, GitHub #167), from end to end: `podssh sftp -b` through the
//! stand-in relay (`scripts/fake-relay.py`, its `rate:` mode, so that the put
//! takes longer than the watch's look) to the tests' SSH server and its
//! `sftp-server`, with `PODSSH_SESSION_BUDGET` lowered, and a put of more
//! than the budget. The 80 % line comes on stderr first, then the transfer
//! stops with the failure of the meter, with no byte lost to a cut; with
//! `-q`, no line comes.
//!
//! The budget is 12 MiB, and the link 1.5 MB/s, for two reasons of the
//! meter's arithmetic. It stops a put when the room for the requests in
//! flight and the framing (3 windows of 512 KiB and 64 KiB, about 1.6 MiB)
//! is gone: that is before 80 % of any budget under 8 MiB, the 1 MiB that
//! is its least among them, and before 95 % of any under 32 MiB. With the
//! watch looking each 250 ms, the line of 80 % of 12 MiB (9.6 MiB) comes
//! 0.8 MiB before the stop, which the slow link makes two looks or more. So
//! 80 % is the line that the test asserts; 95 % is asserted not to come
//! twice. Skipped where Python, openssl or an `sftp-server` is not found.
//!
//! The planted defect: `spawn_sftp` returns `None` at once (the reader never
//! starts), so that no line comes.

#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{without_proxy, Cell, Session};

const LIMIT: Duration = Duration::from_secs(90);
const MIB: usize = 1 << 20;

/// What a run of `podssh sftp` did: its code and its stderr.
struct Ran {
    code: Option<i32>,
    err: String,
}

/// `put` of `bytes` bytes with `budget` as the session budget, in a session
/// of the stand-in relay that moves `rate` bytes a second each way; `None`
/// when this host cannot run the stand-in or has no `sftp-server`.
fn put(tag: &str, rate: u32, budget: usize, bytes: usize, flags: &[&str]) -> Option<Ran> {
    if ssh_harness::sftp::server_path().is_none() {
        eprintln!("did not run: no sftp-server here");
        return None;
    }
    let s = Session::start(tag);
    let cell = match Cell::fake_relay_mode(&s, &format!("rate:{rate}"), "the stand-in relay, rate-limited") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    // Bytes that no compression shrinks; the file is in the home, where the
    // far end's sftp-server runs.
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let data: Vec<u8> = (0..bytes)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    std::fs::write(s.home.join("near.bin"), data).unwrap();
    let batch = s.home.join("batch");
    std::fs::write(&batch, "put near.bin near-put.bin\n").unwrap();
    // The cell's arguments are those of `podssh ssh`: the verb, and `-p` as
    // sftp's `-P`; few requests in flight, so that the count follows the relay.
    let mut args = vec!["sftp".to_string(), "-b".into(), batch.display().to_string()];
    args.extend(["-R", "2", "-B", "16384"].map(String::from));
    args.extend(flags.iter().map(|f| f.to_string()));
    args.extend(cell.args.iter().skip(1).map(|a| if a == "-p" { "-P".to_string() } else { a.clone() }));
    let mut child = without_proxy(s.command(&args))
        .current_dir(&s.home)
        .env("PODSSH_SESSION_BUDGET", budget.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = std::io::Read::read_to_string(&mut stderr, &mut text);
        text
    });
    let end = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > end {
            let _ = child.kill();
            panic!("podssh sftp did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Some(Ran { code: status.code(), err: reader.join().unwrap() })
}

/// Where `needle` is in `text`, or a failure that shows `text`.
fn at(text: &str, needle: &str) -> usize {
    text.find(needle).unwrap_or_else(|| panic!("no {needle:?} in: {text}"))
}

// T-700: a put that is larger than the budget says the 80 % line, then stops
// with the meter's words.
#[test]
fn a_put_larger_than_the_budget_says_80_percent_then_stops() {
    let Some(ran) = put("sftp-near-cap", 1_500_000, 12 * MIB, 14 * MIB, &[]) else { return };
    let said = &ran.err;
    let line = at(said, "has carried 80 % of the 12 MiB that podssh sftp sends on one");
    let stop = at(said, "the relay session is near its limits");
    assert!(line < stop, "the line comes before the stop: {said}");
    assert_eq!(said.matches("has carried 80 %").count(), 1, "{said}");
    assert!(said.matches("has carried 95 %").count() <= 1, "{said}");
    assert_ne!(ran.code, Some(0), "a put that the budget stops is no success: {said}");
}

// With -q the lines are hidden as each line of INFO is; the stop still says
// why. The same link and put as above, so that the line would have come.
#[test]
fn with_dash_q_the_lines_are_not_said_but_the_stop_is() {
    let Some(ran) = put("sftp-near-cap-q", 1_500_000, 12 * MIB, 14 * MIB, &["-q"]) else { return };
    let said = &ran.err;
    assert!(!said.contains("has carried"), "no line with -q: {said}");
    assert_ne!(ran.code, Some(0), "{said}");
}
