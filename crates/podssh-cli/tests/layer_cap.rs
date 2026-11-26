//! A relay role with a small byte cap of a session (T-826): 3 MiB each way
//! (`cat`) through `podssh relay serve --max-session-mib 1` on the resumable
//! layer come whole, over links that the client moves to new ones before the
//! role's cap, so that no link ends with the role's Close (`end close 1009
//! session byte cap`); and no link's end is said as a broken pipe or a reset
//! (pod-session's drain, COORD-117 ask 1). It says that it did not run where
//! this host has no openssl for the role's certificate.

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;

use throughput_harness::{Cell, Session};

const LEN: usize = 3 << 20;

#[test]
fn a_small_cap_ends_links_with_the_role_s_close_and_the_bytes_come_whole() {
    let s = Session::start("layer-cap");
    let extra = ["--allow-private", "--max-session-mib", "1"];
    let cell = match Cell::podssh_relay(&s, "podssh's relay role, 1 MiB a session", &extra) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let mut args = cell.args.clone();
    args.insert(1, "-v".into());
    args.push("cat".into());
    // Bytes each way at once: the client sends while the role ends a link,
    // so that a socket closed with them unread resets.
    let sent: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let mut child = s
        .stand_in(&args, &ca)
        .env("PODSSH_RELAY_LAYER", "yes")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let feed = sent.clone();
    let writer = std::thread::spawn(move || {
        use std::io::Write;
        let _ = stdin.write_all(&feed);
    });
    let out = child.wait_with_output().unwrap();
    let _ = writer.join();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(out.stdout == sent, "the bytes came whole: {} of {LEN}: {err}", out.stdout.len());
    let events = std::fs::read_to_string(s.home.join("fake-relay-normal-events.log")).unwrap_or_default();
    // The client moves each link before the role's cap (T-826): the move
    // threshold and both windows fit under it, and the old link is held while
    // the new one greets (pod-session, podcrates' entries 953 and 958).
    // The line's words, before its fields (T-1016).
    let capped =
        events.lines().filter(|l| podssh_relay::serve::said::words(l) == "end close 1009 session byte cap").count();
    assert_eq!(capped, 0, "no link ends at the cap: {events}\n{err}");
    assert!(err.contains("moved to a new link before the relay's limits"), "the session moved: {err}");
    let lost =
        err.lines().filter(|l| l.contains("Broken pipe") || l.contains("broken pipe") || l.contains("reset by peer"));
    let lost: Vec<&str> = lost.collect();
    assert!(lost.is_empty(), "a link's end said as its write's error, not the role's Close: {lost:?}");
}
