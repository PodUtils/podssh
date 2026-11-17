//! The offer of a relay host that the user named (T-812, found by the
//! black-box pass of T-809). With `PODSSH_RELAY_LAYER` unset, a fresh run
//! reads its `/relays.json` once, takes the layer where the host offers it,
//! and so `podssh proxy` half-closes: a closed stdin ends the run at once.
//! And a read that failed at once (the relay down) is no offer kept for a
//! day, which turned the layer off for that day: the planted defect keeps
//! it. It says that it did not run where this host has no openssl for the
//! role's certificate.

mod held_port;
mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(30);

/// `podssh proxy` in `s` through `relay` to the session's sshd, stdin
/// closed: its code and how long it took.
fn proxy(s: &Session, ca: &str, relay: &str, addr: &str) -> (Option<i32>, Duration, String) {
    let args: Vec<String> = ["proxy", "--relay-host", relay, "--relay-addr", addr, "127.0.0.1", &s.port.to_string()]
        .into_iter()
        .map(String::from)
        .collect();
    let mut child = s
        .stand_in(&args, ca)
        .env_remove("PODSSH_RELAY_LAYER")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let took = started.elapsed();
    let out = child.wait_with_output().unwrap();
    (code, took, String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Each kept offer of `port` in the cache's places of the session.
fn kept_offers(s: &Session, port: u16) -> Vec<std::path::PathBuf> {
    let name = format!("relay-offer-relay-a.test-{port}.json");
    let tmp = std::env::temp_dir();
    let mut places = vec![s.home.join("cache").join("podssh"), s.home.join(".cache").join("podssh")];
    if let Ok(entries) = std::fs::read_dir(&tmp) {
        places.extend(
            entries
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("podssh-"))),
        );
    }
    places.into_iter().map(|dir| dir.join(&name)).filter(|file| file.exists()).collect()
}

#[test]
fn a_named_relay_s_offer_is_read_once_and_a_failed_read_is_not_kept() {
    let s = Session::start("offer-read");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, addr, ca) = (at("--relay-host"), at("--relay-addr"), at("--ca-file"));
    // The relay down: a port where nothing listens. Its failed read is no
    // offer kept, so a later run reads again.
    let (dead, _held) = held_port::refusing();
    let (code, _, err) = proxy(&s, &ca, &format!("relay-a.test:{dead}"), &addr);
    assert_ne!(code, Some(0), "{err}");
    let kept = kept_offers(&s, dead);
    assert!(kept.is_empty(), "a failed read was kept as an offer: {kept:?}");
    // The relay up: its offer read once, the layer taken, so a closed stdin
    // ends the run at once (the contract's road has no half-close).
    let (code, took, err) = proxy(&s, &ca, &relay, &addr);
    assert_eq!(code, Some(0), "the run ended in {took:?}: {err}");
    assert!(took < Duration::from_secs(15), "{took:?}: {err}");
}
