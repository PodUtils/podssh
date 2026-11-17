//! `health --preflight`'s road (T-813, found by the black-box pass of T-809):
//! a session that the relay carried says the relay, in the resumable layer
//! or not, never `direct`. Through podssh's own relay role, which offers the
//! layer: with `PODSSH_RELAY_LAYER=yes` the line names the layer, with `no`
//! the relay's limits. The planted defect, the layer's road read as no
//! relay, says `direct`. It says that it did not run where this host has no
//! openssl for the role's certificate.

mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(150);

/// The road line of `health --preflight` in `cell`, with the layer `layer`.
fn road_line(s: &Session, cell: &Cell, layer: &str) -> String {
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let mut args = vec!["health".to_string()];
    args.extend(cell.args[1..cell.args.len() - 1].iter().cloned());
    args.push("--preflight".into());
    args.push(cell.args.last().unwrap().clone());
    let mut child = s
        .stand_in(&args, &ca)
        .env("PODSSH_RELAY_LAYER", layer)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("health --preflight did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    text.lines().find(|l| l.contains(" road ")).unwrap_or_else(|| panic!("no road line: {text}")).to_string()
}

#[test]
fn the_road_of_a_session_that_the_relay_carried_is_the_relay() {
    let s = Session::start("health-road");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let layered = road_line(&s, &cell, "yes");
    assert!(layered.contains("in the resumable layer"), "{layered}");
    let contract = road_line(&s, &cell, "no");
    assert!(contract.contains("ends a session at"), "{contract}");
    for line in [&layered, &contract] {
        assert!(!line.contains("direct"), "{line}");
    }
}
