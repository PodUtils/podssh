//! The words of the relay's idle cut (T-814, found by the black-box pass of
//! T-809): a relay of the user's own can set any idle limit (`relay serve
//! --idle 3`), so the hint never names 180 s as this relay's. `podssh proxy`
//! to a target that sends nothing, with stdin silent past the limit, through
//! podssh's own relay role on the contract's road: 69, the relay's 1001,
//! then a hint that names its 3 s where its `/relays.json` was read, else
//! its idle limit with no number of its own. The planted defect, 180 s as
//! the limit of any relay, fails it.

mod ssh_harness;
mod throughput_harness;

use std::net::TcpListener;
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(60);

#[test]
fn an_idle_cut_names_the_relay_s_own_limit_or_none() {
    let s = Session::start("idle-hint");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private", "--idle", "3"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    // A target that takes the connection and says nothing.
    let silent = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        for stream in silent.incoming().flatten() {
            kept.push(stream);
        }
    });
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let ca = at("--ca-file");
    let args: Vec<String> = ["proxy", "--relay-host", &at("--relay-host"), "--relay-addr", &at("--relay-addr")]
        .into_iter()
        .map(String::from)
        .chain(["127.0.0.1".to_string(), port.to_string()])
        .collect();
    let mut child = s
        .stand_in(&args, &ca)
        .env("PODSSH_RELAY_LAYER", "no")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // stdin open and silent: the relay's idle limit ends the session.
    let _stdin = child.stdin.take();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh proxy did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let out = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(69), "{err}");
    assert!(err.contains("1001 idle timeout"), "{err}");
    assert!(err.contains("after 3 s with no traffic") || err.contains("after its idle limit"), "{err}");
    assert!(!err.contains("after 180 s"), "another relay's limit named as this one's: {err}");
}
