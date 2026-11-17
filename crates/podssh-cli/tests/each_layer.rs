//! `podssh each` on the resumable layer's road (T-811, found by the
//! black-box pass of T-809): the sessions of one process share the
//! process's connection of HTTP/2 to the relay, and each one ran on a
//! runtime of its own, so the end of the first broke the streams of the
//! others ("broken pipe", then a failed handshake of the layer). Through
//! podssh's own relay role, which offers the layer, three hosts that answer
//! and one name that does not: in each of five runs, each good host gives 0
//! with no link lost, and the bad one fails alone. It says that it did not
//! run where this host has no openssl for the role's certificate.

mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);

#[test]
fn each_session_of_one_process_on_the_layer_s_road_ends_well() {
    let s = Session::start("each-layer");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    // The cell's words of `ssh`, less its verb and its host, then each's.
    let mut args = vec!["each".to_string()];
    args.extend(cell.args[1..cell.args.len() - 1].iter().cloned());
    args.push("tester@127.0.0.1,127.0.0.1,localhost,tester@no-such-host.invalid".into());
    args.extend(["--", "true"].map(String::from));
    for run in 1..=5 {
        let mut child = s
            .stand_in(&args, &ca)
            .env("PODSSH_RELAY_LAYER", "yes")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let said = std::thread::spawn(move || {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text);
            text
        });
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > LIMIT {
                let _ = child.kill();
                panic!("run {run}: podssh each did not end within {LIMIT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let err = said.join().unwrap();
        assert!(err.contains("3 gave 0, 1 failed"), "run {run}: {err}");
        for lost in ["broken pipe", "the link failed", "handshake failed"] {
            assert!(!err.contains(lost), "run {run}: a session lost its link ({lost}): {err}");
        }
    }
}
