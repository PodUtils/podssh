//! The warning before the relay's idle cut with `--persist` (T-583): through
//! podssh's relay role with an idle cut of 12 s, in front of the stand-in
//! SSH server with tmux (`tests/tmux_harness`), with keepalives off and no
//! resumable layer, `podssh ssh --persist` says once that the relay ends the
//! session and that `--persist` attaches again after it, then attaches the
//! same session again after the cut. The lead of 175 s against the client's
//! cut of 180 s makes the line come after 5 s of silence. A host that cannot
//! make the role's certificate says that the test did not run.

#![cfg(unix)]

mod ssh_harness;
mod throughput_harness;
mod tmux_harness;

use std::io::{Read, Write};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

/// How long each step may take: the role's cut is 12 s.
const LIMIT: Duration = Duration::from_secs(60);

fn collect(mut from: impl Read + Send + 'static, into: Arc<Mutex<String>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = from.read(&mut buf) {
            if n == 0 {
                break;
            }
            into.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    });
}

fn wait_for(seen: &Arc<Mutex<String>>, other: &Arc<Mutex<String>>, text: &str, count: usize) {
    let started = Instant::now();
    while seen.lock().unwrap().matches(text).count() < count {
        assert!(
            started.elapsed() < LIMIT,
            "no {text:?} ({count}); this stream: {:?}; the other: {:?}",
            seen.lock().unwrap(),
            other.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn persist_through_the_relay_role_warns_before_its_idle_cut_and_attaches_again() {
    let s = Session::start("persist-idle");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private", "--idle", "12"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let key = s.home.join("host_key");
    let (port, _tmux) = s.runtime.block_on(tmux_harness::start(&key, true));
    let mut args: Vec<String> =
        ["ssh", "--persist", "--relay-host", &relay, "--ca-file", &ca].iter().map(|w| w.to_string()).collect();
    args.extend(["--relay-addr", "relay-a.test=127.0.0.1", "--idle-warn", "175", "-p"].map(String::from));
    args.push(port.to_string());
    args.extend(["-o", "ServerAliveInterval=0"].map(String::from));
    args.extend(s.common());
    args.push("tester@127.0.0.1".into());
    let mut child = s
        .stand_in(&args, &ca)
        .env("PODSSH_RELAY_LAYER", "no")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("podssh ssh runs");
    let (out, err) = (Arc::new(Mutex::new(String::new())), Arc::new(Mutex::new(String::new())));
    collect(child.stdout.take().unwrap(), out.clone());
    collect(child.stderr.take().unwrap(), err.clone());
    let mut stdin = child.stdin.take().unwrap();
    wait_for(&out, &err, "[podssh] attached", 1);
    // Nothing is typed: the warning, then the relay's cut, then the attach.
    wait_for(&err, &out, "--persist attaches again after it", 1);
    wait_for(&err, &out, "attaching the tmux session podssh again", 1);
    wait_for(&out, &err, "[podssh] attached", 2);
    let said = err.lock().unwrap().clone();
    assert!(said.contains("the relay ends this session in "), "{said}");
    let _ = stdin.write_all(b"tmux kill-session\n");
    let _ = stdin.flush();
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh did not end; stderr: {:?}", err.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(code, Some(0), "{:?}", err.lock().unwrap());
}
