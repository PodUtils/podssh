//! The credentials of Cloudflare Access on the relay's roads (T-718),
//! through the stand-in relay (`scripts/fake-relay.py --mode access`),
//! which, as the gate of Access does, answers 403 to each request without
//! its service token. `podssh ssh`: a relay host named by `--access-host`
//! gets the two headers from their files and the command runs; with no host
//! named, or another host named, no header goes out and the gate's 403 ends
//! the run with 255, as for each first hop that ssh does not reach (the
//! planted defect: headers sent to no host, or to each). A pair's road and
//! `operator`: with the relay named by `AccessHost` in the settings, a pair
//! is made, its node comes online and an operator's bytes come back from
//! its TARGET; with no settings, the pair's request gets the gate's 403.
//! The checks say that they did not run when this host has no Python or no
//! openssl for the stand-in.

mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use ssh_harness::GREETING;
use throughput_harness::{lines_of, wait_for, Cell, Session};

const LIMIT: Duration = Duration::from_secs(120);
/// The stand-in gate's service token: made-up values, as in
/// `scripts/fake-relay.py`.
const ID: &str = "id-of-the-stand-in.access";
const SECRET: &str = "secret-of-the-stand-in-7c1e";

/// The stand-in relay behind its gate, or `None` where it cannot run.
fn gated(s: &Session) -> Option<Cell> {
    match Cell::fake_relay_mode(s, "access", "the stand-in relay behind a gate of Access") {
        Ok(cell) => Some(cell),
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

/// The value of `flag` among the cell's arguments.
fn at(cell: &Cell, flag: &str) -> String {
    cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap()
}

/// The two files of the stand-in gate's service token, in the session's
/// home, and the variables that name them.
fn credentials(s: &Session) -> [(&'static str, PathBuf); 2] {
    let (id, secret) = (s.home.join("access-id"), s.home.join("access-secret"));
    std::fs::write(&id, format!("{ID}\n")).unwrap();
    std::fs::write(&secret, format!("{SECRET}\n")).unwrap();
    [("PODSSH_CF_ACCESS_CLIENT_ID_FILE", id), ("PODSSH_CF_ACCESS_CLIENT_SECRET_FILE", secret)]
}

/// The code, stdout and stderr of `child`, with `input` on its stdin, within
/// [`LIMIT`].
fn finish(mut child: Child, input: Vec<u8>, what: &str) -> (i32, Vec<u8>, String) {
    if let Some(mut stdin) = child.stdin.take() {
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = out.read_to_end(&mut bytes);
        bytes
    });
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err.read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code().unwrap_or(-1);
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("{what} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (code, reader.join().unwrap(), said.join().unwrap())
}

/// What `podssh ssh` in `cell` said with `extra` before its host: the code,
/// stdout and stderr.
fn ssh(s: &Session, cell: &Cell, extra: &[&str]) -> (i32, Vec<u8>, String) {
    let mut args = cell.args.clone();
    let host = args.len() - 1;
    for (i, word) in extra.iter().enumerate() {
        args.insert(host + i, word.to_string());
    }
    args.push("greet".into());
    let mut cmd = s.stand_in(&args, &at(cell, "--ca-file"));
    cmd.envs(credentials(s));
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    finish(child, Vec::new(), "podssh ssh")
}

/// An echo server on a free port of the loopback, for a node's TARGET.
fn echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut reader = stream.try_clone().unwrap();
                let mut writer = stream;
                let _ = std::io::copy(&mut reader, &mut writer);
            });
        }
    });
    port
}

#[test]
fn the_relay_behind_access_lets_in_the_host_that_was_named_alone() {
    let s = Session::start("access-relay");
    let Some(cell) = gated(&s) else { return };
    let (code, out, err) = ssh(&s, &cell, &["--access-host", "relay-a.test"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, GREETING.as_bytes());
    assert!(!err.contains(SECRET), "{err}");

    // The plants: no host named, and another host named; neither sends the
    // headers, and the gate refuses each.
    for extra in [&[][..], &["--access-host", "another.test"][..]] {
        let (code, _, err) = ssh(&s, &cell, extra);
        assert_eq!(code, 255, "{extra:?}: {err}");
        assert!(err.contains("403"), "{extra:?}: {err}");
        assert!(!err.contains(SECRET), "{extra:?}: {err}");
    }
}

#[test]
fn a_pair_s_road_and_operator_reach_the_relay_behind_access() {
    let s = Session::start("access-pair");
    let Some(cell) = gated(&s) else { return };
    let (relay, ca) = (at(&cell, "--relay-host"), at(&cell, "--ca-file"));
    let settings = s.home.join("access-settings");
    std::fs::write(&settings, "AccessHost relay-a.test\n").unwrap();
    let podssh = |words: &[&str], named: bool| {
        let mut args: Vec<String> = words.iter().map(|w| w.to_string()).collect();
        args.extend(["--relay-addr", "relay-a.test=127.0.0.1"].map(String::from));
        let mut cmd = s.stand_in(&args, &ca);
        cmd.envs(credentials(&s)).current_dir(&s.home);
        match named {
            true => cmd.env("PODSSH_SETTINGS", &settings),
            false => cmd.env("PODSSH_SETTINGS", "none"),
        };
        cmd
    };
    let pair = |named: bool| {
        let mut cmd = podssh(&["relay", "pair", "box", "--relay-host", &relay], named);
        let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        finish(child, Vec::new(), "podssh relay pair")
    };

    // The plant: no host named, so no header; the gate refuses the pair.
    let (code, _, err) = pair(false);
    assert_ne!(code, 0, "{err}");
    assert!(err.contains("403"), "{err}");
    assert!(!err.contains(SECRET), "{err}");

    let (code, _, err) = pair(true);
    assert_eq!(code, 0, "{err}");
    let target = format!("127.0.0.1:{}", echo());
    let mut node = podssh(&["node", "box", &target], true).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    // Online on the pair's road, not the Piping Server's: the probe of the
    // upgrade carries the headers too, so the gate does not refuse it.
    wait_for(&lines, "online").expect("the node is online behind the gate");
    let sent: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
    let mut operator = podssh(&["operator", "box"], true);
    let child = operator.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (code, out, err) = finish(child, sent.clone(), "podssh operator");
    assert_eq!(code, 0, "{err}");
    assert!(out == sent, "{} bytes came back: {err}", out.len());
    assert!(!err.contains(SECRET), "{err}");
}
