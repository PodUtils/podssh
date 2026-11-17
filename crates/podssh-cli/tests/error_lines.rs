//! One cause, one line (T-809, after podnet's QA round, PodUtils/podnet#649):
//! `podssh ssh` through podssh's own relay role to a port where nothing
//! listens ends with 255 within its limit, and says the cause once. The
//! layer's road says that the relay could not reach the target; the SSH
//! client's own words of the closed connection ("the connection closed
//! unexpectedly") are no second line. The planted defect: both lines, as
//! before. It says that it did not run where this host has no openssl for
//! the role's certificate.

mod held_port;
mod ssh_harness;
mod throughput_harness;

use std::io::Read;
use std::process::Stdio;
use std::time::{Duration, Instant};

use throughput_harness::{Cell, Session};

const LIMIT: Duration = Duration::from_secs(60);

#[test]
fn a_refused_target_is_one_line_and_255() {
    let s = Session::start("error-lines");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let mut args = cell.args.clone();
    let port = args.iter().position(|a| a == "-p").unwrap() + 1;
    let (closed, _held) = held_port::refusing();
    args[port] = closed.to_string();
    args.push("true".into());
    let mut child =
        s.stand_in(&args, &ca).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            panic!("podssh ssh to a closed port did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let err = said.join().unwrap();
    assert_eq!(code, Some(255), "{err}");
    let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 1, "one cause, one line: {err}");
    assert!(lines[0].contains("could not reach") && lines[0].contains("refused"), "{err}");
}

/// One cause, one line, for each failure that needs no relay (T-817): one
/// table, one rule. Each row: its words, the stdin, the code, and a text
/// that the line names once. The planted defect of T-817, a dial's cause
/// with its target said twice, fails the first row.
#[test]
fn each_failure_with_no_relay_is_one_line_with_its_code() {
    let (closed, _held) = held_port::refusing();
    let closed = closed.to_string();
    let target = format!("127.0.0.1:{closed}");
    let rows: Vec<(Vec<String>, &str, i32, String)> = vec![
        (vec!["pipe".into(), "-".into(), format!("tcp:{target}")], "", 69, target.clone()),
        (
            vec!["config".into(), "import".into(), "ansible".into(), "-".into()],
            "[g]\nh1 ansible_port=notnum\n",
            65,
            "ansible_port=notnum".into(),
        ),
        (vec!["update".into(), "--check".into()], "", 69, "PODSSH_OFFLINE".into()),
    ];
    let home = std::env::temp_dir().join(format!("podssh-error-lines-{}-{closed}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    for (words, input, code, named) in rows {
        let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(&words)
            .env("HOME", &home)
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env("PODSSH_OFFLINE", if words[0] == "update" { "1" } else { "" })
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().unwrap();
            let _ = stdin.write_all(input.as_bytes());
        }
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > LIMIT {
                let _ = child.kill();
                panic!("{words:?} did not end within {LIMIT:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let out = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(out.status.code(), Some(code), "{words:?}: {err}");
        assert_eq!(lines.len(), 1, "{words:?}: one line: {err}");
        assert_eq!(lines[0].matches(named.as_str()).count(), 1, "{words:?}: {named} named once: {err}");
    }
    let _ = std::fs::remove_dir_all(&home);
}

/// `ssh node://` to a pair whose node is not online (T-817): 255 and the
/// node's cause once, with no line of the SSH client's own closed
/// connection before it.
#[test]
fn a_node_that_is_not_online_is_one_line() {
    let s = Session::start("error-lines-node");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, addr, ca) = (at("--relay-host"), at("--relay-addr"), at("--ca-file"));
    let off = |cmd: &mut std::process::Command| {
        for name in ["PODSSH_LAST_RESORT", "PODSSH_TRANSIT", "PODSSH_PIPING"] {
            cmd.env(name, "no");
        }
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let mut pair =
        s.stand_in(&words(&["relay", "pair", "lines-off", "--relay-host", &relay, "--relay-addr", &addr]), &ca);
    off(&mut pair);
    let paired = pair.stdin(Stdio::null()).output().unwrap();
    assert_eq!(paired.status.code(), Some(0), "{}", String::from_utf8_lossy(&paired.stderr));
    let mut args = words(&["ssh", "--relay-addr", &addr]);
    args.extend(s.common());
    args.extend(words(&["node://tester@lines-off", "true"]));
    let mut ssh = s.stand_in(&args, &ca);
    off(&mut ssh);
    let out = ssh.stdin(Stdio::null()).output().unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> =
        err.lines().filter(|l| !l.trim().is_empty() && !l.contains("a new key for this client")).collect();
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert_eq!(lines.len(), 1, "one cause, one line: {err}");
    assert!(lines[0].contains("node unavailable"), "{err}");
}

/// A relay that the user named, its layer's offer kept from a run before,
/// down now (T-817): 255 and the connect's cause once, at once, with no line
/// that the session goes on and no wait for a second road to the same dead
/// host.
#[test]
#[cfg(unix)]
fn a_named_relay_that_is_down_is_one_line() {
    let s = Session::start("error-lines-down");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let mut args = cell.args.clone();
    args.push("true".into());
    let run = || {
        let out = s.stand_in(&args, &ca).env_remove("PODSSH_RELAY_LAYER").stdin(Stdio::null()).output().unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned())
    };
    let (code, err) = run();
    assert_eq!(code, Some(0), "the run that keeps the offer: {err}");
    for pid in s.pids() {
        let _ = std::process::Command::new("kill").arg(pid.to_string()).status();
    }
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    let (code, err) = run();
    let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(code, Some(255), "{err}");
    assert_eq!(lines.len(), 1, "one cause, one line: {err}");
    assert!(lines[0].contains("could not connect"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10), "{:?}: {err}", started.elapsed());
}

/// A target that takes the connection and closes it with no byte, as a
/// proxy on the way does with a target that it cannot reach (T-821): 255,
/// and one line that says so, not the closed stream's words alone.
#[test]
fn a_target_taken_and_closed_with_no_byte_is_said_so() {
    let s = Session::start("error-lines-taken");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let taker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taker.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in taker.incoming().flatten() {
            std::thread::sleep(Duration::from_millis(500));
            drop(stream);
        }
    });
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let mut args = cell.args.clone();
    let at = args.iter().position(|a| a == "-p").unwrap() + 1;
    args[at] = port.to_string();
    args.push("true".into());
    for layer in ["no", "yes"] {
        let out = s.stand_in(&args, &ca).env("PODSSH_RELAY_LAYER", layer).stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(out.status.code(), Some(255), "layer {layer}: {err}");
        assert_eq!(lines.len(), 1, "layer {layer}: one cause, one line: {err}");
        if layer == "yes" {
            assert!(lines[0].contains("taken and then closed"), "what happened, not the closed stream: {err}");
        }
    }
}

/// One cause, one line, for each verb that runs a session on the layer's
/// road (T-824): a refused target says the relay's cause once in `each`,
/// `scp`, `sftp` and `health`, with no line of the client's closed
/// connection after it. One table, one rule; the planted defect, the road
/// that says its cause where the verb claimed it, fails each row.
#[test]
fn a_refused_target_is_one_line_in_each_verb() {
    let s = Session::start("error-lines-verbs");
    let cell = match Cell::podssh_relay(&s, "podssh's relay role", &["--allow-private"]) {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let ca = cell.args.iter().position(|a| a == "--ca-file").map(|i| cell.args[i + 1].clone()).unwrap();
    let (closed, _held) = held_port::refusing();
    let closed = closed.to_string();
    // The cell's flags with the closed port, and its target last.
    let (target, flags) = cell.args[1..].split_last().unwrap();
    let mut flags = flags.to_vec();
    let at = flags.iter().position(|a| a == "-p").unwrap() + 1;
    flags[at] = closed.clone();
    let upper: Vec<String> = flags.iter().map(|a| if a == "-p" { "-P".to_string() } else { a.clone() }).collect();
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let rows: [(&str, Vec<String>, Vec<String>); 4] = [
        ("each", flags.clone(), words(&[target, "--", "true"])),
        ("scp", upper.clone(), vec![format!("{target}:x"), s.home.join("x").display().to_string()]),
        ("sftp", upper, vec!["-b".into(), "-".into(), target.clone()]),
        ("health", flags.clone(), vec![target.clone()]),
    ];
    for (verb, flags, tail) in rows {
        let mut args = vec![verb.to_string()];
        if verb == "scp" {
            args.extend(words(&["--timeout", "30s"]));
        }
        args.extend(flags);
        args.extend(tail);
        let out = s.stand_in(&args, &ca).env("PODSSH_RELAY_LAYER", "yes").stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        // `each`'s summary of its hosts is its own, after the cause.
        let lines: Vec<&str> = err.lines().filter(|l| !l.trim().is_empty() && !l.starts_with("podssh each:")).collect();
        assert_ne!(out.status.code(), Some(0), "{verb}: {err}");
        assert_eq!(lines.len(), 1, "{verb}: one cause, one line: {err}");
        assert!(lines[0].contains("could not reach") && lines[0].contains(&closed), "{verb}: {err}");
        for echo in ["broken pipe", "closed unexpectedly", "taken and then closed"] {
            assert!(!err.contains(echo), "{verb}: the client's echo: {err}");
        }
    }
}
