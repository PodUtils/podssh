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
                // A graceful end: the FIN after the last byte, then the
                // node's close, as Windows gives a close with no shutdown
                // to its peer as a reset, which the operator reads as a cut
                // (69) (T-753).
                let _ = writer.shutdown(std::net::Shutdown::Write);
                let _ = reader.set_read_timeout(Some(std::time::Duration::from_secs(5)));
                let _ = std::io::copy(&mut reader, &mut std::io::sink());
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

/// Write `id` and `secret` into files tagged `tag` in `s.home` and return the
/// `_FILE` environment bindings.
fn credentials_with(s: &Session, tag: &str, id: &str, secret: &str) -> [(&'static str, PathBuf); 2] {
    let (id_path, secret_path) = (s.home.join(format!("access-id-{tag}")), s.home.join(format!("access-secret-{tag}")));
    std::fs::write(&id_path, format!("{id}\n")).unwrap();
    std::fs::write(&secret_path, format!("{secret}\n")).unwrap();
    [("PODSSH_CF_ACCESS_CLIENT_ID_FILE", id_path), ("PODSSH_CF_ACCESS_CLIENT_SECRET_FILE", secret_path)]
}

/// Write a synthetic pair for `relay_host:port` expiring at `expires_ms` into a
/// private file under `s.home` for `--pair-file`.
fn synthetic_pair_file(s: &Session, label: &str, relay_host: &str, port: u16, expires_ms: i64) -> String {
    let name = format!("p-{}", "0".repeat(32));
    let token = "a".repeat(64);
    let body = format!(
        r#"{{"name":"{name}","node_token":"{token}","connect_token":"{token}","stop_token":"{token}","expires":{expires_ms}}}"#
    );
    let relay = podssh_relay::relay::Relay { host: relay_host.into(), port };
    let pair = podssh_relay::pair::parse(&relay, body.as_bytes(), expires_ms - 3_600_000).unwrap();
    let dir = s.home.join("synthetic-pairs");
    podssh_relay::cache::private_dir(&dir).unwrap();
    podssh_relay::pair::store_in_first(&[dir], label, &pair).unwrap().to_string_lossy().into_owned()
}

/// T-718: when Cloudflare Access refuses a node (bad/revoked service token or
/// missing `--access-host`), `podssh node` stays off the Piping Server fallback,
/// exits 77 with a true line naming Access and its variables (never a secret),
/// while a stopped/unknown pair with valid Access credentials still reports the
/// relay's pair refusal, an expired pair stays expired, and `--print-unit`
/// prevents systemd restarts on 77 when `--access-host` is set.
#[test]
fn a_node_refused_by_access_exits_77_and_names_the_variables_not_the_secret() {
    const WRONG_SECRET: &str = "revoked-secret-of-the-stand-in-9b2d";

    let s = Session::start("access-node-exit");
    let Some(cell) = gated(&s) else { return };
    let (relay, ca) = (at(&cell, "--relay-host"), at(&cell, "--ca-file"));
    let port: u16 = relay.rsplit_once(':').unwrap().1.parse().unwrap();
    let settings = s.home.join("access-settings");
    std::fs::write(&settings, "AccessHost relay-a.test\n").unwrap();

    // Make a live, unexpired pair through the Access gate with valid credentials.
    let mut make = s.stand_in(
        &["relay", "pair", "box", "--relay-host", &relay, "--relay-addr", "relay-a.test=127.0.0.1"].map(String::from),
        &ca,
    );
    make.envs(credentials(&s)).env("PODSSH_SETTINGS", &settings);
    let child = make.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (code, _, err) = finish(child, Vec::new(), "podssh relay pair");
    assert_eq!(code, 0, "{err}");

    let target = format!("127.0.0.1:{}", echo());
    let run_node = |extra: &[&str], creds: Option<[(&'static str, PathBuf); 2]>| {
        let mut args: Vec<String> = vec!["node".into(), "box".into(), target.clone()];
        args.extend(extra.iter().map(|w| w.to_string()));
        args.extend(["--relay-addr".into(), "relay-a.test=127.0.0.1".into()]);
        let mut cmd = s.stand_in(&args, &ca);
        cmd.env("PODSSH_SETTINGS", "none").env_remove("PODSSH_PIPING");
        if let Some(creds) = creds {
            cmd.envs(creds);
        }
        let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        finish(child, Vec::new(), "podssh node")
    };

    // 1. Named --access-host with bad/revoked Access credentials: exits 77,
    //    names Cloudflare Access and the _FILE variables, never falls back to
    //    Piping Server, never blames the pair, never prints any secret.
    let bad = credentials_with(&s, "bad", ID, WRONG_SECRET);
    let (code, _, err) = run_node(&["--access-host", "relay-a.test"], Some(bad));
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("Cloudflare Access") && err.contains("403"), "{err}");
    assert!(
        err.contains("PODSSH_CF_ACCESS_CLIENT_ID_FILE") && err.contains("PODSSH_CF_ACCESS_CLIENT_SECRET_FILE"),
        "{err}"
    );
    assert!(!err.contains("the relay refused the pair"), "must not blame the pair: {err}");
    assert!(!err.contains("ppng.io"), "must not fall back to Piping Server: {err}");
    assert!(!err.contains(WRONG_SECRET) && !err.contains(SECRET), "must never leak a secret: {err}");

    // 2. Missing --access-host against the Access-gated relay: exits 77,
    //    names Cloudflare Access and --access-host, never falls back to Piping.
    let (code, _, err) = run_node(&[], None);
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("Cloudflare Access") && err.contains("--access-host"), "{err}");
    assert!(!err.contains("the relay refused the pair"), "{err}");
    assert!(!err.contains("ppng.io"), "{err}");

    // 3. Control: valid Access credentials with an unknown/stopped pair -> the
    //    gate lets it through and the relay returns `403 reverse: forbidden`,
    //    so the node blames the pair (77), not Cloudflare Access.
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let unknown_file = synthetic_pair_file(&s, "stopped", "relay-a.test", port, now_ms + 3_600_000);
    let (code, _, err) =
        run_node(&["--pair-file", &unknown_file, "--access-host", "relay-a.test"], Some(credentials(&s)));
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("the relay refused the pair (403)"), "{err}");
    assert!(!err.contains("Cloudflare Access"), "relay pair refusal must not blame Access: {err}");
    assert!(!err.contains(SECRET), "{err}");

    // 4. Control: expired pair stays an expired-pair 77 and never blames Access.
    let expired_file = synthetic_pair_file(&s, "expired", "relay-a.test", port, now_ms - 60_000);
    let (code, _, err) =
        run_node(&["--pair-file", &expired_file, "--access-host", "relay-a.test"], Some(credentials(&s)));
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("expired") && !err.contains("Cloudflare Access"), "{err}");

    // 5. Operator refused by Access: exits 77, names Access and _FILE vars, no secret.
    let mut op = s.stand_in(
        &["operator", "box", "--access-host", "relay-a.test", "--relay-addr", "relay-a.test=127.0.0.1"]
            .map(String::from),
        &ca,
    );
    op.envs(credentials_with(&s, "op-bad", ID, WRONG_SECRET)).env("PODSSH_SETTINGS", "none");
    let child = op.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (code, _, err) = finish(child, Vec::new(), "podssh operator bad access");
    assert_eq!(code, 77, "{err}");
    assert!(err.contains("Cloudflare Access") && err.contains("PODSSH_CF_ACCESS_CLIENT_SECRET_FILE"), "{err}");
    assert!(!err.contains(WRONG_SECRET), "{err}");

    // 6. --print-unit prevents systemd restarts on 77 with --access-host, and
    //    keeps 64 78 without it.
    let (code, out, err) = run_node(&["--access-host", "relay-a.test", "--print-unit"], Some(credentials(&s)));
    assert_eq!(code, 0, "{err}");
    let unit_with = String::from_utf8_lossy(&out);
    assert!(unit_with.contains("RestartPreventExitStatus=64 77 78\n"), "{unit_with}");

    let (code, out, err) = run_node(&["--print-unit"], None);
    assert_eq!(code, 0, "{err}");
    let unit_plain = String::from_utf8_lossy(&out);
    assert!(unit_plain.contains("RestartPreventExitStatus=64 78\n"), "{unit_plain}");
}
