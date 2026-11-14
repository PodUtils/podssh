//! `podssh serve NAME` (T-107, Approach item 5): the node of the pair NAME
//! whose sessions podssh's own SSH server answers in the process, with no
//! TARGET and no listener. Through the stand-in relay of the reverse road
//! (Python and openssl), `podssh ssh node://` logs in to it with the
//! authorized key, runs a command whose exit comes back, and is refused with
//! another key; `--stdio` with NAME is 64. A host with neither Python nor
//! openssl says that the test did not run. Unix's.

#![cfg(unix)]

mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use std::process::Stdio;

use throughput_harness::{lines_of, wait_for, Cell, Session};

#[test]
fn an_operator_logs_in_to_serve_name_through_the_relay_and_its_exit_comes_back() {
    let s = Session::start("serve-node");
    let cell = match Cell::fake_relay_mode(&s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1");
    let words = |w: &[&str]| w.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let out = s
        .stand_in(&words(&["relay", "pair", "lab", "--relay-host", &relay]), &ca)
        .env(pins.0, pins.1)
        .output()
        .unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));

    // The session's key logs in; the authorized key is its public half.
    let key = s.home.join("host_key");
    let public = std::fs::read_to_string(key.with_extension("pub")).unwrap();
    let serve = words(&["serve", "lab", "--authorized-key", public.trim(), "--shell", "/bin/sh"]);
    let mut node =
        s.stand_in(&serve, &ca).env(pins.0, pins.1).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    s.keep(node);
    let first = wait_for(&lines, "serving").expect("serve's node starts");
    assert!(first.contains("podssh serve, in this process"), "{first}");
    wait_for(&lines, "online").expect("the node is online");

    let user = std::env::var("USER").unwrap_or_else(|_| "tester".into());
    let login = |identity: &std::path::Path| {
        let mut args = vec!["ssh".to_string(), "-i".into(), identity.display().to_string()];
        args.extend(["-o".into(), "IdentitiesOnly=yes".into()]);
        args.extend(s.common());
        args.extend([format!("node://{user}@lab"), "echo SERVED-$((40+2)); exit 3".into()]);
        s.stand_in(&args, &ca).env(pins.0, pins.1).stdin(Stdio::null()).output().unwrap()
    };
    let out = login(&key);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(3), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "SERVED-42\n", "{err}");
    assert_eq!(s.connections.load(std::sync::atomic::Ordering::SeqCst), 0, "no TARGET is dialled: {err}");

    // Another key is refused by serve, as sshd refuses it.
    let other = s.home.join("other_key");
    let made = s
        .command(&words(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &other.display().to_string()]))
        .output()
        .unwrap();
    assert!(made.status.success());
    let out = login(&other);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(255), "{err}");
    assert!(err.contains("Permission denied") || err.contains("publickey"), "{err}");
    s.revoke_later("lab");
}

#[test]
fn stdio_and_name_together_are_a_usage_error() {
    let s = Session::start("serve-node-usage");
    let args = ["serve", "--stdio", "lab", "--authorized-key", "ssh-ed25519 AAAA x"].map(String::from);
    let out = s.command(&args).stdin(Stdio::null()).output().unwrap();
    assert_eq!(out.status.code(), Some(64), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--stdio and NAME"));
}
