//! `--policy FILE` (T-838) against OpenSSH's own server on this machine's
//! loopback: software that podssh did not write. A policy that names only
//! `curve25519-sha256` passes a server set to `KexAlgorithms
//! curve25519-sha256` and finds a mismatch (78) on one with its default
//! list; `podssh ssh` stops at that mismatch before any login; a port with
//! no server gives no reading (69); a field that podssh does not know is
//! refused before anything connects (78). A host with no sshd skips the
//! server's cases, and says so.

mod live_harness;

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The bound on each run of podssh.
const LIMIT: Duration = Duration::from_secs(60);

const ONLY_CURVE25519: &str = "# One key exchange.\nname = \"curve25519 only\"\nversion = 1\n\
key exchanges = curve25519-sha256\n";

struct Ran {
    code: Option<i32>,
    out: String,
    err: String,
}

/// `podssh VERB --direct -p PORT --policy POLICY ARGS u@127.0.0.1`, with
/// HOME in `dir`, no proxy and no ssh_config, within [`LIMIT`].
fn podssh(dir: &Path, verb: &str, port: u16, policy: &Path, args: &[&str]) -> Ran {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args([verb, "--direct", "-p", &port.to_string(), "--policy"]).arg(policy);
    cmd.args(["-o", "BatchMode=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=no", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.arg("u@127.0.0.1").args(args);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir).env("USERPROFILE", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("podssh runs");
    let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stdout.read_to_string(&mut text);
        text
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh {verb} still ran after {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Ran { code: status.code(), out: out.join().unwrap(), err: err.join().unwrap() }
}

fn verdict(ran: &Ran) -> Value {
    serde_json::from_str(ran.out.trim())
        .unwrap_or_else(|e| panic!("stdout is no verdict ({e}): {}{}", ran.out, ran.err))
}

/// The server, with `more` at the end of its configuration; `None` where
/// this host runs none, said once.
fn sshd(dir: &Path, more: &str) -> Option<live_harness::sshd::Sshd> {
    let authorized = dir.join("authorized_keys");
    std::fs::write(&authorized, "").unwrap();
    match live_harness::sshd::start_with(dir, &authorized, more) {
        Ok(server) => Some(server),
        Err(why) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

fn policy_file(dir: &Path, text: &str) -> std::path::PathBuf {
    let file = dir.join("policy.txt");
    std::fs::write(&file, text).unwrap();
    file
}

#[test]
fn health_judges_the_server_s_key_exchanges_with_no_login() {
    let dir = live_harness::scratch("policy-health");
    let policy = policy_file(&dir, ONLY_CURVE25519);
    let Some(set) = sshd(&dir, "KexAlgorithms curve25519-sha256\n") else { return };
    let ran = podssh(&dir, "health", set.port, &policy, &[]);
    let doc = verdict(&ran);
    assert_eq!((ran.code, doc["verdict"].as_str()), (Some(0), Some("pass")), "{doc} {}", ran.err);
    assert_eq!(doc["policy"], "curve25519 only");
    drop(set);

    let other = live_harness::scratch("policy-health-default");
    let Some(default) = sshd(&other, "") else { return };
    let ran = podssh(&other, "health", default.port, &policy, &[]);
    let doc = verdict(&ran);
    assert_eq!((ran.code, doc["verdict"].as_str()), (Some(78), Some("mismatch")), "{doc} {}", ran.err);
    let mismatch = &doc["mismatches"][0];
    assert_eq!(mismatch["field"], "key exchanges", "{doc}");
    assert!(mismatch["actual"].as_array().is_some_and(|a| a.len() > 1), "the default list came: {doc}");
}

#[test]
fn ssh_stops_at_a_mismatch_before_any_login() {
    let dir = live_harness::scratch("policy-ssh");
    let policy = policy_file(&dir, ONLY_CURVE25519);
    let Some(server) = sshd(&dir, "") else { return };
    let ran = podssh(&dir, "ssh", server.port, &policy, &["true"]);
    let doc = verdict(&ran);
    assert_eq!((ran.code, doc["exit"].as_i64()), (Some(78), Some(78)), "{doc} {}", ran.err);
    assert!(ran.err.contains("refusing to log in"), "{}", ran.err);
    // The login never began: BatchMode with no key would end it with 255.
    assert!(!ran.err.contains("Permission denied"), "{}", ran.err);
}

#[test]
fn a_port_with_no_server_gives_no_reading() {
    let dir = live_harness::scratch("policy-none");
    let policy = policy_file(&dir, ONLY_CURVE25519);
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let ran = podssh(&dir, "health", port, &policy, &[]);
    let doc = verdict(&ran);
    assert_eq!((ran.code, doc["verdict"].as_str()), (Some(69), Some("no reading")), "{doc} {}", ran.err);
    assert!(doc["why"].as_str().is_some_and(|w| !w.is_empty()), "{doc}");
}

#[test]
fn a_field_that_podssh_does_not_know_is_refused_before_anything_connects() {
    let dir = live_harness::scratch("policy-unknown");
    let policy = policy_file(&dir, "name = \"x\"\nversion = 1\nminimum_strength = high\n");
    for verb in ["health", "ssh"] {
        // Port 9 of the loopback: nothing would answer, and nothing is asked.
        let ran = podssh(&dir, verb, 9, &policy, &[]);
        assert_eq!(ran.code, Some(78), "{verb}: {}", ran.err);
        assert!(ran.err.contains("line 3") && ran.err.contains("minimum_strength"), "{verb}: {}", ran.err);
        assert!(ran.out.is_empty(), "{verb}: {}", ran.out);
    }
}
