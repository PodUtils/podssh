//! `podssh serve --policy FILE` (T-838) against software that podssh did
//! not write: OpenSSH's client, with the server as its ProxyCommand. A
//! client policy that names one key exchange lets in a client that offers
//! it alone (OpenSSH adds its markers, which the policy does not judge),
//! and refuses OpenSSH's default offer before authentication: the client
//! hears the policy's name in a disconnect, and serve's line names the
//! mismatch. A policy of a server is refused at the start (78). Unix's, as
//! `serve_openssh.rs`; a host with no OpenSSH client says that the test did
//! not run.

#![cfg(unix)]

mod serve_kit;

use std::process::{Command, Stdio};

use serve_kit::{finish, have_openssh, keygen, openssh_with, podssh_env, scratch, Scratch, BIN};

/// A scratch home with the key `id` (listed) made, or None where this host
/// has no OpenSSH client.
fn home(tag: &str) -> Option<Scratch> {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    Some(dir)
}

/// A policy file in `home` whose lines follow its name and version; the
/// words that serve takes after its keys.
fn policy(home: &std::path::Path, file: &str, lines: &str) -> String {
    let path = home.join(file);
    std::fs::write(&path, format!("name = \"curve only\"\nversion = 1\n{lines}")).unwrap();
    format!(" --policy '{}'", path.display())
}

/// Whether this host's OpenSSH client offers `kex` (`ssh -Q kex`).
fn knows_kex(kex: &str) -> bool {
    let out = Command::new("ssh").args(["-Q", "kex"]).stdin(Stdio::null()).output();
    out.is_ok_and(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.trim() == kex))
}

#[test]
fn a_client_inside_the_policy_logs_in_and_one_outside_is_refused_before_authentication() {
    let Some(dir) = home("policy") else { return };
    if !knows_kex("curve25519-sha256") {
        eprintln!("did not run: this OpenSSH client has no curve25519-sha256");
        return;
    }
    let (home, key) = (&dir.0, dir.0.join("id"));
    let serve = policy(home, "clients.txt", "client policy = true\nkey exchanges = curve25519-sha256\n");

    // Inside: the one key exchange, with OpenSSH's markers beside it.
    let inside = ["-o", "KexAlgorithms=curve25519-sha256"];
    let (code, err) = finish(openssh_with(home, &key, "accept-new", &serve, &inside, &["echo IN"]));
    assert_eq!(code, Some(0), "a client inside the policy logs in: {err}");
    assert!(!err.contains("refused before authentication"), "{err}");

    // Outside: OpenSSH's default offer names more key exchanges.
    let (code, err) = finish(openssh_with(home, &key, "accept-new", &serve, &[], &["echo IN"]));
    assert_eq!(code, Some(255), "a client outside the policy is refused: {err}");
    assert!(err.contains("do not meet the policy \"curve only\""), "the client hears the policy: {err}");
    let line = err.lines().find(|l| l.contains("refused before authentication")).unwrap_or_default();
    assert!(line.starts_with("podssh serve: client with no address (a pipe)"), "serve's line: {err}");
    assert!(line.contains("key exchanges: expected curve25519-sha256, got "), "the mismatch is named: {err}");
    assert_eq!(line.matches("key exchanges").count(), 1, "the field is said once (T-869): {line}");
    assert!(!err.contains("Authenticated"), "no key logged in: {err}");
}

#[test]
fn a_policy_of_a_server_is_refused_at_the_start() {
    let Some(dir) = home("policy-server") else { return };
    let home = &dir.0;
    let serve = policy(home, "servers.txt", "key exchanges = curve25519-sha256\n");
    let script = format!("exec '{BIN}' serve --stdio --authorized-keys '{}'{serve}", home.join("id.pub").display());
    let mut cmd = Command::new("sh");
    cmd.args(["-c", &script]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    podssh_env(&mut cmd, home);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("judges a server") && err.contains("client policy = true"), "{err}");
}
