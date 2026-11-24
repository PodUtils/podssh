//! The one-time code of `podssh serve --stdio --totp FILE` (T-115) against
//! software that podssh did not write: OpenSSH's client, with serve as its
//! ProxyCommand, and the code from `SSH_ASKPASS`, a script that runs
//! `oathtool --totp -b` on the secret that `podssh serve --totp-new` made.
//! The login works; the same code on a second login is refused; a wrong
//! code is refused, and serve's stderr says why. Unix's; a host with no
//! OpenSSH client or no `oathtool` says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serve_kit::{finish, have_openssh, keygen, podssh_env, scratch, serve_command, Scratch, BIN};

fn have_oathtool() -> bool {
    Command::new("oathtool").arg("--version").stdin(Stdio::null()).output().is_ok_and(|o| o.status.success())
}

/// A scratch home with a key and a secret, or None where a tool is missing.
fn home(tag: &str) -> Option<Scratch> {
    if !have_openssh() || !have_oathtool() {
        eprintln!("did not run: no OpenSSH client or no oathtool here");
        return None;
    }
    let dir = scratch(tag);
    keygen(&dir.0, &dir.0.join("id"));
    let out = Command::new(BIN).args(["serve", "--totp-new"]).arg(dir.0.join("totp")).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), dir.0.join("totp").display().to_string());
    Some(dir)
}

/// An askpass script at `path` that prints `body`'s output.
fn askpass(path: &Path, body: &str) {
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// OpenSSH with the key, then keyboard-interactive answered by `ask`, never
/// by a terminal; `ssh` takes no BatchMode, which would skip the prompt.
fn ssh(home: &Path, ask: &Path, remote: &str) -> Command {
    let proxy = serve_command(home, &format!(" --totp '{}'", home.join("totp").display()));
    let mut cmd = Command::new("ssh");
    cmd.args(["-F", "/dev/null", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=VERBOSE"])
        .args(["-o", "PreferredAuthentications=publickey,keyboard-interactive"])
        .args(["-o", "NumberOfPasswordPrompts=1", "-o", "StrictHostKeyChecking=accept-new"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()))
        .args(["-o", "HostKeyAlias=podssh-serve-test", "-o", "ConnectTimeout=30"])
        .arg("-i")
        .arg(home.join("id"))
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .arg("anyone@box")
        .arg(remote)
        .env("SSH_ASKPASS", ask)
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", ":0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    podssh_env(&mut cmd, home);
    cmd
}

/// Wait until the step of 30 s has 20 s left, so that two logins in a row
/// get one code from oathtool.
fn early_in_a_step() {
    let into = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() % 30;
    if into > 10 {
        std::thread::sleep(Duration::from_secs(31 - into));
    }
}

#[test]
fn the_code_logs_in_once_and_a_wrong_one_is_refused() {
    let Some(dir) = home("totp") else { return };
    let ask = dir.0.join("ask");
    askpass(&ask, &format!("exec oathtool --totp -b \"$(cat '{}')\"", dir.0.join("totp").display()));
    early_in_a_step();
    let (code, err) = finish(ssh(&dir.0, &ask, "exit 4"));
    assert_eq!(code, Some(4), "the key and the code log in: {err}");
    let (code, err) = finish(ssh(&dir.0, &ask, "exit 4"));
    assert_eq!(code, Some(255), "the same code again: {err}");
    assert!(err.contains("used already"), "serve says why: {err}");
    let wrong = dir.0.join("wrong");
    askpass(&wrong, "echo 000000");
    // A key's wait after its failure.
    std::thread::sleep(Duration::from_secs(2));
    let (code, err) = finish(ssh(&dir.0, &wrong, "exit 4"));
    assert_eq!(code, Some(255), "a wrong code: {err}");
    assert!(err.contains("one-time code refused"), "{err}");
}
