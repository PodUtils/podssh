//! `podssh serve --listen` (T-124) against software that podssh did not
//! write: OpenSSH's client logs in with `ssh -p PORT` to a loopback port
//! that serve bound (port 0, read back from serve's line), runs a command,
//! and gets its output and its exit status; a key that is not listed is
//! refused. Unix's, as `serve_openssh.rs`; a host with no OpenSSH client
//! says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serve_kit::{have_openssh, keygen, podssh_env, run, scratch, BIN};

const MARKER: &str = "LISTEN-MARKER";

/// serve on `127.0.0.1:0`, and the port that its line names.
fn listen(home: &Path) -> (Child, u16) {
    let mut cmd = Command::new(BIN);
    cmd.args(["serve", "--listen", "127.0.0.1:0", "--authorized-keys"])
        .arg(home.join("id.pub"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    podssh_env(&mut cmd, home);
    let mut child = cmd.spawn().expect("podssh serve starts");
    let err = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    // The reader goes on after the port, so that serve never blocks on a full pipe.
    std::thread::spawn(move || {
        for line in BufReader::new(err).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    let mut seen = Vec::new();
    while let Ok(line) = rx.recv_timeout(Duration::from_secs(30)) {
        if let Some(rest) = line.split("listening on 127.0.0.1:").nth(1) {
            let port = rest.split(':').next().unwrap().parse().expect("a port in serve's line");
            return (child, port);
        }
        seen.push(line);
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("serve named no port within 30 s: {seen:?}");
}

fn ssh(home: &Path, key: &Path, port: u16, remote: &[&str]) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=30"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()))
        .args(["-o", "StrictHostKeyChecking=accept-new", "-o", "HostKeyAlias=podssh-serve-listen"])
        .arg("-i")
        .arg(key)
        .args(["-p", &port.to_string(), "anyone@127.0.0.1"])
        .args(remote)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    podssh_env(&mut cmd, home);
    cmd
}

fn stop(mut child: Child) {
    // SIGTERM is serve's clean stop (T-117); a kill only where it did not end.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    for _ in 0..100 {
        if child.try_wait().ok().flatten().is_some() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("serve did not end within 10 s of SIGTERM");
}

#[test]
fn openssh_logs_in_on_the_port_and_an_unlisted_key_is_refused() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    let dir = scratch("listen-openssh");
    keygen(&dir.0, &dir.0.join("id"));
    keygen(&dir.0, &dir.0.join("other"));
    let (serve, port) = listen(&dir.0);

    let (code, out, err) = run(ssh(&dir.0, &dir.0.join("id"), port, &[&format!("echo {MARKER}; exit 7")]), None);
    let (code_other, _, err_other) = run(ssh(&dir.0, &dir.0.join("other"), port, &["true"]), None);
    stop(serve);

    assert_eq!(code, Some(7), "{err}");
    assert_eq!(String::from_utf8_lossy(&out).trim(), MARKER, "{err}");
    // OpenSSH's own code for a failed login, with its own words.
    assert_eq!(code_other, Some(255), "{err_other}");
    assert!(err_other.contains("Permission denied"), "{err_other}");
}
