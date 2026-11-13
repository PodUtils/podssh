//! `podssh serve --stdio` (T-107) against software that podssh did not
//! write: OpenSSH's client, with the server as its ProxyCommand and nothing
//! listening. An authorized key logs in and `-N` stays up; another key gets
//! `Permission denied (publickey)`; a second start keeps the host key, which
//! the first one made in the cache with mode 0600, so a strict client takes
//! it, and its command runs (T-108, whole in `serve_openssh.rs`). With no
//! key at all, the start is refused with 78. Unix's: OpenSSH for Windows takes no
//! command line of a shell for a ProxyCommand. A host with no OpenSSH client
//! says that the test did not run.

#![cfg(unix)]

mod serve_kit;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serve_kit::{finish, have_openssh, keygen, openssh, podssh_env, scratch, BIN, LIMIT};

/// Kills a child that a test left running.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// `ssh -N` that logs in and stays: the lines of its stderr until one says
/// that it authenticated, then still running a moment later.
fn stays_up(cmd: Command) -> String {
    let mut cmd = cmd;
    let mut child = Killed(cmd.spawn().expect("ssh runs"));
    let pipe = child.0.stderr.take().expect("stderr");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + LIMIT;
    let mut seen = String::new();
    while !seen.contains("Authenticated to") {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => {
                seen.push_str(&line);
                seen.push('\n');
            }
            Err(_) => panic!("no login within {LIMIT:?}: {seen}"),
        }
    }
    std::thread::sleep(Duration::from_secs(2));
    assert!(child.0.try_wait().expect("wait").is_none(), "ssh -N ended after its login: {seen}");
    #[cfg(target_os = "linux")]
    no_capability_in_the_server(child.0.id(), &seen);
    seen
}

/// After the start, each thread of the server, ssh's ProxyCommand, holds
/// no capability (T-698): as root too, where the drop has work to do.
#[cfg(target_os = "linux")]
fn no_capability_in_the_server(ssh: u32, seen: &str) {
    // ssh's children, by the parent that each process names.
    let parent = format!("PPid:\t{ssh}");
    let children: Vec<String> = std::fs::read_dir("/proc")
        .map(|dir| dir.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>())
        .unwrap_or_default()
        .into_iter()
        .filter(|pid| pid.chars().all(|c| c.is_ascii_digit()))
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/status")).is_ok_and(|s| s.lines().any(|l| l == parent))
        })
        .collect();
    let mut servers = 0;
    for pid in &children {
        let is_podssh = std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|exe| exe.ends_with("podssh"));
        let Ok(tasks) = std::fs::read_dir(format!("/proc/{pid}/task")) else { continue };
        if !is_podssh {
            continue;
        }
        servers += 1;
        for task in tasks.flatten() {
            let status = std::fs::read_to_string(task.path().join("status")).unwrap_or_default();
            for line in status.lines().filter(|l| ["CapInh:", "CapPrm:", "CapEff:"].iter().any(|c| l.starts_with(c))) {
                let mask = line.split_whitespace().nth(1).unwrap_or("");
                assert!(mask.chars().all(|c| c == '0'), "{pid}/{:?}: {line}: {seen}", task.file_name());
            }
        }
    }
    assert_eq!(servers, 1, "ssh's ProxyCommand is podssh serve: {children:?}: {seen}");
}

#[test]
fn openssh_logs_in_with_an_authorized_key_and_keeps_the_host_key() {
    if !have_openssh() {
        eprintln!("did not run: no OpenSSH client here");
        return;
    }
    let dir = scratch("openssh");
    let home = dir.0.clone();
    let (key, other) = (home.join("id"), home.join("other"));
    keygen(&home, &key);
    keygen(&home, &other);

    // The first start makes the host key, and the listed key logs in.
    let seen = stays_up(openssh(&home, &key, "accept-new", &["-N"]));
    assert!(seen.contains("podssh serve: host key SHA256:"), "{seen}");
    let host_key = home.join("cache").join("serve_host_ed25519_key");
    let mode =
        std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(&host_key).expect("the host key").permissions());
    assert_eq!(mode & 0o777, 0o600, "the host key's mode");

    // Another key is refused, by OpenSSH's words.
    let (code, err) = finish(openssh(&home, &other, "accept-new", &["-N"]));
    assert_eq!(code, Some(255), "{err}");
    assert!(err.contains("Permission denied (publickey)"), "{err}");

    // A later start keeps the host key: a strict client takes it, and its
    // command runs (T-108).
    let (code, err) = finish(openssh(&home, &key, "yes", &["true"]));
    assert!(!err.contains("Host key verification failed") && !err.contains("CHANGED"), "{err}");
    assert!(err.contains("Authenticated to"), "{err}");
    assert!(!err.contains("exec request failed"), "{err}");
    assert_eq!(code, Some(0), "{err}");
}

#[test]
fn no_authorized_key_refuses_the_start() {
    let dir = scratch("nokey");
    let mut cmd = Command::new(BIN);
    cmd.args(["serve", "--stdio"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    podssh_env(&mut cmd, &dir.0);
    cmd.env("HOME", "/nonexistent");
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("no authorized key"), "{err}");
    // Nothing was made: a start that cannot serve leaves no host key.
    assert!(!dir.0.join("cache").join("serve_host_ed25519_key").exists());
}

#[test]
fn serve_without_stdio_is_a_usage_error() {
    let dir = scratch("usage");
    let mut cmd = Command::new(BIN);
    cmd.args(["serve"]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    podssh_env(&mut cmd, &dir.0);
    let (code, err) = finish(cmd);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--stdio"), "{err}");
}
