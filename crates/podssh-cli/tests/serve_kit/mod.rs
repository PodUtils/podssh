//! What the tests of `podssh serve --stdio` against OpenSSH's client share
//! (`serve_stdio.rs`, T-107; `serve_openssh.rs`, T-108 and T-222): a scratch
//! home, podssh's environment there, a throwaway key, OpenSSH's `ssh` with
//! the server as its ProxyCommand, and a run of it within a limit.

// Each test file uses a part of the kit.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_podssh");
pub const LIMIT: Duration = Duration::from_secs(60);

/// A scratch directory, removed at the end of the test.
pub struct Scratch(pub PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn scratch(tag: &str) -> Scratch {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-serve-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

/// podssh's environment: its home and its cache in the scratch directory.
pub fn podssh_env(cmd: &mut Command, home: &Path) {
    cmd.env("HOME", home).env("PODSSH_CACHE_DIR", home.join("cache")).env("XDG_CACHE_HOME", home.join("cache"));
    cmd.env_remove("XDG_RUNTIME_DIR");
}

pub fn have_openssh() -> bool {
    Command::new("ssh").arg("-V").stdin(Stdio::null()).output().is_ok_and(|o| o.status.success())
}

/// A throwaway Ed25519 key at `path`, made by podssh's own keygen.
pub fn keygen(home: &Path, path: &Path) {
    let mut cmd = Command::new(BIN);
    cmd.args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"]).arg(path).stdin(Stdio::null());
    podssh_env(&mut cmd, home);
    let out = cmd.output().expect("podssh keygen runs");
    assert!(out.status.success(), "podssh keygen: {}", String::from_utf8_lossy(&out.stderr));
}

/// OpenSSH's client with `podssh serve --stdio SERVE...` as its
/// ProxyCommand, logging in with `key`, the host key kept in the scratch
/// `known_hosts`; `ssh` takes `options` before the destination and `remote`
/// after it.
pub fn openssh_with(home: &Path, key: &Path, strict: &str, serve: &str, options: &[&str], remote: &[&str]) -> Command {
    let proxy = format!("'{BIN}' serve --stdio --authorized-keys '{}'{serve}", home.join("id.pub").display());
    let mut cmd = Command::new("ssh");
    cmd.args(["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "LogLevel=VERBOSE"])
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", home.join("known_hosts").display()))
        .arg("-o")
        .arg(format!("StrictHostKeyChecking={strict}"))
        .args(["-o", "HostKeyAlias=podssh-serve-test", "-o", "ConnectTimeout=30"])
        .arg("-i")
        .arg(key)
        .arg("-o")
        .arg(format!("ProxyCommand={proxy}"))
        .args(options)
        .arg("anyone@box")
        .args(remote)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // The ProxyCommand's variables are podssh's: its home and its cache.
    podssh_env(&mut cmd, home);
    cmd
}

/// [`openssh_with`] with serve's defaults and no option.
pub fn openssh(home: &Path, key: &Path, strict: &str, remote: &[&str]) -> Command {
    openssh_with(home, key, strict, "", &[], remote)
}

/// `cmd`'s exit code and stderr, within [`LIMIT`]; a run past it is killed,
/// and fails the test.
pub fn finish(cmd: Command) -> (Option<i32>, String) {
    let (code, _, err) = run(cmd, None);
    (code, err)
}

/// `cmd`'s exit code, stdout and stderr, with `input` on its stdin (else
/// the null device), within [`LIMIT`]: each stream on a thread of its own,
/// so that a large output never waits for the input to end.
pub fn run(mut cmd: Command, input: Option<Vec<u8>>) -> (Option<i32>, Vec<u8>, String) {
    if input.is_some() {
        cmd.stdin(Stdio::piped()).stdout(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("ssh runs");
    let mut err_pipe = child.stderr.take().expect("stderr");
    let (err_tx, err_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err_pipe.read_to_string(&mut text);
        let _ = err_tx.send(text);
    });
    let (out_tx, out_rx) = mpsc::channel();
    if let Some(mut out_pipe) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = out_pipe.read_to_end(&mut bytes);
            let _ = out_tx.send(bytes);
        });
    } else {
        let _ = out_tx.send(Vec::new());
    }
    if let (Some(mut stdin), Some(input)) = (child.stdin.take(), input) {
        std::thread::spawn(move || {
            let _ = stdin.write_all(&input);
        });
    }
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{cmd:?} did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let out = out_rx.recv_timeout(LIMIT).unwrap_or_default();
    (status.code(), out, err_rx.recv_timeout(LIMIT).unwrap_or_default())
}
