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
    openssh_proxy(home, key, strict, &serve_command(home, serve), options, remote)
}

/// The command line of `podssh serve --stdio` with the scratch key listed,
/// and `serve` after it.
pub fn serve_command(home: &Path, serve: &str) -> String {
    format!("'{BIN}' serve --stdio --authorized-keys '{}'{serve}", home.join("id.pub").display())
}

/// [`openssh_with`] with `proxy` whole as the ProxyCommand, as a test that
/// wraps serve to learn its pid (T-117).
pub fn openssh_proxy(home: &Path, key: &Path, strict: &str, proxy: &str, options: &[&str], remote: &[&str]) -> Command {
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

/// A ProxyCommand that runs serve in the background of a shell, so that
/// a test learns serve's pid (`serve.pid`) and its exit code
/// (`serve.status`); serve keeps the shell's stdin, the client's pipe
/// (T-117, T-118).
// A command of `&` gets /dev/null as its stdin before its own redirections
// (POSIX, with no job control), so the client's pipe goes by descriptor 3.
// OpenSSH sends its ProxyCommand SIGHUP as it ends: the shell ignores it
// once serve runs (serve keeps its own), and lives to write the status.
pub fn wrapped_serve(home: &Path) -> String {
    let script = home.join("serve.sh");
    let text = format!(
        "#!/bin/sh\nexec 3<&0\n{} <&3 3<&- &\necho $! > '{}'\ntrap '' HUP\nwait $!\necho $? > '{}'\n",
        serve_command(home, ""),
        home.join("serve.pid").display(),
        home.join("serve.status").display()
    );
    std::fs::write(&script, text).unwrap();
    format!("sh '{}'", script.display())
}

/// The number in `file`, once it is there and whole, within [`LIMIT`].
pub fn number_in(file: &Path) -> i32 {
    let deadline = Instant::now() + LIMIT;
    loop {
        if let Some(n) = std::fs::read_to_string(file).ok().and_then(|t| t.trim().parse().ok()) {
            return n;
        }
        assert!(Instant::now() < deadline, "{} did not come", file.display());
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Whether `pid` runs: a zombie that no one reaped yet runs no more.
#[cfg(unix)]
pub fn runs(pid: i32) -> bool {
    if Path::new("/proc/self/stat").exists() {
        return std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
            s.rsplit_once(')').and_then(|(_, rest)| rest.split_whitespace().next()).is_some_and(|st| st != "Z")
        });
    }
    // SAFETY: kill with 0 sends nothing; it only asks.
    unsafe { libc::kill(pid, 0) == 0 }
}

/// Wait until `pid` runs no more, within `limit`; whether it ended.
#[cfg(unix)]
pub fn ends_within(pid: i32, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while runs(pid) {
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

/// The resident memory of `pid` in KiB, where `/proc` tells it.
pub fn resident_kib(pid: i32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("VmRSS:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}
