//! `podssh serve NAME` reads its keys again on SIGHUP (T-855), as `--stdio`
//! does (T-117, T-842). Through the stand-in relay of the reverse road, two
//! keys of an `--authorized-keys` file each hold a session; the file loses
//! one key and the node gets SIGHUP. With `--revoke-ends-sessions` the
//! removed key's session ends, the node names the key, and the other session
//! lives to its end; without it, both live, the next login of the removed key
//! is refused, and a file that is gone keeps the set before. Unix's; a host
//! with neither Python nor openssl says that the test did not run.

#![cfg(unix)]

mod pair_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// The command of each long session: a line when it runs, a line at its end.
const LONG: &str = "echo UP; sleep 15; echo LIVED";
/// How long a revoked session may take to end after the SIGHUP: well under
/// the session's own 15 s.
const REVOKE_LIMIT: Duration = Duration::from_secs(10);
/// How long a session that lives may take to end.
const END_LIMIT: Duration = Duration::from_secs(45);

/// A child that is killed and reaped when the test leaves, at each end.
struct Running(Option<Child>);

impl Running {
    /// Its exit within `limit`, or None (killed) past it.
    fn exit_within(&mut self, limit: Duration) -> Option<ExitStatus> {
        let child = self.0.as_mut()?;
        let started = Instant::now();
        loop {
            if let Ok(Some(status)) = child.try_wait() {
                self.0 = None;
                return Some(status);
            }
            if started.elapsed() > limit {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The lines of a child's stdout, as they come.
fn stdout_of(child: &mut Child) -> Receiver<String> {
    let stdout = child.stdout.take().expect("stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = tx.send(line);
        }
    });
    rx
}

fn hangup(pid: u32) {
    let pid = i32::try_from(pid).expect("a pid");
    // SAFETY: kill has no memory effect.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGHUP) }, 0, "SIGHUP to the node");
}

fn words(w: &[&str]) -> Vec<String> {
    w.iter().map(|s| s.to_string()).collect()
}

/// The node of `serve NAME` with its keys in a file, and what a login needs.
struct Node {
    lines: Receiver<String>,
    pid: u32,
    ca: String,
    file: PathBuf,
    /// The two keys and their public lines.
    keys: [(PathBuf, String); 2],
}

const PINS: (&str, &str) = ("PODSSH_RELAY_ADDR", "relay-a.test=127.0.0.1");

/// Pair `label` at the stand-in relay and start its node of serve, with both
/// keys in the file; None where the stand-in cannot run here.
fn start(s: &Session, label: &str, revoke: bool) -> Option<Node> {
    let cell = match Cell::fake_relay_mode(s, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return None;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let out = s.stand_in(&words(&["relay", "pair", label, "--relay-host", &relay]), &ca).env(PINS.0, PINS.1).output();
    let out = out.unwrap();
    assert!(out.status.success(), "podssh relay pair: {}", String::from_utf8_lossy(&out.stderr));
    s.revoke_later(label);

    let one = s.home.join("host_key");
    let two = s.home.join("other_key");
    let mut made = s.command(&words(&["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &two.display().to_string()]));
    assert!(made.stdin(Stdio::null()).output().unwrap().status.success());
    let public = |key: &Path| std::fs::read_to_string(key.with_extension("pub")).unwrap().trim().to_string();
    let keys = [(one.clone(), public(&one)), (two.clone(), public(&two))];
    let file = s.home.join("authorized_keys");
    std::fs::write(&file, format!("{}\n{}\n", keys[0].1, keys[1].1)).unwrap();

    let shown = file.display().to_string();
    let mut serve = words(&["serve", label, "--authorized-keys", &shown, "--shell", "/bin/sh"]);
    if revoke {
        serve.push("--revoke-ends-sessions".into());
    }
    let mut cmd = s.stand_in(&serve, &ca);
    cmd.env(PINS.0, PINS.1).stdin(Stdio::null()).stderr(Stdio::piped());
    let mut node = cmd.spawn().unwrap();
    let (lines, pid) = (lines_of(&mut node), node.id());
    s.keep(node);
    wait_for(&lines, "serving").expect("serve's node starts");
    wait_for(&lines, "online").expect("the node is online");
    Some(Node { lines, pid, ca, file, keys })
}

impl Node {
    /// `podssh ssh node://user@LABEL COMMAND` with the key `which`.
    fn login(&self, s: &Session, label: &str, which: usize, command: &str) -> Command {
        let user = std::env::var("USER").unwrap_or_else(|_| "tester".into());
        let mut args = vec!["ssh".to_string(), "-i".into(), self.keys[which].0.display().to_string()];
        args.extend(["-o".into(), "IdentitiesOnly=yes".into()]);
        args.extend(s.common());
        args.extend([format!("node://{user}@{label}"), command.into()]);
        let mut cmd = s.stand_in(&args, &self.ca);
        cmd.env(PINS.0, PINS.1).stdin(Stdio::null());
        cmd
    }

    /// A long session of the key `which`, once its command runs.
    fn hold(&self, s: &Session, label: &str, which: usize) -> (Running, Receiver<String>) {
        let mut cmd = self.login(s, label, which, LONG);
        let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let out = stdout_of(&mut child);
        let running = Running(Some(child));
        let up = out.recv_timeout(Duration::from_secs(60));
        assert_eq!(up.as_deref(), Ok("UP"), "the session of key {which} runs its command");
        (running, out)
    }

    /// The file with the key `which` alone, then SIGHUP; the reload's line.
    fn keep_only(&self, which: usize) -> String {
        std::fs::write(&self.file, format!("{}\n", self.keys[which].1)).unwrap();
        hangup(self.pid);
        wait_for(&self.lines, "SIGHUP: the authorized keys read again").expect("the node reads its keys again")
    }
}

/// The session lived to its end: exit 0 and its last line.
fn lived(mut running: Running, out: &Receiver<String>, which: usize) {
    let status = running.exit_within(END_LIMIT);
    assert_eq!(status.and_then(|s| s.code()), Some(0), "the session of key {which} lives to its end");
    assert_eq!(out.recv_timeout(Duration::from_secs(5)).as_deref(), Ok("LIVED"), "key {which}");
}

#[test]
fn with_the_flag_a_sighup_ends_the_removed_keys_session_of_the_node_alone() {
    let s = Session::start("serve-node-reload-ends");
    let Some(node) = start(&s, "lab-ends", true) else { return };
    let (mut gone, gone_out) = node.hold(&s, "lab-ends", 0);
    let (kept, kept_out) = node.hold(&s, "lab-ends", 1);

    let line = node.keep_only(1);
    assert!(line.contains("1 in all"), "{line}");
    let named = wait_for(&node.lines, "its session ends").expect("the node names the ended key");
    assert!(named.contains("removed from the authorized keys"), "{named}");

    let status = gone.exit_within(REVOKE_LIMIT);
    let code = status.and_then(|s| s.code());
    assert!(code.is_some_and(|c| c != 0), "the removed key's session ends, not at its own end: {code:?}");
    assert!(gone_out.try_iter().all(|l| l != "LIVED"), "the removed key's command did not reach its end");
    lived(kept, &kept_out, 1);
}

#[test]
fn without_the_flag_a_sighup_ends_nothing_and_a_file_that_is_gone_keeps_the_set() {
    let s = Session::start("serve-node-reload-keeps");
    let Some(node) = start(&s, "lab-keeps", false) else { return };
    let (gone, gone_out) = node.hold(&s, "lab-keeps", 0);
    let (kept, kept_out) = node.hold(&s, "lab-keeps", 1);

    let line = node.keep_only(1);
    assert!(line.contains("1 in all"), "{line}");
    lived(gone, &gone_out, 0);
    lived(kept, &kept_out, 1);

    // The next login meets the new set: the removed key is refused.
    let out = node.login(&s, "lab-keeps", 0, "true").output().unwrap();
    assert_eq!(out.status.code(), Some(255), "{}", String::from_utf8_lossy(&out.stderr));

    // A file that is gone keeps the set before, and the node serves on.
    std::fs::remove_file(&node.file).unwrap();
    hangup(node.pid);
    let stays = wait_for(&node.lines, "the set before stays").expect("one line says why the set stays");
    assert!(stays.contains("no such file"), "{stays}");
    let out = node.login(&s, "lab-keeps", 1, "echo AGAIN").output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "AGAIN\n");
}
