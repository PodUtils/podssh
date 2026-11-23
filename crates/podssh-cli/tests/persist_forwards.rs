//! The state word of each forward (T-840) against OpenSSH's sshd, software
//! that podssh did not write (`live_harness::sshd`), with `--direct`. With
//! `--persist -N -L`, a stand-in of the network between podssh and the
//! server cuts the link and refuses each dial for a while: the forward says
//! `waiting`, with the loss, then `up` once the link is back, and carries
//! again. A server with `AllowTcpForwarding no` refuses a `-R` (`refused`,
//! with `--persist` too) and a `-W` (`refused (administratively
//! prohibited)`), as `--result-file` lists them. `-N` has no pty and so no
//! `~#`: the lines of `--persist` and the result file carry the words. A
//! host with no sshd skips each test with a line, as its neighbours do.
#![cfg(unix)]

mod cleanup;
mod live_harness;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How long each step may take: a new connection of `--persist` waits the
/// relay's backoff first, a few seconds at its first attempts.
const LIMIT: Duration = Duration::from_secs(60);

/// A fresh directory, removed when the test ends.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().subsec_nanos();
    let dir = std::env::temp_dir().join(format!("podssh-persist-fwd-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// A key of the test, and OpenSSH's server that takes it with the lines
/// `more` in its configuration; `None`, said, where no sshd runs here.
fn server(dir: &Path, more: &str) -> Option<(PathBuf, live_harness::sshd::Sshd)> {
    let key = dir.join("id");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .stdin(Stdio::null())
        .status()
        .expect("podssh keygen runs");
    assert!(made.success());
    match live_harness::sshd::start_with(dir, &key.with_extension("pub"), more) {
        Ok(sshd) => Some((key, sshd)),
        Err(why) => {
            eprintln!("did not run: {why}");
            None
        }
    }
}

/// `podssh ssh --direct` to this user at `port` with `key`, and `flags`.
fn podssh(dir: &Path, key: &Path, port: u16, flags: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "--direct", "-p", &port.to_string(), "-i"]).arg(key);
    cmd.args(["-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"]);
    cmd.args(["-o", "StrictHostKeyChecking=accept-new", "-o"]);
    cmd.arg(format!("UserKnownHostsFile={}", dir.join("known_hosts").display()));
    cmd.args(flags).arg(format!("{}@127.0.0.1", live_harness::this_user()));
    cmd.env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none").env("HOME", dir);
    for name in ["PODSSH_OFFLINE", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    cmd
}

/// A process that is killed when the test ends, also when it fails, with
/// its stderr as it comes.
struct Running {
    child: Child,
    err: Arc<Mutex<String>>,
}

impl Running {
    fn start(mut cmd: Command) -> Running {
        let mut child = cmd.spawn().expect("podssh ssh runs");
        let err = Arc::new(Mutex::new(String::new()));
        let (mut from, into) = (child.stderr.take().unwrap(), err.clone());
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = from.read(&mut buf) {
                if n == 0 {
                    break;
                }
                into.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n]));
            }
        });
        Running { child, err }
    }

    fn err(&self) -> String {
        self.err.lock().unwrap().clone()
    }

    /// Until stderr, from byte `from` on, has a line that holds `want`:
    /// where that line ends.
    fn line_with(&mut self, want: &str, from: usize) -> usize {
        let deadline = Instant::now() + LIMIT;
        loop {
            let err = self.err();
            if let Some(at) = err.get(from..).and_then(|rest| rest.find(want)) {
                let end = err[from + at..].find('\n').map_or(err.len(), |n| from + at + n);
                return end;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!("podssh ended ({status}) before a line with {want:?}: {err}");
            }
            assert!(Instant::now() < deadline, "no line with {want:?} within {LIMIT:?}: {err}");
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The network between podssh and the server, as the test sets it: while
/// open, each connection to its port goes on to the server; [`Gate::cut`]
/// ends each one and closes the port, so that each dial is refused, until
/// [`Gate::open`] listens on it again.
struct Gate {
    port: u16,
    open: Arc<AtomicBool>,
    links: Arc<Mutex<Vec<TcpStream>>>,
}

impl Gate {
    fn new(server: u16) -> Gate {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = first.local_addr().unwrap().port();
        let (open, links) = (Arc::new(AtomicBool::new(true)), Arc::new(Mutex::new(Vec::new())));
        let gate = Gate { port, open: open.clone(), links: links.clone() };
        std::thread::spawn(move || {
            let mut listener = Some(first);
            loop {
                if !open.load(Ordering::SeqCst) {
                    listener = None;
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                // std sets SO_REUSEADDR on Unix: the port binds again at once.
                if listener.is_none() {
                    listener = TcpListener::bind(("127.0.0.1", port)).ok();
                }
                let Some(bound) = &listener else {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                };
                let _ = bound.set_nonblocking(true);
                match bound.accept() {
                    Ok((client, _)) => pass(client, server, &links),
                    Err(_) => std::thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        gate
    }

    fn cut(&self) {
        self.open.store(false, Ordering::SeqCst);
        for link in self.links.lock().unwrap().drain(..) {
            let _ = link.shutdown(Shutdown::Both);
        }
    }

    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
    }
}

/// One connection through the gate, both ways, each half on a thread.
fn pass(client: TcpStream, server: u16, links: &Mutex<Vec<TcpStream>>) {
    let _ = client.set_nonblocking(false);
    let Ok(far) = TcpStream::connect(("127.0.0.1", server)) else { return };
    let mut kept = links.lock().unwrap();
    for (from, to) in [(&client, &far), (&far, &client)] {
        let (Ok(mut from), Ok(mut to)) = (from.try_clone(), to.try_clone()) else { return };
        std::thread::spawn(move || {
            let _ = std::io::copy(&mut from, &mut to);
            let _ = to.shutdown(Shutdown::Both);
        });
    }
    kept.push(client);
    kept.push(far);
}

/// A port of the loopback that nothing holds now, for a listener of `-L`.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// `bytes` through the listener of `-L` at `port`, to the echo and back
/// within `wait`.
fn echoes(port: u16, bytes: &[u8], wait: Duration) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else { return false };
    let _ = stream.set_read_timeout(Some(wait));
    if stream.write_all(bytes).is_err() {
        return false;
    }
    let mut back = vec![0u8; bytes.len()];
    stream.read_exact(&mut back).is_ok() && back == bytes
}

#[test]
fn persist_l_says_waiting_through_a_cut_and_up_once_back() {
    let dir = scratch("cut");
    let Some((key, sshd)) = server(&dir, "") else { return };
    let gate = Gate::new(sshd.port);
    let (echo, local) = (live_harness::echo_server(), free_port());
    let spec = format!("{local}:127.0.0.1:{echo}");
    let mut run = Running::start(podssh(&dir, &key, gate.port, &["--persist", "-N", "-L", spec.as_str()]));

    let at = run.line_with(&format!("{spec}: up"), 0);
    assert!(echoes(local, b"before the cut", Duration::from_secs(10)), "{}", run.err());

    gate.cut();
    // The line of the change names the loss after the word.
    let at = run.line_with(&format!("{spec}: waiting: "), at);
    // No link carries the listener through the loss.
    let during = echoes(local, b"during the cut", Duration::from_millis(1500));
    assert!(!during, "a connection was carried with no link: {}", run.err());

    gate.open();
    run.line_with(&format!("{spec}: up"), at);
    assert!(echoes(local, b"after the cut", Duration::from_secs(10)), "{}", run.err());
}

#[test]
fn a_server_that_forbids_forwarding_refuses_r_and_w() {
    let dir = scratch("refused");
    let Some((key, sshd)) = server(&dir, "AllowTcpForwarding no\n") else { return };
    let echo = live_harness::echo_server();

    // With --persist, a refused -R is a warning, and its word a line.
    let spec = format!("0:127.0.0.1:{echo}");
    let mut run = Running::start(podssh(&dir, &key, sshd.port, &["--persist", "-N", "-R", spec.as_str()]));
    run.line_with(&format!("-R {spec}: refused"), 0);
    drop(run);

    // Without it, ExitOnForwardFailure ends the run, and the result lists
    // the forward refused; a -R refusal carries no reason in SSH.
    let result = dir.join("r.json");
    let path = result.to_str().unwrap();
    let flags = ["-N", "-o", "ExitOnForwardFailure=yes", "-R", spec.as_str(), "--result-file", path];
    let r = finished(podssh(&dir, &key, sshd.port, &flags), &result, Some(255));
    let f = &r["forwards"][0];
    assert_eq!(
        (f["name"].as_str(), f["state"].as_str()),
        (Some(format!("-R {spec}").as_str()), Some("refused")),
        "{r}"
    );
    assert!(f["reason"].is_null(), "{r}");

    // A -W whose channel the policy refuses: the reason of RFC 4254.
    let target = format!("127.0.0.1:{echo}");
    let r =
        finished(podssh(&dir, &key, sshd.port, &["-W", target.as_str(), "--result-file", path]), &result, Some(255));
    let f = &r["forwards"][0];
    assert_eq!((f["state"].as_str(), f["failed"].as_u64()), (Some("refused"), Some(1)), "{r}");
    assert_eq!(f["reason"].as_str(), Some("administratively prohibited"), "{r}");
}

/// A run of `cmd` to its end, within [`LIMIT`], with the exit code `code`:
/// the object of its result file.
fn finished(cmd: Command, result: &Path, code: Option<i32>) -> serde_json::Value {
    let _ = std::fs::remove_file(result);
    let mut run = Running::start(cmd);
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = run.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "podssh still ran after {LIMIT:?}: {}", run.err());
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), code, "{}", run.err());
    let text = std::fs::read_to_string(result).unwrap_or_else(|e| panic!("no result file ({e}): {}", run.err()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{e}: {text}"))
}
