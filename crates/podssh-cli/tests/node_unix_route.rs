//! A node's route to a Unix socket (T-714) from end to end, through the
//! stand-in relay's reverse road on the loopback: a stand-in service on a
//! socket in a temporary directory reads the caller's line and echoes it.
//! Two keys give two lines; a key that the door refuses gives the socket no
//! connection; a route with no `--caller-line` gets no line; a socket that
//! is gone is named. On Windows the socket is AF_UNIX. Each check says that
//! it did not run when this host has no Python or no openssl for the
//! stand-in.

mod ssh_harness;
mod throughput_harness;
// The service's listener: AF_UNIX by WinSock on Windows.
mod unix_sock;

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use throughput_harness::{lines_of, wait_for, Cell, Session};

/// How long the stand-in service waits for a line.
const WAIT: Duration = Duration::from_secs(5);

/// A service at `path` that reads one line of each connection and answers
/// `got LINE`, and counts the connections.
fn echo_line(path: &str) -> Arc<AtomicUsize> {
    let listener = unix_sock::Listener::bind(path);
    let count = Arc::new(AtomicUsize::new(0));
    let counted = count.clone();
    std::thread::spawn(move || {
        while let Some(mut stream) = listener.accept() {
            counted.fetch_add(1, Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(WAIT));
            let (mut line, mut byte) = (Vec::new(), [0u8; 1]);
            while let Ok(1) = stream.read(&mut byte) {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            let _ = stream.write_all(b"got ");
            let _ = stream.write_all(&line);
        }
    });
    count
}

/// A service at `path` that writes `raw` first, and keeps what came to it.
fn raw(path: &str) -> Arc<Mutex<Vec<u8>>> {
    let listener = unix_sock::Listener::bind(path);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let kept = seen.clone();
    std::thread::spawn(move || {
        while let Some(mut stream) = listener.accept() {
            let _ = stream.write_all(b"raw\n");
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut came = Vec::new();
            let _ = stream.read_to_end(&mut came);
            kept.lock().unwrap().extend(came);
        }
    });
    seen
}

/// What an operator got: its exit code, stdout and stderr.
fn ran(cmd: &mut Command) -> (i32, String, String) {
    let out = cmd.stdin(Stdio::null()).output().unwrap();
    let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    (out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr))
}

/// A short directory of its own: a socket's address holds about 100 bytes.
fn socket_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pt714-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn a_unix_route_gets_the_line_of_each_key_that_the_door_let_in() {
    let session = Session::start("unix-route");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[String]| {
        let mut cmd = session.stand_in(&args[..1], &ca);
        cmd.args(&pins).args(&args[1..]);
        cmd
    };
    let words = |list: &[&str]| list.iter().map(|w| w.to_string()).collect::<Vec<_>>();
    let (rc, _, err) = ran(&mut command(&words(&["relay", "pair", "lab", "--relay-host", &relay])));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    let dir = socket_dir();
    let path = |name: &str| dir.join(name).display().to_string();
    let (api, plain, gone) = (path("api.sock"), path("raw.sock"), path("missing.sock"));
    let api_seen = echo_line(&api);
    let raw_seen = raw(&plain);
    // In a directory of its own: the node refuses an allowlist that others
    // can change, as this host's temporary directory lets them.
    let private = session.home.join("private");
    podssh_relay::cache::private_dir(&private).unwrap();
    let allow = private.join("allow");
    std::fs::write(&allow, "# no key yet\n").unwrap();
    let node_args = words(&[
        "node",
        "lab",
        &format!("api=unix-connect:{api}"),
        &format!("raw=unix-connect:{plain}"),
        &format!("gone=unix-connect:{gone}"),
        "--caller-line",
        "api",
        "--allow",
        &allow.display().to_string(),
    ]);
    let mut node = command(&node_args).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let lines = lines_of(&mut node);
    session.keep(node);
    let first = wait_for(&lines, "serving").expect("the node starts");
    assert!(first.contains(&format!("api=unix-connect:{api} (caller line)")), "the first line names it: {first}");
    wait_for(&lines, "online").expect("the node is online");
    let key = |name: &str| session.home.join(name).display().to_string();
    let (key_a, key_b) = (key("a.key"), key("b.key"));
    let operator = |route: &str, client: &str| ran(&mut command(&words(&["operator", "--client-key", client, route])));
    // No key in the allowlist: each key is refused, and the socket sees
    // no connection.
    let fingerprint = |client: &str| {
        let (rc, _, err) = operator("lab/api", client);
        assert_ne!(rc, 0, "{err}");
        let refused = err.lines().find(|l| l.contains("refused this client's key")).expect("the key is named");
        let found = refused.split_whitespace().find(|w| w.starts_with("SHA256:")).expect("the client's key");
        found.trim_end_matches([':', ';']).to_string()
    };
    let (fp_a, fp_b) = (fingerprint(key_a.as_str()), fingerprint(key_b.as_str()));
    assert_ne!(fp_a, fp_b);
    assert_eq!(api_seen.load(Ordering::SeqCst), 0, "a key that the door refused reached the socket");
    std::fs::write(&allow, format!("{fp_a} routes=api,raw,gone a\n{fp_b} routes=api b\n")).unwrap();
    // Each key let in: its own line, which the service reads before the stream.
    let said = || lines.try_iter().collect::<Vec<_>>().join("\n");
    for (client, fp) in [(key_a.as_str(), &fp_a), (key_b.as_str(), &fp_b)] {
        let (rc, out, err) = operator("lab/api", client);
        assert_eq!(rc, 0, "{err}\nthe node:\n{}", said());
        assert_eq!(out, format!("got podssh-caller v1 {fp} api\n"), "{err}");
    }
    assert_eq!(api_seen.load(Ordering::SeqCst), 2);
    // A route that the key may not use is refused before the socket.
    let (rc, out, err) = operator("lab/raw", key_b.as_str());
    assert!(rc != 0 && out.is_empty() && err.contains("may not use the route raw"), "{err}");
    // With no --caller-line, the node writes nothing of its own.
    let (rc, out, err) = operator("lab/raw", key_a.as_str());
    assert_eq!((rc, out.as_str()), (0, "raw\n"), "{err}");
    assert!(raw_seen.lock().unwrap().is_empty(), "a plain route got bytes of the node");
    // A socket that is gone: its path is named.
    let (rc, _, err) = operator("lab/gone", key_a.as_str());
    assert!(rc != 0 && err.contains("missing.sock"), "{err}\nthe node:\n{}", said());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_node_refuses_a_unix_route_that_it_cannot_serve() {
    let home = throughput_harness::scratch("unix-route-refused");
    // The scratch home goes at the end, also when an assertion fails: the
    // gate fails on a test that leaves its directory.
    struct Gone(std::path::PathBuf);
    impl Drop for Gone {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _gone = Gone(home.clone());
    for (extra, says) in [
        (vec!["--sshd"], "--sshd"),
        (vec!["--exit"], "--exit"),
        (vec!["--no-e2e"], "--no-e2e"),
        (vec!["--caller-line", "web"], "no route web"),
    ] {
        let mut args = vec!["node".to_string(), "lab".into(), "api=unix-connect:/tmp/pt714.sock".into()];
        args.extend(extra.iter().map(|w| w.to_string()));
        let (rc, _, err) = ran(&mut throughput_harness::command_in(&home, &args));
        assert_eq!(rc, 64, "{extra:?}: {err}");
        assert!(err.contains(says), "{extra:?}: {err}");
    }
    let args = ["node", "lab", "unix-connect:/tmp/pt714.sock"].map(String::from);
    let (rc, _, err) = ran(&mut throughput_harness::command_in(&home, &args));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("has a route"), "{err}");
}

/// A session through a Unix route goes on across the node's own upgrade in
/// place (T-714, T-668): the route's socket goes to the new binary as a TCP
/// target's does, and its bytes come whole.
#[cfg(unix)]
#[test]
fn a_unix_route_s_session_goes_on_across_the_node_s_upgrade() {
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    const DOWN: u64 = 32 << 20;
    let session = Session::start("unix-route-upgrade");
    let cell = match Cell::fake_relay_mode(&session, "normal", "the stand-in relay") {
        Ok(cell) => cell,
        Err((_, why)) => {
            eprintln!("did not run: {why}");
            return;
        }
    };
    let at = |flag: &str| cell.args.iter().position(|a| a == flag).map(|i| cell.args[i + 1].clone()).unwrap();
    let (relay, ca) = (at("--relay-host"), at("--ca-file"));
    let pins = ["--relay-addr".to_string(), "relay-a.test=127.0.0.1".to_string()];
    let command = |args: &[&str]| {
        let mut cmd = session.stand_in(&[args[0].to_string()], &ca);
        cmd.args(&pins).args(&args[1..]);
        cmd
    };
    let (rc, _, err) = ran(&mut command(&["relay", "pair", "lab", "--relay-host", &relay]));
    assert_eq!(rc, 0, "podssh relay pair: {err}");
    let dir = std::env::temp_dir().join(format!("pt714u-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("src.sock").display().to_string();
    // The service: DOWN bytes to each connection, then the end.
    let listener = UnixListener::bind(&sock).expect("a socket in the test's directory");
    std::thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let chunk = vec![0x5au8; 1 << 16];
            let mut left = DOWN;
            while left > 0 {
                let n = left.min(chunk.len() as u64) as usize;
                if stream.write_all(&chunk[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
        }
    });
    let route = format!("src=unix-connect:{sock}");
    let mut node = command(&["node", "lab", &route]).stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let pid = node.id() as libc::pid_t;
    let lines = lines_of(&mut node);
    session.keep(node);
    wait_for(&lines, "online").expect("the node is online");

    let mut operator = command(&["operator", "lab/src"]);
    let mut child = operator.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (quarter_tx, quarter_rx) = std::sync::mpsc::channel();
    let counted = std::thread::spawn(move || {
        let (mut buf, mut total) = (vec![0u8; 1 << 16], 0u64);
        while let Ok(n) = stdout.read(&mut buf) {
            if n == 0 {
                break;
            }
            total += n as u64;
            if total >= DOWN / 4 {
                let _ = quarter_tx.send(());
            }
        }
        total
    });
    let mut stderr = child.stderr.take().unwrap();
    let said = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    quarter_rx.recv_timeout(Duration::from_secs(120)).expect("a quarter of the bytes came before the upgrade");
    // SAFETY: a signal to the node that this test started, which runs.
    assert_eq!(unsafe { libc::kill(pid, libc::SIGUSR2) }, 0);
    let went = wait_for(&lines, "sessions go to").expect("the node hands its sessions over");
    assert!(went.contains("1 of 1 sessions go to"), "{went}");
    let took = wait_for(&lines, "sessions over from").expect("the new binary takes them");
    assert!(took.contains("took 1 of 1 sessions over"), "{took}");

    let deadline = Instant::now() + Duration::from_secs(180);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("32 MiB through the Unix route did not come within 180 s of the upgrade");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let (total, err) = (counted.join().unwrap(), said.join().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(status.code(), Some(0), "{err}");
    assert_eq!(total, DOWN, "{err}");
    // SAFETY: a probe of a pid that this test started; no signal is sent.
    assert_eq!(unsafe { libc::kill(pid, 0) }, 0, "the node runs on in its own process");
}
