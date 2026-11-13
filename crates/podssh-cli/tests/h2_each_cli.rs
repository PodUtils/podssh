//! The WebSocket over HTTP/2 (T-321, RFC 8441) of the CLI: `podssh each`
//! over 8 hosts through one `podssh relay serve`, OpenSSH's sshd behind it,
//! on one TLS connection. The role listens on the loopback with a leaf of
//! the run's own CA (`http_road_cli_support::role_certificate`), offering
//! `h2` before `http/1.1` as it does by default; in front of it a counter of
//! TCP connections on the loopback, which carries each byte both ways and
//! counts what each connection carried, so that the test sees where the
//! sessions' bytes went with no hook in the role. OpenSSH's sshd, software
//! that podssh did not write (`live_harness::sshd`), listens on 8 ports of
//! the loopback, one for each host, and each host's `cat` of one file of 4
//! MiB comes back, through `--output-dir`, with the file's digest.
//!
//! What proves the one connection: one connection of the counter carried
//! each host's 4 MiB, and each other carried less than 1 MiB (a mint, a
//! document); `-v` says of each host's session that it went over HTTP/2,
//! one on a connection that it opened at most, the others on one that they
//! share; the role said `upgrade` once for each host, each stream being the
//! role's upgrade of its path. The resumable layer, which a named role
//! offers and which keeps its own upgrade, is turned off
//! (`PODSSH_RELAY_LAYER=no`), and `PODSSH_H2` is unset: its default takes
//! the road to a relay host that the user named. Where this host has no
//! sshd, or no user name for it, the test says that it did not run.
//!
//!     cargo test -p podssh-cli --test h2_each_cli
#![cfg(unix)]

mod cloud_support;
mod http_road_cli_support;
mod live_harness;
mod ssh_harness;
mod throughput_harness;

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use http_road_cli_support::{bytes, role_certificate, run, MIB, NAME};
use sha2::{Digest, Sha256};
use throughput_harness::{without_proxy, Session};

/// The hosts of the fan-out: `each`'s default `--parallel`, so that each
/// starts at once, and under the role's 16 streams of one connection.
const HOSTS: usize = 8;
/// What each host's `cat` sends back.
const SIZE: usize = 4 * MIB;
/// Each other connection of the counter carries less than this: a mint, a
/// document, no session.
const SMALL: u64 = MIB as u64;
/// The bound of each wait of the setup.
const WAIT: Duration = Duration::from_secs(30);

/// What one connection of the counter carried: toward the role, and back.
#[derive(Default)]
struct Carried {
    up: AtomicU64,
    down: AtomicU64,
}

/// The counter in front of the role: its port, and what each connection
/// that it took carried, in the order taken.
struct Counter {
    port: u16,
    seen: Arc<Mutex<Vec<Arc<Carried>>>>,
}

impl Counter {
    /// A listener on the loopback, each connection carried to `role`.
    fn start(role: u16) -> Counter {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen: Arc<Mutex<Vec<Arc<Carried>>>> = Arc::default();
        let kept = seen.clone();
        std::thread::spawn(move || {
            for client in listener.incoming().map_while(Result::ok) {
                let Ok(upstream) = TcpStream::connect(("127.0.0.1", role)) else { continue };
                let carried = Arc::new(Carried::default());
                kept.lock().unwrap().push(carried.clone());
                let (c2, u2) = (client.try_clone().unwrap(), upstream.try_clone().unwrap());
                let up = carried.clone();
                std::thread::spawn(move || pass(client, upstream, |n| up.up.fetch_add(n, Ordering::SeqCst)));
                std::thread::spawn(move || pass(u2, c2, |n| carried.down.fetch_add(n, Ordering::SeqCst)));
            }
        });
        Counter { port, seen }
    }

    /// What each connection carried so far: (up, down).
    fn carried(&self) -> Vec<(u64, u64)> {
        let seen = self.seen.lock().unwrap();
        seen.iter().map(|c| (c.up.load(Ordering::SeqCst), c.down.load(Ordering::SeqCst))).collect()
    }
}

/// Each byte of `from` to `to`, counted as it goes; then the end of `to`'s
/// side, so that the other end reads the close.
fn pass(mut from: TcpStream, mut to: TcpStream, count: impl Fn(u64) -> u64) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
                count(n as u64);
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

/// `podssh relay serve` with its defaults (`--http2 yes`), minting for
/// anyone and dialing the loopback: its port, and the file of its events
/// (its stdout, a line for each mint and upgrade, `h2` for each connection
/// of HTTP/2).
fn role(s: &Session) -> (u16, PathBuf, PathBuf) {
    let (cert, key, ca) = role_certificate(&s.home);
    let (port_file, events, log) = (s.home.join("role-port"), s.home.join("role.events"), s.home.join("role.log"));
    let mut args: Vec<String> =
        ["relay", "serve", "--listen", "127.0.0.1:0", "--mint", "anyone", "--allow-private"].map(String::from).into();
    for (flag, path) in [("--cert", &cert), ("--key", &key), ("--port-file", &port_file)] {
        args.extend([flag.to_string(), path.display().to_string()]);
    }
    let child = without_proxy(s.command(&args))
        .stdin(Stdio::null())
        .stdout(std::fs::File::create(&events).unwrap())
        .stderr(std::fs::File::create(&log).unwrap())
        .spawn()
        .expect("podssh relay serve starts");
    s.keep(child);
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(port) = std::fs::read_to_string(&port_file).ok().and_then(|t| t.trim().parse::<u16>().ok()) {
            return (port, events, ca);
        }
        let said = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(Instant::now() < deadline, "the role did not start within {WAIT:?}: {said}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// This user's name, for OpenSSH's login to the loopback's sshd.
fn this_user() -> Option<String> {
    let name = std::env::var("USER").or_else(|_| std::env::var("LOGNAME")).ok().filter(|u| !u.is_empty());
    name.or_else(|| {
        let out = Command::new("id").arg("-un").output().ok()?;
        Some(String::from_utf8(out.stdout).ok()?.trim().to_string()).filter(|u| !u.is_empty())
    })
}

/// A port of the loopback where nothing listens now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A key of the test in `dir`, made by podssh, for OpenSSH's login.
fn client_key(s: &Session, dir: &Path) -> PathBuf {
    let key = dir.join("id");
    let mut args: Vec<String> = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f"].map(String::from).into();
    args.push(key.display().to_string());
    let made = s.command(&args).stdin(Stdio::null()).output().unwrap();
    assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
    key
}

#[test]
fn each_over_8_hosts_through_the_role_shares_one_tls_connection_with_equal_digests() {
    let s = Session::start("h2-each");
    let Some(user) = this_user() else { return eprintln!("did not run: no user name here, for sshd's login") };
    let dir = s.home.join("openssh");
    std::fs::create_dir_all(&dir).unwrap();
    let key = client_key(&s, &dir);
    // One sshd on 8 ports: each host of the fan-out a port of its own, so
    // that the 8 are 8 hosts to `each`.
    let more: Vec<u16> = (1..HOSTS).map(|_| free_port()).collect();
    let extra: String = more.iter().map(|p| format!("ListenAddress 127.0.0.1:{p}\n")).collect();
    let sshd = match live_harness::sshd::start_with(&dir, &key.with_extension("pub"), &extra) {
        Ok(sshd) => sshd,
        Err(why) => return eprintln!("did not run: {why}"),
    };
    let ports: Vec<u16> = std::iter::once(sshd.port).chain(more).collect();
    // The file that each host sends back, in the scratch directory, which
    // sshd's shell reads too.
    let data = dir.join("data");
    let sent = bytes(SIZE, 21);
    std::fs::write(&data, &sent).unwrap();
    let want = Sha256::digest(&sent);

    let (role_port, events, ca) = role(&s);
    let counter = Counter::start(role_port);
    let hosts: Vec<String> = ports.iter().map(|p| format!("{user}@127.0.0.1:{p}")).collect();
    let out_dir = s.home.join("each-out");
    let mut args: Vec<String> = vec!["each".into(), "-v".into()];
    args.extend(s.common());
    args.extend(["-i".to_string(), key.display().to_string(), "-o".into(), "IdentitiesOnly=yes".into()]);
    args.extend(["--relay-host".to_string(), format!("{NAME}:{}", counter.port)]);
    args.extend(["--relay-addr".to_string(), format!("{NAME}=127.0.0.1")]);
    args.extend(["--ca-file".to_string(), ca.display().to_string()]);
    args.extend(["--output-dir".to_string(), out_dir.display().to_string()]);
    args.extend([hosts.join(","), "--".into(), format!("cat {}", data.display())]);
    let mut cmd = without_proxy(s.command(&args));
    for name in ["PODSSH_RELAY", "PODSSH_RELAY_TOKEN", "PODSSH_H2", "PODSSH_QUIC", "SSL_CERT_FILE"] {
        cmd.env_remove(name);
    }
    // The contract's road, which takes HTTP/2: the layer keeps its own upgrade.
    cmd.env("PODSSH_RELAY_LAYER", "no").env("PODSSH_SETTINGS", "none");
    let ran = run(cmd, Vec::new());
    assert_eq!(ran.code, Some(0), "each host gave 0: {}", ran.err);

    // Each host's bytes came back whole.
    for host in &hosts {
        let file = out_dir.join(format!("{}.out", host.replace(':', "%3A")));
        let got = std::fs::read(&file).unwrap_or_else(|e| panic!("{}: {e}; {}", file.display(), ran.err));
        assert_eq!(got.len(), SIZE, "{host}: each byte came back once; {}", ran.err);
        assert!(Sha256::digest(&got) == want, "{host}: the digests differ");
    }

    // Each session said its road: HTTP/2, on one connection.
    let said = |words: &str| ran.err.lines().filter(|l| l.contains(words)).count();
    let opened = said("over HTTP/2 (RFC 8441), on a connection that it opened");
    let shared = said("over HTTP/2 (RFC 8441), on a connection that it shares");
    assert_eq!(opened + shared, HOSTS, "each session went over HTTP/2: {}", ran.err);
    assert!(opened <= 1, "one connection was opened for the sessions at most: {}", ran.err);

    // The counter: one connection carried each host's bytes, and no other
    // carried a session.
    let carried = counter.carried();
    let bulk: Vec<&(u64, u64)> = carried.iter().filter(|(_, down)| *down >= (HOSTS * SIZE) as u64).collect();
    assert_eq!(bulk.len(), 1, "one connection carried the {HOSTS} sessions: {carried:?}");
    let others = carried.iter().filter(|(_, down)| *down < (HOSTS * SIZE) as u64);
    assert!(others.clone().all(|(up, down)| *up < SMALL && *down < SMALL), "no other carried a session: {carried:?}");

    // The role upgraded each stream's path once: 8 sessions, 8 upgrades.
    let lines = std::fs::read_to_string(&events).unwrap_or_default();
    let upgrades = lines.lines().filter(|l| *l == "upgrade").count();
    assert_eq!(upgrades, HOSTS, "the role's events: {lines}");
    assert!(lines.lines().any(|l| l == "h2"), "the role served HTTP/2: {lines}");
}
