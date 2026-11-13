//! The file hosts' road (T-738) through the binary as it ships, on this
//! machine's loopback: `podssh node --derp` with a pair whose relay is down,
//! and `podssh ssh node://tester@lab cat` with that pair, its DERP road off
//! and each other road off, so the race gives the session to the file
//! hosts' road, the last of all. Nothing in the binary names a stand-in:
//! both ends name the catalog's hosts and broker (`PODSSH_FILEHOSTS` picks
//! two of `pod-services`' kind `file-host`), and the test's proxy
//! (`HTTPS_PROXY`) takes each of those names to a stand-in of the test's CA
//! (`SSL_CERT_FILE`): the file hosts (`filehost_stand_in`, each speaking its
//! form of the catalog), and Mosquitto behind TLS for the broker of the
//! catalog's kind `mqtt-broker`.
//!
//! 256 KiB go up and come back with equal digests; the handshakes ride in
//! their notes on the broker (T-773), and the bulk goes to the hosts: the
//! first host answers 429 past one upload, and the next host of the list
//! takes the next pieces; a host that deletes by token (0x0's form) is asked to delete what
//! was read, with the right token; no host holds a run of the plaintext;
//! the Q78 lines name the third parties. A bad `PODSSH_FILEHOSTS` is refused
//! with 78 at each end before anything connects. The test says "did not
//! run" with no Mosquitto (`PODSSH_MOSQUITTO_TEST_BIN`), which
//! `mqtt-interop.yml` sets, and fails on those words.
//!
//!     PODSSH_MOSQUITTO_TEST_BIN=/usr/sbin/mosquitto \
//!         cargo test -p podssh-cli --features filehost --test carrier_filehost -- --nocapture

#![cfg(feature = "filehost")]

mod cleanup;
mod derp_support;
mod filehost_stand_in;
mod ssh_harness;
// The TLS acceptor of the test's own CA.
#[path = "update_support/mod.rs"]
mod update_support;

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use derp_support::Front;
use filehost_stand_in::{Hosts, Mosquitto, Proxy};
use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use sha2::{Digest, Sha256};

/// The first host, which turns busy, and the next, which deletes by token.
const FIRST: &str = "tmpfiles-org";
const NEXT: &str = "null-pointer-0x0";
/// One upload: the small writes ride in notes, so the session's pieces are
/// the bulk alone, a few each way, and the second must find the first host
/// busy.
const BUSY_AFTER: usize = 1;
/// A start, a refusal: each within this.
const LIMIT: Duration = Duration::from_secs(60);
/// The session: each piece of the bulk waits for its host's pace (23 s and
/// 30 s here, as the catalog publishes); the handshakes' small writes ride
/// in their notes, a poll of the broker each way.
const SESSION_LIMIT: Duration = Duration::from_secs(25 * 60);
const SIZE: usize = 256 * 1024;

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-carrier-filehost-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, none of the settings
/// of the machine that runs it, and each road off but the pair's, DERP's and
/// the file hosts'.
fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in [
        "PODSSH_OFFLINE",
        "PODSSH_DERP",
        "PODSSH_DERP_SERVER",
        "PODSSH_RELAY",
        "PODSSH_RELAY_ADDR",
        "PODSSH_LAST_RESORT",
        "PODSSH_MQTT",
        "PODSSH_FILEHOSTS",
        "SSL_CERT_FILE",
        "SSH_AUTH_SOCK",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        cmd.env_remove(name);
    }
    for off in [
        "PODSSH_TRANSIT",
        "PODSSH_CROC",
        "PODSSH_PIPING",
        "PODSSH_FORWARDER_FALLBACK",
        "PODSSH_ZEROTIER",
        "PODSSH_TOX",
        "PODSSH_YGGDRASIL",
        "PODSSH_HYPERDHT",
        "PODSSH_SYNCTHING_RELAY",
        "PODSSH_ONION",
        "PODSSH_LOCALHOST_RUN",
        "PODSSH_SANDHOLE",
        "PODSSH_LOCALTUNNEL",
        "PODSSH_HOSTC",
        "PODSSH_SMEE",
        "PODSSH_BORE",
        "PODSSH_OPENTUNNEL",
        "PODSSH_PINGGY",
        "PODSSH_SERVEO",
        "PODSSH_SSH_J",
    ] {
        cmd.env(off, "no");
    }
    cmd.env("PODSSH_IROH_PKARR", "off");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// A pair under `lab` in the cache of `home`, whose relay is a port of the
/// loopback where nothing listens: its road fails at once at both ends.
fn store_pair(home: &Path) {
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let relay = podssh_relay::relay::Relay { host: "127.0.0.1".into(), port: closed };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    // The repository's fixture form of a token, which names no credential.
    let token = |kind: &str| format!("testonly{kind}{}", "0".repeat(56 - kind.len()));
    let body = serde_json::json!({
        "name": "p-0123456789abcdef0123456789abcdef",
        "node_token": token("node"),
        "connect_token": token("connect"),
        "stop_token": token("stop"),
        "expires": now + 72 * 3600 * 1000,
    });
    let pair = podssh_relay::pair::parse(&relay, body.to_string().as_bytes(), now).expect("a test pair");
    podssh_relay::pair::store_in_first(&[home.join("cache").join("podssh")], "lab", &pair).expect("stored");
}

/// `cmd` with `input` on stdin, within `limit`: its code, stdout and
/// stderr, each pipe read on a thread of its own; past the limit it is
/// killed, and the test fails with its stderr.
fn run_with(mut cmd: Command, input: Vec<u8>, limit: Duration) -> (Option<i32>, Vec<u8>, String) {
    let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let mut stdin = child.stdin.take().expect("stdin");
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let reader = |mut pipe: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
    };
    let out = reader(Box::new(child.stdout.take().expect("stdout")));
    let err = reader(Box::new(child.stderr.take().expect("stderr")));
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(status) = child.try_wait().expect("wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            let err = String::from_utf8_lossy(&err.join().unwrap_or_default()).into_owned();
            panic!("podssh did not end within {} s; its stderr:\n{err}", limit.as_secs());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let (out, err) = (out.join().unwrap_or_default(), err.join().unwrap_or_default());
    (status.code(), out, String::from_utf8_lossy(&err).into_owned())
}

/// Kills the node when the test ends.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The lines of `lines` up to the first that holds `needle`, within the
/// limit.
fn wait_for(lines: &mpsc::Receiver<String>, needle: &str) -> Vec<String> {
    let deadline = Instant::now() + LIMIT;
    let mut seen = Vec::new();
    loop {
        match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                let found = line.contains(needle);
                seen.push(line);
                if found {
                    return seen;
                }
            }
            Err(_) => panic!("no line with {needle:?} from the node within {} s: {seen:#?}", LIMIT.as_secs()),
        }
    }
}

/// Bytes from a fixed xorshift, so that a byte out of place shows.
fn pattern(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9e37_79b9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x as u8
        })
        .collect()
}

/// The place of the test: the stand-ins in their runtime, and the homes.
struct Lab {
    runtime: tokio::runtime::Runtime,
    derp: Front,
    hosts: Hosts,
    proxy: Proxy,
    _broker: Mosquitto,
    ca: String,
    target: String,
    node_home: PathBuf,
    client_home: PathBuf,
    allow: String,
    client_key: String,
    known: String,
}

impl Lab {
    /// The lab; `None`, with the line that says why, with no Mosquitto.
    fn new(name: &str) -> Option<Lab> {
        let home = scratch(name);
        let broker = Mosquitto::start(&home)?;
        let (forms, missed) = podssh_relay::filehost::services::forms(&[FIRST, NEXT]);
        assert!(missed.is_empty() && forms.len() == 2, "the catalog's forms: {missed:?}");
        let point = podssh_relay::code::brokers(None, None).into_iter().next().expect("a broker in the catalog");
        assert!(point.url.tls && point.url.port == 443, "the catalog's broker is wss:// on 443: {:?}", point.url.host);
        // Each name that the binary will ask the proxy for, in one
        // certificate of the test's CA.
        let mut names: Vec<String> = vec!["127.0.0.1".into(), point.url.host.clone()];
        for form in &forms {
            names.push(podssh_relay::filehost::http::place(&form.upload).expect("an https:// upload").0.host);
            names.extend(form.serves.iter().cloned());
        }
        names.sort();
        names.dedup();
        let named: Vec<&str> = names.iter().map(String::as_str).collect();
        let (acceptor, ca) = update_support::acceptor(&home, &named);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let (derp, hosts, proxy) = runtime.block_on(async {
            let derp = Front::start(acceptor.clone()).await;
            let hosts = Hosts::start(acceptor.clone(), forms.clone(), &[(FIRST, BUSY_AFTER)]).await;
            let broker_front = filehost_stand_in::front(acceptor, broker.port).await;
            let mut routes = HashMap::new();
            for name in names.iter().filter(|n| *n != "127.0.0.1") {
                routes.insert(name.clone(), if *name == point.url.host { broker_front } else { hosts.port });
            }
            (derp, hosts, Proxy::start(routes).await)
        });
        let host_key = home.join("host_key").to_string_lossy().into_owned();
        let (code, _, err) =
            run_with(command(&home, &["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key]), vec![], LIMIT);
        assert_eq!(code, Some(0), "{err}");
        let port = runtime.block_on(ssh_harness::start(Path::new(&host_key)));
        let (node_home, client_home) = (home.join("node"), home.join("client"));
        for dir in [&node_home, &client_home] {
            podssh_relay::cache::private_dir(dir).unwrap();
            store_pair(dir);
        }
        // The client's key of the end-to-end channel, made as a first run
        // makes it, and let in by the node.
        let client_key = client_home.join("client.key").to_string_lossy().into_owned();
        let loaded = file::load(&Place::File(PathBuf::from(&client_key)), &mut OsEntropy).expect("the client's key");
        let allow = node_home.join("allow");
        std::fs::write(&allow, format!("{} the test's client\n", loaded.identity.public().fingerprint())).unwrap();
        Some(Lab {
            runtime,
            derp,
            hosts,
            proxy,
            _broker: broker,
            ca: ca.to_string_lossy().into_owned(),
            target: format!("127.0.0.1:{port}"),
            allow: allow.to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            client_key,
            node_home,
            client_home,
        })
    }

    /// `podssh ARGS` in `home`, through the test's proxy, trusting its CA,
    /// with the two hosts of the road.
    fn podssh(&self, home: &Path, args: &[&str]) -> Command {
        let mut cmd = command(home, args);
        let proxy = self.proxy.url();
        cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("SSL_CERT_FILE", &self.ca);
        cmd.env("PODSSH_FILEHOSTS", format!("{FIRST},{NEXT}"));
        cmd
    }

    /// `podssh node lab TARGET --derp`, and its lines, once its broker's
    /// road is said.
    fn node(&self) -> (Node, Vec<String>) {
        let key = self.node_home.join("node.key").to_string_lossy().into_owned();
        let servers = self.derp.server();
        let words = ["node", "lab", &self.target, "--allow", &self.allow, "--key", &key, "--ca-file", &self.ca];
        let mut cmd = self.podssh(&self.node_home, &words);
        cmd.args(["--derp", "--derp-server", &servers]);
        let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("node: {line}");
                let _ = tx.send(line);
            }
        });
        let node = Node(child);
        // The broker's line of Q78 comes after the road's own.
        let seen = wait_for(&lines, "a public MQTT broker that nobody vouches for");
        (node, seen)
    }

    /// `podssh ssh` from the client's home, its DERP road off.
    fn ssh(&self, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["-o", "ConnectTimeout=1200", "--ca-file", &self.ca, "--client-key", &self.client_key]);
        args.extend_from_slice(words);
        let mut cmd = self.podssh(&self.client_home, &args);
        cmd.env("PODSSH_DERP", "no");
        cmd
    }
}

#[test]
fn a_session_of_ssh_goes_through_the_file_hosts_and_the_broker_with_equal_digests() {
    let Some(lab) = Lab::new("session") else { return };
    let (_node, started) = lab.node();
    let said = started.join("\n");
    assert!(said.contains("nobody vouches for"), "the node's line of Q78 for the broker: {said}");

    let sent = pattern(SIZE);
    let started = Instant::now();
    let (code, out, err) = run_with(lab.ssh(&["-v", "node://tester@lab", "cat"]), sent.clone(), SESSION_LIMIT);
    let took = started.elapsed();
    let record = lab.hosts.record(|r| format!("{r:#?}").chars().take(4000).collect::<String>());
    let asked = format!("asked {:?}, refused {:?}", lab.proxy.asked.lock().unwrap(), lab.proxy.refused.lock().unwrap());
    assert_eq!(code, Some(0), "{err}\n{record}\n{asked}");
    assert_eq!(out.len(), SIZE, "{err}");
    assert_eq!(Sha256::digest(&out), Sha256::digest(&sent), "each byte came back once, in order");
    assert!(err.contains("the file-host road answered first"), "the race gave it to the road: {err}");
    assert!(err.contains("nobody vouches for"), "the client's lines of Q78: {err}");
    eprintln!("256 KiB each way through the file hosts' road in {} s", took.as_secs());

    lab.hosts.record(|r| {
        let count = |map: &HashMap<String, usize>, id: &str| map.get(id).copied().unwrap_or_default();
        assert!(r.strange.is_empty(), "requests that no form explains: {:#?}", r.strange);
        assert_eq!(count(&r.uploads, FIRST), BUSY_AFTER, "the first host until it was busy: {r:#?}");
        assert!(count(&r.busy, FIRST) >= 1, "the first host answered 429: {r:#?}");
        assert!(count(&r.uploads, NEXT) >= 1, "the next host took the next pieces: {r:#?}");
        assert!(count(&r.fetches, FIRST) >= 1 && count(&r.fetches, NEXT) >= 1, "each host's pieces read: {r:#?}");
        assert!(count(&r.deletes, NEXT) >= 1, "a piece read at a host that deletes was deleted: {r:#?}");
        assert_eq!(r.bad_deletes, 0, "each delete with the piece's own token");
        assert_eq!((r.pages, r.missing), (0, 0), "no page for a file, no file twice: {r:#?}");
        // Each piece that the host that deletes lost was deleted by the
        // reader, and nothing else took one away.
        let gone = r.ever.iter().filter(|(url, k)| k.id == NEXT && !r.kept.contains_key(*url)).count();
        assert_eq!(gone, count(&r.deletes, NEXT), "{r:#?}");
        // No host holds a run of the plaintext: the pieces are sealed (and
        // the channel and SSH run above them).
        for kept in r.ever.values() {
            for at in (0..SIZE - 64).step_by(4096) {
                let run = &sent[at..at + 64];
                assert!(!kept.bytes.windows(64).any(|w| w == run), "plaintext at {} at offset {at}", kept.id);
            }
        }
    });
    let refused = lab.proxy.refused.lock().unwrap().clone();
    eprintln!("the proxy refused {refused:?} (roads that the test did not stand in for)");
    drop(lab.runtime);
}

#[test]
fn a_bad_podssh_filehosts_is_refused_with_78_at_each_end_before_anything_connects() {
    // No broker or host is needed: each end refuses before a connection.
    let home = scratch("refusals");
    let (node_home, client_home) = (home.join("node"), home.join("client"));
    for dir in [&node_home, &client_home] {
        podssh_relay::cache::private_dir(dir).unwrap();
        store_pair(dir);
    }
    let allow = node_home.join("allow");
    std::fs::write(&allow, "# no client\n").unwrap();
    let allow = allow.to_string_lossy().into_owned();
    let started = Instant::now();
    let bad = |mut cmd: Command| {
        cmd.env("PODSSH_FILEHOSTS", "tmpfiles-org,elsewhere").env("HTTPS_PROXY", "http://127.0.0.1:9");
        run_with(cmd, Vec::new(), LIMIT)
    };
    let node = ["node", "lab", "127.0.0.1:22", "--allow", allow.as_str(), "--derp", "--derp-server", "127.0.0.1:9"];
    let (code, _, err) = bad(command(&node_home, &node));
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("PODSSH_FILEHOSTS: ") && err.contains("elsewhere"), "{err}");
    let (code, out, err) = bad(command(&client_home, &["ssh", "-o", "BatchMode=yes", "node://tester@lab", "true"]));
    assert_eq!(code, Some(78), "{err}");
    assert!(out.is_empty() && err.contains("PODSSH_FILEHOSTS: ") && err.contains("elsewhere"), "{err}");
    assert!(started.elapsed() < LIMIT, "each refusal came before any connection");
}
