//! The ssh-j road of the command line from end to end (T-570), on this
//! machine's loopback: a stand-in of ssh-j.com (`ssh_j_stand_in`), a public
//! SSH jump server where a remote forward names a port and `ssh -J` reaches
//! it by name, under the user that holds it; a stand-in proxy of the node's
//! and the client's that takes a CONNECT to the server's name on port 22
//! alone, or refuses it; an SSH server for the node's TARGET; `podssh node
//! lab TARGET --ssh-j --allow FILE`, whose user and name at the server its
//! key gives, and `podssh ssh node://tester@lab greet` with the pair's road
//! down, which derives the same name from the node's key (`--node-key`, or
//! the pins of NAME) and reaches it last of all; stderr names the third
//! party. 1 MiB comes down whole. Another key finds another name, and no
//! node; a stranger at the name is refused by the end-to-end channel; a node
//! whose session the server cut holds its name again; a node with no pair
//! and each other road off serves the road unasked (Q78). Planted: the name
//! not derived from the key (`scripts/plants/t570-name-of-no-key.patch`),
//! and the test of the client's name fails.

mod cleanup;
mod ssh_harness;
mod ssh_j_stand_in;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use ssh_j_stand_in::{Key, StandIn, SERVER};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-ssh-j-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's
/// server and the stand-in proxy, the roads of the test alone, and none of
/// the settings of the machine that runs the test.
fn command(home: &Path, proxy: u16, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_DERP", "PODSSH_DERP_SERVER", "PODSSH_RELAY", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    for name in ["SSL_CERT_FILE", "SSH_AUTH_SOCK", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "http_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env_remove("PODSSH_LAST_RESORT");
    let proxy = format!("http://127.0.0.1:{proxy}");
    cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("HTTP_PROXY", &proxy);
    cmd.env("PODSSH_SSH_J", SERVER);
    // The bore road, which a node that ssh-j's road reached nothing for would serve next (T-569).
    cmd.env("PODSSH_BORE", "no");
    // No other road, no public forwarder and no record at n0's server.
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_PINGGY", "no").env("PODSSH_SERVEO", "no");
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("PODSSH_FORWARDER_FALLBACK", "no");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit: (code, stdout, stderr),
/// both pipes read while it runs.
fn run(cmd: &mut Command) -> (i32, String, String) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let drain = |mut pipe: Box<dyn std::io::Read + Send>| {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            String::from_utf8_lossy(&bytes).into_owned()
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap())), drain(Box::new(child.stderr.take().unwrap())));
    let deadline = Instant::now() + LIMIT;
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("podssh did not end within {} s; it said: {}", LIMIT.as_secs(), err.join().unwrap_or_default());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let code = child.wait().expect("wait").code().unwrap_or(-1);
    (code, out.join().unwrap_or_default(), err.join().unwrap_or_default())
}

/// Kills the node when the test ends.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The lines of the node's stderr up to the first that holds `needle`.
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

/// The stand-in proxy: a CONNECT to the server's name on port 22 goes to
/// its port, unless `refuse` is set, as a proxy that refuses port 22; each
/// other is refused.
async fn proxy(ssh: u16, refuse: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let refuse = refuse.clone();
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let passed = matches!((request.method.as_str(), target), ("CONNECT", Ok((host, 22))) if host == SERVER);
                if !passed || refuse.load(Ordering::SeqCst) {
                    let words = "this proxy passes the server's name on port 22 alone";
                    let _ = tcp.write_all(&podssh_ws::http::request::refusal(403, words, &[])).await;
                    return;
                }
                let Ok(mut far) = TcpStream::connect((Ipv4Addr::LOCALHOST, ssh)).await else { return };
                let _ = tcp.write_all(&podssh_ws::http::request::established()).await;
                if !rest.is_empty() && far.write_all(&rest).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut far).await;
            });
        }
    });
    port
}

/// The place of one test: its runtime, which serves the stand-in, the proxy
/// and the SSH server; the node's home and the client's.
struct Lab {
    runtime: tokio::runtime::Runtime,
    stand_in: Arc<StandIn>,
    proxy: u16,
    /// Whether the proxy refuses port 22.
    refuse: Arc<AtomicBool>,
    target: String,
    node_home: PathBuf,
    client_home: PathBuf,
    allow: PathBuf,
    client_key: String,
    known: String,
}

/// What a node said of its road: its name at the server and its key.
struct Said {
    lines: mpsc::Receiver<String>,
    name: Key,
    key: String,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let home = scratch(name);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let stand_in = Arc::new(StandIn::default());
        let refuse = Arc::new(AtomicBool::new(false));
        let proxy_port = runtime.block_on(async { proxy(stand_in.listen().await, refuse.clone()).await });
        let host_key = home.join("host_key");
        let host_key_text = host_key.to_string_lossy().into_owned();
        let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text];
        let (rc, _, err) = run(&mut command(&home, proxy_port, &keygen));
        assert_eq!(rc, 0, "{err}");
        let port = runtime.block_on(ssh_harness::start(&host_key));
        let (node_home, client_home) = (home.join("node"), home.join("client"));
        for dir in [&node_home, &client_home] {
            podssh_relay::cache::private_dir(dir).unwrap();
        }
        let allow = node_home.join("allow");
        std::fs::write(&allow, "# the client keys that may come in\n").unwrap();
        Lab {
            runtime,
            stand_in,
            proxy: proxy_port,
            refuse,
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    /// `podssh node lab TARGET` with `extra`, the node key `key` and `env`;
    /// the node, and what it said once it named its road.
    fn node(&self, key: &str, extra: &[&str], env: &[(&str, &str)]) -> (Node, Said) {
        let (key, allow) = (self.node_home.join(key), self.allow.to_string_lossy().into_owned());
        let key = key.to_string_lossy().into_owned();
        let mut args = vec!["node", "lab", self.target.as_str(), "--allow", allow.as_str(), "--key", key.as_str()];
        args.extend_from_slice(extra);
        let mut cmd = command(&self.node_home, self.proxy, &args);
        cmd.envs(env.iter().copied());
        let mut child = cmd.stdin(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let node = Node(child);
        let seen = wait_for(&lines, ": ssh-j name ");
        let line = seen.last().unwrap();
        let named = line.split(": ssh-j name ").nth(1).unwrap().split_whitespace().next().unwrap();
        let (user, address) = named.split_once('@').expect("USER@ADDRESS");
        let name = (user.to_string(), address.to_string(), 22);
        let key = line.split("--node-key ").nth(1).unwrap().trim_end_matches(')').to_string();
        assert!(key.starts_with("SHA256:"), "{line}");
        // The lines before the name, for a test that reads them.
        let (tx, earlier) = mpsc::channel();
        for line in seen {
            let _ = tx.send(line);
        }
        std::thread::spawn(move || {
            for line in lines.iter() {
                let _ = tx.send(line);
            }
        });
        (node, Said { lines: earlier, name, key })
    }

    /// `podssh ssh` from the client's home, with its key and known hosts.
    fn ssh(&self, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--client-key", &self.client_key]);
        args.extend_from_slice(words);
        command(&self.client_home, self.proxy, &args)
    }

    /// Let the client's key in, as the node's operator does.
    fn let_in(&self) {
        let key = file::load(&Place::File(PathBuf::from(&self.client_key)), &mut OsEntropy).expect("the key");
        let mut list = std::fs::OpenOptions::new().append(true).open(&self.allow).unwrap();
        writeln!(list, "{} the test's client", key.identity.public().fingerprint()).unwrap();
    }

    /// The client's pins of `lab`, as an earlier session leaves them.
    fn pin(&self, key: &str) {
        let cache = self.client_home.join("cache").join("podssh");
        podssh_relay::cache::private_dir(&cache).unwrap();
        std::fs::write(cache.join("known-nodes"), format!("lab {key}\n")).unwrap();
    }

    /// A pair of the client's under `lab` whose relay is a port of the
    /// loopback where nothing listens, so the pair's road fails at once.
    fn pair_down(&self) {
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
        let cache = self.client_home.join("cache").join("podssh");
        podssh_relay::pair::store_in_first(&[cache], "lab", &pair).expect("the pair stored");
    }
}

#[test]
fn with_the_pair_s_road_down_the_race_gives_the_session_to_ssh_j_by_the_name_of_the_node_s_key() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let (_node, said) = lab.node("node.key", &["--ssh-j"], &[]);
    let lines: Vec<String> = said.lines.try_iter().collect();
    assert!(lines.iter().any(|l| l.contains("nobody vouches for") && l.contains("Q78")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains("host key") && l.contains("unpinned")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains("over the ssh-j road alone")), "{lines:#?}");
    assert!(said.name.0.starts_with("podssh-") && said.name.1.starts_with('n'), "{:?}", said.name);
    assert_eq!(lab.stand_in.users(), vec![said.name.0.clone()], "the user that the node's key gives");
    assert_eq!(lab.stand_in.forwards(), vec![said.name.clone()], "one forward, of the key's name, on port 22");

    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--node-key", &said.key, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the ssh-j road answered first"), "{err}");
    assert!(err.contains("a third party that nobody vouches for"), "the line of Q78: {err}");
    assert!(err.contains("when each road before it failed (the node's key"), "last of all: {err}");
    assert_eq!(lab.stand_in.opens().last(), Some(&said.name), "the client derived the node's name");

    // 1 MiB down, whole.
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &said.key, "node://tester@lab", "source 1048576"]));
    assert_eq!((rc, out.len()), (0, 1 << 20), "{err}");

    // No --node-key: the key that the pins of NAME hold.
    lab.pin(&said.key);
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    assert!(err.contains("the ssh-j road answered first"), "{err}");

    // PODSSH_LAST_RESORT=no: the pair's road alone, which fails.
    let (rc, out, err) = run(lab.ssh(&["node://tester@lab", "greet"]).env("PODSSH_LAST_RESORT", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("ssh-j"), "no ssh-j road with PODSSH_LAST_RESORT=no: {err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 1, "one forward for the node");
    drop(lab.runtime);
}

/// The test of the client's name (T-570's Prove): another key gives another
/// user and another address, where no node is, so the road finds none; the
/// planted defect that derives the name from anything but the key makes the
/// two names one.
#[test]
fn a_client_derives_the_name_from_the_key_it_holds_and_another_key_finds_no_node() {
    let lab = Lab::new("name");
    lab.let_in();
    lab.pair_down();
    let (_node, said) = lab.node("node.key", &["--ssh-j"], &[]);
    let other = file::load(&Place::File(lab.client_home.join("other.key")), &mut OsEntropy).expect("a key");
    let other = other.identity.public().fingerprint();
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--node-key", &other, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(out.is_empty(), "{out:?}");
    assert!(err.contains("has no node at"), "the server refused the name: {err}");
    let asked = lab.stand_in.opens().last().cloned().expect("the client asked for a name");
    assert_ne!(asked.0, said.name.0, "another key, another user");
    assert_ne!(asked.1, said.name.1, "another key, another address");
    assert_eq!(lab.stand_in.visits.load(Ordering::SeqCst), 0, "nothing went down the node's forward");
    drop(lab.runtime);
}

/// The stand-in gives the node's name to another node's forward: the
/// client, which holds the first node's key, refuses the second by the
/// end-to-end channel, with no output of the stranger's.
#[test]
fn a_stranger_at_the_name_is_refused_by_the_end_to_end_channel() {
    let lab = Lab::new("stranger");
    lab.let_in();
    lab.pair_down();
    let (_node, said) = lab.node("node.key", &["--ssh-j"], &[]);
    let (_stranger, other) = lab.node("stranger.key", &["--ssh-j"], &[]);
    assert_ne!(other.name, said.name, "another key, another name");
    lab.stand_in.hijack(&said.name, &other.name);
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &said.key, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(out.is_empty(), "nothing of the stranger's: {out:?}");
    assert!(err.contains("refused the node"), "refused by the end-to-end channel: {err}");
    assert!(lab.stand_in.visits.load(Ordering::SeqCst) >= 1, "the stranger was reached, and refused");
    drop(lab.runtime);
}

/// The server's restart cuts each session and lets its names go: the node
/// holds its name again, and a client reaches it there.
#[test]
fn a_node_whose_session_the_server_cut_holds_its_name_again() {
    let lab = Lab::new("again");
    lab.let_in();
    lab.pair_down();
    let (_node, said) = lab.node("node.key", &["--ssh-j"], &[]);
    // The lines up to the first name, which the node said already.
    let _: Vec<String> = said.lines.try_iter().collect();
    lab.stand_in.cut_all();
    let again = wait_for(&said.lines, ": ssh-j name ");
    assert!(again.iter().any(|l| l.contains("ended; a new one, under the same name")), "{again:#?}");
    assert_eq!(lab.stand_in.forwards(), vec![said.name.clone(), said.name.clone()], "the same name again");
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &said.key, "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    drop(lab.runtime);
}

#[test]
fn a_node_with_no_pair_and_each_other_road_off_serves_ssh_j_unasked_and_names_the_third_party() {
    let lab = Lab::new("unasked");
    let (_node, said) = lab.node("node.key", &[], &[("PODSSH_DERP", "no")]);
    let lines: Vec<String> = said.lines.try_iter().collect();
    let unasked = lines.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(unasked.contains("PODSSH_PINGGY=no") && unasked.contains("the last"), "{unasked}");
    assert!(unasked.contains("PODSSH_SERVEO=no turns the Serveo road off"), "{unasked}");
    assert!(
        lines.iter().any(|l| l.contains("nobody vouches for") && l.contains("PODSSH_LAST_RESORT=no")),
        "{lines:#?}"
    );
    drop(lab.runtime);
}

#[test]
fn the_switches_turn_the_road_off_and_a_refused_port_22_says_why() {
    let lab = Lab::new("refused");
    for (var, value) in [("PODSSH_LAST_RESORT", "no"), ("PODSSH_SSH_J", "no")] {
        let mut cmd = command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target, "--ssh-j", "--allow"]);
        cmd.arg(&lab.allow).env(var, value);
        let (rc, out, err) = run(&mut cmd);
        assert_eq!(rc, 64, "{var}: stdout {out:?}, stderr {err}");
        assert!(err.contains(&format!("{var}=no turns the ssh-j road off")), "{err}");
    }
    let (rc, out, err) = run(&mut command(&lab.node_home, lab.proxy, &["node", "lab", &lab.target, "--ssh-j"]));
    assert_eq!(rc, 64, "stdout {out:?}, stderr {err}");
    assert!(err.contains("--ssh-j needs --allow FILE"), "{err}");
    let words = ["node", "lab", &lab.target, "--ssh-j", "--pinggy"];
    let (rc, _, err) = run(&mut command(&lab.node_home, lab.proxy, &words));
    assert_eq!(rc, 64, "{err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 0, "no forward made");

    // A proxy that refuses port 22, and no forwarder: the road says why.
    lab.let_in();
    lab.pair_down();
    let (_node, said) = lab.node("node.key", &["--ssh-j"], &[]);
    lab.refuse.store(true, Ordering::SeqCst);
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &said.key, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(err.contains("PODSSH_FORWARDER_FALLBACK=no keeps the forwarders out"), "{err}");
    drop(lab.runtime);
}
