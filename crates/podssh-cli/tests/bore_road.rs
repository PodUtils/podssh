//! The bore road of the command line from end to end (T-569), on this
//! machine's loopback: the relay's stand-in of bore's server
//! (`bore_stand_in`, from bore's source), behind a stand-in proxy of the
//! node's and the client's that takes a CONNECT to the server's name, at its
//! control port and at each public port, or refuses the public ports, as a
//! proxy that allows 443 alone refuses each port but its own; an SSH server
//! for the node's TARGET; `podssh node lab TARGET --bore --allow FILE`,
//! whose ports at the server its key gives, and `podssh ssh
//! node://tester@lab greet` with the pair's road down, which derives the
//! same ports from the node's key (`--node-key`) and reaches it last of all;
//! stderr names the third party. 1 MiB comes down whole. A client whose
//! proxy refuses the port, with no forwarder, says why; a node with no pair
//! and each other road off serves the road unasked (Q78); the switches turn
//! it off. UNVERIFIED until it runs.

#[path = "../../podssh-relay/tests/bore_stand_in/mod.rs"]
mod bore_stand_in;
mod cleanup;
mod ssh_harness;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use bore_stand_in::StandIn;
use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);
/// The server's name, which the stand-in proxy alone resolves.
const SERVER: &str = "bore.stand-in.test";

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-bore-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's
/// server and proxy, the roads of the test alone, and none of the settings
/// of the machine that runs the test.
fn command(home: &Path, proxy: u16, server: &str, args: &[&str]) -> Command {
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
    cmd.env("PODSSH_BORE", server);
    // No other road, no public forwarder and no record at n0's server.
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_PINGGY", "no").env("PODSSH_SERVEO", "no");
    cmd.env("PODSSH_SSH_J", "no");
    // Nor the last roads before this one (Q78): localhost.run (T-565), localtunnel (T-568).
    cmd.env("PODSSH_LOCALHOST_RUN", "no")
        .env("PODSSH_SANDHOLE", "no")
        .env("PODSSH_LOCALTUNNEL", "no")
        .env("PODSSH_HOSTC", "no")
        .env("PODSSH_SMEE", "no");
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("PODSSH_FORWARDER_FALLBACK", "no");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit: (code, stdout, stderr).
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

/// The stand-in proxy: a CONNECT to the server's name goes to that port of
/// the loopback; with `refuse`, only to the control port `control`.
async fn proxy(control: u16, refuse: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let refuse = refuse.clone();
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let to = match (request.method.as_str(), target) {
                    ("CONNECT", Ok((host, port))) if host == SERVER => port,
                    _ => 0,
                };
                if to == 0 || (to != control && refuse.load(Ordering::SeqCst)) {
                    let words = "this proxy passes the server's name alone, and with refuse its control port alone";
                    let _ = tcp.write_all(&podssh_ws::http::request::refusal(403, words, &[])).await;
                    return;
                }
                let Ok(mut far) = TcpStream::connect((Ipv4Addr::LOCALHOST, to)).await else { return };
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
    _stand_in: StandIn,
    proxy: u16,
    server: String,
    refuse: Arc<AtomicBool>,
    target: String,
    node_home: PathBuf,
    client_home: PathBuf,
    allow: PathBuf,
    client_key: String,
    known: String,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let home = scratch(name);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let stand_in = runtime.block_on(StandIn::start(None, 1024..=65535, Duration::from_millis(100)));
        let refuse = Arc::new(AtomicBool::new(false));
        let proxy_port = runtime.block_on(proxy(stand_in.port, refuse.clone()));
        let server = format!("{SERVER}:{}", stand_in.port);
        let host_key = home.join("host_key");
        let host_key_text = host_key.to_string_lossy().into_owned();
        let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text];
        let (rc, _, err) = run(&mut command(&home, proxy_port, &server, &keygen));
        assert_eq!(rc, 0, "{err}");
        let port = runtime.block_on(ssh_harness::start(&host_key));
        let (node_home, client_home) = (home.join("node"), home.join("client"));
        for dir in [&node_home, &client_home] {
            podssh_relay::cache::private_dir(dir).unwrap();
        }
        let allow = node_home.join("allow");
        std::fs::write(&allow, "# the client keys that may come in\n").unwrap();
        let client_key = client_home.join("client.key").to_string_lossy().into_owned();
        let known = client_home.join("known_hosts").to_string_lossy().into_owned();
        let target = format!("127.0.0.1:{port}");
        Lab {
            runtime,
            _stand_in: stand_in,
            proxy: proxy_port,
            server,
            refuse,
            target,
            node_home,
            client_home,
            allow,
            client_key,
            known,
        }
    }

    fn command(&self, home: &Path, args: &[&str]) -> Command {
        command(home, self.proxy, &self.server, args)
    }

    /// `podssh node lab TARGET` with `extra` and `env`; the node, its lines
    /// once it named its port, and the key that its line names.
    fn node(&self, extra: &[&str], env: &[(&str, &str)]) -> (Node, Vec<String>, String) {
        let key = self.node_home.join("node.key").to_string_lossy().into_owned();
        let allow = self.allow.to_string_lossy().into_owned();
        let mut args = vec!["node", "lab", self.target.as_str(), "--allow", allow.as_str(), "--key", key.as_str()];
        args.extend_from_slice(extra);
        let mut cmd = self.command(&self.node_home, &args);
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
        let seen = wait_for(&lines, ": bore port ");
        let line = seen.last().unwrap();
        let key = line.split("--node-key ").nth(1).unwrap().trim_end_matches(')').to_string();
        assert!(key.starts_with("SHA256:"), "{line}");
        // The rest of the node's lines go nowhere, so that its pipe never fills.
        std::thread::spawn(move || for _ in lines.iter() {});
        (node, seen, key)
    }

    fn ssh(&self, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--client-key", &self.client_key]);
        args.extend_from_slice(words);
        self.command(&self.client_home, &args)
    }

    /// Let the client's key in, as the node's operator does.
    fn let_in(&self) {
        let key = file::load(&Place::File(PathBuf::from(&self.client_key)), &mut OsEntropy).expect("the key");
        let mut list = std::fs::OpenOptions::new().append(true).open(&self.allow).unwrap();
        writeln!(list, "{} the test's client", key.identity.public().fingerprint()).unwrap();
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
fn with_the_pair_s_road_down_the_race_gives_the_session_to_bore_at_a_port_of_the_node_s_key() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let (_node, lines, key) = lab.node(&["--bore"], &[]);
    assert!(lines.iter().any(|l| l.contains("nobody vouches for") && l.contains("raw TCP")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains("over the bore road alone")), "{lines:#?}");

    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--node-key", &key, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the bore road answered first"), "{err}");
    assert!(err.contains("a third party that nobody vouches for"), "the line of Q78: {err}");
    assert!(err.contains("when each road before it failed (the node's key"), "last of all: {err}");

    // 1 MiB down, whole.
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &key, "node://tester@lab", "source 1048576"]));
    assert_eq!((rc, out.len()), (0, 1 << 20), "{err}");

    // PODSSH_LAST_RESORT=no: the pair's road alone, which fails.
    let (rc, out, err) = run(lab.ssh(&["node://tester@lab", "greet"]).env("PODSSH_LAST_RESORT", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("bore road"), "no bore road with PODSSH_LAST_RESORT=no: {err}");
    drop(lab.runtime);
}

/// A proxy that allows its control port alone, as one that allows 443 alone
/// refuses each other: with no forwarder, the road says why.
#[test]
fn a_client_whose_proxy_refuses_the_port_says_why_and_names_the_forwarders() {
    let lab = Lab::new("refused");
    lab.let_in();
    lab.pair_down();
    let (_node, _, key) = lab.node(&["--bore"], &[]);
    lab.refuse.store(true, Ordering::SeqCst);
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &key, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(err.contains("no port of the node's key"), "{err}");
    assert!(err.contains("PODSSH_FORWARDER_FALLBACK=no keeps the forwarders out"), "{err}");
    drop(lab.runtime);
}

#[test]
fn a_node_with_no_pair_and_each_other_road_off_serves_bore_unasked_and_names_the_third_party() {
    let lab = Lab::new("unasked");
    let (_node, lines, _) = lab.node(&[], &[("PODSSH_DERP", "no")]);
    let unasked = lines.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(unasked.contains("PODSSH_SSH_J=no turns the ssh-j road off") && unasked.contains("the last"), "{unasked}");
    for road in
        ["PODSSH_LOCALHOST_RUN=no turns the localhost.run road off", "PODSSH_LOCALTUNNEL=no turns the localtunnel"]
    {
        assert!(unasked.contains(road), "{road}: {unasked}");
    }
    assert!(lines.iter().any(|l| l.contains("nobody vouches for") && l.contains("PODSSH_BORE=no")), "{lines:#?}");
    drop(lab.runtime);
}

#[test]
fn the_switches_turn_the_road_off_before_anything_connects() {
    let lab = Lab::new("switches");
    let allow = lab.allow.to_string_lossy().into_owned();
    for (var, value) in [("PODSSH_LAST_RESORT", "no"), ("PODSSH_BORE", "no")] {
        let mut cmd = lab.command(&lab.node_home, &["node", "lab", &lab.target, "--bore", "--allow", &allow]);
        cmd.env(var, value);
        let (rc, out, err) = run(&mut cmd);
        assert_eq!(rc, 64, "{var}: stdout {out:?}, stderr {err}");
        assert!(err.contains(&format!("{var}=no turns the bore road off")), "{err}");
    }
    let words = ["node", "lab", &lab.target, "--bore", "--ssh-j", "--allow", &allow];
    let (rc, _, err) = run(&mut lab.command(&lab.node_home, &words));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--ssh-j"), "{err}");
    drop(lab.runtime);
}
