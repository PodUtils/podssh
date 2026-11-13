//! The road of a tunnel of HTTP made by `ssh -R` from end to end (T-565),
//! localhost.run's, on this machine's loopback: a stand-in of localhost.run
//! (`ssh_tunnel_http_stand_in`), whose SSH server takes a remote forward of
//! port 80 and names an HTTPS name on the session, and whose edge ends a
//! visitor's TLS and sends plain HTTP down the tunnel; a stand-in proxy of
//! the node's and the client's that takes a CONNECT to the server's name on
//! port 22 and to the tunnels' names on 443 alone; an SSH server for the
//! node's TARGET; `podssh node lab TARGET --localhost-run --allow FILE`, and
//! `podssh ssh node://tester@lab --tunnel-url https://NAME greet` with the
//! pair's road down: the race goes to the tunnel's WebSocket, and stderr
//! names the third party. 1 MiB comes down whole; a later run with no name
//! dials the one kept, last; `PODSSH_LAST_RESORT=no` turns that off. With
//! `--relay`, a request of the role's path through the tunnel gets the
//! role's answer, and another path 404. A stranger at the name is refused
//! by the end-to-end channel; a new name of the tunnel is said and carries
//! the next session; a node with no pair and each other road off serves the
//! road unasked (Q78). As Sandhole (T-743): a key made for the login alone,
//! a name under the server's own, and port 443 refused before 22. As srv.us
//! (T-566): `ssh_tunnel_http_words`. Planted: a visitor's request of the role's path never
//! given to the role (`scripts/plants/t565-role-not-taken.patch`), and the
//! test of the role's contract fails.

mod cleanup;
mod ssh_harness;
mod ssh_tunnel_http_stand_in;
// The tests of srv.us's word (T-566), apart for the length of this file.
mod ssh_tunnel_http_words;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use ssh_harness::GREETING;
use ssh_tunnel_http_stand_in::{StandIn, SERVER, ZONE};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-ssh-tunnel-http-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's
/// server, its CA and the stand-in proxy, the roads of the test alone, and
/// none of the settings of the machine that runs the test.
fn command(home: &Path, proxy: u16, ca: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_DERP", "PODSSH_DERP_SERVER", "PODSSH_RELAY", "PODSSH_RELAY_ADDR"] {
        cmd.env_remove(name);
    }
    for name in ["SSH_AUTH_SOCK", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "http_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env_remove("PODSSH_LAST_RESORT");
    // The edge's TLS is the stand-in CA's, as localhost.run's is a public CA's.
    cmd.env("SSL_CERT_FILE", ca);
    let proxy = format!("http://127.0.0.1:{proxy}");
    cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("HTTP_PROXY", &proxy);
    cmd.env("PODSSH_LOCALHOST_RUN", SERVER).env("PODSSH_SANDHOLE", "no");
    // The word of srv.us (T-566), which its tests name.
    cmd.env("PODSSH_SRV_US", "no");
    // No other road, no public forwarder and no record at n0's server.
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_PINGGY", "no").env("PODSSH_SERVEO", "no").env("PODSSH_SSH_J", "no");
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("PODSSH_FORWARDER_FALLBACK", "no");
    // Nor the last roads after this one (Q78): localtunnel (T-568), bore (T-569).
    cmd.env("PODSSH_LOCALTUNNEL", "no").env("PODSSH_HOSTC", "no").env("PODSSH_SMEE", "no").env("PODSSH_BORE", "no");
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

/// The name of a line `... tunnel https://NAME (...)`.
fn name_of(line: &str) -> String {
    let after = line.split(": tunnel https://").nth(1).expect("a line of the tunnel");
    after.split_whitespace().next().unwrap().to_string()
}

/// The stand-in proxy: a CONNECT to the server's name on port 22 goes to
/// its SSH port, one to a tunnel's name on 443 to the edge; each other is
/// refused.
async fn proxy(ssh: u16, edge: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let to = match (request.method.as_str(), target) {
                    // The zone is the server of the Sandhole stand-in, whose tunnels are under it.
                    ("CONNECT", Ok((host, 22))) if host == SERVER || host == ZONE => ssh,
                    ("CONNECT", Ok((host, 443))) if host.ends_with(&format!(".{ZONE}")) => edge,
                    _ => {
                        let words = "this proxy passes the names of the service alone";
                        let _ = tcp.write_all(&podssh_ws::http::request::refusal(403, words, &[])).await;
                        return;
                    }
                };
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
    stand_in: Arc<StandIn>,
    proxy: u16,
    /// The edge's port of plain HTTP, which a test asks directly.
    http: u16,
    ca: PathBuf,
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
        let stand_in = Arc::new(StandIn::default());
        let (proxy_port, http, ca_pem) = runtime.block_on(async {
            let (ssh, https, http, ca) = stand_in.listen().await;
            (proxy(ssh, https).await, http, ca)
        });
        let ca = home.join("ca.pem");
        std::fs::write(&ca, ca_pem).unwrap();
        let host_key = home.join("host_key");
        let host_key_text = host_key.to_string_lossy().into_owned();
        let keygen = ["keygen", "-q", "-t", "ed25519", "-N", "", "-f", &host_key_text];
        let (rc, _, err) = run(&mut command(&home, proxy_port, &ca, &keygen));
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
            http,
            ca,
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    /// `podssh node lab TARGET --allow FILE --key KEY` with `extra` and
    /// `env`: the node, its lines up to the first name of its tunnel, and
    /// the receiver of its later lines.
    fn node(&self, key: &str, extra: &[&str], env: &[(&str, &str)]) -> (Node, Vec<String>, mpsc::Receiver<String>) {
        let (key, allow) = (self.node_home.join(key), self.allow.to_string_lossy().into_owned());
        let key = key.to_string_lossy().into_owned();
        let mut args = vec!["node", "lab", self.target.as_str(), "--allow", allow.as_str(), "--key", key.as_str()];
        args.extend_from_slice(extra);
        let mut cmd = command(&self.node_home, self.proxy, &self.ca, &args);
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
        let seen = wait_for(&lines, ": tunnel https://");
        (node, seen, lines)
    }

    /// The fingerprint of the node's key in the file `key`, once it ran.
    fn key_of(&self, key: &str) -> String {
        let key = file::load(&Place::File(self.node_home.join(key)), &mut OsEntropy).expect("the node's key");
        key.identity.public().fingerprint()
    }

    /// `podssh ssh` from the client's home, with its key and known hosts.
    fn ssh(&self, words: &[&str]) -> Command {
        let known = format!("UserKnownHostsFile={}", self.known);
        let mut args = vec!["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", &known];
        args.extend_from_slice(&["--client-key", &self.client_key]);
        args.extend_from_slice(words);
        command(&self.client_home, self.proxy, &self.ca, &args)
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

    /// `GET PATH` of the tunnel `name` on the edge's plain port: the answer.
    fn get(&self, name: &str, path: &str) -> String {
        self.runtime.block_on(async {
            let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, self.http)).await.unwrap();
            let ask = format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n");
            tcp.write_all(ask.as_bytes()).await.unwrap();
            let mut answer = Vec::new();
            let read = tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await;
            read.expect("an answer in time").unwrap();
            String::from_utf8_lossy(&answer).into_owned()
        })
    }
}

#[test]
fn with_the_pair_s_road_down_the_race_gives_the_session_to_the_tunnel_s_websocket() {
    let lab = Lab::new("race");
    lab.let_in();
    lab.pair_down();
    let (_node, lines, _) = lab.node("node.key", &["--localhost-run"], &[]);
    assert!(lines.iter().any(|l| l.contains("nobody vouches for") && l.contains("Q78")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains("host key") && l.contains("unpinned")), "{lines:#?}");
    assert!(lines.iter().any(|l| l.contains("over the localhost.run road alone")), "{lines:#?}");
    let name = name_of(lines.last().unwrap());
    assert_eq!(name, format!("t1.{ZONE}"), "the name of the line of the marker, not a host of the welcome");
    assert_eq!(lab.stand_in.users(), ["nokey"], "the user of a tunnel with no key");
    assert_eq!(lab.stand_in.forwards(), [("localhost".to_string(), 80)], "the forward of ssh -R 80:localhost:PORT");
    let url = format!("https://{name}");

    let (rc, out, err) = run(&mut lab.ssh(&["-v", "--tunnel-url", &url, "node://tester@lab", "greet"]));
    assert_eq!(rc, 0, "stdout {out:?}, stderr {err}");
    assert_eq!(out, GREETING, "the command's output over the road");
    assert!(err.contains("the localhost.run road answered first"), "{err}");
    assert!(err.contains("a third party that nobody vouches for"), "the line of Q78: {err}");

    // 1 MiB down, whole.
    let (rc, out, err) = run(&mut lab.ssh(&["--tunnel-url", &url, "node://tester@lab", "source 1048576"]));
    assert_eq!((rc, out.len()), (0, 1 << 20), "{err}");

    // No --tunnel-url: the name kept under NAME, last of all.
    let (rc, out, err) = run(&mut lab.ssh(&["-v", "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    assert!(err.contains("when each road before it failed (a kept name"), "{err}");

    // PODSSH_LAST_RESORT=no: the pair's road alone, which fails.
    let (rc, out, err) = run(lab.ssh(&["node://tester@lab", "greet"]).env("PODSSH_LAST_RESORT", "no"));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(!err.contains("localhost.run"), "no such road with PODSSH_LAST_RESORT=no: {err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 1, "one tunnel for the node");
    drop(lab.runtime);
}

/// The test of the role's contract (T-565's Prove): behind the tunnel, the
/// role answers its paths, and the node's WebSocket path refuses a request
/// with no upgrade. The planted defect gives no request to the role, so
/// its path meets the node's 404.
#[test]
fn with_relay_the_role_answers_its_paths_through_the_tunnel_and_another_path_is_404() {
    let lab = Lab::new("relay");
    let (_node, lines, _) = lab.node("node.key", &["--localhost-run", "--relay"], &[]);
    let name = name_of(lines.last().unwrap());
    let health = lab.get(&name, "/health");
    assert!(health.starts_with("HTTP/1.1 200 ") && health.contains("\"contract\""), "{health}");
    let other = lab.get(&name, "/index.html");
    assert!(other.starts_with("HTTP/1.1 404 "), "{other}");
    assert!(lab.stand_in.visits.load(Ordering::SeqCst) >= 2, "each request went down the tunnel");
    drop(lab.runtime);
}

/// The stand-in gives the node's name to another node's tunnel: the client,
/// which holds the first node's key, refuses the second by the end-to-end
/// channel, with no output of the stranger's.
#[test]
fn a_stranger_at_the_name_is_refused_by_the_end_to_end_channel() {
    let lab = Lab::new("stranger");
    lab.let_in();
    lab.pair_down();
    let (_node, lines, _) = lab.node("node.key", &["--localhost-run"], &[]);
    let (_stranger, others, _) = lab.node("stranger.key", &["--localhost-run"], &[]);
    let (name, other) = (name_of(lines.last().unwrap()), name_of(others.last().unwrap()));
    assert_ne!(name, other, "a tunnel each");
    lab.stand_in.hijack(&name, &other);
    let (key, url) = (lab.key_of("node.key"), format!("https://{name}"));
    let (rc, out, err) = run(&mut lab.ssh(&["--node-key", &key, "--tunnel-url", &url, "node://tester@lab", "greet"]));
    assert_eq!(rc, 255, "stdout {out:?}, stderr {err}");
    assert!(out.is_empty(), "nothing of the stranger's: {out:?}");
    assert!(err.contains("refused the node"), "refused by the end-to-end channel: {err}");
    drop(lab.runtime);
}

/// A free name changes: the node says the new one, and a client reaches it
/// there; the old name reaches nothing.
#[test]
fn a_new_name_of_the_tunnel_is_said_and_carries_the_next_session() {
    let lab = Lab::new("renamed");
    lab.let_in();
    lab.pair_down();
    let (_node, lines, rest) = lab.node("node.key", &["--localhost-run"], &[]);
    let name = name_of(lines.last().unwrap());
    let new = lab.runtime.block_on(lab.stand_in.rename(&name));
    let said = wait_for(&rest, ": tunnel https://");
    assert!(said.iter().any(|l| l.contains("gave the tunnel a new name")), "{said:#?}");
    assert_eq!(name_of(said.last().unwrap()), new);
    let url = format!("https://{new}");
    let (rc, out, err) = run(&mut lab.ssh(&["--tunnel-url", &url, "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    drop(lab.runtime);
}

#[test]
fn a_node_with_no_pair_and_each_other_road_off_serves_the_road_unasked_and_names_the_third_party() {
    let lab = Lab::new("unasked");
    let (_node, lines, _) = lab.node("node.key", &[], &[("PODSSH_DERP", "no")]);
    let unasked = lines.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(unasked.contains("PODSSH_SSH_J=no turns the ssh-j road off") && unasked.contains("the last"), "{unasked}");
    assert!(unasked.contains("PODSSH_PINGGY=no"), "{unasked}");
    let q78 = lines.iter().any(|l| l.contains("nobody vouches for") && l.contains("PODSSH_LAST_RESORT=no"));
    assert!(q78, "{lines:#?}");
    drop(lab.runtime);
}

#[test]
fn the_switches_turn_the_road_off_and_a_node_needs_a_door() {
    let lab = Lab::new("switches");
    for (var, value) in [("PODSSH_LAST_RESORT", "no"), ("PODSSH_LOCALHOST_RUN", "no")] {
        let words = ["node", "lab", &lab.target, "--localhost-run", "--allow"];
        let mut cmd = command(&lab.node_home, lab.proxy, &lab.ca, &words);
        cmd.arg(&lab.allow).env(var, value);
        let (rc, out, err) = run(&mut cmd);
        assert_eq!(rc, 64, "{var}: stdout {out:?}, stderr {err}");
        assert!(err.contains(&format!("{var}=no turns the localhost.run road off")), "{err}");
    }
    let words = ["node", "lab", &lab.target, "--localhost-run"];
    let (rc, out, err) = run(&mut command(&lab.node_home, lab.proxy, &lab.ca, &words));
    assert_eq!(rc, 64, "stdout {out:?}, stderr {err}");
    assert!(err.contains("--localhost-run needs --allow FILE"), "{err}");
    let words = ["node", "lab", &lab.target, "--localhost-run", "--ssh-j"];
    let (rc, _, err) = run(&mut command(&lab.node_home, lab.proxy, &lab.ca, &words));
    assert_eq!(rc, 64, "{err}");
    let (rc, _, err) = run(&mut lab.ssh(&["--tunnel-url", "http://x.lhr.life", "node://tester@lab", "true"]));
    assert_eq!(rc, 64, "{err}");
    assert!(err.contains("--tunnel-url"), "{err}");
    assert_eq!(lab.stand_in.made.load(Ordering::SeqCst), 0, "no tunnel made");
    drop(lab.runtime);
}

/// Sandhole's shape (T-743): the server asks for a key, any key, and names
/// tunnels under its own name; its port 443 is refused here, so the leg
/// takes 22. Each login's key is a new one, never the node's.
#[test]
fn as_sandhole_a_key_made_for_the_login_and_a_name_under_the_server_carry_the_session() {
    let lab = Lab::new("sandhole");
    lab.stand_in.sandhole.store(true, Ordering::SeqCst);
    lab.let_in();
    lab.pair_down();
    let env = [("PODSSH_SANDHOLE", ZONE), ("PODSSH_LOCALHOST_RUN", "no")];
    let (_node, lines, _) = lab.node("node.key", &["--sandhole"], &env);
    assert!(lines.iter().any(|l| l.contains("raw SSH on port 22, as tunnel")), "{lines:#?}");
    let name = name_of(lines.last().unwrap());
    assert_eq!(name, format!("t1.{ZONE}"), "a name under the server's own is the tunnel's");
    let (_other, _, _) = lab.node("other.key", &["--sandhole"], &env);
    assert_eq!(lab.stand_in.users(), ["tunnel", "tunnel"]);
    let keys = lab.stand_in.keys();
    assert!(keys.len() == 2 && keys[0] != keys[1], "a key for each login: {keys:?}");
    let url = format!("https://{name}");
    let (rc, out, err) = run(&mut lab.ssh(&["--tunnel-url", &url, "node://tester@lab", "greet"]));
    assert_eq!((rc, out.as_str()), (0, GREETING), "{err}");
    drop(lab.runtime);
}
