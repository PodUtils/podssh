//! The Serveo road of the command line from end to end (T-549), on this
//! machine's loopback: a stand-in of Serveo's server (`serveo_stand_in`),
//! written from Serveo's documents; a stand-in proxy of the node's and the
//! client's that takes a CONNECT to the server's name on 443 and 22 alone, as
//! a cage whose proxy passes them and nothing else (and, when asked, refuses
//! 443); an SSH server for the node's TARGET; `podssh node lab TARGET
//! --serveo --allow FILE`, whose alias the test computes from the node's key
//! apart from podssh's code; and `podssh ssh node://tester@lab greet` with
//! the pair's road down and the node's key named by `--node-key`, then by
//! the pins: the race goes to Serveo last, and stderr names the third party.
//! A mebibyte goes each way under the channel. An alias that Serveo holds
//! sends the node to the next of its series, where the client finds it; a
//! stranger at the alias is refused by the end-to-end channel. A node with no
//! pair, the Pinggy road off or reaching no server, serves the road unasked
//! (Q78). Planted: the alias not derived from the key
//! (`scripts/plants/t549-alias-not-of-key.patch`), and the test of the
//! node's alias fails.

mod cleanup;
mod serveo_stand_in;
mod ssh_harness;

use std::io::{BufRead, BufReader, Write};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use podssh_relay::identity::file::{self, Place};
use podssh_relay::session::OsEntropy;
use serveo_stand_in::{StandIn, SERVER};
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);

/// The alias `k` of a key's fingerprint, written here apart from podssh's
/// code from the derivation that T-549 records: `p`, then the hex of the
/// first 20 bytes of SHA-256 over the context, the fingerprint and `k`.
fn alias_of(fingerprint: &str, k: u8) -> String {
    let mut bytes = b"podssh serveo alias v1\0".to_vec();
    bytes.extend_from_slice(fingerprint.as_bytes());
    bytes.push(k);
    let digest = Sha256::digest(&bytes);
    format!("p{}", digest[..20].iter().map(|b| format!("{b:02x}")).collect::<String>())
}

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-serveo-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's server
/// and proxy, and none of the settings of the machine that runs the test.
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
    cmd.env("PODSSH_SERVEO", SERVER);
    // The roads of the test alone: no OpenTunnel, no Pinggy, no transit
    // relay, no Piping Server, no record at n0's server of pkarr, no ssh-j.
    cmd.env("PODSSH_OPENTUNNEL", "no").env("PODSSH_PINGGY", "no").env("PODSSH_TRANSIT", "no");
    cmd.env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off").env("PODSSH_SSH_J", "no").env("PODSSH_CROC", "no");
    // Nor the last roads of all (Q78): localhost.run (T-565), localtunnel (T-568), bore (T-569).
    cmd.env("PODSSH_LOCALHOST_RUN", "no").env("PODSSH_SANDHOLE", "no");
    cmd.env("PODSSH_SRV_US", "no").env("PODSSH_TUNNL_GG", "no");
    cmd.env("PODSSH_LOCALTUNNEL", "no").env("PODSSH_HOSTC", "no").env("PODSSH_SMEE", "no").env("PODSSH_BORE", "no");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Run `podssh ARGS` to its end, within the limit, with `stdin` as its
/// input: (code, stdout, stderr). Both pipes are read while it runs.
fn run_with(cmd: &mut Command, stdin: Stdio) -> (i32, String, String) {
    let mut child = cmd.stdin(stdin).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
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

fn run(cmd: &mut Command) -> (i32, String, String) {
    run_with(cmd, Stdio::null())
}

/// Kills the node when the test ends.
struct Node(Child);

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The stand-in proxy: a CONNECT to the server's name on 443 or 22 goes to
/// its SSH port, each other is refused, and 443 too while `no_443` is set.
async fn proxy(ssh: u16, no_443: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let no_443 = no_443.clone();
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let passed = match (request.method.as_str(), target) {
                    ("CONNECT", Ok((host, 443))) => host == SERVER && !no_443.load(Ordering::SeqCst),
                    ("CONNECT", Ok((host, 22))) => host == SERVER,
                    _ => false,
                };
                if !passed {
                    let words = "this proxy passes the service's name alone";
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
    no_443: Arc<AtomicBool>,
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
        let no_443 = Arc::new(AtomicBool::new(false));
        let proxy_port = runtime.block_on(async { proxy(stand_in.listen().await, no_443.clone()).await });
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
            no_443,
            target: format!("127.0.0.1:{port}"),
            client_key: client_home.join("client.key").to_string_lossy().into_owned(),
            known: client_home.join("known_hosts").to_string_lossy().into_owned(),
            node_home,
            client_home,
            allow,
        }
    }

    /// The fingerprint of the node key `key`, made here when it is missing,
    /// as the node then loads it.
    fn node_key(&self, key: &str) -> String {
        let place = Place::File(self.node_home.join(key));
        file::load(&place, &mut OsEntropy).expect("the node's key").identity.public().fingerprint()
    }

    /// `podssh node lab TARGET` with `extra`, the node key `key` and `env`:
    /// the node, its lines up to its alias's, and the alias.
    fn node(&self, key: &str, extra: &[&str], env: &[(&str, &str)]) -> (Node, Vec<String>, String) {
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
        let deadline = Instant::now() + LIMIT;
        let mut seen = Vec::new();
        loop {
            match lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line) if line.contains(": alias ") => {
                    let alias = line.split(": alias ").nth(1).unwrap().split_whitespace().next().unwrap().to_string();
                    seen.push(line);
                    return (node, seen, alias);
                }
                Ok(line) => seen.push(line),
                Err(_) => panic!("no alias from the node within {} s: {seen:#?}", LIMIT.as_secs()),
            }
        }
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

    /// The client's cache, where its pair and its pins are.
    fn cache(&self) -> PathBuf {
        let cache = self.client_home.join("cache").join("podssh");
        podssh_relay::cache::private_dir(&cache).unwrap();
        cache
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
        podssh_relay::pair::store_in_first(&[self.cache()], "lab", &pair).expect("the pair stored");
    }
}

// The cases, apart from the lab for the length of this file.
mod serveo_cases;
