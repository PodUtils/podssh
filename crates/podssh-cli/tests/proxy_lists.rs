//! The public proxy nodes of the lists, last of all the forward road's
//! fallbacks (T-574, the operator's rulings Q78, Q79 and Q90), as a process:
//! `podssh ssh` with no road named, each relay host and each forwarder
//! refused, takes a VLESS node from a list and reaches the test's SSH server
//! through Xray-core, a server that podssh did not write (the release that
//! `scripts/interop-vless.sh` pins, its path in `PODSSH_XRAY_TEST_BIN`, set
//! by `proxy-lists-interop.yml`). Xray-core serves VLESS over a WebSocket and
//! TLS on the loopback, under a certificate that `openssl` makes for the run.
//!
//! podssh is pointed at the stand-ins by `https_proxy` and `--ca-file`
//! alone, as it would reach the lists and the nodes through a proxy: a front
//! proxy of this test sends the node's name to Xray-core's port as it is
//! (Xray-core's own TLS), and each other name to the proxy of
//! `cloud_support`, which re-terminates TLS with the test's CA. There the
//! first list of `pod-services`' catalog, at its own host and path, serves a
//! list of two lines: a node that fronts another name, which the filters of
//! Q79 must skip, and the node of Xray-core; each other name (the relay
//! hosts, the forwarders) gets 503. `--ca-file` holds both CAs.
//!
//! The test of Xray-core says "did not run" with no Xray-core, and the
//! workflow fails on it; the test of the two switches needs none.

mod cloud_support;
mod ssh_harness;

use std::io::Read;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cloud_support::{command, read_head, scratch, Handler, Proxy, Scratch, Stream};
use podssh_cli::forwarder::nodes::{List, PLAN};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

/// The bound of one run of podssh: each relay host, each forwarder and the
/// round together.
const LIMIT: Duration = Duration::from_secs(180);
/// A throwaway user of the test's own Xray-core, no credential.
const ID: &str = "6f1c2d3e-4b5a-4c6d-8e7f-9a0b1c2d3e4f";
/// The name of the node that carries, and the WebSocket's path.
const NODE: &str = "vless-node.test";
const WS_PATH: &str = "/pl";
/// A node whose SNI and `Host` are another name than its host: it fronts
/// `FRONTED`, and the filters must skip it before any dial.
const FRONTING: &str = "fronting-node.test";
const FRONTED: &str = "fronted-site.test";

/// Xray-core serving VLESS on the loopback; killed when the test ends.
struct Xray {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Xray {
    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("xray.log")).unwrap_or_default()
    }
}

fn openssl(dir: &Path, args: &[&str]) {
    let status = Command::new("openssl").args(args).current_dir(dir).stdout(Stdio::null()).status();
    assert!(status.map(|s| s.success()).unwrap_or(false), "openssl {args:?} failed");
}

/// The server in `dir`, its CA in `dir/ca.pem`, or `None` (and the words
/// "did not run") with no binary.
fn xray(dir: &Path) -> Option<Xray> {
    let Some(bin) = std::env::var_os("PODSSH_XRAY_TEST_BIN") else {
        println!("did not run: PODSSH_XRAY_TEST_BIN names no Xray-core (proxy-lists-interop.yml sets it)");
        return None;
    };
    std::fs::create_dir_all(dir).unwrap();
    // A root and a leaf: webpki takes no CA as the server's own certificate.
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
    let subj = ["-days", "2", "-subj", "/CN=proxy-lists-test-root"];
    openssl(dir, &[&["req", "-x509"][..], &ec, &["-keyout", "ca.key", "-out", "ca.pem"], &subj].concat());
    let cn = format!("/CN={NODE}");
    openssl(dir, &[&["req"][..], &ec, &["-keyout", "srv.key", "-out", "srv.csr", "-subj", cn.as_str()]].concat());
    std::fs::write(dir.join("leaf.cnf"), format!("subjectAltName=DNS:{NODE}\nbasicConstraints=CA:FALSE\n")).unwrap();
    let sign = ["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out"];
    openssl(dir, &[&sign[..], &["srv.pem", "-days", "2", "-extfile", "leaf.cnf"]].concat());
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let config = serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vless",
            "settings": {"clients": [{"id": ID}], "decryption": "none"},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "wsSettings": {"path": WS_PATH},
                "tlsSettings": {"alpn": ["http/1.1"], "certificates": [{
                    "certificateFile": dir.join("srv.pem"), "keyFile": dir.join("srv.key")
                }]}
            }
        }],
        // freedom blackholes a private target unless a final rule allows it
        // (`proxy/freedom/freedom.go`), and the test's server is the loopback.
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}]
    });
    std::fs::write(dir.join("config.json"), config.to_string()).unwrap();
    let log = std::fs::File::create(dir.join("xray.log")).unwrap();
    let child = Command::new(bin)
        .args(["run", "-c"])
        .arg(dir.join("config.json"))
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("Xray-core starts");
    let xray = Xray { child, dir: dir.to_path_buf(), port };
    let until = Instant::now() + Duration::from_secs(20);
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < until, "Xray-core did not listen: {}", xray.log());
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(xray)
}

/// A share line as the lists give one: VLESS over a WebSocket and TLS on
/// 443, its SNI and its `Host` named.
fn line(host: &str, sni: &str, name: &str) -> String {
    let query = format!("encryption=none&security=tls&type=ws&path=%2Fpl&sni={sni}&host={sni}");
    format!("vless://{ID}@{host}:443?{query}#{name}")
}

/// The list that the stand-in serves: the fronting node first, so that a
/// filter that kept it would dial it before the good one.
fn list_body() -> String {
    [line(FRONTING, FRONTED, "fronts"), line(NODE, NODE, "carries"), String::new()].join("\n")
}

/// The first list of the catalog, whose host and path the stand-in takes.
fn first_list() -> List {
    PLAN.lists.first().cloned().expect("pod-services names a list of the kind proxy-list")
}

/// The handler behind the intercepting proxy: the list at its host and
/// path, each GET of it counted in `served`; 503 to each other request, a
/// relay host's and a forwarder's.
fn handler(list: List, served: Arc<Mutex<usize>>) -> Handler {
    let body = Arc::new(list_body());
    Arc::new(move |host: String, mut tls: Stream| {
        let (list, body, served) = (list.clone(), body.clone(), served.clone());
        Box::pin(async move {
            // The request read whole first, so that the answer is not lost
            // to a reset of unread bytes.
            let Ok(head) = read_head(&mut tls).await else { return };
            let path = head.split_whitespace().nth(1).unwrap_or_default();
            let reply = if host == list.host && path == list.path && head.starts_with("GET ") {
                *served.lock().unwrap() += 1;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            } else {
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
            };
            let _ = tls.write_all(reply.as_bytes()).await;
            let _ = tls.shutdown().await;
        })
    })
}

/// The front proxy: each CONNECT kept in order; the node's name to
/// Xray-core's port as it is, each other one to the intercepting proxy.
async fn front(behind: u16, node: Option<u16>, seen: Arc<Mutex<Vec<String>>>) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let seen = seen.clone();
            tokio::spawn(async move {
                let Ok(head) = read_head(&mut tcp).await else { return };
                let target = head.strip_prefix("CONNECT ").and_then(|r| r.split_whitespace().next()).unwrap_or("");
                seen.lock().unwrap().push(target.to_string());
                let host = target.rsplit_once(':').map_or(target, |(h, _)| h);
                let mut up = match (host == NODE, node) {
                    (true, Some(xray)) => {
                        let Ok(up) = TcpStream::connect(("127.0.0.1", xray)).await else { return };
                        if tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await.is_err() {
                            return;
                        }
                        up
                    }
                    _ => {
                        let Ok(mut up) = TcpStream::connect(("127.0.0.1", behind)).await else { return };
                        if up.write_all(head.as_bytes()).await.is_err() {
                            return;
                        }
                        up
                    }
                };
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut up).await;
            });
        }
    });
    port
}

/// The test's SSH server, Xray-core when given, and the two proxies.
struct World {
    // Dropped first: Xray-core stops before its directory goes.
    xray: Option<Xray>,
    dir: Scratch,
    sshd: u16,
    front: u16,
    ca_file: PathBuf,
    list: List,
    connects: Arc<Mutex<Vec<String>>>,
    /// The GETs of the list that the stand-in answered.
    served: Arc<Mutex<usize>>,
    // Dropped last: the server and the proxies run on it.
    _runtime: tokio::runtime::Runtime,
}

fn world(name: &str, with_xray: bool) -> Option<World> {
    let dir = scratch(&format!("proxy-lists-{name}"));
    let xray = match with_xray {
        true => Some(xray(&dir.join("xray"))?),
        false => None,
    };
    std::fs::create_dir_all(dir.join("tmp")).unwrap();
    let key = dir.join("host_key");
    let made = Command::new(env!("CARGO_BIN_EXE_podssh"))
        .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(made.success());
    let list = first_list();
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let sshd = runtime.block_on(ssh_harness::start(&key));
    let served: Arc<Mutex<usize>> = Arc::default();
    let proxy = runtime.block_on(Proxy::start(&dir, handler(list.clone(), served.clone())));
    let connects: Arc<Mutex<Vec<String>>> = Arc::default();
    let front = runtime.block_on(front(proxy.port, xray.as_ref().map(|x| x.port), connects.clone()));
    // One file of both roots: the intercepting proxy's and Xray-core's.
    let mut roots = std::fs::read_to_string(&proxy.ca_file).unwrap();
    if let Some(x) = &xray {
        roots.push_str(&std::fs::read_to_string(x.dir.join("ca.pem")).unwrap());
    }
    let ca_file = dir.join("roots.pem");
    std::fs::write(&ca_file, roots).unwrap();
    Some(World { dir, sshd, front, ca_file, list, connects, served, xray, _runtime: runtime })
}

/// `podssh -v ssh ... greet` to the test's server with no road named, the
/// direct road and the `ws://` probe off, through the front proxy, `set`
/// added: its exit code, its stdout and its stderr.
fn ssh(w: &World, set: &[(&str, &str)]) -> (Option<i32>, String, String) {
    let known = format!("UserKnownHostsFile={}", w.dir.join("known_hosts").display());
    let (ca, port) = (w.ca_file.display().to_string(), w.sshd.to_string());
    let opts = ["ssh", "-v", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"];
    let road = ["--ca-file", ca.as_str(), "-p", port.as_str(), "u@127.0.0.1", "greet"];
    let args = [&opts[..], &[known.as_str()], &road].concat();
    let mut cmd = command(&w.dir, &args, None, &[]);
    for name in [
        "PODSSH_FORWARDER",
        "PODSSH_FORWARDER_FALLBACK",
        "PODSSH_RELAY",
        "PODSSH_RELAY_FAILOVER",
        "PODSSH_RELAY_ADDR",
        "PODSSH_RELAY_TOKEN",
        "PODSSH_PROXY_LISTS",
        "PODSSH_LAST_RESORT",
        "PODSSH_SESSION_LOG",
        "SSH_AUTH_SOCK",
    ] {
        cmd.env_remove(name);
    }
    // The direct road comes before the forwarders (T-363), and the test's
    // server would take it; a ws:// probe would leave the stand-ins.
    cmd.env("https_proxy", format!("http://127.0.0.1:{}", w.front))
        .env("PODSSH_DIRECT", "no")
        .env("PODSSH_CLEARTEXT", "no")
        .env("PODSSH_SETTINGS", "none")
        .env("PODSSH_CACHE_DIR", w.dir.join("cache"))
        .env("TMPDIR", w.dir.join("tmp"));
    for (name, value) in set {
        cmd.env(name, value);
    }
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut all = String::new();
        let _ = stdout.read_to_string(&mut all);
        all
    });
    let mut stderr = child.stderr.take().unwrap();
    let err = std::thread::spawn(move || {
        let mut all = String::new();
        let _ = stderr.read_to_string(&mut all);
        all
    });
    let started = Instant::now();
    let code = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status.code();
        }
        if started.elapsed() > LIMIT {
            let _ = child.kill();
            let _ = child.wait();
            panic!("podssh still ran after {LIMIT:?}: {}", err.join().unwrap());
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    (code, out.join().unwrap(), err.join().unwrap())
}

/// The hosts of each CONNECT that the front proxy took, in order.
fn hosts(w: &World) -> Vec<String> {
    let connects = w.connects.lock().unwrap().clone();
    connects.iter().map(|c| c.rsplit_once(':').map_or(c.as_str(), |(h, _)| h).to_string()).collect()
}

/// The round takes the node from the list and carries the session through
/// Xray-core to the server, after each relay host; the node that fronts
/// another name is skipped and never dialed; stderr says the third party
/// before the round and names the node that carries.
#[test]
fn the_fallback_takes_a_listed_node_through_xray_and_skips_the_fronting_line() {
    let Some(w) = world("xray", true) else { return };
    let (code, out, err) = ssh(&w, &[]);
    let xray_log = w.xray.as_ref().map(Xray::log).unwrap_or_default();
    assert_eq!(code, Some(0), "{err}\nXray-core: {xray_log}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    let target = format!("127.0.0.1:{}", w.sshd);
    let list = &w.list.host;

    // The line before the round: the target, the lists' hosts, the third party.
    let before = format!(
        "no forwarder carried it: podssh sends {target} to a public VLESS or Trojan node from the public lists of \
         proxy nodes at {list}"
    );
    assert!(err.contains(&before), "{err}");
    assert!(err.contains("a third party that nobody vouches for, which sees the target's name"), "{err}");
    // The fronting line was counted out, as -v says.
    let skipped = format!("the list at {list}: left out: 1 with an SNI or a Host that is another name than the host");
    assert!(err.contains(&skipped), "the fronting line was not skipped: {err}");
    // The node that carries, by its host, with no ID.
    let carries = format!("the public VLESS node vless://{NODE}:443{WS_PATH} (");
    assert!(err.contains(&carries), "{err}");
    let source = format!("from the list at {list}) carries the session to {target}, in place of the relay");
    assert!(err.contains(&source), "{err}");
    assert!(!err.contains(ID), "a line holds the node's ID");

    // The list once; a relay host before the node; the fronting node and the
    // name that it fronts never.
    assert_eq!(*w.served.lock().unwrap(), 1, "the list was fetched once");
    let hosts = hosts(&w);
    let at = |h: &str| hosts.iter().position(|c| c == h);
    let relay = hosts.iter().position(|h| h.ends_with("relay.ajam.dev")).unwrap_or_else(|| panic!("{hosts:?}"));
    let node = at(NODE).unwrap_or_else(|| panic!("the node was not dialed: {hosts:?}"));
    assert!(relay < node, "the relay hosts first: {hosts:?}");
    assert!(at(FRONTING).is_none() && at(FRONTED).is_none(), "the fronting node was dialed: {hosts:?}");
    // A list was read, so no node of the binary was tried.
    for built_in in built_in_hosts() {
        assert!(at(&built_in).is_none(), "a node of the binary was dialed: {built_in}");
    }
}

/// The hosts of the nodes that the binary ships, as the round reads them.
fn built_in_hosts() -> Vec<String> {
    let body = PLAN.built_in.join("\n");
    let listed = podssh_ws::proxy_nodes::list::parse(body.as_bytes()).map(|l| l.nodes).unwrap_or_default();
    listed.iter().map(|n| n.address().0.trim_start_matches('[').trim_end_matches(']').to_string()).collect()
}

/// Either switch turns the round off: no list is fetched, no node dialed,
/// and the run ends with the relay's code. No Xray-core is needed.
#[test]
fn either_switch_turns_the_round_off() {
    let w = world("off", false).expect("a world with no Xray-core");
    for switch in ["PODSSH_PROXY_LISTS", "PODSSH_LAST_RESORT"] {
        w.connects.lock().unwrap().clear();
        let (code, out, err) = ssh(&w, &[(switch, "no")]);
        assert_eq!(code, Some(255), "{switch}: {err}");
        assert!(out.is_empty(), "{switch}: {err}");
        assert!(err.contains("each relay host failed: podssh sends"), "{switch}: the forwarders came: {err}");
        assert!(!err.contains("to a public VLESS or Trojan node"), "{switch}: {err}");
        let why = "the public proxy nodes are not tried: PODSSH_PROXY_LISTS or PODSSH_LAST_RESORT says no";
        assert!(err.contains(why), "{switch}: -v says why: {err}");
        assert_eq!(*w.served.lock().unwrap(), 0, "{switch}: a list was fetched");
        let hosts = hosts(&w);
        assert!(!hosts.iter().any(|h| h == NODE || h == FRONTING), "{switch}: {hosts:?}");
        let built_in = built_in_hosts();
        assert!(!hosts.iter().any(|h| built_in.contains(h)), "{switch}: a node of the binary: {hosts:?}");
    }
}
