//! The localtunnel road (T-568) against a stand-in of localtunnel's server
//! on this machine's loopback, in the test's process, which speaks the
//! protocol that localtunnel/server 0.0.8 speaks (read on 2026-11-10): its
//! API answers `GET /NAME` with `{id, port, max_conn_count, url}` (and `ip`,
//! as the hosted one may), its port takes the node's TCP connections, and
//! it sends each visitor down one of them: a request written again as
//! Node's HTTP client writes it (`lib/Client.js`, `handleRequest`), or a
//! WebSocket's head as it came, then each byte both ways
//! (`handleUpgrade`). Its public side answers 511, the hosted server's page
//! for browsers, to a request with no `Bypass-Tunnel-Reminder`.
//!
//! The node's keeper and router of podssh-relay serve the relay role's
//! `/health` and a link of the node; the client's link passes the page by
//! its header. Planted (`scripts/plants/t568-no-bypass-header.patch`): the
//! client's request leaves the header out, and the test of the page fails.
//! The binary's `podssh node lab --localtunnel --relay` asks the name of its
//! key, says its URL on stdout and answers `/health` over its connection;
//! its refusals come before any connection.

mod cleanup;

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use podssh_relay::localtunnel::api::{self, Tunnel};
use podssh_relay::localtunnel::keep::{self, Keep, Serve, Serving};
use podssh_relay::localtunnel::route::{self, Router, Visit, Visiting};
use podssh_relay::localtunnel::{link, Service, HEADER};
use podssh_relay::opentunnel::dial::BoxIo;
use podssh_relay::serve::{self as role, Config, Mint};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};

const LIMIT: Duration = Duration::from_secs(30);
const ZONE: &str = "lt.test";

/// The stand-in of localtunnel's server: its API's port, its tunnels' port,
/// the node's connections as they come, and the paths that the API was asked.
struct StandIn {
    api: u16,
    connections: AsyncMutex<mpsc::Receiver<TcpStream>>,
    asked: Arc<Mutex<Vec<String>>>,
}

impl StandIn {
    async fn start(count: usize) -> StandIn {
        let api = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let tunnels = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let (api_port, port) = (api.local_addr().unwrap().port(), tunnels.local_addr().unwrap().port());
        let asked = Arc::new(Mutex::new(Vec::new()));
        let seen = asked.clone();
        tokio::spawn(async move {
            while let Ok((mut tcp, _)) = api.accept().await {
                let Ok((head, _)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { continue };
                seen.lock().unwrap().push(head.target.clone());
                // As `server.js`: the name asked for, else a random one.
                let id = head.target.trim_start_matches('/').trim_start_matches("?new").to_string();
                let id = if id.is_empty() { "heavy-puma-9".to_string() } else { id };
                let body = format!(
                    r#"{{"id":"{id}","port":{port},"max_conn_count":{count},"url":"https://{id}.{ZONE}","ip":"127.0.0.1"}}"#
                );
                let answer = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let _ = tcp.write_all(answer.as_bytes()).await;
            }
        });
        let (sender, connections) = mpsc::channel(64);
        tokio::spawn(async move {
            while let Ok((tcp, _)) = tunnels.accept().await {
                if sender.send(tcp).await.is_err() {
                    return;
                }
            }
        });
        StandIn { api: api_port, connections: AsyncMutex::new(connections), asked }
    }

    fn service(&self) -> Service {
        Service::parse(&format!("http://127.0.0.1:{}", self.api)).unwrap()
    }

    /// One of the node's connections, as the server's agent hands it out.
    async fn connection(&self) -> TcpStream {
        let mut connections = self.connections.lock().await;
        tokio::time::timeout(LIMIT, connections.recv()).await.expect("a connection of the node in time").unwrap()
    }
}

/// The public side of the stand-in for one visitor: the hosted server's
/// page (511) for a request with no header, else the head as it came down
/// `connection`, then each byte both ways (`handleUpgrade`).
async fn public_side(mut visitor: TcpStream, mut connection: TcpStream) {
    let Ok((head, pending)) = podssh_ws::http::read_request(&mut visitor, Vec::new()).await else { return };
    if head.header(HEADER).is_none() {
        let page = "HTTP/1.1 511 Network Authentication Required\r\nContent-Length: 15\r\n\r\nTunnel Reminder";
        let _ = visitor.write_all(page.as_bytes()).await;
        return;
    }
    let mut raw = format!("{} {} HTTP/1.1\r\n", head.method, head.target);
    for (name, value) in head.headers.iter() {
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    let _ = connection.write_all(raw.as_bytes()).await;
    let _ = connection.write_all(&pending).await;
    let _ = tokio::io::copy_bidirectional(&mut visitor, &mut connection).await;
}

fn cfg() -> Arc<Config> {
    Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: role::tokens::Tokens::new([9; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Default::default(),
        pairs: Default::default(),
        resumes: Default::default(),
        answered: Default::default(),
        events: None,
        brake: Default::default(),
        usage: Default::default(),
    })
}

/// The node's links, here an echo of their bytes.
fn echo() -> Visit {
    Arc::new(|mut link: DuplexStream| -> Visiting {
        Box::pin(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok(n) = link.read(&mut buf).await {
                if n == 0 || link.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
        })
    })
}

/// The node's tunnel at the stand-in, kept by podssh-relay's keeper, with
/// the role and the echo behind it; the tunnel, and the stop.
async fn node(stand_in: &StandIn, name: &str) -> (Tunnel, watch::Sender<bool>) {
    let router = Arc::new(Router { role: Some(cfg()), alone: false, visit: Some(echo()) });
    let serve: Serve = Arc::new(move |io: BoxIo, tunnel: Arc<Tunnel>| -> Serving {
        Box::pin(route::serve(router.clone(), tunnel.host.clone(), io))
    });
    let kept = Keep {
        service: stand_in.service(),
        api: api::tls(podssh_ws::Trust::Default, ProxyChoice::Direct),
        connect: keep::tcp(ProxyChoice::Direct),
        asked: Some(name.to_string()),
        serve,
        say: Arc::new(|_| {}),
    };
    let (stop, stopped) = watch::channel(false);
    let first = keep::asked(&kept, stopped.clone()).await.expect("a tunnel").expect("not stopped");
    tokio::spawn(keep::run(kept, first.clone(), |_: &Tunnel| {}, stopped));
    (first, stop)
}

/// A link of the client through the stand-in's public side, as `link::open`
/// makes it after its TLS.
async fn client_link(stand_in: &StandIn, host: &str) -> Result<DuplexStream, String> {
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = public.local_addr().unwrap().port();
    let connection = stand_in.connection().await;
    tokio::spawn(async move {
        if let Ok((visitor, _)) = public.accept().await {
            public_side(visitor, connection).await;
        }
    });
    let tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    let session = link::over(tcp, host, LIMIT).await?;
    Ok(podssh_ssh::relay_stream::spawn(session).0)
}

#[tokio::test]
async fn the_node_asks_its_name_and_serves_the_role_s_health_on_a_connection() {
    let stand_in = StandIn::start(2).await;
    let (tunnel, _stop) = node(&stand_in, "podssh-0011223344556677").await;
    assert_eq!(tunnel.url(), "https://podssh-0011223344556677.lt.test");
    assert_eq!(stand_in.asked.lock().unwrap().as_slice(), ["/podssh-0011223344556677"]);
    // A request as Node's HTTP client writes it, on a connection it keeps.
    let mut connection = stand_in.connection().await;
    let request = "GET /health HTTP/1.1\r\nhost: podssh-0011223344556677.lt.test\r\nConnection: keep-alive\r\n\r\n";
    connection.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, connection.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200 ") && answer.contains("\"contract\""), "{answer}");
    // The role closed that connection after its answer: the node opens another at once.
    let _second = stand_in.connection().await;
    let _third = stand_in.connection().await;
}

#[tokio::test]
async fn the_client_s_upgrade_carries_the_bypass_header_past_the_reminder_page() {
    let stand_in = StandIn::start(2).await;
    let (tunnel, _stop) = node(&stand_in, "podssh-8899aabbccddeeff").await;
    let mut link = match client_link(&stand_in, &tunnel.host).await {
        Ok(link) => link,
        Err(why) => panic!("the client met the stand-in's page for browsers, or no link: {why}"),
    };
    link.write_all(b"hello through the tunnel").await.unwrap();
    let mut echoed = vec![0u8; 24];
    tokio::time::timeout(LIMIT, link.read_exact(&mut echoed)).await.expect("the echo in time").unwrap();
    assert_eq!(&echoed, b"hello through the tunnel");
}

#[tokio::test]
async fn a_request_with_no_header_meets_the_page_and_the_client_names_it() {
    let stand_in = StandIn::start(1).await;
    let _node = node(&stand_in, "podssh-0123456789abcdef").await;
    let public = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = public.local_addr().unwrap().port();
    let connection = stand_in.connection().await;
    tokio::spawn(async move {
        if let Ok((visitor, _)) = public.accept().await {
            public_side(visitor, connection).await;
        }
    });
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
    tcp.write_all(b"GET / HTTP/1.1\r\nHost: x.lt.test\r\nUser-Agent: Mozilla/5.0\r\n\r\n").await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("the page in time").unwrap();
    assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 511 "));
    assert!(link::refusal("x.lt.test", 511, "").contains("page for browsers"));
}

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-localtunnel-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the stand-in's
/// server, and no other road of a tunnel.
fn command(home: &Path, server: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_RELAY", "PODSSH_LAST_RESORT", "SSL_CERT_FILE", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_LOCALTUNNEL", server).env("PODSSH_DERP", "no").env("PODSSH_OPENTUNNEL", "no");
    cmd.env("PODSSH_PINGGY", "no").env("PODSSH_SERVEO", "no").env("PODSSH_SSH_J", "no");
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    // Nor the last roads beside this one (Q78): localhost.run (T-565), bore (T-569).
    cmd.env("PODSSH_LOCALHOST_RUN", "no").env("PODSSH_SANDHOLE", "no").env("PODSSH_BORE", "no");
    cmd.env("HOME", home).env("USERPROFILE", home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("LOCALAPPDATA", home.join("cache"));
    cmd
}

/// Kills the node when the test ends.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn the_binary_s_node_says_its_url_and_its_role_answers_over_a_connection() {
    let home = scratch("binary");
    let allow = home.join("allow");
    std::fs::write(&allow, "# the client keys that may come in\n").unwrap();
    let (allow, key) = (allow.to_string_lossy().into_owned(), home.join("node.key").to_string_lossy().into_owned());
    let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let stand_in = runtime.block_on(StandIn::start(1));
    let server = format!("http://127.0.0.1:{}", stand_in.api);
    let args = ["node", "lab", "--localtunnel", "--relay", "--allow", &allow, "--key", &key];
    let mut cmd = command(&home, &server, &args);
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().expect("it runs");
    let mut node = Killed(child);
    let mut stdout = BufReader::new(node.0.stdout.take().unwrap());
    let mut url = String::new();
    stdout.read_line(&mut url).expect("the URL on stdout");
    let asked = stand_in.asked.lock().unwrap().clone();
    let name = asked.first().expect("the API was asked").trim_start_matches('/').to_string();
    assert!(name.starts_with("podssh-") && name.len() == 23, "the name of the node's key: {name}");
    assert_eq!(url.trim(), format!("https://{name}.{ZONE}"));
    let answer = runtime.block_on(async {
        let mut connection = stand_in.connection().await;
        let request = format!("GET /health HTTP/1.1\r\nhost: {name}.{ZONE}\r\nConnection: keep-alive\r\n\r\n");
        connection.write_all(request.as_bytes()).await.unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(LIMIT, connection.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
        String::from_utf8_lossy(&answer).into_owned()
    });
    assert!(answer.starts_with("HTTP/1.1 200 ") && answer.contains("\"contract\""), "{answer}");
    drop(node);
}

#[test]
fn the_binary_refuses_the_road_turned_off_and_a_node_with_no_door_before_any_connection() {
    let home = scratch("refusals");
    let started = Instant::now();
    let run = |server: &str, args: &[&str]| {
        let out = command(&home, server, args).stdin(Stdio::null()).output().expect("it runs");
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned(), out.stdout.is_empty())
    };
    let (code, err, empty) = run("no", &["node", "lab", "127.0.0.1:22", "--localtunnel", "--allow", "allow"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("PODSSH_LOCALTUNNEL=no turns the localtunnel road off") && empty, "{err}");
    let (code, err, _) = run("http://127.0.0.1:9", &["node", "lab", "127.0.0.1:22", "--localtunnel"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--localtunnel needs --allow FILE"), "{err}");
    let (code, err, _) = run("http://192.0.2.1", &["node", "lab", "127.0.0.1:22", "--localtunnel", "--allow", "a"]);
    assert_eq!(code, Some(78), "a server over http:// off the loopback: {err}");
    let (code, err, _) = run("http://127.0.0.1:9", &["node", "lab", "127.0.0.1:22", "--localtunnel", "--no-e2e"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(started.elapsed() < LIMIT, "each refusal came before any connection");
}
