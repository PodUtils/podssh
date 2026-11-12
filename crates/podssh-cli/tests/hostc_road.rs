//! The hostc road (T-742) against software that podssh did not write:
//! hostc's own server (`akazwz/hostc`, `apps/server`, Apache-2.0, pinned at
//! `c19ff67` by `.github/workflows/hostc-interop.yml`) under its local
//! runtime, in a container, with a plain squid as the proxy of the node and
//! of the client. Each test of the server needs its variables, which the
//! workflow sets, and says "did not run" without them:
//!
//! - `PODSSH_HOSTC_TEST_SERVER`, the server's API (`http://127.0.0.1:8787`),
//!   and `PODSSH_HOSTC_TEST_ZONE`, its `TUNNEL_DOMAIN`: the node's keeper of
//!   podssh-relay asks a tunnel and keeps its socket; a request of the role's
//!   `/health` at the tunnel's name gets the role's answer, and a WebSocket
//!   at `/` is a link whose 1 MiB comes back with an equal digest, each way;
//!   the server answers 426 to a version other than 5;
//! - with `PODSSH_HOSTC_TEST_TARGET` (an OpenSSH sshd), `..._IDENTITY` (its
//!   user's key), `..._USER`, `..._CA` (the TLS front's CA of the tunnels'
//!   names on 443) and `..._PROXY` (squid): `podssh node lab TARGET --hostc`
//!   behind it, and `podssh ssh node://lab --tunnel-url URL 'echo ok'` with
//!   the pair's road down;
//! - `PODSSH_HOSTC_LIVE=1`: the same keeper through the hosted server
//!   (`PODSSH_HOSTC`, else pod-services), short (Q94), one throwaway tunnel
//!   freed at the end with 4000.
//!
//! The refusals of the binary need nothing and run each time. Planted
//! (T-742's Prove, in the unit tests of `podssh_relay::hostc::bridge_http`):
//! a window granted for bytes that the role did not take, and an answer's
//! body sent past the server's grants.

mod cleanup;

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::hostc::api::{self, Tunnel};
use podssh_relay::hostc::keep::{self, Keep};
use podssh_relay::hostc::link::Beat;
use podssh_relay::hostc::Service;
use podssh_relay::identity::file::{self, Place};
use podssh_relay::pinggy::far::Visitor;
use podssh_relay::serve::{self as role, behind::Behind, Config, Mint};
use podssh_relay::session::OsEntropy;
use podssh_relay::ssh_http::visit::{self, Visited};
use podssh_ws::{ProxyChoice, Trust};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

const LIMIT: Duration = Duration::from_secs(60);

/// A variable of the test, or the line that says why the test did not run.
fn var(name: &str) -> Option<String> {
    let value = std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    if value.is_none() {
        eprintln!("did not run: {name} is not set (.github/workflows/hostc-interop.yml sets it)");
    }
    value
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

/// The node's tunnel at `service`, kept by podssh-relay's keeper: each
/// stream served as the node serves it, the role's paths to the role and a
/// link echoed. The tunnel, and the stop.
async fn node(service: Service, trust: Trust, proxy: ProxyChoice) -> (Tunnel, watch::Sender<bool>) {
    let kept = Keep {
        service,
        dial: api::tls(trust, proxy),
        say: Arc::new(|line| eprintln!("node: {line}")),
        beat: Beat::default(),
    };
    let first = keep::first(&kept).await.expect("a tunnel of the server");
    let (queue, mut visitors) = mpsc::channel::<Visitor>(64);
    let name = first.host.clone();
    tokio::spawn(async move {
        while let Some(visitor) = visitors.recv().await {
            let origin: Arc<dyn podssh_relay::quick::origin::Origin> =
                Arc::new(Behind::new(cfg(), name.clone(), false));
            tokio::spawn(async move {
                if let Visited::Layer(mut link) = visit::serve(visitor.stream, Some(origin)).await {
                    let mut buf = vec![0u8; 64 * 1024];
                    while let Ok(n) = link.read(&mut buf).await {
                        if n == 0 || link.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
    let (stop, stopped) = watch::channel(false);
    tokio::spawn(keep::run(kept, first.clone(), queue, |_: &Tunnel| {}, stopped));
    (first, stop)
}

/// The server's public side for the tunnel `host`, on the API's own port,
/// as its Worker routes a visitor by `Host` (`index.ts`).
async fn visitor(server: &Service) -> TcpStream {
    TcpStream::connect((server.host.as_str(), server.port)).await.expect("the server's port")
}

#[tokio::test]
async fn at_hostc_s_own_server_the_role_answers_and_a_link_carries_a_mebibyte_each_way() {
    let (Some(server), Some(zone)) = (var("PODSSH_HOSTC_TEST_SERVER"), var("PODSSH_HOSTC_TEST_ZONE")) else { return };
    let service = Service::parse(&server).expect("a server of the loopback");
    let (tunnel, stop) = node(service.clone(), Trust::Default, ProxyChoice::Direct).await;
    assert!(tunnel.host.ends_with(&format!(".{zone}")), "{tunnel:?}");
    // Give the socket its first second before the first visitor.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut tcp = visitor(&service).await;
    let ask = format!("GET /health HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", tunnel.host);
    tcp.write_all(ask.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(LIMIT, tcp.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200 ") && answer.contains("\"contract\""), "{answer}");
    // A WebSocket at `/`: one link, echoed; 1 MiB out, 1 MiB back.
    let tcp = visitor(&service).await;
    let session = podssh_relay::localtunnel::link::over(tcp, &tunnel.host, LIMIT).await.expect("the link's upgrade");
    let (mut link, _) = podssh_ssh::relay_stream::spawn(session);
    let sent: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let (mut from, mut to) = tokio::io::split(&mut link);
    let writing = async {
        to.write_all(&sent).await.unwrap();
        to.flush().await.unwrap();
    };
    let mut back = vec![0u8; sent.len()];
    let reading = tokio::time::timeout(LIMIT, from.read_exact(&mut back));
    let ((), read) = tokio::join!(writing, reading);
    read.expect("the mebibyte back in time").unwrap();
    assert_eq!(Sha256::digest(&back), Sha256::digest(&sent), "equal digests each way");
    // The version: anything but 5 is 426, with no fallback.
    let mut tcp = visitor(&service).await;
    let headers = [("hostc-protocol", "4")];
    let authority = service.authority();
    let refused = podssh_ws::http::exchange(&mut tcp, "POST", &authority, api::TUNNELS, &headers, b"", 4096);
    assert_eq!(refused.await.unwrap().status, 426, "the server speaks one version alone");
    let _ = stop.send(true);
}

#[tokio::test]
async fn live_through_the_hosted_server_the_role_answers_at_the_tunnel_s_name() {
    if var("PODSSH_HOSTC_LIVE").as_deref() != Some("1") {
        return;
    }
    let service = match podssh_relay::hostc::from_env().expect("PODSSH_HOSTC") {
        podssh_relay::hostc::Setting::On(service) => service,
        // pod-services names no server yet, and the run named none.
        podssh_relay::hostc::Setting::Unnamed => {
            return eprintln!("did not run: {}", podssh_relay::hostc::unnamed_words());
        }
        podssh_relay::hostc::Setting::Off(by) => panic!("{by}=no, with PODSSH_HOSTC_LIVE=1"),
    };
    let started = Instant::now();
    let (tunnel, stop) = node(service, Trust::Default, ProxyChoice::FromEnvironment).await;
    eprintln!("the tunnel came in {} ms", started.elapsed().as_millis());
    tokio::time::sleep(Duration::from_secs(1)).await;
    let proxy = ProxyChoice::FromEnvironment;
    let mut tls = podssh_ws::client::open_tls(&tunnel.host, 443, &tunnel.host, &Trust::Default, &proxy, LIMIT)
        .await
        .expect("TLS to the tunnel's name");
    let response = podssh_ws::http::exchange(&mut tls, "GET", &tunnel.host, "/health", &[], b"", 64 * 1024);
    let response = tokio::time::timeout(LIMIT, response).await.expect("an answer in time").unwrap();
    assert_eq!(response.status, 200, "{}", String::from_utf8_lossy(&response.body));
    eprintln!("the role's /health through the hosted server in {} ms", started.elapsed().as_millis());
    let _ = stop.send(true);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-hostc-road-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// `podssh ARGS` with HOME and the cache under `home`, the server of
/// `server`, and no other road of a tunnel.
fn command(home: &Path, server: &str, args: &[&str]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
    for name in ["PODSSH_OFFLINE", "PODSSH_RELAY", "PODSSH_LAST_RESORT", "SSH_AUTH_SOCK"] {
        cmd.env_remove(name);
    }
    cmd.env("PODSSH_HOSTC", server).env("PODSSH_DERP", "no").env("PODSSH_OPENTUNNEL", "no");
    cmd.env("PODSSH_PINGGY", "no").env("PODSSH_SERVEO", "no").env("PODSSH_SSH_J", "no");
    cmd.env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no").env("PODSSH_PIPING", "no").env("PODSSH_IROH_PKARR", "off");
    cmd.env("PODSSH_FORWARDER_FALLBACK", "no");
    // Nor the last roads beside this one (Q78).
    cmd.env("PODSSH_LOCALHOST_RUN", "no").env("PODSSH_SANDHOLE", "no").env("PODSSH_LOCALTUNNEL", "no");
    cmd.env("PODSSH_BORE", "no");
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
fn the_binary_refuses_the_road_turned_off_and_a_node_with_no_door_before_any_connection() {
    let home = scratch("refusals");
    let started = Instant::now();
    let run = |server: &str, args: &[&str]| {
        let out = command(&home, server, args).stdin(Stdio::null()).output().expect("it runs");
        (out.status.code(), String::from_utf8_lossy(&out.stderr).into_owned(), out.stdout.is_empty())
    };
    let (code, err, empty) = run("no", &["node", "lab", "127.0.0.1:22", "--hostc", "--allow", "allow"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("PODSSH_HOSTC=no turns the hostc road off") && empty, "{err}");
    let (code, err, _) = run("http://127.0.0.1:9", &["node", "lab", "127.0.0.1:22", "--hostc"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--hostc needs --allow FILE"), "{err}");
    let (code, err, _) = run("http://192.0.2.1", &["node", "lab", "127.0.0.1:22", "--hostc", "--allow", "a"]);
    assert_eq!(code, Some(78), "a server over http:// off the loopback: {err}");
    let (code, err, _) = run("http://127.0.0.1:9", &["node", "lab", "127.0.0.1:22", "--hostc", "--no-e2e"]);
    assert_eq!(code, Some(64), "{err}");
    let (code, err, _) = run("http://127.0.0.1:9", &["node", "lab", "127.0.0.1:22", "--hostc", "--bore"]);
    assert_eq!(code, Some(64), "{err}");
    assert!(err.contains("--hostc is one road and --bore is another"), "{err}");
    assert!(started.elapsed() < LIMIT, "each refusal came before any connection");
}

#[test]
fn the_binary_s_node_behind_hostc_s_server_carries_a_session_of_ssh_with_the_pair_s_road_down() {
    let Some(server) = var("PODSSH_HOSTC_TEST_SERVER") else { return };
    let (Some(target), Some(identity)) = (var("PODSSH_HOSTC_TEST_TARGET"), var("PODSSH_HOSTC_TEST_IDENTITY")) else {
        return;
    };
    let (Some(user), Some(ca), Some(proxy)) =
        (var("PODSSH_HOSTC_TEST_USER"), var("PODSSH_HOSTC_TEST_CA"), var("PODSSH_HOSTC_TEST_PROXY"))
    else {
        return;
    };
    let home = scratch("ssh");
    let (node_home, client_home) = (home.join("node"), home.join("client"));
    for dir in [&node_home, &client_home] {
        podssh_relay::cache::private_dir(dir).unwrap();
    }
    let with_proxy = |mut cmd: Command| {
        cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("SSL_CERT_FILE", &ca);
        cmd
    };
    // The client's key of the end-to-end channel, made here as a first run
    // makes it (64 hex digits, not an OpenSSH key), and let in by the node.
    let client_key = client_home.join("client.key").to_string_lossy().into_owned();
    let loaded = file::load(&Place::File(PathBuf::from(&client_key)), &mut OsEntropy).expect("the client's key");
    let allow = node_home.join("allow");
    std::fs::write(&allow, format!("{} the test's client\n", loaded.identity.public().fingerprint())).unwrap();
    let (allow, key) =
        (allow.to_string_lossy().into_owned(), node_home.join("node.key").to_string_lossy().into_owned());
    let args = ["node", "lab", &target, "--hostc", "--allow", &allow, "--key", &key];
    let mut cmd = with_proxy(command(&node_home, &server, &args));
    let child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn().expect("it runs");
    let mut node = Killed(child);
    let mut url = String::new();
    BufReader::new(node.0.stdout.take().unwrap()).read_line(&mut url).expect("the URL on stdout");
    let url = url.trim().to_string();
    assert!(url.starts_with("https://"), "{url}");
    let words = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-i",
        &identity,
        "--client-key",
        &client_key,
        "--tunnel-url",
        &url,
    ];
    let destination = format!("node://{user}@lab");
    let mut words = words.to_vec();
    words.extend_from_slice(&[destination.as_str(), "echo ok"]);
    let out = with_proxy(command(&client_home, &server, &words)).stdin(Stdio::null()).output().expect("ssh runs");
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok", "{err}");
    assert!(err.contains("hostc") && err.contains("nobody vouches for"), "the line of Q78: {err}");
    drop(node);
}
