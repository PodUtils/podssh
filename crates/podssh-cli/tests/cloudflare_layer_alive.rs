//! `podssh ssh cf://HOST` and the user's `ServerAliveInterval` (T-703, GitHub
//! #172), from end to end, with a stand-in for Cloudflare's edge on the
//! loopback: a proxy of the test that takes `CONNECT HOST:443` and joins it to
//! a TLS server of the test's own CA (`--ca-file`), which takes the WebSocket
//! upgrade at `/` as the tunnel's origin does and gives its bytes to a far
//! end. The far end is a podssh node's: the resumable layer greets, with the
//! end-to-end channel above it, as `podssh node --quick-tunnel` serves each
//! visitor, in front of the tests' SSH server; or a `cloudflared` service,
//! the SSH server's bytes as they are, which greets with no layer.
//!
//! Pass: a layer and `ServerAliveInterval 30` give the one warning and the
//! interval stays; a layer and no interval give no warning and no keepalives;
//! an interval of 0, and a far end with no layer, give no warning.
//!
//! The planted defect: `layer_alive::decide` never answers `Warn`, so that
//! the first test fails.

#![cfg(unix)]
#![allow(dead_code)]

mod cleanup;
mod ssh_harness;
mod update_support;

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use podssh_relay::e2e::ends::Node;
use podssh_relay::identity::Identity;
use podssh_relay::reverse::{E2e, Handler, Layered, SessionId};
use podssh_relay::session::Settings;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);
/// The name of the tunnel's rule, as `cf://` takes it.
const HOST: &str = "lab.example.test";
/// A fragment of the warning that `node://` prints for the same setting.
const WARNING: &str = "ServerAliveInterval ends the session after ServerAliveCountMax keepalives";
/// What the verbose line of the dropped keepalives says.
const DROPPED: &str = "no SSH keepalives";

/// What the stand-in's far end greets with.
#[derive(Clone, Copy)]
enum Far {
    /// A podssh node's: the layer, then the channel.
    Node,
    /// `cloudflared`'s service: the SSH server, its bytes as they are.
    Service,
}

/// The stand-ins of one run: the proxy that the client is given, and the CA
/// of the TLS server behind it.
struct Stand {
    home: PathBuf,
    proxy: u16,
    ca: PathBuf,
    _runtime: tokio::runtime::Runtime,
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-cf-alive-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    cleanup::at_test_end(&dir);
    dir
}

/// The edge's WebSocket as bytes: after the upgrade, the visitor's frames
/// are the bytes of one pipe (`podssh_relay::quick::visitor`).
async fn upgraded(
    mut tls: impl AsyncReadExt + AsyncWriteExt + Unpin + Send + 'static,
) -> Option<tokio::io::DuplexStream> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if tls.read(&mut byte).await.ok()? == 0 || head.len() > 16 << 10 {
            return None;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    let key = head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))?;
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\r\n",
        podssh_ws::handshake::accept_key(key.trim())
    );
    tls.write_all(answer.as_bytes()).await.ok()?;
    let (from_edge, to_edge) = tokio::io::split(tls);
    Some(podssh_relay::quick::visitor::websocket(from_edge, to_edge))
}

impl Stand {
    /// The stand-ins in front of the tests' SSH server, with the far end
    /// `far`.
    fn start(name: &str, far: Far) -> Stand {
        let home = scratch(name);
        let key = home.join("host_key");
        let status = Command::new(env!("CARGO_BIN_EXE_podssh"))
            .args(["keygen", "-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap();
        assert!(status.success());
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let (ca, proxy) = runtime.block_on(async {
            let ssh = ssh_harness::start(&key).await;
            let (acceptor, ca) = update_support::acceptor(&home, &[HOST]);
            let tls = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let tls_port = tls.local_addr().unwrap().port();
            // The node's side of the layer, one for the run: a visitor that
            // resumes finds its session.
            let me = Arc::new(Identity::from_seed(&[7; 32]));
            let node = Node::open_to_all(me, Arc::new(podssh_relay::e2e::NoEvents));
            let target = podssh_relay::reverse::tcp::handler("127.0.0.1".into(), ssh, LIMIT, false);
            let layered = Arc::new(Layered::new(E2e::new(target, node), Settings::default(), 64 << 20));
            let ids = Arc::new(std::sync::atomic::AtomicU64::new(1));
            tokio::spawn(async move {
                while let Ok((tcp, _)) = tls.accept().await {
                    let (acceptor, layered, ids) = (acceptor.clone(), layered.clone(), ids.clone());
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else { return };
                        let Some(mut visitor) = upgraded(tls).await else { return };
                        match far {
                            Far::Node => {
                                let n = ids.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let Ok(id) = SessionId::parse(format!("{n:032x}").as_bytes()) else { return };
                                let Ok(mut session) = layered.open(id).await else { return };
                                let _ = tokio::io::copy_bidirectional(&mut visitor, &mut session).await;
                            }
                            Far::Service => {
                                let Ok(mut ssh) = TcpStream::connect(("127.0.0.1", ssh)).await else { return };
                                let _ = tokio::io::copy_bidirectional(&mut visitor, &mut ssh).await;
                            }
                        }
                    });
                }
            });
            // The proxy: CONNECT HOST:443 reaches the TLS server.
            let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_port = proxy.local_addr().unwrap().port();
            tokio::spawn(async move {
                while let Ok((mut client, _)) = proxy.accept().await {
                    tokio::spawn(async move {
                        let mut head = Vec::new();
                        let mut byte = [0u8; 1];
                        while !head.ends_with(b"\r\n\r\n") {
                            if client.read(&mut byte).await.unwrap_or(0) == 0 {
                                return;
                            }
                            head.push(byte[0]);
                        }
                        let wanted = format!("CONNECT {HOST}:443 ");
                        let (code, to) = if String::from_utf8_lossy(&head).starts_with(&wanted) {
                            ("200 Connection Established", TcpStream::connect(("127.0.0.1", tls_port)).await.ok())
                        } else {
                            ("403 Forbidden", None)
                        };
                        let _ = client.write_all(format!("HTTP/1.1 {code}\r\n\r\n").as_bytes()).await;
                        if let Some(mut to) = to {
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut to).await;
                        }
                    });
                }
            });
            (ca, proxy_port)
        });
        Stand { home, proxy, ca, _runtime: runtime }
    }

    /// `podssh ssh cf://tester@HOST greet`, with `extra` words before the
    /// destination: its code, stdout and stderr, within the limit.
    fn ssh(&self, extra: &[&str]) -> (Option<i32>, String, String) {
        let known = self.home.join("known_hosts");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.args(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o"]);
        cmd.arg(format!("UserKnownHostsFile={}", known.display()));
        cmd.arg("--ca-file").arg(&self.ca).args(extra);
        cmd.arg(format!("cf://tester@{HOST}")).arg("greet");
        cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", &self.home).env("USERPROFILE", &self.home);
        cmd.env("XDG_CACHE_HOME", self.home.join("cache")).env("PODSSH_TRANSIT", "no").env("PODSSH_CROC", "no");
        // Nor the last roads of all (Q78): localhost.run (T-565), localtunnel (T-568), bore (T-569).
        cmd.env("PODSSH_LOCALHOST_RUN", "no").env("PODSSH_SANDHOLE", "no");
        cmd.env("PODSSH_LOCALTUNNEL", "no").env("PODSSH_HOSTC", "no").env("PODSSH_SMEE", "no").env("PODSSH_BORE", "no");
        for name in ["PODSSH_OFFLINE", "SSH_AUTH_SOCK", "NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "https_proxy"]
        {
            cmd.env_remove(name);
        }
        cmd.env("HTTPS_PROXY", format!("http://127.0.0.1:{}", self.proxy));
        let out = run(cmd);
        (out.0, String::from_utf8_lossy(&out.1).into_owned(), String::from_utf8_lossy(&out.2).into_owned())
    }
}

/// Run `cmd` with no stdin, within the limit: its code, stdout and stderr.
fn run(mut cmd: Command) -> (Option<i32>, Vec<u8>, Vec<u8>) {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let (out, err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let out = std::thread::spawn(move || drain(out));
    let err = std::thread::spawn(move || drain(err));
    let deadline = Instant::now() + LIMIT;
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("podssh did not end within {LIMIT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (status.code(), out.join().unwrap(), err.join().unwrap())
}

fn drain(mut from: impl std::io::Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = from.read_to_end(&mut bytes);
    bytes
}

/// How many times `err` says the warning.
fn warnings(err: &str) -> usize {
    err.matches(WARNING).count()
}

// T-703: a layer, and an interval that the user named: one warning, and the
// interval stays (the line of the dropped keepalives is not said).
#[test]
fn a_layer_and_an_interval_that_the_user_named_give_one_warning_and_keep_the_interval() {
    let stand = Stand::start("warn", Far::Node);
    let (code, out, err) = stand.ssh(&["-v", "-o", "ServerAliveInterval=30"]);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(err.contains("greets with the resumable layer"), "the far end was taken for a node: {err}");
    assert_eq!(warnings(&err), 1, "one warning: {err}");
    assert!(!err.contains(DROPPED), "the user's interval stays: {err}");
}

// A layer, and no interval named: no warning, and the keepalives that SSH
// would send are dropped, as the layer's heartbeat finds a dead link.
#[test]
fn a_layer_and_no_interval_give_no_warning_and_no_keepalives() {
    let stand = Stand::start("drop", Far::Node);
    let (code, out, err) = stand.ssh(&["-v"]);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert_eq!(warnings(&err), 0, "{err}");
    assert!(err.contains(DROPPED), "the keepalives are dropped: {err}");
}

// An interval of 0 is no keepalive at all: nothing to warn about.
#[test]
fn an_interval_of_zero_on_a_layer_has_nothing_to_warn_about() {
    let stand = Stand::start("zero", Far::Node);
    let (code, out, err) = stand.ssh(&["-v", "-o", "ServerAliveInterval=0"]);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(err.contains("greets with the resumable layer"), "{err}");
    assert_eq!(warnings(&err), 0, "{err}");
}

// A far end that greets with no layer is cloudflared's service: no warning,
// and the user's keepalives are not touched.
#[test]
fn a_far_end_with_no_layer_gives_no_warning_and_keeps_the_keepalives() {
    let stand = Stand::start("service", Far::Service);
    let (code, out, err) = stand.ssh(&["-v", "-o", "ServerAliveInterval=30"]);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(out, ssh_harness::GREETING, "{err}");
    assert!(!err.contains("resumable layer"), "no layer: {err}");
    assert_eq!(warnings(&err), 0, "{err}");
    assert!(!err.contains(DROPPED), "{err}");
}

// `node://NAME` with the same setting prints the same warning, before it
// connects, as before: one constant for both roads.
#[test]
fn a_node_destination_prints_the_same_warning_once() {
    let home = scratch("node");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
    cmd.args(["ssh", "-o", "BatchMode=yes", "-o", "ServerAliveInterval=30", "node://lab", "greet"]);
    cmd.env("PODSSH_SSH_CONFIG", "none").env("HOME", &home).env("USERPROFILE", &home);
    cmd.env("XDG_CACHE_HOME", home.join("cache")).env("PODSSH_OFFLINE", "1");
    let (_, _, err) = run(cmd);
    let err = String::from_utf8_lossy(&err);
    assert_eq!(warnings(&err), 1, "{err}");
}
