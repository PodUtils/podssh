//! The DNS road over DNS over HTTPS (T-900), through the binary: `podssh
//! node box TARGET --carrier dns:NODE` on the loopback, and `podssh operator
//! --carrier dns:CLIENT box` whose FILE names `resolver =
//! https://NAME/dns-query`. The client reaches that resolver only through a
//! stand-in HTTP proxy (`HTTPS_PROXY`) that answers each CONNECT: NAME is
//! pinned to an address of TEST-NET-1, which the proxy maps to a front of
//! the test. The front speaks TLS of a CA of the test (`SSL_CERT_FILE`) and
//! RFC 8484's GET of the wire form, and passes each query to the node's
//! responder (pod-link's) as UDP. Bytes come back whole from an echo server
//! behind the node; the proxy saw the CONNECT, and the front the queries.
//! Nothing leaves the loopback.

mod live_harness;
mod net_doc_kit;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use live_harness::{echo_server, scratch};
use net_doc_kit::NAME;
use podssh_relay::identity::Identity;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const LIMIT: Duration = Duration::from_secs(240);
const ZONE: &str = "t.example";
const NODE_SEED: [u8; 32] = [1; 32];
const CLIENT_SEED: [u8; 32] = [2; 32];
/// NAME's address for the client: TEST-NET-1, never a host; the proxy maps
/// it to the front.
const PINNED: &str = "192.0.2.10";

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn key_file(dir: &Path, name: &str, seed: [u8; 32]) -> String {
    let hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    pod_core::files::create_private(&dir.join(name), format!("{hex}\n").as_bytes()).expect("a private key file");
    Identity::from_seed(&seed).public().hex()
}

/// FILE at `path`, its owner's alone: podssh refuses one that others can
/// change, and an umask of 002 would make it 664.
fn write_conf(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// The front of DNS over HTTPS: each `GET PATH?dns=B64` of a kept HTTP/1.1
/// connection goes to `node` as one UDP query, and its answer comes back as
/// `application/dns-message`. Its port, and the count of queries.
fn front(rt: &tokio::runtime::Runtime, cert: &str, key: &str, node: SocketAddr) -> (u16, Arc<AtomicUsize>) {
    let alpn = [podssh_ws::tls_server::HTTP1];
    let acceptor = podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &alpn).expect("the TLS");
    let listener = rt.block_on(tokio::net::TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(AtomicUsize::new(0));
    let count = asked.clone();
    rt.spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, count) = (acceptor.clone(), count.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut held = Vec::new();
                loop {
                    let Some(end) = head_end(&mut tls, &mut held).await else { return };
                    let head = String::from_utf8_lossy(&held[..end]).into_owned();
                    held.drain(..end);
                    let Some(query) = query_of(&head) else { return };
                    count.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = match ask(node, &query).await {
                        Some(answer) => (200, answer),
                        None => (504, Vec::new()),
                    };
                    let reply = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
                        body.len()
                    );
                    if tls.write_all(&[reply.into_bytes(), body].concat()).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (port, asked)
}

/// The end of the next request's head in `held`, reading more as needed.
async fn head_end(tls: &mut (impl tokio::io::AsyncRead + Unpin), held: &mut Vec<u8>) -> Option<usize> {
    let mut chunk = [0u8; 4096];
    loop {
        if let Some(at) = held.windows(4).position(|w| w == b"\r\n\r\n") {
            return Some(at + 4);
        }
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => held.extend_from_slice(&chunk[..n]),
        }
    }
}

/// The DNS message of `GET /dns-query?dns=B64 HTTP/1.1`.
fn query_of(head: &str) -> Option<Vec<u8>> {
    let target = head.lines().next()?.strip_prefix("GET ")?.split(' ').next()?;
    let (path, query) = target.split_once('?')?;
    if path != "/dns-query" {
        return None;
    }
    let b64 = query.split('&').find_map(|kv| kv.strip_prefix("dns="))?;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(b64).ok()
}

/// One query to the node's responder, and its answer within 10 s.
async fn ask(node: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    socket.send_to(query, node).await.ok()?;
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(Duration::from_secs(10), socket.recv(&mut buf)).await.ok()?.ok()?;
    buf.truncate(n);
    Some(buf)
}

/// A proxy that answers each CONNECT with 200 and carries it to `front`;
/// its port, and each target that was asked.
fn proxy(front: u16) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = asked.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut conn) = conn else { return };
            let seen = seen.clone();
            std::thread::spawn(move || {
                let (mut head, mut byte) = (Vec::new(), [0u8; 1]);
                while !head.ends_with(b"\r\n\r\n") {
                    if conn.read(&mut byte).unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
                let target = line.strip_prefix("CONNECT ").and_then(|r| r.split(' ').next()).unwrap_or("");
                seen.lock().unwrap().push(target.to_string());
                let Ok(far) = TcpStream::connect(("127.0.0.1", front)) else { return };
                let _ = conn.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                let (mut a, mut b) = (conn.try_clone().unwrap(), far.try_clone().unwrap());
                let (mut c, mut d) = (conn, far);
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut a, &mut b);
                    let _ = b.shutdown(std::net::Shutdown::Write);
                });
                let _ = std::io::copy(&mut d, &mut c);
                let _ = c.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    (port, asked)
}

/// `cmd` with `input` on stdin, within [`LIMIT`]: its code, stdout, stderr.
fn run_with(mut cmd: std::process::Command, input: Vec<u8>) -> (Option<i32>, Vec<u8>, String) {
    let child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().expect("it runs");
    let mut child = Running(child);
    let mut stdin = child.0.stdin.take().expect("stdin");
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let mut out_pipe = child.0.stdout.take().expect("stdout");
    let mut err_pipe = child.0.stderr.take().expect("stderr");
    let out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = out_pipe.read_to_end(&mut bytes);
        bytes
    });
    let err = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = err_pipe.read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + LIMIT;
    let code = loop {
        if let Some(status) = child.0.try_wait().expect("wait") {
            break status.code();
        }
        assert!(Instant::now() < deadline, "{cmd:?} did not end within {LIMIT:?}");
        std::thread::sleep(Duration::from_millis(50));
    };
    (code, out.join().unwrap_or_default(), err.join().unwrap_or_default())
}

#[test]
fn an_operator_reaches_a_node_over_dns_over_https_through_a_proxy_and_both_end_with_0() {
    let home = scratch("dns-https");
    let _scratch = Scratch(home.clone());
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let listen: SocketAddr =
        format!("127.0.0.1:{}", UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()).parse().unwrap();
    let (ca, cert, key) = net_doc_kit::ca_and_leaf();
    let ca_file = home.join("ca.pem");
    std::fs::write(&ca_file, ca).unwrap();
    let (front_port, queries) = front(&rt, &cert, &key, listen);
    let (proxy_port, connects) = proxy(front_port);

    let _ = key_file(&home, "node.key", NODE_SEED);
    let client_key = key_file(&home, "client.key", CLIENT_SEED);
    let node_pub = Identity::from_seed(&NODE_SEED).public().hex();
    let node_conf = home.join("node.conf");
    let text = format!("zone = {ZONE}\nlisten = {listen}\nkey-file = node.key\npeer = {client_key}\n");
    write_conf(&node_conf, &text);
    let client_conf = home.join("client.conf");
    let text =
        format!("zone = {ZONE}\nresolver = https://{NAME}/dns-query\nkey-file = client.key\npeer = {node_pub}\n");
    write_conf(&client_conf, &text);

    let target = format!("127.0.0.1:{}", echo_server());
    let node_carrier = format!("dns:{}", node_conf.display());
    let node = live_harness::command(&home, &["node", "box", &target, "--carrier", &node_carrier])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the node runs");
    let mut node = Running(node);
    std::thread::sleep(Duration::from_millis(500));

    let client_carrier = format!("dns:{}", client_conf.display());
    let mut operator = live_harness::command(&home, &["operator", "--carrier", &client_carrier, "box"]);
    for name in ["NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy", "https_proxy"] {
        operator.env_remove(name);
    }
    operator.env("HTTPS_PROXY", format!("http://127.0.0.1:{proxy_port}"));
    operator.env("SSL_CERT_FILE", &ca_file).env("PODSSH_RELAY_ADDR", format!("{NAME}={PINNED}"));
    let sent: Vec<u8> = (0..8192u32).map(|i| (i.wrapping_mul(131) % 251) as u8).collect();
    let (code, out, err) = run_with(operator, sent.clone());

    let deadline = Instant::now() + Duration::from_secs(60);
    let node_code = loop {
        if let Some(status) = node.0.try_wait().expect("wait") {
            break status.code();
        }
        if Instant::now() > deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut node_err = String::new();
    if let (Some(_), Some(mut pipe)) = (node_code, node.0.stderr.take()) {
        let _ = pipe.read_to_string(&mut node_err);
    }
    let seen = format!("CONNECTs {:?}, queries {}", connects.lock().unwrap(), queries.load(Ordering::SeqCst));
    let both = format!("{err}\nthe node: {node_err}\n{seen}");
    assert_eq!(code, Some(0), "{both}");
    assert!(out == sent, "{} bytes came back, changed or short: {both}", out.len());
    assert_eq!(node_code, Some(0), "the client's Close ends the node: {both}");
    let connects = connects.lock().unwrap().clone();
    assert!(!connects.is_empty(), "the client went around the proxy: {both}");
    for asked in &connects {
        assert!(asked == &format!("{PINNED}:443") || asked == &format!("{NAME}:443"), "CONNECT {asked}: {both}");
    }
    assert!(queries.load(Ordering::SeqCst) > 0, "the front got no query: {both}");
}

/// A resolver URL with no path is refused before anything connects (78).
#[test]
fn a_resolver_url_with_no_path_is_78_before_anything_connects() {
    let home = scratch("dns-https-bad");
    let _scratch = Scratch(home.clone());
    let node_pub = Identity::from_seed(&NODE_SEED).public().hex();
    let _ = key_file(&home, "client.key", CLIENT_SEED);
    let conf = home.join("client.conf");
    let text = format!("zone = {ZONE}\nresolver = https://{NAME}\nkey-file = client.key\npeer = {node_pub}\n");
    write_conf(&conf, &text);
    let carrier = format!("dns:{}", conf.display());
    let operator = live_harness::command(&home, &["operator", "--carrier", &carrier, "box"]);
    let (code, _, err) = run_with(operator, Vec::new());
    assert_eq!(code, Some(78), "{err}");
    assert!(err.contains("the path is missing"), "{err}");
}
