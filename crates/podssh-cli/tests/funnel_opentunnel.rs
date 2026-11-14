//! `podssh funnel TARGET --opentunnel` from end to end (T-532), on this
//! machine's loopback: podssh-relay's stand-in OpenTunnel server
//! (`tests/opentunnel_stand_in`), its API behind TLS of its own CA and its
//! visitors' port raw, as the service's; a stand-in proxy that takes a
//! CONNECT to the service's names alone, as a cage whose proxy passes TLS by
//! name; Python's `http.server`, software that podssh did not write, as
//! TARGET; and curl, software that podssh did not write either, as the
//! visitor, which checks the funnel's certificate for the tunnel's own name
//! with the stand-in's CA. A GET and a POST of 100 KiB come back through the
//! tunnel, and stderr has the line about TLS; a WebSocket's upgrade passes
//! to an echo and back; a funnel started again keeps its URL and binds no
//! new CSR; a funnel with no flag whose quick tunnel the proxy refuses takes
//! the road unasked (Q76). Each test that needs Python or curl says "did
//! not run" where they are missing. Planted
//! (`scripts/plants/t532-route-not-root.patch`): the funnel's bridge claims
//! its random route in place of `@`, so the URL's name reaches no bridge and
//! curl gets nothing.

mod cleanup;
#[path = "../../podssh-relay/tests/opentunnel_stand_in/mod.rs"]
mod opentunnel_stand_in;

use std::io::{BufRead, BufReader};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use opentunnel_stand_in::{StandIn, DOMAIN};
use podssh_ws::frame::{self, Frame, Role};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const LIMIT: Duration = Duration::from_secs(60);
const TLS_LINE: &str = "TLS ends at this host; OpenTunnel sees the names, the times and the sizes.";

/// TARGET: a GET of /hello, and a POST of /sum answered with its body's
/// SHA-256 and the Connection header that it came with.
const SERVER: &str = r#"
import hashlib, http.server, os, sys

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *args): pass
    def answer(self, out):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
        self.close_connection = True
    def do_GET(self):
        self.answer(b"hello through the funnel")
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.answer((hashlib.sha256(body).hexdigest() + " " + self.headers.get("Connection", "-")).encode())

ready = sys.argv[1]
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
open(ready + ".tmp", "w").write(str(server.server_address[1]))
os.rename(ready + ".tmp", ready)
server.serve_forever()
"#;

/// A fresh, empty, private scratch directory, removed when the test ends.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("podssh-funnel-opentunnel-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    podssh_relay::cache::private_dir(&dir).expect("a scratch directory");
    cleanup::at_test_end(&dir);
    dir
}

/// Kills a child when the test ends.
struct Killed(Child);

impl Drop for Killed {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Whether `program --version` runs here.
fn found(program: &str) -> bool {
    let quiet = |cmd: &mut Command| cmd.stdout(Stdio::null()).stderr(Stdio::null()).status();
    quiet(Command::new(program).arg("--version")).is_ok_and(|s| s.success())
}

/// Python's server in `dir`, and its port; none with no Python here.
fn python(dir: &Path) -> Option<(Killed, u16)> {
    let program = ["python3", "python"].into_iter().find(|p| found(p))?;
    let (script, ready) = (dir.join("server.py"), dir.join("ready"));
    std::fs::write(&script, SERVER).unwrap();
    let child = Command::new(program).arg("-I").arg(&script).arg(&ready).stdin(Stdio::null()).spawn().ok()?;
    let mut server = Killed(child);
    let deadline = Instant::now() + LIMIT;
    while !ready.exists() {
        assert!(server.0.try_wait().unwrap().is_none(), "Python's server ended before it was ready");
        assert!(Instant::now() < deadline, "Python's server did not start within {} s", LIMIT.as_secs());
        std::thread::sleep(Duration::from_millis(50));
    }
    Some((server, std::fs::read_to_string(&ready).unwrap().trim().parse().unwrap()))
}

/// The stand-in proxy: a CONNECT to the service's name goes to its API, one
/// to a name under it to its visitors' port, and each other is refused.
async fn proxy(api: u16, visitors: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let target = podssh_ws::http::request::connect_target(&request.target);
                let to = match (request.method.as_str(), target) {
                    ("CONNECT", Ok((host, 443))) if host == DOMAIN => api,
                    ("CONNECT", Ok((host, 443))) if host.ends_with(&format!(".{DOMAIN}")) => visitors,
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

/// The place of one test: the stand-in, the proxy, the CA's file and the
/// funnel's home, whose cache keeps the funnel's tunnel.
struct Lab {
    runtime: tokio::runtime::Runtime,
    stand_in: Arc<StandIn>,
    proxy: u16,
    ca: PathBuf,
    home: PathBuf,
}

impl Lab {
    fn new(name: &str) -> Lab {
        let home = scratch(name);
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let stand_in = StandIn::new();
        let ca = home.join("ca.pem");
        std::fs::write(&ca, &stand_in.ca.pem).unwrap();
        let (cert, key) = stand_in.ca.pair(DOMAIN);
        let acceptor =
            podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &[podssh_ws::tls_server::HTTP1])
                .expect("the API's TLS");
        let proxy_port = runtime.block_on(async {
            let api = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let visitors = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let (api_port, visitors_port) = (api.local_addr().unwrap().port(), visitors.local_addr().unwrap().port());
            let serving = stand_in.clone();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = api.accept().await {
                    let (acceptor, serving) = (acceptor.clone(), serving.clone());
                    tokio::spawn(async move {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            serving.serve_api(tls).await;
                        }
                    });
                }
            });
            let serving = stand_in.clone();
            tokio::spawn(async move {
                while let Ok((tcp, _)) = visitors.accept().await {
                    tokio::spawn(serving.clone().serve_visitor(tcp));
                }
            });
            proxy(api_port, visitors_port).await
        });
        Lab { runtime, stand_in, proxy: proxy_port, ca, home }
    }

    /// `podssh funnel ARGS` with the stand-in's service, its CA and the proxy,
    /// and none of the settings of the machine that runs the test.
    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_podssh"));
        cmd.arg("funnel").args(args).env("PODSSH_SSH_CONFIG", "none").env("PODSSH_SETTINGS", "none");
        for name in ["PODSSH_OFFLINE", "SSH_AUTH_SOCK", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"] {
            cmd.env_remove(name);
        }
        let proxy = format!("http://127.0.0.1:{}", self.proxy);
        cmd.env("HTTPS_PROXY", &proxy).env("https_proxy", &proxy).env("HTTP_PROXY", &proxy);
        cmd.env("PODSSH_OPENTUNNEL", format!("https://{DOMAIN}")).env("SSL_CERT_FILE", &self.ca);
        cmd.env("HOME", &self.home).env("USERPROFILE", &self.home);
        cmd.env("XDG_CACHE_HOME", self.home.join("cache")).env("LOCALAPPDATA", self.home.join("cache"));
        cmd
    }

    /// A funnel of `args`, its URL once it printed one, and its lines.
    fn funnel(&self, args: &[&str]) -> (Killed, String, mpsc::Receiver<String>) {
        let mut cmd = self.command(args);
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("podssh funnel runs");
        let (stdout, stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let (lines_tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = lines_tx.send(line);
            }
        });
        let (url_tx, url) = mpsc::channel();
        std::thread::spawn(move || {
            let mut first = String::new();
            let _ = BufReader::new(stdout).read_line(&mut first);
            let _ = url_tx.send(first.trim().to_string());
        });
        let funnel = Killed(child);
        let url = url.recv_timeout(LIMIT).unwrap_or_default();
        let said: Vec<String> = lines.try_iter().collect();
        assert!(url.starts_with("https://"), "no URL within {} s: {said:#?}", LIMIT.as_secs());
        let (tx, again) = mpsc::channel();
        for line in said {
            let _ = tx.send(line);
        }
        std::thread::spawn(move || {
            for line in lines.iter() {
                let _ = tx.send(line);
            }
        });
        (funnel, url, again)
    }

    /// curl ARGS through the proxy, with the stand-in's CA: (code, stdout,
    /// stderr); none with no curl here.
    fn curl(&self, args: &[&str]) -> Option<(i32, String, String)> {
        if !found("curl") {
            return None;
        }
        let proxy = format!("http://127.0.0.1:{}", self.proxy);
        let mut cmd = Command::new("curl");
        // schannel (curl on Windows) asks the test CA's revocation status,
        // which no responder answers; the option is curl's on each system.
        cmd.args(["-q", "-sS", "--max-time", "20", "--ssl-no-revoke", "--proxy", &proxy, "--cacert"])
            .arg(&self.ca)
            .args(args);
        let out = cmd.stdin(Stdio::null()).output().expect("curl runs");
        let text = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
        Some((out.status.code().unwrap_or(-1), text(&out.stdout), text(&out.stderr)))
    }
}

/// The lines said so far.
fn said(lines: &mpsc::Receiver<String>) -> Vec<String> {
    std::thread::sleep(Duration::from_millis(200));
    lines.try_iter().collect()
}

/// A URL of the funnel: the tunnel's own name under the stand-in's domain.
fn check_url(url: &str) {
    let host = url.strip_prefix("https://").and_then(|rest| rest.strip_suffix('/')).unwrap_or_default();
    let id = host.strip_suffix(&format!(".{DOMAIN}")).unwrap_or_default();
    assert!(!id.is_empty() && !id.contains('.'), "the tunnel's own name, no route: {url}");
}

#[test]
fn a_funnel_through_opentunnel_serves_python_to_curl_with_tls_that_ends_here() {
    let lab = Lab::new("curl");
    let Some((_python, port)) = python(&lab.home) else {
        eprintln!("did not run: no Python here");
        return;
    };
    if !found("curl") {
        eprintln!("did not run: no curl here");
        return;
    }
    let target = format!("127.0.0.1:{port}");
    let (_funnel, url, lines) = lab.funnel(&[&target, "--opentunnel"]);
    check_url(&url);
    let lines = said(&lines);
    assert!(lines.iter().any(|l| l.contains(TLS_LINE)), "{lines:#?}");
    let hello = format!("{url}hello");
    let (rc, body, err) = lab.curl(&["-v", &hello]).unwrap();
    assert_eq!(rc, 0, "curl's GET: {err}");
    assert_eq!(body, "hello through the funnel");
    // The funnel offers HTTP/1.1 alone, as podssh-ws serves no HTTP/2.
    let alpn: Vec<&str> = err.lines().filter(|l| l.contains("ALPN") && l.contains("accepted")).collect();
    assert!(alpn.iter().all(|l| l.contains("http/1.1")), "{alpn:#?}");
    let upload: Vec<u8> = (0..100 * 1024u32).map(|i| (i % 251) as u8).collect();
    let file = lab.home.join("upload.bin");
    std::fs::write(&file, &upload).unwrap();
    let want: String = Sha256::digest(&upload).iter().map(|b| format!("{b:02x}")).collect();
    let data = format!("@{}", file.display());
    let sum = format!("{url}sum");
    let (rc, body, err) = lab.curl(&["-H", "Expect:", "--data-binary", &data, &sum]).unwrap();
    assert_eq!(rc, 0, "curl's POST: {err}");
    assert_eq!(body, format!("{want} close"), "the body whole, with Connection: close");
    assert!(lab.stand_in.opens.load(Ordering::SeqCst) >= 2, "each visitor came over the bridge");
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 1, "one tunnel");
    drop(lab.runtime);
}

/// A WebSocket echo on the loopback: one upgrade, then each message back.
async fn websocket_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok((request, rest)) = podssh_ws::http::read_request(&mut tcp, Vec::new()).await else { return };
                let key = request.header("sec-websocket-key").unwrap_or_default().to_string();
                let accept = podssh_ws::handshake::accept_key(&key);
                let answer = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                );
                tcp.write_all(answer.as_bytes()).await.unwrap();
                let (mut inbox, mut chunk) = (rest, vec![0u8; 4096]);
                loop {
                    while let Ok(Some((frame, used))) = frame::decode(&inbox, Role::Client) {
                        inbox.drain(..used);
                        let back = Frame { fin: true, opcode: frame.opcode, payload: frame.payload };
                        tcp.write_all(&frame::encode(&back, Role::Server, [0; 4])).await.unwrap();
                    }
                    let n = tcp.read(&mut chunk).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    inbox.extend_from_slice(&chunk[..n]);
                }
            });
        }
    });
    port
}

/// A visitor's WebSocket at `host`: CONNECT through the proxy, TLS by
/// `host` with the stand-in's CA, the upgrade, one message and its echo.
async fn websocket_through(proxy: u16, host: &str, ca: &Path) -> Vec<u8> {
    let mut tcp = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy)).await.unwrap();
    tcp.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n").as_bytes()).await.unwrap();
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        assert_eq!(tcp.read(&mut byte).await.unwrap(), 1, "the proxy's answer");
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    let trust = podssh_ws::Trust::File(ca.to_path_buf());
    let mut tls = podssh_ws::tls::connect_over(tcp, host, &trust, LIMIT).await.expect("TLS by the tunnel's name");
    let upgrade = format!(
        "GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(upgrade.as_bytes()).await.unwrap();
    let message = Frame { fin: true, opcode: 0x1, payload: b"through the funnel".to_vec() };
    tls.write_all(&frame::encode(&message, Role::Client, [1, 2, 3, 4])).await.unwrap();
    let (mut inbox, mut chunk) = (Vec::new(), vec![0u8; 4096]);
    loop {
        if let Some(end) = inbox.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&inbox[..end]).to_string();
            assert!(head.starts_with("HTTP/1.1 101"), "{head}");
            assert!(head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "the echo's accept key: {head}");
            if let Ok(Some((frame, _))) = frame::decode(&inbox[end + 4..], Role::Server) {
                return frame.payload;
            }
        }
        let n = tokio::time::timeout(LIMIT, tls.read(&mut chunk)).await.expect("the echo in time").unwrap();
        assert!(n > 0, "the funnel closed before the echo");
        inbox.extend_from_slice(&chunk[..n]);
    }
}

#[test]
fn a_websocket_passes_through_the_funnel_and_a_funnel_started_again_keeps_its_url() {
    let lab = Lab::new("websocket");
    let target = format!("127.0.0.1:{}", lab.runtime.block_on(websocket_echo()));
    let (funnel, url, _lines) = lab.funnel(&[&target, "--opentunnel"]);
    check_url(&url);
    let host = url.trim_start_matches("https://").trim_end_matches('/').to_string();
    let back = lab.runtime.block_on(websocket_through(lab.proxy, &host, &lab.ca));
    assert_eq!(back, b"through the funnel");
    drop(funnel);
    // Started again: the same name, from the tunnel kept in the cache.
    let (_funnel, again, lines) = lab.funnel(&[&target, "--opentunnel"]);
    assert_eq!(again, url, "the same URL");
    assert!(said(&lines).iter().any(|l| l.contains("the tunnel kept in")));
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 1, "no second tunnel");
    assert_eq!(lab.stand_in.new_csrs.load(Ordering::SeqCst), 1, "no new CSR");
    drop(lab.runtime);
}

#[test]
fn a_funnel_whose_quick_tunnel_the_proxy_refuses_takes_opentunnel_unasked() {
    let lab = Lab::new("unasked");
    let target = format!("127.0.0.1:{}", lab.runtime.block_on(websocket_echo()));
    // The proxy refuses the quick tunnel's API, as it passes the service's names alone.
    let (_funnel, url, lines) = lab.funnel(&[&target]);
    check_url(&url);
    let lines = said(&lines);
    let unasked = lines.iter().find(|l| l.contains("unasked")).unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(unasked.contains("the quick tunnel could not carry the funnel"), "{unasked}");
    assert!(unasked.contains("Q76") && unasked.contains("PODSSH_OPENTUNNEL=no"), "{unasked}");
    assert!(lines.iter().any(|l| l.contains(TLS_LINE)), "{lines:#?}");
    drop(lab.runtime);
}

#[test]
fn opentunnel_off_or_beside_another_road_is_refused_before_anything_connects() {
    let lab = Lab::new("refused");
    for (extra, env, words) in [
        (&["--opentunnel"][..], Some("no"), "PODSSH_OPENTUNNEL=no turns the OpenTunnel road off"),
        (&["--opentunnel", "--warp"][..], None, "--warp"),
        (&["--opentunnel", "--tunnel-token-file", "token"][..], None, "--tunnel-token-file"),
    ] {
        let mut cmd = lab.command(&[&["127.0.0.1:9"][..], extra].concat());
        if let Some(value) = env {
            cmd.env("PODSSH_OPENTUNNEL", value);
        }
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(64), "{extra:?}: {err}");
        assert!(err.contains(words), "{extra:?}: {err}");
        assert!(out.stdout.is_empty());
    }
    assert_eq!(lab.stand_in.created.load(Ordering::SeqCst), 0, "no tunnel made");
    drop(lab.runtime);
}
