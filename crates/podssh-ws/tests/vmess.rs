//! VMess's AEAD form (T-739) against Xray-core, a server that podssh did not
//! write: the release that `scripts/interop-vless.sh` pins, run by
//! `vmess-interop.yml` (its path in `PODSSH_XRAY_TEST_BIN`), on the loopback,
//! serving VMess over a WebSocket and TLS at `/vm` under a certificate that
//! `openssl` makes for each run. Each cipher carries the target's version
//! line and a large echo; a pipe takes a stream whose target waits for its
//! client; a clock 5 minutes off, and an ID that is not the server's, get no
//! session, and their line names the clock; another path is refused. Each
//! test says "did not run" with no Xray-core, and the workflow fails on it.

mod vless_support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use podssh_ws::vmess::{self, AtEnd, Dial, Opened, Server, VmessError};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use vless_support::{pins, target, BANNER, NAME};

const LIMIT: Duration = Duration::from_secs(20);
/// A throwaway user of the tests' own server, no credential.
const ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const OTHER_ID: &str = "0f5a2d1e-9a7b-4c3d-8e6f-1a2b3c4d5e6f";

/// Xray-core serving VMess on the loopback; killed, and its directory gone,
/// when the test ends.
struct Xray {
    child: Child,
    dir: PathBuf,
    port: u16,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(dir: &Path, program: &str, args: &[&str]) {
    let status = Command::new(program).args(args).current_dir(dir).stdout(Stdio::null()).status();
    assert!(status.map(|s| s.success()).unwrap_or(false), "{program} {args:?} failed");
}

/// The server, or `None` (and the words "did not run") with no binary.
fn xray(tag: &str) -> Option<Xray> {
    let Some(bin) = std::env::var_os("PODSSH_XRAY_TEST_BIN") else {
        println!("did not run: PODSSH_XRAY_TEST_BIN names no Xray-core (vmess-interop.yml sets it)");
        return None;
    };
    let dir = std::env::temp_dir().join(format!("podssh-vmess-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // A root and a leaf: webpki takes no CA as the server's own certificate.
    let ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"];
    let ca = [
        &["req", "-x509"][..],
        &ec,
        &["-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=vmess-test-root"],
    ];
    run(&dir, "openssl", &ca.concat());
    let csr = [&["req"][..], &ec, &["-keyout", "srv.key", "-out", "srv.csr", "-subj", &format!("/CN={NAME}")]];
    run(&dir, "openssl", &csr.concat());
    std::fs::write(dir.join("leaf.cnf"), format!("subjectAltName=DNS:{NAME}\nbasicConstraints=CA:FALSE\n")).unwrap();
    let sign = ["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out"];
    run(&dir, "openssl", &[&sign[..], &["srv.pem", "-days", "2", "-extfile", "leaf.cnf"]].concat());
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let config = serde_json::json!({
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1", "port": port, "protocol": "vmess",
            "settings": {"clients": [{"id": ID}]},
            "streamSettings": {
                "network": "ws", "security": "tls",
                "wsSettings": {"path": "/vm"},
                "tlsSettings": {"certificates": [{
                    "certificateFile": dir.join("srv.pem"), "keyFile": dir.join("srv.key")
                }]}
            }
        }],
        // freedom blackholes a private target unless a final rule allows it
        // (`proxy/freedom/freedom.go`), and the tests' target is the loopback.
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
    let xray = Xray { child, dir, port };
    let until = Instant::now() + LIMIT;
    while std::net::TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < until, "Xray-core did not listen: {}", log_of(&xray));
        std::thread::sleep(Duration::from_millis(100));
    }
    Some(xray)
}

fn log_of(xray: &Xray) -> String {
    std::fs::read_to_string(xray.dir.join("xray.log")).unwrap_or_default()
}

/// v2rayN's line for the server, with `scy`, the ID and the path given.
fn link(port: u16, scy: &str, id: &str, path: &str) -> Server {
    let json = serde_json::json!({
        "v": "2", "ps": "the tests' Xray", "add": NAME, "port": port.to_string(), "id": id, "aid": "0",
        "scy": scy, "net": "ws", "type": "none", "host": NAME, "path": path, "tls": "tls", "sni": NAME
    });
    let line = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json.to_string()));
    Server::parse(&line).unwrap()
}

async fn open(xray: &Xray, server: &Server, aim: u16, pipe: bool, unix: u64) -> Result<Opened, VmessError> {
    let trust = Trust::File(xray.dir.join("ca.pem"));
    let answer = if pipe { vmess::EARLY_WAIT } else { vmess::ANSWER_WAIT };
    let proxy = ProxyChoice::Direct;
    let at_end = if pipe { AtEnd::AfterPeer } else { AtEnd::Now };
    let dial = Dial { trust: &trust, proxy: &proxy, timeout: LIMIT, answer, silence_is_ready: pipe, at_end };
    let opened = vmess::open_at(server, "127.0.0.1", aim, &dial, unix);
    tokio::time::timeout(LIMIT * 2, opened).await.expect("within the limit")
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// `sent` echoed back, read while it goes.
async fn echoes(opened: &mut Opened, sent: &[u8]) {
    let mut back = vec![0u8; sent.len()];
    let (mut read, mut write) = tokio::io::split(&mut opened.stream);
    let up = async {
        write.write_all(sent).await.unwrap();
        write.flush().await.unwrap();
    };
    let both = async { tokio::join!(up, async { read.read_exact(&mut back).await.unwrap() }) };
    tokio::time::timeout(LIMIT * 2, both).await.expect("the echo within the limit");
    assert!(back == sent, "the bytes came back changed");
}

/// Each cipher carries the session: the target's version line first, then
/// 300 KB echoed whole (chunks of each size, the count past a few dozen).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_cipher_carries_a_session_through_xray() {
    let Some(xray) = xray("each") else { return };
    pins();
    let aim = target(true).await;
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    for scy in ["aes-128-gcm", "chacha20-poly1305", "auto"] {
        let server = link(xray.port, scy, ID, "/vm");
        let mut opened = open(&xray, &server, aim, false, now())
            .await
            .unwrap_or_else(|e| panic!("{scy}: {}\n{}", e.line(&server.shown(), "target"), log_of(&xray)));
        assert!(opened.answered && opened.how == "a WebSocket over TLS", "{scy}: {}", opened.how);
        let mut banner = vec![0u8; BANNER.len()];
        tokio::time::timeout(LIMIT, opened.stream.read_exact(&mut banner)).await.unwrap().unwrap();
        assert_eq!(banner, BANNER, "{scy}");
        echoes(&mut opened, &big).await;
    }
}

/// A pipe to a target that waits for its client takes the stream after the
/// silence, and its bytes go and come back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_takes_a_stream_whose_target_waits() {
    let Some(xray) = xray("pipe") else { return };
    pins();
    let aim = target(false).await;
    let server = link(xray.port, "aes-128-gcm", ID, "/vm");
    let mut opened = open(&xray, &server, aim, true, now()).await.unwrap_or_else(|e| panic!("{}", e.line("x", "t")));
    assert!(!opened.answered, "the target said nothing, so the server's answer waits for its bytes");
    echoes(&mut opened, b"the client speaks first").await;
}

/// A clock 5 minutes off, and another ID, get no session; each line names
/// the clock as a cause. Another path is refused by its status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_off_another_id_and_another_path_are_refused() {
    let Some(xray) = xray("refused") else { return };
    pins();
    let aim = target(true).await;
    let server = link(xray.port, "aes-128-gcm", ID, "/vm");
    for (what, server, unix) in [
        ("a clock 5 minutes behind", server.clone(), now() - 300),
        ("a clock 5 minutes ahead", server.clone(), now() + 300),
        ("another ID", link(xray.port, "aes-128-gcm", OTHER_ID, "/vm"), now()),
    ] {
        let failed = match open(&xray, &server, aim, false, unix).await {
            Ok(_) => panic!("{what}: Xray-core carried the session"),
            Err(e) => e,
        };
        assert!(matches!(failed, VmessError::Ended | VmessError::Silent(_)), "{what}: {failed:?}");
        let line = failed.line(&server.shown(), "127.0.0.1:22");
        assert!(line.contains("clock") && !line.contains(ID) && !line.contains(OTHER_ID), "{what}: {line}");
    }
    let elsewhere = link(xray.port, "aes-128-gcm", ID, "/other");
    match open(&xray, &elsewhere, aim, false, now()).await {
        Err(VmessError::Refused { status, .. }) => assert!(status >= 400, "{status}"),
        Err(other) => panic!("another path: {}", other.line("x", "t")),
        Ok(_) => panic!("another path carried the session"),
    }
}
