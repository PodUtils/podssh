//! Trojan (T-491) against stand-ins on the loopback, as trojan-gfw's server
//! behaves (`src/session/serversession.cpp`): after TLS it reads the request,
//! compares the 56 bytes of the hash as they come, and on a match dials the
//! target and relays; on another hash, or a request that it cannot read, it
//! hands the bytes to its fallback, an HTTP server that answers `400`. In TLS
//! alone, and in a WebSocket over TLS at `/tr`, as trojan-go and Xray-core
//! serve it. A session carries the target's version line and an echo; a
//! wrong password is said as the fallback's answer; a wrong path is a 404; a
//! pipe takes a stream whose target waits for its client. A pipe's end of
//! input loses no byte of 1 MiB still on its way: TLS alone carries it as a
//! half-close, and the WebSocket sends no Close until the server's end
//! (T-699). The runs against trojan-gfw, trojan-go and Xray-core are
//! `scripts/interop-trojan.sh`.

mod trojan_support;
mod vless_support;

use std::time::Duration;

use podssh_ws::trojan::{self, AtEnd, Dial, Opened, Server, TrojanError};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trojan_support::{listen, serve_tls, serve_ws, PASSWORD};
use vless_support::{pins, root_file, talker, target, BANNER, NAME};

const LIMIT: Duration = Duration::from_secs(20);

/// A link of the stand-in; each password of the tests needs no encoding.
fn server(port: u16, query: &str, password: &str) -> Server {
    Server::parse(&format!("trojan://{password}@{NAME}:{port}?security=tls&{query}")).unwrap()
}

async fn open(server: &Server, port: u16, root: &std::path::Path, pipe: bool) -> Result<Opened, TrojanError> {
    let trust = Trust::File(root.to_path_buf());
    let answer = if pipe { trojan::EARLY_WAIT } else { trojan::ANSWER_WAIT };
    let proxy = ProxyChoice::Direct;
    let at_end = if pipe { AtEnd::AfterPeer } else { AtEnd::Now };
    let dial = Dial { trust: &trust, proxy: &proxy, timeout: LIMIT, answer, silence_is_ready: pipe, at_end };
    tokio::time::timeout(LIMIT * 2, trojan::open(server, "127.0.0.1", port, &dial)).await.expect("within the limit")
}

/// The target's version line, then `sent` echoed back.
async fn carries(opened: &mut Opened, sent: &[u8]) {
    let mut banner = vec![0u8; BANNER.len()];
    let mut back = vec![0u8; sent.len()];
    let both = async {
        opened.stream.read_exact(&mut banner).await.unwrap();
        // The echo is read while the bytes go: written whole first, they
        // filled each buffer on the way and both ends waited (seen once in
        // the crate's whole run).
        let (mut read, mut write) = tokio::io::split(&mut opened.stream);
        let up = async {
            write.write_all(sent).await.unwrap();
            write.flush().await.unwrap();
        };
        tokio::join!(up, async { read.read_exact(&mut back).await.unwrap() });
    };
    tokio::time::timeout(LIMIT * 2, both).await.expect("the bytes within the limit");
    assert_eq!(banner, BANNER);
    assert!(back == sent, "the bytes came back changed");
}

/// Each transport carries the session: the request names the target, the
/// target's version line comes first, and a large echo comes back whole.
/// The planted hash in upper case fails both: the stand-in compares bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_goes_in_tls_alone_and_in_a_websocket() {
    pins();
    let (root, aim) = (root_file("trojan-each"), target(true).await);
    let big = vec![7u8; 300_000];
    let (tls_port, tls_seen) = listen(serve_tls).await;
    let mut opened = open(&server(tls_port, "type=tcp", PASSWORD), aim, &root, false)
        .await
        .unwrap_or_else(|e| panic!("{}", e.line("tls", "target")));
    assert!(opened.answered && opened.how == "TLS", "{}", opened.how);
    carries(&mut opened, &big).await;
    assert_eq!(*tls_seen.targets.lock().unwrap(), vec![format!("127.0.0.1:{aim}")]);
    let (ws_port, ws_seen) = listen(serve_ws).await;
    let link = server(ws_port, &format!("type=ws&path=%2Ftr&host=front.{NAME}&sni={NAME}"), PASSWORD);
    let mut opened = open(&link, aim, &root, false).await.unwrap_or_else(|e| panic!("{}", e.line("ws", "target")));
    assert!(opened.answered && opened.how == "a WebSocket over TLS", "{}", opened.how);
    carries(&mut opened, &big).await;
    assert_eq!(*ws_seen.paths.lock().unwrap(), vec!["/tr".to_string()]);
}

/// A wrong password is the fallback's answer, said with its status line and
/// never the password; a wrong path is the upgrade's 404.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_password_is_the_fallback_s_answer_and_a_wrong_path_a_404() {
    pins();
    let (root, aim) = (root_file("trojan-wrong"), target(true).await);
    let (tls_port, tls_seen) = listen(serve_tls).await;
    let (ws_port, _) = listen(serve_ws).await;
    for link in [server(tls_port, "type=tcp", "not-the-password"), server(ws_port, "type=ws&path=%2Ftr", "nope")] {
        match open(&link, aim, &root, false).await {
            Err(TrojanError::Fallback(line)) => {
                assert_eq!(line, "HTTP/1.1 400 Bad Request");
                let said = TrojanError::Fallback(line).line(&link.shown(), "t:22");
                assert!(!said.contains("not-the-password") && said.contains("not the server's"), "{said}");
            }
            Ok(_) => panic!("{}: a wrong password carried a session", link.shown()),
            Err(e) => panic!("{}: {}", link.shown(), e.line(&link.shown(), "t:22")),
        }
    }
    assert!(tls_seen.targets.lock().unwrap().is_empty(), "no target for a wrong password");
    match open(&server(ws_port, "type=ws&path=%2Fother", PASSWORD), aim, &root, false).await {
        Err(TrojanError::Refused { status: 404, why }) => assert!(why.contains("/other"), "{why}"),
        Ok(_) => panic!("another path carried a session"),
        Err(e) => panic!("{}", e.line("ws", "t")),
    }
}

/// A pipe's end of input (T-699): this side's input ends at once, while the
/// target's 1 MiB is still on its way. In TLS alone the end is TCP's
/// half-close, which the stand-in passes to the target; over a WebSocket,
/// which has none, the stand-in answers a Close at once and sends nothing
/// after it, so the pipe sends its Close only after the server's. Each byte
/// comes on each. Planted, a Close at the first end, the WebSocket's rest is
/// lost.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_s_end_of_input_loses_no_byte_in_tls_alone_or_in_a_websocket() {
    pins();
    let (root, aim) = (root_file("trojan-end"), talker::talker().await);
    let (tls_port, _) = listen(serve_tls).await;
    let (ws_port, _) = listen(serve_ws).await;
    for link in [server(tls_port, "type=tcp", PASSWORD), server(ws_port, "type=ws&path=%2Ftr", PASSWORD)] {
        let mut opened = open(&link, aim, &root, true).await.unwrap_or_else(|e| panic!("{}", e.line("end", "t")));
        assert!(opened.answered, "{}: the target's first piece came", opened.how);
        opened.stream.shutdown().await.unwrap();
        let got = talker::to_end(&mut opened.stream).await;
        talker::assert_whole(&got, opened.how);
    }
}

/// A pipe's target waits for its client: after the short wait the stream is
/// taken, and the echo comes back; the request's address is the target's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipe_takes_a_stream_whose_target_waits_for_its_client() {
    pins();
    let (root, aim) = (root_file("trojan-pipe"), target(false).await);
    let (tls_port, seen) = listen(serve_tls).await;
    let mut opened = open(&server(tls_port, "", PASSWORD), aim, &root, true)
        .await
        .unwrap_or_else(|e| panic!("{}", e.line("pipe", "t")));
    assert!(!opened.answered, "the target said nothing");
    opened.stream.write_all(b"ping\n").await.unwrap();
    let mut back = [0u8; 5];
    tokio::time::timeout(LIMIT, opened.stream.read_exact(&mut back)).await.expect("the echo in time").unwrap();
    assert_eq!(&back, b"ping\n");
    assert_eq!(seen.targets.lock().unwrap().len(), 1);
}
