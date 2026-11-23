//! The tests of a node's lost link: a socket whose read reset, one whose
//! write failed, and one that answers nothing are let go at once, or well
//! within the node's minute of `409` (`pod-relay`'s `Settings::lost_hold`),
//! so that the node's next socket is taken and its operators reach it. The
//! sockets are pipes; `tests/relay_serve_lost.rs` resets a real one.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_ws::frame;
use podssh_ws::http::request::{self, Request};
use podssh_ws::session::{close_code_and_reason, RelaySession};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, DuplexStream, ReadBuf};

use super::super::pairs::{Made, Pair, Role};
use super::super::request as serve;
use super::*;
use crate::serve::{tokens, Config, Mint};

/// The bound of each wait of these tests but the silent node's.
const LIMIT: Duration = Duration::from_secs(10);

/// A role that mints for anyone, whose lines the test reads.
fn config() -> (Arc<Config>, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let said = lines.clone();
    let cfg = Arc::new(Config {
        version: "podssh test".into(),
        mint: Mint::Anyone,
        tokens: tokens::Tokens::new([5; 32]),
        policy: Default::default(),
        egress: Default::default(),
        limits: Default::default(),
        pairs: Arc::default(),
        resumes: Default::default(),
        answered: Default::default(),
        brake: Default::default(),
        usage: Default::default(),
        cover: None,
        events: Some(Box::new(move |line: &str| said.lock().unwrap().push(line.to_string()))),
    });
    (cfg, lines)
}

/// The upgrade of `path` with `token`, as a node or an operator sends it.
fn upgrade(path: &str, token: &str) -> Request {
    let text = format!(
        "GET {path} HTTP/1.1\r\nHost: relay-a.test\r\nX-Relay-Token: {token}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    request::parse_request(text.as_bytes()).unwrap()
}

/// The pair `made`, as the role keeps it.
fn pair_of(cfg: &Config, made: &Made) -> Arc<Pair> {
    cfg.pairs.find(&made.name, Role::Node, Some(&made.node), tokens::now_ms()).expect("the pair")
}

/// The status of the role's answer on `stream`, and the bytes after its head.
async fn answered<S: AsyncRead + Unpin>(stream: &mut S) -> (u16, Vec<u8>) {
    let mut got = Vec::new();
    let mut chunk = [0u8; 1024];
    let end = loop {
        if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        let n = tokio::time::timeout(LIMIT, stream.read(&mut chunk)).await.expect("an answer in time").unwrap();
        assert!(n > 0, "the role ended with no answer: {:?}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&got[..end]).into_owned();
    let status = head.split(' ').nth(1).and_then(|s| s.parse().ok()).unwrap_or_else(|| panic!("{head}"));
    (status, got[end..].to_vec())
}

/// A socket of the role on a pipe, the role's end of it `ours(pipe)`.
fn over_pipe<S>(cfg: &Arc<Config>, path: &str, token: &str, ours: impl FnOnce(DuplexStream) -> S) -> DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (near, far) = tokio::io::duplex(64 * 1024);
    tokio::spawn(serve(ours(far), upgrade(path, token), Vec::new(), cfg.clone(), None));
    near
}

/// The socket of a node or an operator once its upgrade was taken.
async fn taken<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, who: &str) -> RelaySession<S> {
    let (status, rest) = answered(&mut stream).await;
    assert_eq!(status, 101, "{who}: the upgrade was refused");
    RelaySession::new(stream, rest, None, LIMIT)
}

/// The next text frame of `peer`, as JSON.
async fn text_of<S: AsyncRead + AsyncWrite>(peer: &RelaySession<S>) -> Value {
    let f = tokio::time::timeout(LIMIT, peer.read_frame()).await.expect("a frame in time").expect("a frame");
    assert_eq!(f.opcode, frame::OPCODE_TEXT, "{:?}", String::from_utf8_lossy(&f.payload));
    serde_json::from_slice(&f.payload).expect("JSON")
}

/// Until the role let the node's socket of `pair` go, `limit` at most.
async fn let_go(pair: &Pair, limit: Duration) -> bool {
    let start = tokio::time::Instant::now();
    while pair.lock().node.is_some() {
        if start.elapsed() > limit {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// Until the role said a line that starts with `start`, [`LIMIT`] at most:
/// the socket's task says it just after it let the socket go.
async fn said(lines: &Mutex<Vec<String>>, start: &str) -> bool {
    let begun = tokio::time::Instant::now();
    loop {
        if lines.lock().unwrap().iter().any(|l| l.starts_with(start)) {
            return true;
        }
        if begun.elapsed() > LIMIT {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A stream that breaks as a socket whose peer went away: once `reset` is
/// set, its next read fails as a read after a reset does (the kernel's
/// `ECONNRESET`); once `broken` is set, each write fails, while its reads go
/// on waiting, as a link that said nothing.
struct Breaking {
    inner: DuplexStream,
    broken: Arc<AtomicBool>,
    reset: Arc<AtomicBool>,
}

impl AsyncRead for Breaking {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.reset.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        let read = Pin::new(&mut self.inner).poll_read(cx, buf);
        // Bytes that woke the read after the reset are the reset's.
        if self.reset.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        read
    }
}

impl AsyncWrite for Breaking {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.broken.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The node's read resets: the role lets its socket go at once, so the
/// node's next socket is taken with no `409`, and an operator reaches the
/// node on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_whose_read_reset_is_taken_again_at_once_and_reached() {
    let (cfg, lines) = config();
    let made = cfg.pairs.make(tokens::now_ms()).unwrap();
    let pair = pair_of(&cfg, &made);
    let node_path = format!("/v1/node/{}", made.name);
    let reset = Arc::new(AtomicBool::new(false));
    let resets = reset.clone();
    let broken = Arc::new(AtomicBool::new(false));
    let first = over_pipe(&cfg, &node_path, &made.node, move |inner| Breaking { inner, broken, reset: resets });
    let first = taken(first, "the first node").await;
    assert_eq!(text_of(&first).await["type"], "hello");
    reset.store(true, Ordering::SeqCst);
    // Any byte wakes the role's read, which then meets the reset.
    first.send_ping(b"wake").await.unwrap();

    // Far under the five seconds of a Close that the role would wait for.
    let freed = let_go(&pair, Duration::from_secs(2)).await;
    let mut second = over_pipe(&cfg, &node_path, &made.node, |s| s);
    let (status, rest) = answered(&mut second).await;
    assert_eq!(status, 101, "the node's next socket after a reset (freed in time: {freed})");
    let node = RelaySession::new(second, rest, None, LIMIT);
    assert_eq!(text_of(&node).await["type"], "hello");
    assert!(said(&lines, "reverse node lost: ").await, "{:?}", lines.lock().unwrap());

    let operator = over_pipe(&cfg, &format!("/v1/connect/{}", made.name), &made.connect, |s| s);
    let operator = taken(operator, "the operator").await;
    let open = text_of(&node).await;
    assert_eq!(open["type"], "open", "{open}");
    let id = open["id"].as_str().expect("an id").to_string();
    node.send_text(&json!({ "type": "ready", "id": id }).to_string()).await.unwrap();
    node.send_binary(&[id.as_bytes(), b"SSH-2.0-node\r\n"].concat()).await.unwrap();
    let ready = text_of(&operator).await;
    assert_eq!((ready["type"].as_str(), ready["id"].as_str()), (Some("ready"), Some(id.as_str())));
    let bytes = tokio::time::timeout(LIMIT, operator.read_frame()).await.unwrap().unwrap();
    assert_eq!((bytes.opcode, bytes.payload), (frame::OPCODE_BINARY, b"SSH-2.0-node\r\n".to_vec()));
    drop(first);
}

/// A write to the node fails (the `open` of an operator's session) while
/// its read says nothing: the role lets the socket go at once, not after the
/// wait for a Close that never comes, the operator hears `1011 node
/// disconnected`, and the node's next socket is taken.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_whose_write_failed_is_let_go_at_once_and_its_operator_hears_why() {
    let (cfg, lines) = config();
    let made = cfg.pairs.make(tokens::now_ms()).unwrap();
    let pair = pair_of(&cfg, &made);
    let node_path = format!("/v1/node/{}", made.name);
    let broken = Arc::new(AtomicBool::new(false));
    let breaks = broken.clone();
    let reset = Arc::new(AtomicBool::new(false));
    let node = over_pipe(&cfg, &node_path, &made.node, move |inner| Breaking { inner, broken: breaks, reset });
    let node = taken(node, "the node").await;
    assert_eq!(text_of(&node).await["type"], "hello");
    broken.store(true, Ordering::SeqCst);

    let operator = over_pipe(&cfg, &format!("/v1/connect/{}", made.name), &made.connect, |s| s);
    let operator = taken(operator, "the operator").await;
    // Under the role's five seconds of a wait for a Close.
    let closed = tokio::time::timeout(Duration::from_secs(2), operator.read_frame()).await;
    let closed = closed.expect("the operator's Close at once").expect("a frame");
    assert_eq!(closed.opcode, frame::OPCODE_CLOSE);
    assert_eq!(close_code_and_reason(&closed.payload), (Some(1011), "node disconnected".to_string()));
    assert!(let_go(&pair, Duration::from_secs(1)).await, "the node's socket is let go");
    let why = "reverse node lost: a write to the node failed";
    assert!(said(&lines, why).await, "{:?}", lines.lock().unwrap());

    let next = over_pipe(&cfg, &node_path, &made.node, |s| s);
    let next = taken(next, "the node's next socket").await;
    assert_eq!(text_of(&next).await["type"], "hello");
    drop(node);
}

/// A node's link lost with no reset (nothing comes, no write fails): the
/// role lets its socket go between 30 s and 40 s after the last frame, under
/// the minute after which the node gives the route up, even with no Pong
/// ever heard; a node that answers the role's pings stays.
#[tokio::test(start_paused = true)]
async fn a_node_that_answers_nothing_is_let_go_within_the_nodes_minute() {
    let (cfg, lines) = config();
    let made = cfg.pairs.make(tokens::now_ms()).unwrap();
    let pair = pair_of(&cfg, &made);
    let silent = over_pipe(&cfg, &format!("/v1/node/{}", made.name), &made.node, |s| s);
    let silent = taken(silent, "the silent node").await;
    assert_eq!(text_of(&silent).await["type"], "hello");
    let start = tokio::time::Instant::now();
    assert!(let_go(&pair, Duration::from_secs(55)).await, "the role still holds a node that said nothing");
    let quiet = start.elapsed();
    assert!(quiet >= EVERY * ALLOWED, "let go after {quiet:?}, before the pings were missed");
    assert!(said(&lines, "reverse node lost: ").await, "{:?}", lines.lock().unwrap());
    drop(silent);

    let live = cfg.pairs.make(tokens::now_ms()).unwrap();
    let live_pair = pair_of(&cfg, &live);
    let node = over_pipe(&cfg, &format!("/v1/node/{}", live.name), &live.node, |s| s);
    let node = taken(node, "the live node").await;
    // Its reads answer each Ping, as each WebSocket client does.
    let reads = tokio::spawn(async move { while node.read_frame().await.is_ok() {} });
    tokio::time::sleep(Duration::from_secs(300)).await;
    assert!(live_pair.lock().node.is_some(), "a node that answers each ping keeps its socket");
    reads.abort();
}
