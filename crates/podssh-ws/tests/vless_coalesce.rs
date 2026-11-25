//! COALESCE-1 to COALESCE-3 on podssh's VLESS road: the first write that
//! carries data, counted as transport writes beneath TLS for the WebSocket
//! road and directly for HTTP/1.1 (the count at the wire's boundary, not the
//! bytes the server happened to read), the report's own count for XHTTP over
//! HTTP/2 (not the wire: HPACK compresses the head), the short write that
//! padding filled, and the one-time rule. The shared coalescer and the XHTTP
//! forms are `pod-egress`'s; these tests hold podssh's road to them.

mod vless_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::vless::{self, AtEnd, Dial, FirstWrite, Server};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vless_support::{pins, root_file, target, ws_server, xhttp1_server, xhttp_server, BANNER, ID, NAME};

const LIMIT: Duration = Duration::from_secs(20);
const TARGET: usize = 3_333;

fn server(port: u16, query: &str) -> Server {
    Server::parse(&format!("vless://{ID}@{NAME}:{port}?{query}")).unwrap()
}

fn dial(root: &std::path::Path) -> Dial {
    Dial {
        trust: Trust::File(root.to_path_buf()),
        way: podssh_ws::client::way(&ProxyChoice::Direct),
        timeout: LIMIT,
        answer: vless::ANSWER_WAIT,
        silence_is_ready: false,
        at_end: AtEnd::Now,
        early: None,
    }
}

/// The same dial, whose TCP goes through [`CountingDial`]: every successful
/// transport write's length is kept in `writes`.
fn dial_counting(root: &std::path::Path, writes: Arc<Mutex<Vec<usize>>>) -> Dial {
    let mut way = podssh_ws::client::way(&ProxyChoice::Direct);
    way.dial = Arc::new(CountingDial { writes, label: "counting".into() });
    Dial { way, ..dial(root) }
}

async fn open(link: &Server, aim: u16, root: &std::path::Path) -> vless::Opened {
    open_with(link, aim, &dial(root)).await
}

async fn open_with(link: &Server, aim: u16, dial: &Dial) -> vless::Opened {
    tokio::time::timeout(LIMIT * 2, vless::open(link, "127.0.0.1", aim, dial))
        .await
        .expect("within the limit")
        .unwrap_or_else(|e| panic!("{}", e.line("vless", "target")))
}

/// A dialer that wraps each TCP stream in [`Counting`].
struct CountingDial {
    writes: Arc<Mutex<Vec<usize>>>,
    label: String,
}

impl pod_core::dial::Dial for CountingDial {
    fn label(&self) -> String {
        self.label.clone()
    }

    fn dial<'a>(
        &'a self,
        target: &'a pod_core::dial::Target,
        deadline: tokio::time::Instant,
    ) -> pod_core::dial::BoxFuture<'a, Result<pod_core::dial::Connected, pod_core::failure::Failure>> {
        Box::pin(async move {
            let addrs = podssh_ws::resolve::resolve(&target.host(), target.port(), deadline).await.map_err(|e| {
                pod_core::failure::Failure::new(pod_core::failure::Stage::Dns, pod_core::failure::Class::Unavailable, e)
            })?;
            let tcp = TcpStream::connect(addrs[0]).await.map_err(|e| {
                pod_core::failure::Failure::io(
                    pod_core::failure::Stage::Connect,
                    format!("the connection to {}", addrs[0]),
                    e,
                )
            })?;
            let io = Counting { inner: tcp, writes: self.writes.clone() };
            Ok(pod_core::dial::Connected::new(Box::new(io)))
        })
    }
}

/// A stream that records the length of each non-empty write that the stream
/// beneath TLS accepts, and passes reads and the rest of the write path on.
struct Counting<S> {
    inner: S,
    writes: Arc<Mutex<Vec<usize>>>,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Counting<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Counting<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut self.inner).poll_write(cx, data);
        if let std::task::Poll::Ready(Ok(n)) = &poll
            && *n > 0
        {
            self.writes.lock().unwrap().push(*n);
        }
        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The target's version line, then `sent` back whole.
async fn carries(opened: &mut vless::Opened, sent: &[u8]) {
    let mut banner = vec![0u8; BANNER.len()];
    let mut back = vec![0u8; sent.len()];
    opened.stream.read_exact(&mut banner).await.unwrap();
    let (mut read, mut write) = tokio::io::split(&mut opened.stream);
    let write = async {
        write.write_all(sent).await.unwrap();
        write.flush().await.unwrap();
    };
    tokio::join!(write, async { read.read_exact(&mut back).await.unwrap() });
    assert_eq!(banner, BANNER);
    assert!(back == sent, "the bytes came back changed");
}

/// COALESCE-1 and COALESCE-2 at the transport beneath TLS: the upgrade is
/// one write, carrying 3,333 bytes into one TLS record, padded because the
/// request is short, and the session records that it was short. VLESS's
/// request goes in the first binary message, not in that write: Xray-core's
/// gorilla server refuses a frame before the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_websocket_s_first_write_is_one_write_of_3333_bytes_and_the_head_alone() {
    pins();
    let (root, aim) = (root_file("coalesce-ws"), target(true).await);
    let (ws, seen) = ws_server().await;
    let writes: Arc<Mutex<Vec<usize>>> = Arc::default();
    let mut opened =
        open_with(&server(ws, "type=ws&path=%2Fws&security=tls"), aim, &dial_counting(&root, writes.clone())).await;
    assert_eq!(opened.first_write, FirstWrite { bytes: TARGET, short: true, coalesced: true });
    let writes = writes.lock().unwrap().clone();
    let record: Vec<usize> = writes.iter().copied().filter(|n| *n >= TARGET).collect();
    assert_eq!(record.len(), 1, "one transport write carried the head: {writes:?}");
    assert!((TARGET..=TARGET + 64).contains(&record[0]), "one TLS record of 3,333 plaintext bytes: {writes:?}");
    assert_eq!(*seen.targets.lock().unwrap(), vec![format!("127.0.0.1:{aim}")]);
    carries(&mut opened, b"after the upgrade head").await;
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// COALESCE-1 and COALESCE-2 on XHTTP over HTTP/2, as the report counts them:
/// the first POST's head and its body (VLESS's request) are offered as one
/// write of 3,333 counted bytes, and the report says that it was short. The
/// count is the head's own bytes, before HPACK: measured at the wire, this
/// path's largest TLS record was 633 bytes, the header list compressed, so
/// no claim is made here that 3,333 bytes left in one write (under strace,
/// T-757). The stand's numbered POST 0 is the one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_over_h2_reports_one_coalesced_first_write_of_3333_counted_bytes() {
    pins();
    let (root, aim) = (root_file("coalesce-h2"), target(true).await);
    let (h2, seen) = xhttp_server(&[b"h2"]).await;
    let mut opened = open(&server(h2, "type=xhttp&path=%2Fxh&mode=packet-up&security=tls"), aim, &root).await;
    assert_eq!(opened.first_write, FirstWrite { bytes: TARGET, short: true, coalesced: true });
    carries(&mut opened, b"x").await;
    let requests = seen.requests.lock().unwrap().clone();
    let gets: Vec<_> = requests.iter().filter(|(m, p, _, _)| m == "GET" && p.starts_with("/xh/")).collect();
    assert_eq!(gets.len(), 1, "one GET down: {requests:?}");
    assert!(requests.iter().any(|(m, p, _, _)| m == "POST" && p.ends_with("/0")), "{requests:?}");
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// COALESCE-1 on XHTTP over HTTP/1.1: the transport sees one write of 3,333
/// bytes carrying the upload's first request (the GET's is its head alone),
/// and the report says that the write was short.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn xhttp_over_h1_writes_one_request_of_3333_bytes_at_the_transport() {
    pins();
    let (root, aim) = (root_file("coalesce-h1"), target(true).await);
    let (behind, _) = xhttp1_server(false).await;
    let front = h1_proxy(behind).await;
    let writes: Arc<Mutex<Vec<usize>>> = Arc::default();
    let mut opened = open_with(
        &server(front, "type=xhttp&path=%2Fxh&mode=packet-up&security=none"),
        aim,
        &dial_counting(&root, writes.clone()),
    )
    .await;
    assert_eq!(opened.first_write, FirstWrite { bytes: TARGET, short: true, coalesced: true });
    carries(&mut opened, b"x").await;
    let writes = writes.lock().unwrap().clone();
    assert_eq!(
        writes.iter().filter(|n| **n == TARGET).count(),
        1,
        "one transport write of the coalesced request, not a split: {writes:?}"
    );
    let _ = std::fs::remove_dir_all(root.parent().unwrap());
}

/// COALESCE-3: the coalescer is spent by the first write. A second write is
/// the data alone, and the session still reports the first one.
#[test]
fn a_second_coalesce_cannot_follow_the_first() {
    let mut first = podssh_ws::vless::First::new();
    let (head, data) = (b"POST /xh/ HTTP/1.1\r\nHost: v.example\r\n\r\n".to_vec(), b"\x00the request".to_vec());
    let (frame, coalesced) = first.write(&head, &data);
    assert!(coalesced && frame.len() == TARGET);
    let (again, coalesced) = first.write(&head, b"after");
    assert!(!coalesced && again == b"after");
    assert_eq!(first.report(), FirstWrite { bytes: TARGET, short: true, coalesced: true });
}

/// A stand in front of `behind` that passes each connection through both
/// ways, except a client that begins with the HTTP/2 preface: this path is
/// HTTP/1.1 alone, so that connection is dropped and the road falls back.
async fn h1_proxy(behind: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut chunk = [0u8; 4096];
                let first = match client.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                if chunk[..first].starts_with(b"PRI ") {
                    return;
                }
                let Ok(mut server) = TcpStream::connect(("127.0.0.1", behind)).await else { return };
                if server.write_all(&chunk[..first]).await.is_err() {
                    return;
                }
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            });
        }
    });
    port
}
