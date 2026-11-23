//! XHTTP-1 to XHTTP-3 on podssh's VLESS road: a stand-in proxy on the
//! loopback that terminates the client's cleartext HTTP/2, reads each
//! request's body whole before it sends it on, and, in response mode, holds
//! the answer back before it sends it down (as a proxy that buffers
//! responses does), and refuses an HTTP/1.1 `Upgrade` with 400.
//!
//! Response mode's cap is [`RESPONSE_CAP`] bytes: the proxy flushes the held
//! body when it reaches the cap, when the backend ends the response, or
//! when the backend has sent nothing for [`RESPONSE_IDLE`]. The last rule is
//! what carries a long-lived GET, whose body never ends, past the buffer.
//! The finite-response test proves the whole-body rule; the split test runs
//! behind the same proxy in both modes.
//!
//! Packet-up's requests are whole bodies, so the split completes behind it;
//! a WebSocket upgrade is refused there, which is the case XHTTP is for. The
//! test counts the shape, not only the bytes: one GET down, numbered POSTs up.

mod vless_support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use podssh_ws::vless::{self, AtEnd, Dial, Server, VlessError};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use vless_support::{target, xhttp_plain_server, BANNER, ID};

const LIMIT: Duration = Duration::from_secs(20);
/// Response mode's cap: a held body of this many bytes is flushed whether
/// the backend has ended or not.
const RESPONSE_CAP: usize = 64 * 1024;
/// Response mode's idle rule: a held body is flushed when the backend has
/// sent nothing for this long, so a GET whose body never ends still carries.
const RESPONSE_IDLE: Duration = Duration::from_millis(500);

/// Which side of the exchange the stand-in holds back.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Request bodies are read whole; the answer streams down.
    Request,
    /// Request bodies and answers are both held: an answer whole up to
    /// [`RESPONSE_CAP`], flushed at the cap, at its end, or on
    /// [`RESPONSE_IDLE`] of silence.
    Both,
}

/// What the proxy saw: each request's method and path, how many request
/// bodies it held whole, and how many response bytes each flush carried.
#[derive(Default)]
struct Seen {
    requests: Mutex<Vec<(String, String)>>,
    buffered: Mutex<Vec<usize>>,
    responses: Mutex<Vec<usize>>,
}

fn server(port: u16, query: &str) -> Server {
    Server::parse(&format!("vless://{ID}@127.0.0.1:{port}?{query}")).unwrap()
}

fn dial() -> Dial {
    Dial {
        trust: Trust::Default,
        way: podssh_ws::client::way(&ProxyChoice::Direct),
        timeout: LIMIT,
        answer: vless::ANSWER_WAIT,
        silence_is_ready: false,
        at_end: AtEnd::Now,
        early: None,
    }
}

/// XHTTP-1 and XHTTP-2: packet-up completes behind a proxy that buffers
/// both request bodies and responses, and the shape is one GET down and
/// numbered POSTs up, each numbered from 0.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_split_completes_behind_a_proxy_that_buffers_responses() {
    let aim = target(true).await;
    let (behind, backend) = xhttp_plain_server().await;
    let (front, seen) = buffering_proxy(behind, Mode::Both).await;
    let mut opened = tokio::time::timeout(
        LIMIT * 2,
        vless::open(&server(front, "type=xhttp&path=%2Fxh&mode=packet-up&security=none"), "127.0.0.1", aim, &dial()),
    )
    .await
    .expect("within the limit")
    .unwrap_or_else(|e| panic!("{}", e.line("vless", "target")));
    assert_eq!(opened.how, "XHTTP packet-up over HTTP/2 with no TLS");
    let mut banner = vec![0u8; BANNER.len()];
    opened.stream.read_exact(&mut banner).await.unwrap();
    assert_eq!(banner, BANNER);
    // Two chunks up: each a POST with its whole body, which the proxy held.
    opened.stream.write_all(&vec![7u8; 64 * 1024]).await.unwrap();
    opened.stream.flush().await.unwrap();
    let mut back = vec![0u8; 64 * 1024];
    opened.stream.read_exact(&mut back).await.unwrap();
    assert_eq!(back, vec![7u8; 64 * 1024]);
    let requests = seen.requests.lock().unwrap().clone();
    let gets: Vec<_> = requests.iter().filter(|(m, _)| m == "GET").collect();
    let posts: Vec<_> = requests.iter().filter(|(m, _)| m == "POST").collect();
    assert_eq!(gets.len(), 1, "one GET down: {requests:?}");
    assert!(posts.len() >= 2, "numbered POSTs up: {requests:?}");
    let mut numbers: Vec<u64> =
        posts.iter().filter_map(|(_, p)| p.rsplit('/').next().and_then(|n| n.parse().ok())).collect();
    numbers.sort_unstable();
    assert_eq!(numbers, (0..posts.len() as u64).collect::<Vec<_>>(), "each POST's number, from 0: {requests:?}");
    assert!(seen.buffered.lock().unwrap().len() >= 2, "each request body was held whole before it went on");
    assert!(
        !seen.responses.lock().unwrap().is_empty(),
        "the responses went down from a held buffer, at its cap, its end or its idle rule"
    );
    assert!(!backend.targets.lock().unwrap().is_empty(), "the target was dialled behind the proxy");
}

/// XHTTP-1: a finite answer is held whole and flushed at its end, not
/// streamed chunk by chunk. The backend sends three pieces with a pause
/// between them, so a streaming proxy would record three flushes; the
/// response buffer records one, of the whole body.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_finite_response_body_is_held_whole_and_flushed_at_its_end() {
    let body = finite_body();
    let (behind, backend) = finite_backend(&body).await;
    let (front, seen) = buffering_proxy(behind, Mode::Both).await;
    let tcp = TcpStream::connect(("127.0.0.1", front)).await.unwrap();
    let (sender, connection) = h2::client::handshake(tcp).await.expect("h2 with prior knowledge");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder().method("GET").uri("http://front/finite").body(()).unwrap();
    let (answer, _) = sender.ready().await.expect("the sender").send_request(request, true).expect("the request");
    let answer = answer.await.expect("the answer");
    assert_eq!(answer.status(), 200);
    let mut got = Vec::new();
    let mut down = answer.into_body();
    while let Some(chunk) = down.data().await {
        let chunk = chunk.expect("a chunk of the answer");
        let _ = down.flow_control().release_capacity(chunk.len());
        got.extend_from_slice(&chunk);
    }
    assert_eq!(got, body, "the whole finite body came down");
    assert_eq!(backend.requests.load(std::sync::atomic::Ordering::SeqCst), 1, "one backend request");
    assert_eq!(*seen.responses.lock().unwrap(), vec![body.len()], "one flush, the whole body, at the response's end");
}

/// XHTTP-3: the proxy refuses the WebSocket upgrade with 400, and the road
/// says the status; XHTTP is the way past it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_proxy_refuses_the_upgrade_and_the_road_says_the_status() {
    let aim = target(true).await;
    let (front, _) = buffering_proxy(1, Mode::Request).await;
    let e = vless::open(&server(front, "type=ws&path=%2Fws&security=none"), "127.0.0.1", aim, &dial())
        .await
        .err()
        .expect("the upgrade is refused");
    assert!(matches!(e, VlessError::Refused { status: 400, .. }), "{}", e.line("vless", "target"));
}

/// The stand-in: HTTP/2 with prior knowledge to the client, the mode's hold
/// on each side, and a plain HTTP/1.1 answer of 400 to an `Upgrade`. The
/// HTTP/2 side forwards each request to `behind` as its own HTTP/2 request
/// and answers it in the mode's shape.
async fn buffering_proxy(behind: u16, mode: Mode) -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = kept.clone();
            tokio::spawn(async move {
                let mut peek = [0u8; 4];
                let n = match tcp.peek(&mut peek).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                if &peek[..n] == b"PRI " {
                    serve_h2(tcp, behind, seen, mode).await;
                } else {
                    serve_h1(tcp).await;
                }
            });
        }
    });
    (port, seen)
}

/// HTTP/2 with prior knowledge: each request's body is read whole, then the
/// request goes to `behind`; its answer comes back in the mode's shape.
async fn serve_h2(tcp: TcpStream, behind: u16, seen: Arc<Seen>, mode: Mode) {
    let Ok(mut connection) = h2::server::handshake(tcp).await else { return };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        let seen = seen.clone();
        tokio::spawn(async move {
            let (parts, mut body) = request.into_parts();
            let method = parts.method.to_string();
            let path = parts.uri.path().to_string();
            seen.requests.lock().unwrap().push((method, path));
            let mut whole = Vec::new();
            while let Some(Ok(chunk)) = body.data().await {
                let _ = body.flow_control().release_capacity(chunk.len());
                whole.extend_from_slice(&chunk);
            }
            seen.buffered.lock().unwrap().push(whole.len());
            let status = match forward(behind, parts, whole, &mut respond, &seen, mode).await {
                Ok(()) => return,
                Err(status) => status,
            };
            let answer = http::Response::builder().status(status).body(()).unwrap();
            let _ = respond.send_response(answer, true);
        });
    }
}

/// One request to `behind` over HTTP/2, with its body whole, and the
/// client's answer opened and sent back: as it streams, or held whole up to
/// [`RESPONSE_CAP`] and flushed at the cap, at the end, or on
/// [`RESPONSE_IDLE`] of silence. The error is the status that the client
/// hears where the backend did not answer.
async fn forward(
    behind: u16,
    parts: http::request::Parts,
    body: Vec<u8>,
    respond: &mut h2::server::SendResponse<Bytes>,
    seen: &Seen,
    mode: Mode,
) -> Result<(), u16> {
    let tcp = TcpStream::connect(("127.0.0.1", behind)).await.map_err(|_| 502u16)?;
    let (sender, connection) = h2::client::handshake(tcp).await.map_err(|_| 502u16)?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut out = http::Request::builder().method(parts.method).uri(parts.uri).body(()).map_err(|_| 502u16)?;
    for (name, value) in parts.headers {
        if let Some(name) = name {
            out.headers_mut().append(name, value);
        }
    }
    let mut sender = sender.ready().await.map_err(|_| 502u16)?;
    let (answer, mut send) = sender.send_request(out, false).map_err(|_| 502u16)?;
    send.send_data(Bytes::from(body), true).map_err(|_| 502u16)?;
    let answer = answer.await.map_err(|_| 502u16)?;
    let status = answer.status();
    let mut down =
        respond.send_response(http::Response::builder().status(status).body(()).unwrap(), false).map_err(|_| 502u16)?;
    let mut up = answer.into_body();
    let mut held = Vec::new();
    loop {
        let next = if mode == Mode::Both {
            match tokio::time::timeout(RESPONSE_IDLE, up.data()).await {
                Ok(next) => next,
                Err(_) => {
                    if !held.is_empty() {
                        flush(&mut down, &mut held, false, seen);
                    }
                    continue;
                }
            }
        } else {
            up.data().await
        };
        let Some(chunk) = next else { break };
        let Ok(chunk) = chunk else { break };
        let _ = up.flow_control().release_capacity(chunk.len());
        if mode == Mode::Request {
            if down.send_data(chunk, false).is_err() {
                return Ok(());
            }
            continue;
        }
        held.extend_from_slice(&chunk);
        if held.len() >= RESPONSE_CAP {
            flush(&mut down, &mut held, false, seen);
        }
    }
    if mode == Mode::Both {
        flush(&mut down, &mut held, true, seen);
    } else {
        let _ = down.send_data(Bytes::new(), true);
    }
    Ok(())
}

/// One flush of response mode: the held bytes down, the count kept, and the
/// end where the answer has ended.
fn flush(down: &mut h2::SendStream<Bytes>, held: &mut Vec<u8>, end: bool, seen: &Seen) {
    if held.is_empty() && !end {
        return;
    }
    let bytes = std::mem::take(held);
    seen.responses.lock().unwrap().push(bytes.len());
    let _ = down.send_data(Bytes::from(bytes), end);
}

/// A finite answer, larger than one chunk, that is not the session banner.
fn finite_body() -> Vec<u8> {
    (0..12_288u32).map(|i| (i % 251) as u8).collect()
}

/// The backend of the finite answer, and the count of requests it took.
struct FiniteBackend {
    requests: std::sync::atomic::AtomicUsize,
}

/// A backend that answers each request with `body` in three pieces, a short
/// pause between them, then ends the response.
async fn finite_backend(body: &[u8]) -> (u16, Arc<FiniteBackend>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let backend = Arc::new(FiniteBackend { requests: std::sync::atomic::AtomicUsize::new(0) });
    let kept = backend.clone();
    let body = body.to_vec();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (backend, body) = (kept.clone(), body.clone());
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(tcp).await else { return };
                while let Some(Ok((_request, mut respond))) = connection.accept().await {
                    backend.requests.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let Ok(mut down) =
                        respond.send_response(http::Response::builder().status(200).body(()).unwrap(), false)
                    else {
                        continue;
                    };
                    for piece in body.chunks(4096) {
                        if down.send_data(Bytes::copy_from_slice(piece), false).is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    let _ = down.send_data(Bytes::new(), true);
                }
            });
        }
    });
    (port, backend)
}

/// HTTP/1.1: an `Upgrade` is refused with 400; anything else is 404.
async fn serve_h1(mut tcp: TcpStream) {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.ends_with(b"\r\n\r\n") {
        match tcp.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    let text = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let answer = if text.contains("\r\nupgrade:") {
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    };
    let _ = tcp.write_all(answer.as_bytes()).await;
}
