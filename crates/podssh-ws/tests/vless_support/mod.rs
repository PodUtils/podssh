//! Stand-ins of a VLESS server on the loopback, as Xray-core's behave
//! (`proxy/vless/inbound/inbound.go`, `transport/internet/websocket/hub.go`,
//! `transport/internet/splithttp/hub.go`): over a WebSocket at `/ws`, and over
//! XHTTP at `/xh/` on h2's own HTTP/2 server, which podssh did not write. Each
//! reads VLESS's request, ends the session with no answer for another ID (a
//! Close of 1000, or the end of the GET's body), and otherwise dials the target
//! and sends the answer with the target's first bytes. The XHTTP one answers
//! 400 to a padding out of 100 to 1000 and 404 to another path, and puts
//! packet-up's POSTs in order by their numbers. Xray-core itself runs in
//! `scripts/interop-vless.sh`.

#![allow(dead_code)]

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub mod cert {
    include!("../common/cert_for_test.rs");
}

// The target of the tests of a pipe's end of input (T-699).
#[path = "../common/talker.rs"]
pub mod talker;
// The XHTTP stand-in's handler of each request.
mod xhttp;
// The XHTTP stand-in of HTTP/1.1, on the same table of sessions (T-456).
mod xhttp1;

// Each test binary that takes this module uses a part of it.
#[allow(unused_imports)]
pub use xhttp1::CLOSE_AFTER;

pub const NAME: &str = "vless.test";
pub const BANNER: &[u8] = b"SSH-2.0-stand-in\r\n";
/// The users' ID of the stand-ins, and its bytes.
pub const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const ID_BYTES: [u8; 16] = [0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0, 0];

/// What a stand-in saw of TLS 1.3 early data, one entry for each connection
/// it took: whether the handshake accepted it, and the bytes that arrived
/// before the handshake's answer.
#[derive(Default)]
pub struct EarlySeen {
    /// Whether the handshake of each connection accepted early data.
    pub accepted: Mutex<Vec<bool>>,
    /// The bytes that arrived before each connection's handshake answer.
    pub bytes: Mutex<Vec<Vec<u8>>>,
}

/// What a stand-in saw: each request's method, path, `Host` and padding's
/// length, and each target that a VLESS request named.
#[derive(Default)]
pub struct Seen {
    pub requests: Mutex<Vec<(String, String, String, usize)>>,
    pub targets: Mutex<Vec<String>>,
    /// The connections that the HTTP/1.1 stand-in took.
    pub connections: std::sync::atomic::AtomicUsize,
    /// Each WebSocket upgrade's head, in bytes, as the server read it: one
    /// write of the coalesced first write.
    pub openings: Mutex<Vec<usize>>,
}

pub fn pins() {
    let lo: IpAddr = "127.0.0.1".parse().unwrap();
    podssh_ws::resolve::set_pins(vec![(NAME.into(), lo)]);
}

pub fn root_file(tag: &str) -> Root {
    let dir = std::env::temp_dir().join(format!("podssh-vless-{}-{tag}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("root.pem");
    let der = cert::encoding::self_signed_inner(&cert::encoding::anchor_name(NAME), true).der;
    std::fs::write(&path, cert::encoding::pem(&der)).unwrap();
    Root(path)
}

/// The root's file, its directory gone when the test ends, failed or not:
/// the gate refuses a test that leaves one in the temporary directory.
pub struct Root(PathBuf);

impl std::ops::Deref for Root {
    type Target = std::path::Path;
    fn deref(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// The target: its version line first when `speaks_first`, then an echo.
pub async fn target(speaks_first: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                if speaks_first && tcp.write_all(BANNER).await.is_err() {
                    return;
                }
                let (mut r, mut w) = tcp.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

/// VLESS's request at the front of `buf`, once whole: its ID, its target
/// and its length.
pub fn parse_request(buf: &[u8]) -> Option<([u8; 16], String, usize)> {
    let addons = usize::from(*buf.get(17)?);
    let at = 18 + addons;
    let command = *buf.get(at)?;
    assert_eq!((buf[0], command), (0, 1), "version 0 and TCP");
    let port = u16::from_be_bytes([*buf.get(at + 1)?, *buf.get(at + 2)?]);
    let (host, end) = match buf.get(at + 3)? {
        1 => (format!("{}", std::net::Ipv4Addr::from(<[u8; 4]>::try_from(buf.get(at + 4..at + 8)?).ok()?)), at + 8),
        2 => {
            let len = usize::from(*buf.get(at + 4)?);
            (String::from_utf8(buf.get(at + 5..at + 5 + len)?.to_vec()).ok()?, at + 5 + len)
        }
        kind => panic!("an address of type {kind}"),
    };
    Some((buf[1..17].try_into().ok()?, format!("{host}:{port}"), end))
}

fn acceptor(alpn: &[&[u8]]) -> tokio_rustls::TlsAcceptor {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut config = (**acceptor.config()).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// [`acceptor`] that takes `max_early` bytes of TLS 1.3 early data: rustls
/// sends no `early_data` permission in a ticket unless the size is above 0,
/// so a client never offers 0-RTT to any other stand-in here.
fn acceptor_early(alpn: &[&[u8]], max_early: u32) -> tokio_rustls::TlsAcceptor {
    let (acceptor, _) = cert::server_for(NAME).unwrap();
    let mut config = (**acceptor.config()).clone();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    config.max_early_data_size = max_early;
    tokio_rustls::TlsAcceptor::from(Arc::new(config))
}

/// A VLESS server over a WebSocket at `/ws`, over TLS for [`NAME`], that
/// takes up to `max_early` bytes of early data and records what each
/// connection's handshake did with it.
pub async fn ws_server_early(max_early: u32) -> (u16, Arc<Seen>, Arc<EarlySeen>) {
    let (acceptor, listener) = (acceptor_early(&[], max_early), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let early: Arc<EarlySeen> = Arc::default();
    let kept = seen.clone();
    let seen_early = early.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            kept.connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (acceptor, seen, early) = (acceptor.clone(), kept.clone(), seen_early.clone());
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let (accepted, head) = take_early(&mut tls);
                early.accepted.lock().unwrap().push(accepted);
                early.bytes.lock().unwrap().push(head.clone());
                serve_ws(Prefixed { head, at: 0, inner: tls }, seen).await;
            });
        }
    });
    (port, seen, early)
}

/// What the handshake of an accepted connection did with the early data, and
/// the bytes themselves: the stream's prefix, before any 1-RTT byte.
fn take_early<S>(tls: &mut tokio_rustls::server::TlsStream<S>) -> (bool, Vec<u8>) {
    use std::io::Read as _;
    let (_, session) = tls.get_mut();
    // `early_data` is `Some` exactly where the handshake accepted it, and the
    // bytes are there already, before the session answers anything.
    let Some(mut early) = session.early_data() else { return (false, Vec::new()) };
    let mut head = Vec::new();
    let _ = early.read_to_end(&mut head);
    (true, head)
}

/// A stream whose first bytes came before the handshake's answer, then the
/// TLS stream as usual.
struct Prefixed<S> {
    head: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.at < this.head.len() {
            let n = (this.head.len() - this.at).min(buf.remaining());
            buf.put_slice(&this.head[this.at..this.at + n]);
            this.at += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
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

/// A VLESS server over a WebSocket at `/ws`, over TLS for [`NAME`].
pub async fn ws_server() -> (u16, Arc<Seen>) {
    let (acceptor, listener) = (acceptor(&[]), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            kept.connections.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (acceptor, seen) = (acceptor.clone(), kept.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                serve_ws(tls, seen).await;
            });
        }
    });
    (port, seen)
}

async fn serve_ws<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut tls: S, seen: Arc<Seen>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match tls.read(&mut chunk).await {
            Ok(n) if n > 0 => buffer.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    };
    seen.openings.lock().unwrap().push(end);
    let pending = buffer.split_off(end);
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let path = head.split(' ').nth(1).unwrap_or_default().to_string();
    let field = |name: &str| {
        let mut fields = head.split("\r\n").filter_map(|l| l.split_once(':'));
        fields.find(|(n, _)| n.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())
    };
    seen.requests.lock().unwrap().push(("GET".into(), path.clone(), field("host").unwrap_or_default(), 0));
    if path.split('?').next() != Some("/ws") {
        let _ = tls.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await;
        return;
    }
    let accept = podssh_ws::handshake::accept_key(&field("sec-websocket-key").unwrap_or_default());
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \
         {accept}\r\n\r\n"
    );
    if tls.write_all(answer.as_bytes()).await.is_err() {
        return;
    }
    let session = Arc::new(RelaySession::new(tls, pending, None, Duration::from_secs(30)).as_server());
    let mut got = Vec::new();
    let (id, target, used) = loop {
        let Ok(frame) = session.read_frame().await else { return };
        got.extend_from_slice(&frame.payload);
        if let Some(request) = parse_request(&got) {
            break request;
        }
    };
    let Some(tcp) = dial(id, &target, &seen).await else {
        // As Xray-core's connection closes: a Close of 1000 and no reason.
        let _ = session.send_close(1000, "").await;
        return;
    };
    let (mut rd, mut wr) = tcp.into_split();
    let _ = wr.write_all(&got[used..]).await;
    let up_session = session.clone();
    let up = async move {
        while let Ok(frame) = up_session.read_frame().await {
            if frame.opcode == podssh_ws::frame::OPCODE_CLOSE || wr.write_all(&frame.payload).await.is_err() {
                break;
            }
        }
    };
    let down = async move {
        let (mut buf, mut answer) = (vec![0u8; 16 * 1024], vec![0u8, 0u8]);
        while let Ok(n) = rd.read(&mut buf).await {
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&buf[..n]);
            if session.send_binary(&answer).await.is_err() {
                return;
            }
            answer.clear();
        }
        let _ = session.send_close(1000, "").await;
    };
    tokio::join!(up, down);
}

/// The target of a request whose ID is the stand-in's, else none.
pub(crate) async fn dial(id: [u8; 16], target: &str, seen: &Seen) -> Option<TcpStream> {
    if id != ID_BYTES {
        return None;
    }
    seen.targets.lock().unwrap().push(target.to_string());
    TcpStream::connect(target).await.ok()
}

/// A VLESS server over XHTTP at `/xh/`, over TLS for [`NAME`], offering
/// `alpn`.
pub async fn xhttp_server(alpn: &[&[u8]]) -> (u16, Arc<Seen>) {
    let (acceptor, listener) = (acceptor(alpn), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let port = listener.local_addr().unwrap().port();
    let (seen, sessions): (Arc<Seen>, xhttp::Sessions) = (Arc::default(), Arc::default());
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen, sessions) = (acceptor.clone(), kept.clone(), sessions.clone());
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let Ok(mut connection) = h2::server::handshake(tls).await else { return };
                while let Some(Ok((request, respond))) = connection.accept().await {
                    tokio::spawn(xhttp::handle(request, respond, seen.clone(), sessions.clone()));
                }
            });
        }
    });
    (port, seen)
}

/// [`xhttp_server`] with no TLS, as a link with `security=none` reaches it:
/// HTTP/2 with prior knowledge on the loopback, for a proxy stand-in.
pub async fn xhttp_plain_server() -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (seen, sessions): (Arc<Seen>, xhttp::Sessions) = (Arc::default(), Arc::default());
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (seen, sessions) = (kept.clone(), sessions.clone());
            tokio::spawn(async move {
                let Ok(mut connection) = h2::server::handshake(tcp).await else { return };
                while let Some(Ok((request, respond))) = connection.accept().await {
                    tokio::spawn(xhttp::handle(request, respond, seen.clone(), sessions.clone()));
                }
            });
        }
    });
    (port, seen)
}

/// A VLESS server over XHTTP at `/xh/` that speaks HTTP/1.1 alone, as
/// Xray-core's with `alpn` `http/1.1`: over TLS for [`NAME`] that offers
/// `http/1.1` alone, or with no TLS when `tls` is false.
pub async fn xhttp1_server(tls: bool) -> (u16, Arc<Seen>) {
    let (acceptor, listener) = (acceptor(&[b"http/1.1"]), TcpListener::bind("127.0.0.1:0").await.unwrap());
    let port = listener.local_addr().unwrap().port();
    let (seen, sessions): (Arc<Seen>, xhttp::Sessions) = (Arc::default(), Arc::default());
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, seen, sessions) = (acceptor.clone(), kept.clone(), sessions.clone());
            tokio::spawn(async move {
                if !tls {
                    return xhttp1::serve(tcp, seen, sessions).await;
                }
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                xhttp1::serve(tls, seen, sessions).await;
            });
        }
    });
    (port, seen)
}
