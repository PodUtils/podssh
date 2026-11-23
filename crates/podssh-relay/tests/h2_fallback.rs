//! CONNECT-2 to CONNECT-4 on podssh's HTTP/2 road: a stand-in proxy that
//! refuses the HTTP/1.1 `Upgrade` and takes the extended CONNECT, two
//! sessions on one TLS connection, and a proxy that answers the CONNECT 400
//! (`:protocol` stripped) where the fallback is chosen inside one second.
//! The frames are `pod-ws`'s, and the role's own road is
//! `relay_serve_h2.rs`; this stand-in is a proxy, not the role.
//!
//! A shape names SETTINGS and their order, the connection's window, the
//! order of the request's fields, the PRIORITY frames and the padding of a
//! large DATA frame. The tests below read the client's frames on the wire:
//! the SETTINGS parameters in order, the connection's WINDOW_UPDATE
//! increment, and the ordered pseudo-fields of the CONNECT, decoded with
//! podssh's h2 patch. PRIORITY and padded DATA are recorded in the shape and
//! sent by neither h2 0.4 nor this road.

#![cfg(all(feature = "serve", feature = "plain-ws"))]

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use podssh_ws::h2_road::{self, Fallback, Pool, Road, Shape};
use podssh_ws::{Endpoint, ProxyChoice, Trust, WsClientConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NAME: &str = "h2.proxy.test";
const TOKEN: &str = "the-token-of-the-stand-in";
const LIMIT: Duration = Duration::from_secs(10);
const H2: &[u8] = b"h2";
const HTTP1: &[u8] = b"http/1.1";

/// A key of p256 for rcgen's certificates, as the role's tests make one.
struct Key {
    signing: p256::ecdsa::SigningKey,
    public: Vec<u8>,
}

impl Key {
    fn new() -> Key {
        use p256::elliptic_curve::Generate;
        let signing = p256::ecdsa::SigningKey::generate();
        let public = signing.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Key { signing, public }
    }

    fn pkcs8_pem(&self) -> String {
        #[rustfmt::skip]
        const HEAD: [u8; 35] = [
            0x30, 0x41, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x27, 0x30, 0x25, 0x02, 0x01,
            0x01, 0x04, 0x20,
        ];
        let mut der = HEAD.to_vec();
        der.extend_from_slice(&self.signing.to_bytes());
        pem("PRIVATE KEY", &der)
    }
}

impl rcgen::PublicKeyData for Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        use p256::ecdsa::signature::Signer;
        let signature: p256::ecdsa::Signature = self.signing.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let lines: Vec<&str> = text.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

fn certificates() -> (String, String, String) {
    let (ca_key, leaf_key) = (Key::new(), Key::new());
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name.push(rcgen::DnType::CommonName, "podssh-test-h2-proxy-ca");
    ca.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca, ca_key);
    let mut leaf = rcgen::CertificateParams::new(vec![NAME.to_string()]).unwrap();
    leaf.serial_number = Some(rcgen::SerialNumber::from_slice(&rand::random::<[u8; 16]>()));
    let leaf = leaf.signed_by(&leaf_key, &issuer).unwrap();
    (pem("CERTIFICATE", leaf.der()), leaf_key.pkcs8_pem(), pem("CERTIFICATE", ca_cert.der()))
}

/// What the proxy does with the extended CONNECT.
#[derive(Clone, Copy)]
enum Connect {
    /// A 200, and the stream held: the road carries the session.
    Accept,
    /// A 400: a proxy that strips `:protocol`, so HTTP/1.1 must carry it.
    Refuse,
}

/// What the proxy does with an HTTP/1.1 `Upgrade`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Upgrade {
    /// A 101 and the stream held, as a front end that passes it answers.
    Accept,
    /// A 400 whose body names the refusal, as a proxy that strips the
    /// upgrade and takes the extended CONNECT does.
    Refuse,
}

struct Proxy {
    port: u16,
    accepted: Arc<AtomicUsize>,
    protocol: Arc<AtomicUsize>,
    /// The bytes that the client wrote, for a test that reads the frames in
    /// the order of the wire.
    raw: Arc<Mutex<Vec<u8>>>,
    root: PathBuf,
}

impl Proxy {
    async fn start(what: Connect, upgrade: Upgrade, tag: &str) -> Proxy {
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        podssh_ws::resolve::set_pins(vec![(NAME.into(), lo)]);
        let (cert, key, ca) = certificates();
        let dir = std::env::temp_dir().join(format!("podssh-h2-fallback-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let root = dir.join("root.pem");
        std::fs::write(&root, ca).unwrap();
        let acceptor =
            podssh_ws::tls_server::acceptor(cert.as_bytes(), key.as_bytes(), &[H2, HTTP1]).expect("an acceptor");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (accepted, protocol) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let raw: Arc<Mutex<Vec<u8>>> = Arc::default();
        let (counted, seen, tap) = (accepted.clone(), protocol.clone(), raw.clone());
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                let (acceptor, seen, raw) = (acceptor.clone(), seen.clone(), tap.clone());
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else { return };
                    if tls.get_ref().1.alpn_protocol() == Some(H2) {
                        serve_h2(Tap { inner: tls, seen: raw }, what, seen).await;
                    } else {
                        serve_http1(tls, upgrade).await;
                    }
                });
            }
        });
        Proxy { port, accepted, protocol, raw, root }
    }

    fn config(&self) -> WsClientConfig {
        WsClientConfig {
            endpoint: Endpoint { host: NAME.into(), port: self.port, path: "/connect/127.0.0.1/22".into() },
            trust: Trust::File(self.root.clone()),
            server_name: NAME.into(),
            timeout: LIMIT,
            idle_timeout: None,
            proxy: ProxyChoice::Direct,
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.root.parent().unwrap());
    }
}

/// A stream that copies each byte the client writes into `seen`, so that a
/// test reads the frames in the order of the wire: the preface, SETTINGS,
/// WINDOW_UPDATE, HEADERS and DATA.
struct Tap<S> {
    inner: S,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Tap<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &poll {
            let got = &buf.filled()[before..];
            if !got.is_empty() {
                self.seen.lock().unwrap().extend_from_slice(got);
            }
        }
        poll
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Tap<S> {
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

/// The extended CONNECT and its `:protocol websocket`; a 200 or a 400.
async fn serve_h2<S>(tls: S, what: Connect, seen: Arc<AtomicUsize>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder.enable_connect_protocol();
    let Ok(mut connection) = builder.handshake::<_, Bytes>(tls).await else { return };
    while let Some(Ok((request, mut respond))) = connection.accept().await {
        if request.extensions().get::<h2::ext::Protocol>().is_some_and(|p| p.as_str() == "websocket") {
            seen.fetch_add(1, Ordering::SeqCst);
        }
        let status = match what {
            Connect::Accept => 200,
            Connect::Refuse => 400,
        };
        let answer = http::Response::builder().status(status).body(()).unwrap();
        let Ok(send) = respond.send_response(answer, false) else { continue };
        // Held open: the session is the stream, and the test reads its road.
        tokio::spawn(async move {
            let _send = send;
            tokio::time::sleep(LIMIT).await;
        });
    }
}

/// The upgrade of HTTP/1.1 on a connection whose TLS chose it: a 101 and the
/// stream held where the proxy passes it, else a 400 whose body names the
/// refusal.
async fn serve_http1<S>(mut tls: S, upgrade: Upgrade)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    while !head.ends_with(b"\r\n\r\n") {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
    }
    if upgrade == Upgrade::Refuse {
        let body = "this proxy refuses the HTTP/1.1 Upgrade: it takes HTTP/2's extended CONNECT";
        let answer = format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = tls.write_all(answer.as_bytes()).await;
        return;
    }
    let text = String::from_utf8_lossy(&head);
    let key = text
        .lines()
        .find_map(|line| line.split_once(':').filter(|(n, _)| n.eq_ignore_ascii_case("sec-websocket-key")))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default();
    let accept = podssh_ws::handshake::accept_key(&key);
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    let _ = tls.write_all(answer.as_bytes()).await;
    tokio::time::sleep(LIMIT).await;
}

/// CONNECT-2 and CONNECT-4: the proxy refuses the HTTP/1.1 `Upgrade` and
/// takes the extended CONNECT, and two sessions ride one TLS connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sessions_share_one_connection_where_the_proxy_refuses_the_upgrade() {
    let proxy = Proxy::start(Connect::Accept, Upgrade::Refuse, "shared").await;
    let pool = Pool::new();
    let mut roads = Vec::new();
    for _ in 0..2 {
        let (session, road) = h2_road::connect_on(&pool, &proxy.config(), TOKEN, &Shape::existing())
            .await
            .expect("a session on the road");
        roads.push(road);
        drop(session);
    }
    assert!(roads.iter().all(|r| matches!(r, Road::Stream { .. })), "{roads:?}");
    assert_eq!(proxy.accepted.load(Ordering::SeqCst), 1, "one TLS connection for the two sessions");
    assert_eq!(proxy.protocol.load(Ordering::SeqCst), 2, "each CONNECT named :protocol websocket");
}

/// CONNECT-2: the proxy's refusal of the HTTP/1.1 `Upgrade` is by name, so a
/// client that takes that road learns why it is not the road here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_http1_upgrade_is_refused_by_name() {
    let proxy = Proxy::start(Connect::Accept, Upgrade::Refuse, "refuse").await;
    let config = podssh_ws::tls::config_for(&Trust::File(proxy.root.clone())).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from(NAME.to_string()).unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(config).connect(name, tcp).await.unwrap();
    tls.write_all(
        b"GET /connect/127.0.0.1/22 HTTP/1.1\r\nHost: h2.proxy.test\r\nUpgrade: websocket\r\n\
          Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    )
    .await
    .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(LIMIT, tls.read_to_end(&mut answer)).await;
    let text = String::from_utf8_lossy(&answer);
    assert!(text.starts_with("HTTP/1.1 400 Bad Request"), "the upgrade is refused: {text}");
    assert!(text.contains("refuses the HTTP/1.1 Upgrade"), "the refusal is named: {text}");
}

/// CONNECT-2: a proxy that answers the CONNECT 400 (`:protocol` stripped)
/// chooses the HTTP/1.1 fallback inside one second, not at the end of a
/// stall, and the road says the status.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_extended_connect_falls_back_within_one_second() {
    let proxy = Proxy::start(Connect::Refuse, Upgrade::Accept, "fallback").await;
    let pool = Pool::new();
    let started = Instant::now();
    let (_session, road) = h2_road::connect_on(&pool, &proxy.config(), TOKEN, &Shape::existing())
        .await
        .expect("the fallback carries the session");
    let elapsed = started.elapsed();
    assert_eq!(road, Road::Http1(Fallback::Refused(400)), "{road:?}");
    assert!(elapsed < Duration::from_secs(1), "the fallback took {elapsed:?}");
    assert_eq!(proxy.protocol.load(Ordering::SeqCst), 1, "one CONNECT before the fallback");
}

/// A frame of HTTP/2, as the client wrote it.
struct Frame {
    kind: u8,
    stream: u32,
    payload: Vec<u8>,
}

/// The frames after the preface, in the order of the wire; a truncated tail
/// (the connection ended mid-frame) is dropped.
fn frames(raw: &[u8]) -> Vec<Frame> {
    assert!(raw.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), "the HTTP/2 preface");
    let mut at = 24;
    let mut out = Vec::new();
    while at + 9 <= raw.len() {
        let len = (usize::from(raw[at]) << 16) | (usize::from(raw[at + 1]) << 8) | usize::from(raw[at + 2]);
        if at + 9 + len > raw.len() {
            break;
        }
        out.push(Frame {
            kind: raw[at + 3],
            stream: u32::from_be_bytes([raw[at + 5], raw[at + 6], raw[at + 7], raw[at + 8]]) & 0x7fff_ffff,
            payload: raw[at + 9..at + 9 + len].to_vec(),
        });
        at += 9 + len;
    }
    out
}

/// The SETTINGS parameters of a frame, in the order of the frame.
fn settings_in_order(frame: &Frame) -> Vec<(u16, u32)> {
    assert_eq!(frame.kind, 0x4, "a SETTINGS frame");
    let (parameters, rest) = frame.payload.as_chunks::<6>();
    assert!(rest.is_empty(), "a SETTINGS payload is whole parameters");
    parameters
        .iter()
        .map(|c| (u16::from_be_bytes([c[0], c[1]]), u32::from_be_bytes([c[2], c[3], c[4], c[5]])))
        .collect()
}

/// The ordered fields of the first request's header block, its CONTINUATION
/// frames joined, decoded from HPACK.
fn request_headers(frames: &[Frame]) -> Vec<(String, String)> {
    for (i, frame) in frames.iter().enumerate() {
        if frame.kind == 0x1 && frame.stream != 0 {
            let mut block = frame.payload.clone();
            let mut j = i + 1;
            while j < frames.len() && frames[j].kind == 0x9 {
                block.extend_from_slice(&frames[j].payload);
                j += 1;
            }
            return h2::decode_header_block(&block).expect("an HPACK header block");
        }
    }
    panic!("no request HEADERS on the wire: {:?}", frames.iter().map(|f| f.kind).collect::<Vec<_>>());
}

/// H2-1: the browser shape's SETTINGS, connection window and header order
/// are what the live connection sends, read from its frames in order.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_browser_shape_is_the_recorded_settings_and_the_session_still_carries() {
    let proxy = Proxy::start(Connect::Accept, Upgrade::Refuse, "shape").await;
    let pool = Pool::new();
    let (_session, road) = h2_road::connect_on(&pool, &proxy.config(), TOKEN, &Shape::browser())
        .await
        .expect("a session on the browser shape");
    assert!(matches!(road, Road::Stream { .. }), "{road:?}");
    let raw = proxy.raw.lock().unwrap().clone();
    let frames = frames(&raw);
    let settings = frames.iter().find(|f| f.kind == 0x4 && f.stream == 0).expect("the client's SETTINGS");
    assert_eq!(
        settings_in_order(settings),
        vec![(1, 65_536), (3, 1_000), (4, 6_291_456), (6, 262_144)],
        "Chrome's SETTINGS, id 3 included, in the order of the frame"
    );
    let window = frames.iter().find(|f| f.kind == 0x8 && f.stream == 0).expect("the connection's WINDOW_UPDATE");
    let increment = u32::from_be_bytes([window.payload[0], window.payload[1], window.payload[2], window.payload[3]]);
    assert_eq!(increment, 15_663_105, "Chrome's WINDOW_UPDATE increment, not its target");
    let headers = request_headers(&frames);
    let names: Vec<&str> = headers.iter().map(|(name, _)| name.as_str()).take(5).collect();
    assert_eq!(
        names,
        vec![":method", ":authority", ":scheme", ":path", ":protocol"],
        "Chrome's pseudo-field order on the wire: {headers:?}"
    );
    assert_eq!(headers[0].1, "CONNECT");
    assert_eq!(headers[1].1, format!("{NAME}:{}", proxy.port));
    assert_eq!(headers[2].1, "https");
    assert_eq!(headers[3].1, "/connect/127.0.0.1/22");
    assert_eq!(headers[4].1, "websocket");
    assert!(Shape::browser().priority.is_empty() && Shape::browser().padding.is_none());
}
