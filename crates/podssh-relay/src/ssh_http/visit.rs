//! Each visitor of a node's tunnel of HTTP made by `ssh -R` (T-565): one
//! `forwarded-tcpip` channel that carries the plain HTTP/1.1 that the edge
//! sends down the forward, after it ended the visitor's TLS. Its first
//! request decides what the channel is:
//!
//! - a path of the relay role, where the node serves it (`--relay`): the
//!   role's origin of T-428 ([`crate::quick::origin`]), a pipe in this
//!   process, takes the request and the rest of the channel, as behind a
//!   quick tunnel; the visitor that the edge names in `X-Forwarded-For` is
//!   whom its brake counts (T-454), never who may mint;
//! - a WebSocket's upgrade at `/`: the 101 of RFC 6455, then the bytes of
//!   its messages, one link of the resumable layer, as a quick tunnel's
//!   visitor is ([`crate::quick::visitor`]); the node is the WebSocket's
//!   server, so its frames go unmasked;
//! - anything else: 404, or the refusal of a bad upgrade, and the end.
//!
//! The edge's documents name no bound of a request, nor whether it passes
//! an upgrade (read 2026-11-10); a request that holds no head within 30 s
//! ends the channel.

use std::sync::Arc;
use std::time::Duration;

use podssh_ws::http::request::{self, read_request, Request};
use podssh_ws::server;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::quick::origin::{self, Origin};

/// The path of the node's WebSocket, as a quick tunnel's visitor asks it.
pub const PATH: &str = "/";
/// How long a visitor has for its request's head.
pub const HEAD_WAIT: Duration = Duration::from_secs(30);

/// What became of a visitor's channel.
#[derive(Debug)]
pub enum Visited {
    /// A WebSocket at [`PATH`]: the bytes of its messages, for the layer.
    Layer(DuplexStream),
    /// The relay role took a request of this path, and the channel.
    Role(String),
    /// Refused with this status, and ended.
    Refused(u16),
    /// Gone before a request was read, and why.
    Gone(&'static str),
}

/// Serve the first request of `stream`; `origin` is the relay role, where
/// the node serves it.
pub async fn serve<S>(mut stream: S, origin: Option<Arc<dyn Origin>>) -> Visited
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (head, pending) = match tokio::time::timeout(HEAD_WAIT, read_request(&mut stream, Vec::new())).await {
        Ok(Ok(read)) => read,
        Ok(Err(e)) => {
            let Some(status) = e.status() else { return Visited::Gone("the channel ended before a request") };
            answer(&mut stream, request::refusal(status, &e.to_string(), &[])).await;
            return Visited::Refused(status);
        }
        Err(_) => return Visited::Gone("no request within 30 s"),
    };
    let path = head.target.split(['?', '#']).next().unwrap_or_default().to_string();
    if let Some(role) = origin::taking(&origin, &head.target) {
        let mut pipe = role.connect(visitor_of(&head));
        let mut bytes = head_bytes(&head);
        bytes.extend_from_slice(&pending);
        if pipe.write_all(&bytes).await.is_err() {
            return Visited::Gone("the relay role took no request");
        }
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut pipe).await;
        return Visited::Role(path);
    }
    if path != PATH {
        let why = format!("{path}: not found: this name is a podssh node's, whose WebSocket is at {PATH}");
        answer(&mut stream, request::refusal(404, &why, &[])).await;
        return Visited::Refused(404);
    }
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => {
            answer(&mut stream, refused.answer()).await;
            return Visited::Refused(refused.status);
        }
    };
    if stream.write_all(&server::switching(&key)).await.is_err() {
        return Visited::Gone("the channel ended before the 101");
    }
    // The bytes that came after the head are the WebSocket's first frames.
    let (from, to) = tokio::io::split(stream);
    Visited::Layer(crate::quick::visitor::websocket(std::io::Cursor::new(pending).chain(from), to))
}

/// The visitor's address that the edge names, the first of
/// `X-Forwarded-For` (localhost.run's "HTTP Tunnels"), one address alone.
pub fn visitor_of(head: &Request) -> Option<std::net::IpAddr> {
    head.header("x-forwarded-for")?.split(',').next()?.trim().parse().ok()
}

/// The head of `head` again, as the role reads a request: its line, then
/// each header as it came, with its name in lower case.
fn head_bytes(head: &Request) -> Vec<u8> {
    let mut out = format!("{} {} HTTP/1.{}\r\n", head.method, head.target, head.minor).into_bytes();
    for (name, value) in &head.headers {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Write `reply`, then end the channel.
async fn answer<S: AsyncWrite + Unpin>(stream: &mut S, reply: Vec<u8>) {
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    use podssh_ws::frame::{self, Frame, Role};
    use std::sync::Mutex;

    const LIMIT: Duration = Duration::from_secs(20);

    /// An origin that serves `/health` alone, answers each request with the
    /// bytes it read, and keeps the visitor that it was given.
    #[derive(Default)]
    struct Echo {
        visitor: Mutex<Option<Option<std::net::IpAddr>>>,
    }

    impl Origin for Echo {
        fn serves(&self, path: &str) -> bool {
            path == "/health"
        }

        fn connect(&self, visitor: Option<std::net::IpAddr>) -> DuplexStream {
            *self.visitor.lock().unwrap() = Some(visitor);
            let (ours, mut theirs) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let (head, body) = read_request(&mut theirs, Vec::new()).await.unwrap();
                let host = head.header("host").unwrap_or("-");
                let said = format!("{} {} {host} {}", head.method, head.target, body.len());
                let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{said}", said.len());
                let _ = theirs.write_all(reply.as_bytes()).await;
                let _ = theirs.shutdown().await;
            });
            ours
        }
    }

    async fn ask(request: &[u8], origin: Option<Arc<dyn Origin>>) -> (Visited, String) {
        let (mut visitor, channel) = tokio::io::duplex(64 * 1024);
        visitor.write_all(request).await.unwrap();
        // The visitor sends no more: a channel with no request ends.
        visitor.shutdown().await.unwrap();
        let served = tokio::spawn(serve(channel, origin));
        let mut answer = Vec::new();
        tokio::time::timeout(LIMIT, visitor.read_to_end(&mut answer)).await.expect("an answer in time").unwrap();
        (served.await.unwrap(), String::from_utf8_lossy(&answer).into_owned())
    }

    #[tokio::test]
    async fn a_path_of_the_role_goes_to_the_role_whole_with_the_visitor_that_the_edge_names() {
        let echo = Arc::new(Echo::default());
        let request = b"POST /health HTTP/1.1\r\nHost: a1.lhr.life\r\nX-Forwarded-For: 198.51.100.7, 10.0.0.1\r\n\
            Content-Length: 2\r\n\r\n{}";
        let (visited, answer) = ask(request, Some(echo.clone())).await;
        assert!(matches!(visited, Visited::Role(ref path) if path == "/health"), "{visited:?}");
        assert!(answer.starts_with("HTTP/1.1 200 ") && answer.ends_with("POST /health a1.lhr.life 2"), "{answer}");
        assert_eq!(*echo.visitor.lock().unwrap(), Some(Some("198.51.100.7".parse().unwrap())));
    }

    #[tokio::test]
    async fn another_path_or_no_upgrade_is_refused_and_no_role_means_no_role_s_path() {
        let (visited, answer) = ask(b"GET /index.html HTTP/1.1\r\nHost: a\r\n\r\n", None).await;
        assert!(matches!(visited, Visited::Refused(404)) && answer.starts_with("HTTP/1.1 404 "), "{answer}");
        let (visited, answer) = ask(b"GET /health HTTP/1.1\r\nHost: a\r\n\r\n", None).await;
        assert!(matches!(visited, Visited::Refused(404)), "no role, so not the role's: {answer}");
        let (visited, answer) = ask(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", None).await;
        assert!(matches!(visited, Visited::Refused(status) if status >= 400), "a GET with no upgrade: {answer}");
        let (visited, _) = ask(b"", None).await;
        assert!(matches!(visited, Visited::Gone(_)), "{visited:?}");
    }

    #[tokio::test]
    async fn a_websocket_at_the_root_is_a_link_of_the_messages_bytes_both_ways() {
        let (mut visitor, channel) = tokio::io::duplex(64 * 1024);
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let head = format!(
            "GET / HTTP/1.1\r\nHost: a1.lhr.life\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
             Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        // The first frame comes with the head, as a client may send it.
        let mut sent = head.into_bytes();
        let hello = Frame { fin: true, opcode: 0x2, payload: b"hello".to_vec() };
        sent.extend_from_slice(&frame::encode(&hello, Role::Client, [1, 2, 3, 4]));
        visitor.write_all(&sent).await.unwrap();
        let Visited::Layer(mut link) = serve(channel, None).await else { panic!("no link") };
        let mut got = [0u8; 5];
        tokio::time::timeout(LIMIT, link.read_exact(&mut got)).await.expect("in time").unwrap();
        assert_eq!(&got, b"hello");
        link.write_all(b"back").await.unwrap();
        let mut answer = Vec::new();
        let mut chunk = [0u8; 1024];
        let at = loop {
            let n = tokio::time::timeout(LIMIT, visitor.read(&mut chunk)).await.expect("in time").unwrap();
            answer.extend_from_slice(&chunk[..n]);
            if let Some(at) = answer.windows(4).position(|w| w == b"\r\n\r\n") {
                if let Ok(Some((frame, _))) = frame::decode(&answer[at + 4..], Role::Server) {
                    assert_eq!(frame.payload, b"back");
                    break at;
                }
            }
        };
        let head = String::from_utf8_lossy(&answer[..at]);
        assert!(head.starts_with("HTTP/1.1 101 ") && head.contains("s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{head}");
    }
}
