//! One of a node's connections to the localtunnel server, served: it waits
//! for a visitor's request for as long as the tunnel lives, then reads its
//! head and gives the connection to whom the path is for. The relay role's
//! paths (`crate::serve::serves`), or each path for a node with no TARGET,
//! go to the role with the head read again first, as the role reads a
//! request of its listener (T-428's origin gives it a pipe the same way); a
//! WebSocket to any other path is one link of the node: the 101, then the
//! bytes of its messages, by the quick tunnel's reader of a visitor's
//! frames (`crate::quick::visitor`). Each other request gets 404. The role
//! closes the connection after its answer, and so does a refusal here: the
//! server's agent then takes another of the node's connections, which the
//! node opens again at once ([`super::keep`]).
//!
//! The server passes no address of the visitor that podssh can trust
//! (`lib/Client.js` sends the visitor's own headers), so the role's brake
//! counts each request of the tunnel as one caller's.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use pod_session::client::Rewound;
use podssh_ws::http::request::{self, Request};
use podssh_ws::server;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use crate::serve::{self, Config};

/// The longest head of a visitor's request.
pub const MAX_HEAD: usize = 16 * 1024;
/// How long a head may take once its first byte came.
pub const HEAD_WAIT: Duration = Duration::from_secs(30);

/// The serving of one visitor's link, until it ends.
pub type Visiting = Pin<Box<dyn Future<Output = ()> + Send>>;
/// What a node gives each visitor's WebSocket: one link of its layer.
pub type Visit = Arc<dyn Fn(DuplexStream) -> Visiting + Send + Sync>;

/// Who serves a node's connections.
pub struct Router {
    /// The relay role behind the tunnel (`--relay`), if the node is one.
    pub role: Option<Arc<Config>>,
    /// Each path is the role's: a node with no TARGET.
    pub alone: bool,
    /// The node's links, for a node with a TARGET.
    pub visit: Option<Visit>,
}

/// Whom a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Whom {
    Role,
    Link,
    Nobody,
}

impl Router {
    /// Whom the request of `head` is for.
    pub fn whom(&self, head: &Request) -> Whom {
        let path = head.target.split('?').next().unwrap_or_default();
        if self.role.is_some() && (self.alone || serve::serves(path)) {
            Whom::Role
        } else if self.visit.is_some() && server::asks_upgrade(head) {
            Whom::Link
        } else {
            Whom::Nobody
        }
    }
}

/// Serve one connection of the tunnel whose name is `name`: what the role's
/// signed mint must name (T-448), as a client's TLS asked the server for it.
pub async fn serve<S>(router: Arc<Router>, name: String, mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Some((head, raw, end)) = read_head(&mut stream).await else { return };
    match router.whom(&head) {
        Whom::Role => {
            let Some(cfg) = router.role.clone() else { return };
            // The role reads the head again itself, as from its listener.
            serve::serve_from(Rewound::new(raw, stream), cfg, Some(name), None).await;
        }
        Whom::Link => {
            let Some(visit) = router.visit.clone() else { return };
            let key = match server::check_upgrade(&head) {
                Ok(key) => key,
                Err(refused) => {
                    let _ = stream.write_all(&refused.answer()).await;
                    return;
                }
            };
            if stream.write_all(&server::switching(&key)).await.is_err() {
                return;
            }
            // The bytes after the head are the visitor's first frames.
            let (from, to) = tokio::io::split(Rewound::new(raw[end..].to_vec(), stream));
            visit(crate::quick::visitor::websocket(from, to)).await;
        }
        Whom::Nobody => {
            let path = head.target.split('?').next().unwrap_or_default();
            let _ = stream.write_all(&request::refusal(404, &format!("{path}: not found"), &[])).await;
        }
    }
}

/// The head of the connection's first request: it, the bytes read, and
/// where the head ends in them. None when the connection ends first, the
/// head is too long or too slow once begun, or it does not parse.
async fn read_head<S>(stream: &mut S) -> Option<(Request, Vec<u8>, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut raw = Vec::with_capacity(2048);
    let mut chunk = vec![0u8; 4096];
    // A connection waits for its first visitor for as long as the tunnel
    // lives: no bound until the first byte.
    let first = stream.read(&mut chunk).await.ok().filter(|n| *n > 0)?;
    raw.extend_from_slice(&chunk[..first]);
    let rest = async {
        loop {
            if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                return Some(at + 4);
            }
            if raw.len() > MAX_HEAD {
                return None;
            }
            let n = stream.read(&mut chunk).await.ok().filter(|n| *n > 0)?;
            raw.extend_from_slice(&chunk[..n]);
        }
    };
    let waited = tokio::time::timeout(HEAD_WAIT, rest).await;
    let end = match waited {
        Ok(Some(end)) => end,
        Ok(None) => {
            let _ = stream.write_all(&request::refusal(431, "the request's head is too long", &[])).await;
            return None;
        }
        Err(_) => return None,
    };
    match request::parse_request(&raw[..end]) {
        Ok(head) => Some((head, raw, end)),
        Err(e) => {
            let _ = stream.write_all(&request::refusal(400, &e.to_string(), &[])).await;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(text: &str) -> Request {
        request::parse_request(text.as_bytes()).unwrap()
    }

    const UPGRADE: &str = "GET / HTTP/1.1\r\nHost: n.lt.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
                           Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";

    fn visit() -> Visit {
        Arc::new(|_: DuplexStream| -> Visiting { Box::pin(async {}) })
    }

    #[test]
    fn the_role_s_paths_go_to_the_role_and_a_websocket_elsewhere_to_the_node() {
        let none = Router { role: None, alone: false, visit: Some(visit()) };
        assert_eq!(none.whom(&head(UPGRADE)), Whom::Link);
        let health = head("GET /health HTTP/1.1\r\nHost: n.lt.test\r\n\r\n");
        assert_eq!(none.whom(&health), Whom::Nobody, "no role: the node's links alone");
        let plain = head("GET / HTTP/1.1\r\nHost: n.lt.test\r\n\r\n");
        assert_eq!(none.whom(&plain), Whom::Nobody, "a visit with no upgrade");
        let no_visit = Router { role: None, alone: false, visit: None };
        assert_eq!(no_visit.whom(&head(UPGRADE)), Whom::Nobody);
    }

    #[tokio::test]
    async fn a_head_that_comes_whole_or_in_pieces_is_read_and_its_bytes_kept() {
        let (mut ours, mut theirs) = tokio::io::duplex(64 * 1024);
        let reading =
            tokio::spawn(async move { read_head(&mut theirs).await.map(|(head, raw, end)| (head.target, raw, end)) });
        ours.write_all(b"GET /health HTTP/1.1\r\nHo").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        ours.write_all(b"st: n.lt.test\r\n\r\nNEXT").await.unwrap();
        let (target, raw, end) = reading.await.unwrap().expect("a head");
        assert_eq!(target, "/health");
        assert_eq!(&raw[end..], b"NEXT", "the bytes after the head are kept for whom it is");
    }

    #[tokio::test]
    async fn a_connection_that_ends_before_a_visitor_came_reads_no_head() {
        let (ours, mut theirs) = tokio::io::duplex(1024);
        drop(ours);
        assert!(read_head(&mut theirs).await.is_none());
    }
}
