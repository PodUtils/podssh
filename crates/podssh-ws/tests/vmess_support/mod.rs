//! A stand-in VMess server over a plain WebSocket on the loopback: it takes
//! the upgrade, then records each binary message the client sends, in order,
//! and answers nothing. What the tests read is the bytes that arrived at the
//! server, not a report of what the client meant to send.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// How long a test waits for a message that the client was asked to send.
const WAIT: Duration = Duration::from_secs(10);

/// What the stand-in saw.
#[derive(Default)]
pub struct Seen {
    /// Each upgrade's head, as the server read it.
    pub heads: Mutex<Vec<String>>,
    /// The length of the one write that carried each head.
    pub openings: Mutex<Vec<usize>>,
    /// Each binary message's payload, in the order they arrived.
    pub messages: Mutex<Vec<Vec<u8>>>,
}

impl Seen {
    /// Message `n` of the session, once it has arrived.
    pub async fn message(&self, n: usize) -> Vec<u8> {
        let started = tokio::time::Instant::now();
        loop {
            if let Some(found) = self.messages.lock().unwrap().get(n) {
                return found.clone();
            }
            assert!(started.elapsed() < WAIT, "message {n} did not arrive within {} s", WAIT.as_secs());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

/// A VMess stand-in on `127.0.0.1`, its port, and what it saw.
pub async fn ws_server() -> (u16, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen: Arc<Seen> = Arc::default();
    let kept = seen.clone();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let seen = kept.clone();
            tokio::spawn(async move {
                serve(tcp, seen).await;
            });
        }
    });
    (port, seen)
}

async fn serve<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(mut stream: S, seen: Arc<Seen>) {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut chunk).await {
            Ok(n) if n > 0 => buffer.extend_from_slice(&chunk[..n]),
            _ => return,
        }
    };
    seen.openings.lock().unwrap().push(end);
    let pending = buffer.split_off(end);
    let head = String::from_utf8_lossy(&buffer).into_owned();
    let field = |name: &str| {
        let mut fields = head.split("\r\n").filter_map(|l| l.split_once(':'));
        fields.find(|(n, _)| n.trim().eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())
    };
    let accept = podssh_ws::handshake::accept_key(&field("sec-websocket-key").unwrap_or_default());
    seen.heads.lock().unwrap().push(head);
    let answer = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: \
         {accept}\r\n\r\n"
    );
    if stream.write_all(answer.as_bytes()).await.is_err() {
        return;
    }
    let session = Arc::new(RelaySession::new(stream, pending, None, Duration::from_secs(30)).as_server());
    while let Ok(frame) = session.read_frame().await {
        if frame.opcode == podssh_ws::frame::OPCODE_CLOSE {
            return;
        }
        seen.messages.lock().unwrap().push(frame.payload);
    }
}
