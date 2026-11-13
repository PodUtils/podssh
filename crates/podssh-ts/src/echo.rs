//! An echo on the node's own tailnet stack (T-106): node A of the live test
//! with two nodes, which `podssh ts -W A:PORT` (node B) reaches. It waits on
//! a socket of the fork's smoltcp stack, in this process: no socket of the
//! host is bound, and nothing outside the tailnet reaches it. Each
//! connection sends back each byte that it gets, then ends its sending side
//! at the end of its input, and tells what it got: the bytes and their
//! SHA-256, which the test compares with what node B sent.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::node::{NodeError, TsNode};

/// What one connection of the echo got, and sent back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Echoed {
    pub bytes: u64,
    /// The SHA-256 of those bytes, in lower-case hex.
    pub sha256: String,
}

/// An echo that serves until it is dropped.
pub struct Echo {
    /// Where node B reaches it: the node's tailnet address, and the port.
    pub addr: SocketAddr,
    /// One line for each connection that ended: what it got, or why it
    /// failed.
    pub ended: mpsc::UnboundedReceiver<Result<Echoed, String>>,
    accepting: JoinHandle<()>,
}

impl Drop for Echo {
    fn drop(&mut self) {
        self.accepting.abort();
    }
}

/// A digest as lower-case hex, as `sha256sum` writes one.
pub fn hex_sha256(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// The echo on `port` of `node`'s tailnet address, once the first network
/// map gave the node one, within `limit`.
pub async fn start(node: &TsNode, port: u16, limit: Duration) -> Result<Echo, NodeError> {
    let ip: Ipv4Addr = node.address_within(limit).await?;
    let addr = SocketAddr::from((ip, port));
    let listener = node.device().tcp_listen(addr).await.map_err(|e| NodeError::Fork(e.to_string()))?;
    let (tell, ended) = mpsc::unbounded_channel();
    let accepting = tokio::spawn(async move {
        loop {
            let conn = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    let _ = tell.send(Err(format!("accept: {e}")));
                    return;
                }
            };
            let tell = tell.clone();
            tokio::spawn(async move {
                let _ = tell.send(echo_one(conn).await.map_err(|e| e.to_string()));
            });
        }
    });
    Ok(Echo { addr, ended, accepting })
}

/// Each byte of `conn` back to it, until its end of input; then its
/// sending side ends too, so that the peer's read ends.
async fn echo_one(conn: tailscale::netstack::TcpStream) -> std::io::Result<Echoed> {
    // Pinned, as the reads and writes of tokio's traits ask of a stream.
    let mut conn = Box::pin(conn);
    let mut hash = Sha256::new();
    let mut bytes = 0u64;
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
        bytes += n as u64;
        conn.write_all(&buf[..n]).await?;
    }
    conn.flush().await?;
    // The end of a stream is its shutdown: a dropped write half did not
    // always tell the peer (docs/tailscale.md, "Rules").
    conn.shutdown().await?;
    Ok(Echoed { bytes, sha256: hex_sha256(&hash.finalize()) })
}
