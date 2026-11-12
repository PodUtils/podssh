//! HyperDHT as a road of a pair where UDP passes (T-736, the operator's
//! rulings Q77 and Q82): both ends join HyperDHT through its bootstrap
//! nodes, the node announces a topic made of its key, which the pair's
//! connect token makes, and the client looks the topic up and connects by
//! that key, a hole punched through both NATs, Noise and a secret stream
//! over UDX (`peeroxide`, a port of Hyperswarm). The stream of each session
//! is a byte stream ([`pump`]) under the end-to-end channel, which checks the
//! client's key against the node's allowlist: HyperDHT's handshake has no
//! test of a key. Where no bootstrap node answers within [`BOOTSTRAP_LIMIT`],
//! UDP did not pass, and the road says so.

use std::io;
use std::time::Duration;

use peeroxide::{JoinOpts, KeyPair, SwarmConfig, SwarmConnection, SwarmHandle};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// How long the DHT's bootstrap may take: past it, UDP did not pass.
pub const BOOTSTRAP_LIMIT: Duration = Duration::from_secs(15);
/// How often a client looks the node's topic up again.
pub const LOOK_AGAIN: Duration = Duration::from_secs(5);
/// The bytes of one message of the secret stream.
const CHUNK: usize = 32 * 1024;
/// What a stream holds between the secret stream and its reader.
const BUFFER: usize = 256 * 1024;

/// Where the road's lines go.
pub type Say = std::sync::Arc<dyn Fn(String) + Send + Sync>;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// The node's key pair in HyperDHT, from the pair's name and connect token.
pub fn node_keys(name: &str, token: &str) -> KeyPair {
    KeyPair::from_seed(hash(&[b"podssh hyperdht node", name.as_bytes(), token.as_bytes()]))
}

/// The topic that the node of key `node` announces.
pub fn topic(node: &[u8; 32]) -> [u8; 32] {
    hash(&[b"podssh hyperdht topic", node])
}

/// One end in HyperDHT: the swarm, its task, and its connections.
pub struct End {
    handle: SwarmHandle,
    task: JoinHandle<()>,
    connections: mpsc::Receiver<SwarmConnection>,
}

impl Drop for End {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Join HyperDHT through `bootstrap` (`HOST:PORT`, or `IP@NAME:PORT`) with
/// `keys`, or a fresh key pair; an error once the bootstrap did not answer.
pub async fn join(bootstrap: &[String], keys: Option<KeyPair>) -> io::Result<End> {
    let mut config = SwarmConfig::default();
    config.key_pair = keys;
    config.dht.dht.bootstrap = bootstrap.to_vec();
    // A DHT of the loopback alone (a test's) takes no peer from elsewhere,
    // and has no NAT to punch through.
    if !bootstrap.is_empty() && bootstrap.iter().all(|at| at.starts_with("127.")) {
        config.dht.dht.host = "127.0.0.1".into();
        config.dht.dht.firewalled = false;
    }
    let not_passed = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no bootstrap node of HyperDHT answered within {} s: UDP did not pass", BOOTSTRAP_LIMIT.as_secs()),
        )
    };
    let started = tokio::time::timeout(BOOTSTRAP_LIMIT, peeroxide::spawn(config)).await;
    let (task, handle, connections) = match started {
        Err(_) => return Err(not_passed()),
        Ok(Err(e)) => return Err(io::Error::other(format!("HyperDHT: {e}"))),
        Ok(Ok(started)) => started,
    };
    let end = End { handle, task, connections };
    // The bootstrap ends with no answer too: a table with no node is one.
    if end.handle.dht().dht().table_size().await.unwrap_or(0) == 0 {
        return Err(not_passed());
    }
    Ok(end)
}

impl End {
    /// As the node of the pair: announce the topic of its key, and give each
    /// session's stream to `visitors` until they close.
    pub async fn serve(mut self, visitors: mpsc::Sender<DuplexStream>, say: Say) {
        let me = self.handle.key_pair().public_key;
        let mut opts = JoinOpts::default();
        opts.client = false;
        if let Err(e) = self.handle.join(topic(&me), opts).await {
            say(format!("HyperDHT did not take the node's topic: {e}"));
            return;
        }
        // The announce reaches the DHT before the node says that it waits.
        if let Err(e) = self.handle.flush().await {
            say(format!("HyperDHT did not take the node's announce: {e}"));
        }
        say("waits for its operators in HyperDHT".into());
        while let Some(connection) = self.connections.recv().await {
            if visitors.send(pump(connection)).await.is_err() {
                break;
            }
        }
        let _ = self.handle.destroy().await;
    }

    /// As a client: the session to the node of key `node`, within `limit`.
    /// The swarm looks a topic up once at its join, so the client joins
    /// again each [`LOOK_AGAIN`]: a node that announced after the first
    /// lookup is found at the next.
    pub async fn link(&mut self, node: [u8; 32], limit: Duration) -> io::Result<DuplexStream> {
        let deadline = tokio::time::Instant::now() + limit;
        let topic = topic(&node);
        while tokio::time::Instant::now() < deadline {
            let mut opts = JoinOpts::default();
            opts.server = false;
            self.handle.join(topic, opts).await.map_err(|e| io::Error::other(format!("HyperDHT: {e}")))?;
            let round = (tokio::time::Instant::now() + LOOK_AGAIN).min(deadline);
            let found = tokio::time::timeout_at(round, async {
                while let Some(connection) = self.connections.recv().await {
                    if *connection.remote_public_key() == node {
                        return Some(connection);
                    }
                }
                None
            })
            .await;
            let _ = self.handle.leave(topic).await;
            match found {
                Ok(Some(connection)) => return Ok(pump(connection)),
                Ok(None) => return Err(io::Error::other("HyperDHT's swarm ended")),
                Err(_) => {}
            }
        }
        Err(io::Error::new(io::ErrorKind::TimedOut, "the node did not answer through HyperDHT in time"))
    }
}

/// A connection's secret stream, whose messages are a byte stream each way.
fn pump(connection: SwarmConnection) -> DuplexStream {
    let (near, far) = tokio::io::duplex(BUFFER);
    let (mut from, mut to) = tokio::io::split(far);
    let (mut read, mut write) = connection.peer.stream.into_split();
    tokio::spawn(async move {
        while let Ok(Some(message)) = read.read().await {
            if to.write_all(&message).await.is_err() {
                break;
            }
        }
        let _ = to.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; CHUNK];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if write.write(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = write.shutdown().await;
    });
    near
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_s_key_and_topic_are_the_pair_s() {
        assert_eq!(node_keys("lab", "t1").public_key, node_keys("lab", "t1").public_key);
        assert_ne!(node_keys("lab", "t1").public_key, node_keys("lab", "t2").public_key);
        assert_ne!(node_keys("lab", "t1").public_key, node_keys("lan", "t1").public_key);
        let node = node_keys("lab", "t1").public_key;
        assert_ne!(topic(&node), node, "the topic is not the key itself");
    }
}
