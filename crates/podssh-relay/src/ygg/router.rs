//! This end in Yggdrasil's network: Ironwood's encrypted packet connection,
//! set as Yggdrasil's own nodes set it (the subnet's key in the bloom
//! filters, [`super::key`], and their largest message between peers), and
//! one link to a public peer that is dialed again when it ends. Packets go
//! to an end's Ed25519 key and come from one; Ironwood finds the path, and
//! encrypts each packet end to end with its own sessions.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use ironwood::{Addr, Config, EncryptedPacketConn, PacketConn};

use super::key::subnet_key;
use super::link::{self, Dial, Peer};

/// The largest message between two peers, as Yggdrasil's nodes allow it.
pub const PEER_MESSAGE: u64 = 65535 * 2;
/// The waits between two dials of a peer: the first, and the most.
const AGAIN_FIRST: Duration = Duration::from_secs(1);
const AGAIN_MOST: Duration = Duration::from_secs(32);

/// Where the router's lines go.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// This end's place in the network.
pub struct Router {
    conn: Arc<EncryptedPacketConn>,
    secret: SigningKey,
}

impl Router {
    /// A router with the key `secret`; it reaches nobody until [`Router::peer`].
    pub fn new(secret: SigningKey) -> Arc<Router> {
        let config = Config::default()
            .with_bloom_transform(|key: [u8; 32]| subnet_key(&key))
            .with_peer_max_message_size(PEER_MESSAGE);
        let conn = ironwood::new_encrypted_packet_conn(secret.clone(), config);
        Arc::new(Router { conn, secret })
    }

    /// This end's key, its address in the network.
    pub fn key(&self) -> [u8; 32] {
        self.secret.verifying_key().to_bytes()
    }

    /// The largest packet that [`Router::send`] takes.
    pub fn mtu(&self) -> usize {
        usize::try_from(self.conn.mtu()).unwrap_or(usize::MAX)
    }

    /// One packet to the end of key `to`; Ironwood looks for its path first,
    /// and drops what it cannot place, as a network of datagrams does.
    pub async fn send(&self, to: &[u8; 32], packet: &[u8]) -> Result<(), String> {
        self.conn.write_to(packet, &Addr(*to)).await.map(|_| ()).map_err(|e| e.to_string())
    }

    /// The next packet, and the key of the end that sent it; `None` once
    /// the router is closed.
    pub async fn recv(&self, buf: &mut [u8]) -> Option<(usize, [u8; 32])> {
        self.conn.read_from(buf).await.ok().map(|(n, from)| (n, from.0))
    }

    /// Keep a link to `peer` for the router's life: each that ends is
    /// dialed again after [`AGAIN_FIRST`], doubled to [`AGAIN_MOST`].
    /// Returns when the router is closed.
    pub async fn peer(self: Arc<Self>, peer: Peer, dial: Dial, say: Say) {
        let mut wait = AGAIN_FIRST;
        while !self.conn.is_closed() {
            match link::open(&peer, &dial, &self.secret).await {
                Ok((meta, stream)) => {
                    wait = AGAIN_FIRST;
                    say(format!("linked to the peer {peer} of Yggdrasil's network"));
                    let ended = self.conn.handle_conn(Addr(meta.key), Box::new(stream), meta.priority).await;
                    let why = ended.err().map(|e| format!(": {e}")).unwrap_or_default();
                    say(format!("the link to the peer {peer} ended{why}"));
                }
                Err(e) => say(format!("no link to the peer {peer}: {e}")),
            }
            if self.conn.is_closed() {
                return;
            }
            tokio::time::sleep(wait).await;
            wait = (wait * 2).min(AGAIN_MOST);
        }
    }

    /// Close the router: its links end, and [`Router::recv`] gives `None`.
    pub async fn close(&self) {
        let _ = self.conn.close().await;
    }
}
