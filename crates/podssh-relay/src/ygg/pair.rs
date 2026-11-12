//! A pair's road through Yggdrasil's network (T-735): the node's key comes
//! from the pair's name and connect token, so each of its operators knows
//! the node's address with no word between them; a client with a key of its
//! own says hello to it, with a proof of the token, again each
//! [`HELLO_EVERY`] until the node welcomes it (Ironwood drops what it cannot
//! place yet). Each session is a stream of its own ([`crate::packet_stream`])
//! under an id that the client picks, so that one end's sessions never mix.
//! Another end of the network that knows the node's key but not the token
//! opens nothing: its hello does not prove the token.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tokio::io::DuplexStream;
use tokio::sync::{mpsc, oneshot};

use super::router::Router;
use crate::packet_stream::{self, In, Packets, Shape};

/// The first byte of each of podssh's packets on the network, then a kind.
const MAGIC: u8 = 0x70;
const HELLO: u8 = 1;
const WELCOME: u8 = 2;
const STREAM: u8 = 3;
/// How often a client says hello again.
pub const HELLO_EVERY: Duration = Duration::from_secs(1);
/// The stream's shape: packets well under a link's largest message, as a
/// path crosses links that each take one whole.
pub const SHAPE: Shape = Shape { chunk: 8 * 1024, window: 256 * 1024, again: Duration::from_secs(1) };
/// The most sessions that a node serves at once.
pub const MAX_SESSIONS: usize = 64;
/// The largest packet read.
const READ: usize = 64 * 1024;

type Key = [u8; 32];
type Feed = mpsc::Sender<io::Result<In<()>>>;

fn hash(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// A fresh key of a client, for one run.
pub fn fresh_secret() -> SigningKey {
    SigningKey::from_bytes(&rand::random())
}

/// The node's key in the network, from the pair's name and connect token.
pub fn node_secret(name: &str, token: &str) -> SigningKey {
    SigningKey::from_bytes(&hash(&[b"podssh ygg node", name.as_bytes(), token.as_bytes()]))
}

fn proof(token: &str, client: &Key, node: &Key, session: u64) -> [u8; 32] {
    hash(&[b"podssh ygg hello", token.as_bytes(), client, node, &session.to_be_bytes()])
}

fn packet(kind: u8, session: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + body.len());
    out.extend_from_slice(&[MAGIC, kind]);
    out.extend_from_slice(&session.to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// A packet of podssh's: its kind, its session and its body.
fn parse(bytes: &[u8]) -> Option<(u8, u64, &[u8])> {
    let (&[MAGIC, kind], rest) = bytes.split_first_chunk::<2>()? else { return None };
    let (session, body) = rest.split_first_chunk::<8>()?;
    Some((kind, u64::from_be_bytes(*session), body))
}

/// One session's packets, as its stream sends them.
struct Session {
    router: Arc<Router>,
    to: Key,
    id: u64,
}

impl Packets for Session {
    type Other = ();

    async fn send(&mut self, payload: Vec<u8>) -> io::Result<()> {
        // A packet that the router cannot place is lost, as on any network:
        // the stream sends it again.
        let _ = self.router.send(&self.to, &packet(STREAM, self.id, &payload)).await;
        Ok(())
    }

    async fn other(&mut self, (): ()) -> io::Result<bool> {
        Ok(true)
    }
}

/// What a node serves: the token that a hello proves, and where each new
/// session's stream goes.
pub struct Serve {
    pub token: String,
    pub visitors: mpsc::Sender<DuplexStream>,
}

/// The sessions of one router, its reader, and the welcomes that clients
/// wait for.
pub struct Ends {
    router: Arc<Router>,
    sessions: Mutex<HashMap<(Key, u64), Feed>>,
    welcomes: Mutex<HashMap<(Key, u64), oneshot::Sender<()>>>,
}

impl Ends {
    /// Read `router`'s packets for its sessions; with `serve`, take the
    /// hellos of the pair's clients as a node.
    pub fn start(router: Arc<Router>, serve: Option<Serve>) -> Arc<Ends> {
        let ends = Arc::new(Ends { router, sessions: Mutex::default(), welcomes: Mutex::default() });
        tokio::spawn(ends.clone().read(serve));
        ends
    }

    fn open(&self, peer: Key, id: u64) -> Option<DuplexStream> {
        let mut sessions = self.sessions.lock().ok()?;
        sessions.retain(|_, feed| !feed.is_closed());
        if sessions.len() >= MAX_SESSIONS {
            return None;
        }
        let (feed, incoming) = mpsc::channel(256);
        sessions.insert((peer, id), feed);
        Some(packet_stream::stream(Session { router: self.router.clone(), to: peer, id }, incoming, SHAPE))
    }

    async fn read(self: Arc<Self>, serve: Option<Serve>) {
        let mut buf = vec![0u8; READ];
        let me = self.router.key();
        while let Some((n, from)) = self.router.recv(&mut buf).await {
            let Some((kind, id, body)) = parse(&buf[..n]) else { continue };
            match kind {
                STREAM => {
                    let feed = self.sessions.lock().ok().and_then(|s| s.get(&(from, id)).cloned());
                    if let Some(feed) = feed {
                        // A full feed drops the packet: the stream sends it again.
                        let _ = feed.try_send(Ok(In::Data(body.to_vec())));
                    }
                }
                HELLO => {
                    let Some(serve) = &serve else { continue };
                    if body != proof(&serve.token, &from, &me, id) {
                        continue;
                    }
                    let known = self.sessions.lock().is_ok_and(|s| s.contains_key(&(from, id)));
                    if !known {
                        let Some(stream) = self.open(from, id) else { continue };
                        if serve.visitors.send(stream).await.is_err() {
                            return;
                        }
                    }
                    let _ = self.router.send(&from, &packet(WELCOME, id, &[])).await;
                }
                WELCOME => {
                    if let Some(waiting) = self.welcomes.lock().ok().and_then(|mut w| w.remove(&(from, id))) {
                        let _ = waiting.send(());
                    }
                }
                _ => {}
            }
        }
    }

    /// A session to the node of key `node`, proved with `token`, within `limit`.
    pub async fn link(&self, node: Key, token: &str, limit: Duration) -> io::Result<DuplexStream> {
        let id: u64 = rand::random();
        let (welcomed, mut welcome) = oneshot::channel();
        if let Ok(mut w) = self.welcomes.lock() {
            w.insert((node, id), welcomed);
        }
        let hello = packet(HELLO, id, &proof(token, &self.router.key(), &node, id));
        let waited = tokio::time::timeout(limit, async {
            let mut again = tokio::time::interval(HELLO_EVERY);
            loop {
                tokio::select! {
                    _ = again.tick() => {
                        let _ = self.router.send(&node, &hello).await;
                    }
                    got = &mut welcome => return got.is_ok(),
                }
            }
        })
        .await;
        if let Ok(mut w) = self.welcomes.lock() {
            w.remove(&(node, id));
        }
        match waited {
            Ok(true) => self.open(node, id).ok_or_else(|| io::Error::other("too many sessions on this router")),
            _ => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the node did not answer through Yggdrasil's network in time",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_s_key_is_the_pair_s_and_a_packet_reads_back() {
        let (a, b) = (node_secret("lab", "t1").verifying_key(), node_secret("lab", "t1").verifying_key());
        assert_eq!(a, b);
        assert_ne!(a, node_secret("lab", "t2").verifying_key());
        assert_ne!(a, node_secret("lan", "t1").verifying_key());
        let bytes = packet(HELLO, 7, b"proof");
        assert_eq!(parse(&bytes), Some((HELLO, 7, &b"proof"[..])));
        assert_eq!(parse(&bytes[..5]), None);
        assert_eq!(parse(&[0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0]), None, "an IPv6 packet of Yggdrasil's is not podssh's");
        let (client, node) = ([1; 32], [2; 32]);
        assert_ne!(proof("t1", &client, &node, 7), proof("t2", &client, &node, 7));
        assert_ne!(proof("t1", &client, &node, 7), proof("t1", &client, &node, 8));
    }
}
