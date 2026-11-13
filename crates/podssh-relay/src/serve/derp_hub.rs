//! The hub of the DERP route (T-106): the clients that are up, one for each
//! node key; the handshake of each; and the packets between them, as
//! derper forwards them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::{framed, read_keys, Link, REFUSED_CODE, REFUSED_REASON};
use crate::derp::frame::{kind, HEADER, KEY, MAGIC, MAX_FRAME, MAX_PACKET, NONCE};
use crate::derp::{Key, Secret};
use crate::serve::Config;

/// The packets that wait for one receiver; a packet past them is dropped,
/// as derper drops one of a full queue: WireGuard and the TCP inside it
/// send again what was lost.
const QUEUE: usize = 32;
/// A keepalive frame this often, as derper sends one, so that a proxy on
/// the way keeps an idle link.
const KEEPALIVE: Duration = Duration::from_secs(60);
/// How long a client has for its info after the server's key.
const HANDSHAKE: Duration = Duration::from_secs(30);

/// One client of the hub: its connection's number, and its queue.
pub(super) struct Client {
    pub(super) id: u64,
    queue: mpsc::Sender<Vec<u8>>,
}

/// The DERP server: its key, the file of the keys that it admits, and the
/// clients that are up, one for each key.
pub struct Hub {
    secret: Secret,
    keys: PathBuf,
    pub(super) clients: Mutex<HashMap<Key, Client>>,
    next: AtomicU64,
}

pub(super) fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Hub {
    pub fn new(secret: Secret, keys: PathBuf) -> Hub {
        Hub { secret, keys, clients: Mutex::default(), next: AtomicU64::new(0) }
    }

    /// The server's public key, which its first frame and its 101 name.
    pub fn public(&self) -> Key {
        self.secret.public()
    }

    /// Whether the file admits `key`, read now; `Err` when it cannot be read.
    pub(super) fn admits(&self, key: &Key) -> Result<bool, String> {
        Ok(read_keys(&self.keys)?.contains(key))
    }

    /// `key` up on a new connection: an older one of the same key loses its
    /// queue and ends, as derper keeps the newest.
    pub(super) fn join(&self, key: Key) -> (u64, mpsc::Receiver<Vec<u8>>) {
        let (queue, waiting) = mpsc::channel(QUEUE);
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        lock(&self.clients).insert(key, Client { id, queue });
        (id, waiting)
    }

    /// The connection `id` of `key` ended: its entry goes, unless a newer
    /// connection took the key.
    pub(super) fn leave(&self, key: &Key, id: u64) {
        let mut clients = lock(&self.clients);
        if clients.get(key).is_some_and(|c| c.id == id) {
            clients.remove(key);
        }
    }

    /// A SendPacket of `from`: its packet to the key that it names, as a
    /// RecvPacket that names `from`. A receiver that is not up, or whose
    /// queue is full, loses it.
    pub(super) fn forward(&self, from: &Key, body: &[u8]) {
        if body.len() < KEY || body.len() - KEY > MAX_PACKET {
            return;
        }
        let mut to = [0u8; KEY];
        to.copy_from_slice(&body[..KEY]);
        let Some(queue) = lock(&self.clients).get(&Key(to)).map(|c| c.queue.clone()) else { return };
        let _ = queue.try_send(framed(kind::RECV_PACKET, &[&from.0[..], &body[KEY..]].concat()));
    }

    /// The handshake, then the packets of one node until its end; `stream`
    /// holds the bytes that came after the request's head.
    pub(crate) async fn serve<S>(&self, link: Arc<Link<S>>, mut stream: Vec<u8>, cfg: &Config)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let first = [&MAGIC[..], &self.secret.public().0[..]].concat();
        if !link.send(&framed(kind::SERVER_KEY, &first)).await {
            return;
        }
        let info = match tokio::time::timeout(HANDSHAKE, next(&link, &mut stream)).await {
            Ok(Some((kind::CLIENT_INFO, body))) if body.len() >= KEY + NONCE + 16 => body,
            _ => return,
        };
        let mut raw = [0u8; KEY];
        raw.copy_from_slice(&info[..KEY]);
        let key = Key(raw);
        // A box that does not open was not sealed by the key that it names.
        if self.secret.open(&key, &info[KEY..]).is_err() {
            link.close(1002, "the client's info does not open").await;
            return;
        }
        let refused = match self.admits(&key) {
            Ok(true) => None,
            // The whole key, which is public, so that its owner can list it.
            Ok(false) => Some(format!("nodekey:{}, not in {}", key.hex(), self.keys.display())),
            Err(why) => Some(format!("nodekey:{}: {why}", key.hex())),
        };
        if let Some(why) = refused {
            cfg.event(&format!("derp: refused the node key {why}"));
            link.close(REFUSED_CODE, REFUSED_REASON).await;
            return;
        }
        let (id, waiting) = self.join(key);
        let sealed = self.secret.seal(&key, br#"{"version":2}"#, rand::random());
        if !link.send(&framed(kind::SERVER_INFO, &sealed)).await {
            self.leave(&key, id);
            return;
        }
        cfg.event(&format!("derp: the node key {} is up", key.short()));
        let mut writer = tokio::spawn(write_queue(link.clone(), waiting));
        loop {
            let frame = tokio::select! {
                frame = next(&link, &mut stream) => frame,
                // A newer connection of the key took its queue.
                _ = &mut writer => None,
            };
            let Some((t, body)) = frame else { break };
            match t {
                kind::SEND_PACKET => self.forward(&key, &body),
                kind::PING if body.len() >= 8 => {
                    let _ = link.send(&framed(kind::PONG, &body[..8])).await;
                }
                // NotePreferred, WatchConns and the mesh's frames ask nothing here.
                _ => {}
            }
        }
        writer.abort();
        self.leave(&key, id);
        cfg.event(&format!("derp: the node key {} is down", key.short()));
    }
}

/// The frames of a client's queue to its link, and a keepalive each
/// [`KEEPALIVE`]; ends when the queue's sender goes, or a write fails.
async fn write_queue<S>(link: Arc<Link<S>>, mut waiting: mpsc::Receiver<Vec<u8>>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let mut tick = tokio::time::interval(KEEPALIVE);
    tick.tick().await;
    loop {
        tokio::select! {
            frame = waiting.recv() => match frame {
                Some(frame) => {
                    if !link.send(&frame).await {
                        return;
                    }
                }
                None => {
                    link.close(1000, "a newer connection of this node key").await;
                    return;
                }
            },
            _ = tick.tick() => {
                if !link.send(&framed(kind::KEEP_ALIVE, &[])).await {
                    return;
                }
            }
        }
    }
}

/// The next DERP frame of the client: its kind and its body; `None` at the
/// end of the link, or at a frame longer than DERP's largest. The frames
/// span a WebSocket's messages: their ends mean nothing.
async fn next<S>(link: &Link<S>, stream: &mut Vec<u8>) -> Option<(u8, Vec<u8>)>
where
    S: AsyncRead + AsyncWrite + Send,
{
    loop {
        if stream.len() >= HEADER {
            let len = u32::from_be_bytes([stream[1], stream[2], stream[3], stream[4]]) as usize;
            if len > MAX_FRAME {
                return None;
            }
            if stream.len() >= HEADER + len {
                let t = stream[0];
                let body = stream[HEADER..HEADER + len].to_vec();
                stream.drain(..HEADER + len);
                return Some((t, body));
            }
        }
        if !link.more(stream).await {
            return None;
        }
    }
}
