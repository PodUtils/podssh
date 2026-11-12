//! A pair's road through a Tox TCP relay (T-734): the node holds one
//! connection to the relay under a key that the pair's connect token makes,
//! so that each of its operators knows it, and waits there for a hello. A
//! client connects with a fresh key and sends its hello to the node's key,
//! out of band, again each [`HELLO_EVERY`] (the relay says nothing of a
//! delivery); the node answers with the key of a new connection of its own
//! for that client alone, and the two route to each other: one routed
//! connection for each session, each on a connection of its own, so that one
//! stream's pace never holds another's.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::sync::{mpsc, Mutex};

use super::routed::meet;
use super::wire::{connect, Keys, Packet, KEY};

/// A connection to the relay, as the caller dials it (through a proxy).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}
pub type Dialing = Pin<Box<dyn std::future::Future<Output = io::Result<Box<dyn Io>>> + Send>>;
pub type Dial = Arc<dyn Fn() -> Dialing + Send + Sync>;
/// Where the road's lines go.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// The hello's words, and the answer's, before the new key.
const HELLO: &[u8] = b"podssh-tox-1 hello";
const OFFER: &[u8] = b"podssh-tox-1 offer ";
/// How often a client sends its hello again.
pub const HELLO_EVERY: Duration = Duration::from_secs(2);
/// How long a session's two ends have to meet.
pub const MEET_LIMIT: Duration = Duration::from_secs(20);

/// The node's key on the relay, from the pair's name and connect token,
/// which each of its operators holds.
pub fn node_keys(name: &str, token: &str) -> Keys {
    let mut hash = Sha256::new();
    hash.update(b"podssh tox node\0");
    for part in [name.as_bytes(), token.as_bytes()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Keys::of_seed(hash.finalize().into())
}

/// The relay among `relays` for the pair `name`: by the SHA-256 of the name,
/// so that both ends pick the same one with no word between them.
pub fn pick<'a, T>(name: &str, relays: &'a [T]) -> Option<&'a T> {
    if relays.is_empty() {
        return None;
    }
    let digest = Sha256::digest(name.as_bytes());
    let n = u64::from_be_bytes(digest[..8].try_into().unwrap_or_default());
    relays.get((n % relays.len() as u64) as usize)
}

async fn connected(
    dial: &Dial,
    relay: &[u8; KEY],
    keys: &Keys,
) -> io::Result<(
    super::wire::Sender<tokio::io::WriteHalf<Box<dyn Io>>>,
    super::wire::Receiver<tokio::io::ReadHalf<Box<dyn Io>>>,
)> {
    let io = dial().await?;
    let (read, write) = tokio::io::split(io);
    connect(read, write, relay, keys).await
}

/// The node: wait on the relay for clients, and give each session's stream
/// to `visitors`; dial the relay again, after 1 s, doubled to 32 s, when its
/// connection ends. Returns when `visitors` closes.
pub async fn serve(dial: Dial, relay: [u8; KEY], node: Keys, visitors: mpsc::Sender<DuplexStream>, say: Say) {
    let mut wait = Duration::from_secs(1);
    let node = Arc::new(node);
    loop {
        match connected(&dial, &relay, &node).await {
            Ok((sender, mut receiver)) => {
                wait = Duration::from_secs(1);
                say("waits for its operators on the Tox relay".into());
                let sender = Arc::new(Mutex::new(sender));
                loop {
                    match receiver.recv().await {
                        Ok(Packet::Oob { from, data }) if data == HELLO => {
                            let (dial, sender, visitors, say) =
                                (dial.clone(), sender.clone(), visitors.clone(), say.clone());
                            tokio::spawn(async move {
                                if let Err(e) = session(dial, relay, from, sender, visitors).await {
                                    say(format!("a session on the Tox relay did not start: {e}"));
                                }
                            });
                        }
                        Ok(Packet::Ping(ping)) => {
                            if sender.lock().await.pong(ping).await.is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            say(format!("its connection to the Tox relay ended: {e}"));
                            break;
                        }
                    }
                    if visitors.is_closed() {
                        return;
                    }
                }
            }
            Err(e) => say(format!("the Tox relay did not take its connection: {e}")),
        }
        if visitors.is_closed() {
            return;
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(32));
    }
}

/// One client's session at the node: a connection of its own, its key
/// offered to the client, and the route.
async fn session<W: AsyncWrite + Unpin>(
    dial: Dial,
    relay: [u8; KEY],
    client: [u8; KEY],
    waiting: Arc<Mutex<super::wire::Sender<W>>>,
    visitors: mpsc::Sender<DuplexStream>,
) -> io::Result<()> {
    let keys = Keys::fresh();
    let (sender, receiver) = connected(&dial, &relay, &keys).await?;
    let mut offer = OFFER.to_vec();
    offer.extend_from_slice(&keys.public());
    waiting.lock().await.oob(&client, &offer).await?;
    let stream = meet(sender, receiver, client, MEET_LIMIT).await?;
    visitors.send(stream).await.map_err(|_| io::Error::other("the node stopped"))
}

/// The client: reach the node of key `node` on the relay, within `limit`.
pub async fn link(dial: &Dial, relay: [u8; KEY], node: [u8; KEY], limit: Duration) -> io::Result<DuplexStream> {
    let keys = Keys::fresh();
    let (mut sender, mut receiver) = connected(dial, &relay, &keys).await?;
    let offered = tokio::time::timeout(limit, async {
        let mut again = tokio::time::interval(HELLO_EVERY);
        loop {
            tokio::select! {
                _ = again.tick() => sender.oob(&node, HELLO).await?,
                got = receiver.recv() => match got? {
                    Packet::Oob { from, data } if from == node => {
                        if let Some(key) = data.strip_prefix(OFFER).and_then(|k| <[u8; KEY]>::try_from(k).ok()) {
                            return Ok::<_, io::Error>(key);
                        }
                    }
                    Packet::Ping(ping) => sender.pong(ping).await?,
                    _ => {}
                },
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the node did not answer on the Tox relay in time"))??;
    meet(sender, receiver, offered, MEET_LIMIT).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_node_s_key_is_the_pair_s_and_the_relay_is_the_name_s() {
        assert_eq!(node_keys("lab", "t1").public(), node_keys("lab", "t1").public());
        assert_ne!(node_keys("lab", "t1").public(), node_keys("lab", "t2").public());
        assert_ne!(node_keys("lab", "t1").public(), node_keys("lan", "t1").public());
        let relays = [1, 2, 3, 4, 5];
        assert_eq!(pick("lab", &relays), pick("lab", &relays));
        assert!(pick::<u8>("lab", &[]).is_none());
    }
}
