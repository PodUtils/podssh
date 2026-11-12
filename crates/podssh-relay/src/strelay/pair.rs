//! A pair's road through one of Syncthing's relays (T-571). The node keeps a
//! connection in protocol mode to the relay under the device ID of the
//! pair's certificate, answers its pings, and joins each session that the
//! relay invites it to; a client with a fresh certificate asks the relay to
//! connect it to that device ID and joins the session that it is invited
//! to. A session is a TCP connection of its own to the relay, joined by the
//! invitation's key, which then carries the bytes as they are. The relay
//! sees them: the end-to-end channel above keeps them.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::cert::{self, DeviceId, Identity};
use super::wire::{self, Message, ALREADY_CONNECTED, NOT_FOUND, SUCCESS};

/// A connection to a relay, as the caller dials it (through a proxy).
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}
pub type BoxIo = Box<dyn Io>;
pub type Dialing = Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>>;
/// TCP to `IP:PORT`, through `HTTPS_PROXY` where one is set.
pub type Dial = Arc<dyn Fn(IpAddr, u16) -> Dialing + Send + Sync>;
/// Where the road's lines go.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// How long a step of the protocol may take: a join, an answer.
pub const STEP_LIMIT: Duration = Duration::from_secs(20);

/// A relay: its address and its device ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relay {
    pub ip: IpAddr,
    pub port: u16,
    pub id: DeviceId,
}

/// The node's certificate, from the pair's name and connect token.
pub fn node_identity(name: &str, token: &str) -> Identity {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for part in [&b"podssh strelay node"[..], name.as_bytes(), token.as_bytes()] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Identity::of_seed(hash.finalize().into())
}

async fn step<T>(what: &str, future: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(STEP_LIMIT, future).await.map_err(|_| {
        io::Error::new(io::ErrorKind::TimedOut, format!("Syncthing's relay did not answer {what} in time"))
    })?
}

/// Protocol mode: TLS to the relay, held to its device ID, as `me`.
async fn protocol(dial: &Dial, relay: &Relay, me: &Identity) -> io::Result<tokio_rustls::client::TlsStream<BoxIo>> {
    let config = cert::config(relay.id, me).map_err(io::Error::other)?;
    let tcp = step("the connection", dial(relay.ip, relay.port)).await?;
    let connector = tokio_rustls::TlsConnector::from(config);
    step("TLS", connector.connect(ServerName::IpAddress(relay.ip.into()), tcp)).await
}

/// Session mode: a connection of its own to the invitation's address (the
/// relay's when it names none), joined by its key.
async fn session(dial: &Dial, relay: &Relay, key: Vec<u8>, address: &[u8], port: u16) -> io::Result<BoxIo> {
    let ip = match address.len() {
        4 => IpAddr::from(<[u8; 4]>::try_from(address).unwrap_or_default()),
        16 => IpAddr::from(<[u8; 16]>::try_from(address).unwrap_or_default()),
        _ => relay.ip,
    };
    // Go writes an IPv4 address in 16 bytes, mapped into IPv6.
    let ip = ip.to_canonical();
    let ip = if ip.is_unspecified() { relay.ip } else { ip };
    let mut tcp = step("the session's connection", dial(ip, port)).await?;
    wire::write(&mut tcp, &Message::JoinSession { key }).await?;
    match step("the session's join", wire::read(&mut tcp)).await? {
        Message::Response { code: SUCCESS, .. } => Ok(tcp),
        Message::Response { code: ALREADY_CONNECTED, .. } => Err(io::Error::other(
            "the relay took the other end's join at the same moment and refused this one (already connected)",
        )),
        Message::Response { message, .. } => Err(io::Error::other(format!("the relay refused the session: {message}"))),
        other => Err(io::Error::other(format!("the relay answered the session's join with {other:?}"))),
    }
}

/// How long a client waits before its join of a session. The relay takes a
/// session's second connection only while its session waits for one (Go's
/// `AddConnection` hands it on with no wait) and refuses one that comes at
/// the same moment as the first, whose key it has then spent: the node joins
/// at once, the client a little later.
pub const CLIENT_SPACING: Duration = Duration::from_millis(100);

/// The node: join `relay` as `me` and give each session's stream to
/// `visitors`; join again, after 1 s doubled to 32 s, when the connection
/// ends. Returns when `visitors` closes.
pub async fn serve(dial: Dial, relay: Relay, me: Identity, visitors: mpsc::Sender<BoxIo>, say: Say) {
    let mut wait = Duration::from_secs(1);
    while !visitors.is_closed() {
        match joined(&dial, &relay, &me, &visitors, &say, &mut wait).await {
            Ok(()) => return,
            Err(e) => say(format!("its connection to Syncthing's relay ended: {e}")),
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(32));
    }
}

async fn joined(
    dial: &Dial,
    relay: &Relay,
    me: &Identity,
    visitors: &mpsc::Sender<BoxIo>,
    say: &Say,
    wait: &mut Duration,
) -> io::Result<()> {
    let mut tls = protocol(dial, relay, me).await?;
    wire::write(&mut tls, &Message::JoinRelay { token: String::new() }).await?;
    match step("the join", wire::read(&mut tls)).await? {
        Message::Response { code: SUCCESS, .. } => {}
        Message::RelayFull => return Err(io::Error::other("the relay is full")),
        other => return Err(io::Error::other(format!("the relay refused the join: {other:?}"))),
    }
    *wait = Duration::from_secs(1);
    say("waits for its operators on Syncthing's relay".into());
    loop {
        match wire::read(&mut tls).await? {
            Message::Invitation { key, address, port, server_socket: true, .. } => {
                let (dial, relay, visitors, say) = (dial.clone(), *relay, visitors.clone(), say.clone());
                tokio::spawn(async move {
                    match session(&dial, &relay, key, &address, port).await {
                        Ok(stream) => {
                            let _ = visitors.send(stream).await;
                        }
                        Err(e) => say(format!("a session on Syncthing's relay did not start: {e}")),
                    }
                });
            }
            Message::Ping => wire::write(&mut tls, &Message::Pong).await?,
            Message::RelayFull => return Err(io::Error::other("the relay is full")),
            _ => {}
        }
        if visitors.is_closed() {
            return Ok(());
        }
    }
}

/// The client: a session to the node of device ID `node` on `relay`, with
/// a fresh certificate, within `limit`.
pub async fn link(dial: &Dial, relay: &Relay, node: DeviceId, limit: Duration) -> io::Result<BoxIo> {
    let asked = async {
        let mut tls = protocol(dial, relay, &Identity::fresh()).await?;
        wire::write(&mut tls, &Message::Connect { id: node.to_vec() }).await?;
        loop {
            match wire::read(&mut tls).await? {
                Message::Invitation { from, key, address, port, server_socket: false } if from == node => {
                    tokio::time::sleep(CLIENT_SPACING).await;
                    return session(dial, relay, key, &address, port).await;
                }
                Message::Response { code: NOT_FOUND, .. } => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "the node is not on this relay of Syncthing's",
                    ));
                }
                Message::Response { message, .. } => {
                    return Err(io::Error::other(format!("the relay refused: {message}")))
                }
                Message::Ping => wire::write(&mut tls, &Message::Pong).await?,
                _ => {}
            }
        }
    };
    tokio::time::timeout(limit, asked)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no session on Syncthing's relay in time"))?
}
