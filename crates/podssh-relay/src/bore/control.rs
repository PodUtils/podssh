//! The node's control connection to a bore server, as bore's own client
//! keeps it (`src/client.rs` at `00a735a89917`): a connection to the control
//! port, the answer to a `Challenge` where the server has a secret, then
//! `Hello` with a port of the node's key, and the server's `Hello` back;
//! then the server's messages until the connection ends. Each `Connection`
//! is taken on a new connection to the control port, with the same answer
//! and `Accept` with its UUID, which bore's server pairs with the visitor
//! that waits (10 s at most); the node then writes its hello, and the
//! connection is the visitor's stream, raw. The `Accept` never goes on the
//! control connection: bore's server reads nothing there after `Hello`.

use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

use super::wire::{self, ClientMessage, ServerMessage};
use super::{BoxIo, Dial, Say, Service, CONNECT_LIMIT};
use crate::pinggy::far::Visitor;

/// A control connection that heard nothing this long is lost: bore's
/// server sends a `Heartbeat` each 500 ms.
pub const SILENCE: Duration = Duration::from_secs(15);

/// A node's registration at a server: the public port that it holds, its
/// place in the series, and its control connection.
pub struct Registered {
    pub port: u16,
    pub at: usize,
    /// The ports of the series that the server refused before it, each with
    /// the server's words.
    pub refused: Vec<(u16, String)>,
    control: BufReader<BoxIo>,
}

impl std::fmt::Debug for Registered {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Registered {{ port: {}, at: {} }}", self.port, self.at)
    }
}

/// The next message of `from` within `limit`, or why there is none.
async fn heard<R>(from: &mut R, limit: Duration, what: &str) -> Result<Option<ServerMessage>, String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(limit, wire::recv(from)).await {
        Ok(heard) => heard,
        Err(_) => Err(format!("no {what} from the server within {} s", limit.as_secs())),
    }
}

/// A new connection to `service`'s control port, through `dial`, with the
/// answer to its `Challenge` where `service` has a secret.
pub async fn open(dial: &Dial, service: &Service) -> Result<BoxIo, String> {
    let mut io = tokio::time::timeout(CONNECT_LIMIT, dial(&service.host, service.port))
        .await
        .unwrap_or_else(|_| Err(format!("{service}: no connection within {} s", CONNECT_LIMIT.as_secs())))?;
    if let Some(secret) = &service.secret {
        let challenge = match heard(&mut io, CONNECT_LIMIT, "challenge").await? {
            Some(ServerMessage::Challenge(uuid)) => uuid,
            Some(_) => return Err(format!("{service} sent no challenge first: it asks no secret")),
            None => return Err(format!("{service} closed the connection: it asks no secret")),
        };
        let tag = wire::answer(secret.expose(), &challenge)
            .ok_or_else(|| format!("{service} sent a challenge that is not a UUID"))?;
        wire::send(&mut io, &ClientMessage::Authenticate(tag)).await?;
    }
    Ok(io)
}

/// Why a server's first answer to `Hello` was a `Challenge`.
fn asks_secret(service: &Service) -> String {
    format!(
        "{service} asks a secret (bore server --secret): it is a private server, and the bore road knows no \
         secret of it"
    )
}

/// Register at `service`: `Hello` with each of `ports` in turn, on a new
/// control connection each, until the server gives one. A server that
/// cannot be reached, or that asks a secret that nobody gave, ends it at
/// once; a port that the server refuses (another holds it, or it is outside
/// the server's range) sends it to the next.
pub async fn register(dial: &Dial, service: &Service, ports: &[u16]) -> Result<Registered, String> {
    let mut refused = Vec::new();
    for (at, &port) in ports.iter().enumerate() {
        let io = open(dial, service).await?;
        let mut control = BufReader::new(io);
        wire::send(control.get_mut(), &ClientMessage::Hello(port)).await?;
        match heard(&mut control, CONNECT_LIMIT, "answer to Hello").await? {
            Some(ServerMessage::Hello(given)) if given == port => {
                return Ok(Registered { port, at, refused, control });
            }
            // A port that the node did not ask is one that no client derives.
            Some(ServerMessage::Hello(given)) => refused.push((port, format!("the server gave the port {given}"))),
            Some(ServerMessage::Error(words)) => refused.push((port, words.chars().take(120).collect())),
            Some(ServerMessage::Challenge(_)) => return Err(asks_secret(service)),
            Some(_) => return Err(format!("{service} did not answer Hello as bore's server does")),
            None => return Err(format!("{service} closed the control connection before its answer to Hello")),
        }
    }
    let each: Vec<String> = refused.iter().map(|(port, words)| format!("{port}: {words}")).collect();
    Err(format!("{service} refused each port of the node's key ({})", each.join("; ")))
}

/// Take the visitor `uuid` on a new connection: `Accept`, then the node's
/// hello; the stream is then the visitor's.
async fn accept(dial: &Dial, service: &Service, uuid: &str, hello: &[u8]) -> Result<BoxIo, String> {
    let mut io = open(dial, service).await?;
    wire::send(&mut io, &ClientMessage::Accept(uuid.to_string())).await?;
    io.write_all(hello).await.map_err(|e| format!("the hello to a visitor: {e}"))?;
    io.flush().await.map_err(|e| format!("the hello to a visitor: {e}"))?;
    Ok(io)
}

/// Hold `registered` until its control connection ends: each `Connection`
/// taken on its own connection with `hello`, and given to `queue` as a
/// visitor. Returns why the connection ended.
pub async fn hold(
    registered: Registered,
    dial: Dial,
    service: Service,
    hello: Vec<u8>,
    queue: mpsc::Sender<Visitor>,
    say: Say,
) -> String {
    let Registered { mut control, port, .. } = registered;
    loop {
        let uuid = match heard(&mut control, SILENCE, "heartbeat").await {
            Ok(Some(ServerMessage::Connection(uuid))) => uuid,
            Ok(Some(ServerMessage::Heartbeat)) => continue,
            // bore's client warns of these and goes on.
            Ok(Some(ServerMessage::Hello(_) | ServerMessage::Challenge(_))) => continue,
            Ok(Some(ServerMessage::Error(words))) => {
                say(format!("{service} said: {}", words.chars().take(120).collect::<String>()));
                continue;
            }
            Ok(None) => return format!("{service} closed the control connection of the port {port}"),
            Err(why) => return why,
        };
        if wire::uuid_bytes(&uuid).is_none() {
            say(format!("{service} named a visitor by no UUID; it is passed over"));
            continue;
        }
        let (dial, service, hello) = (dial.clone(), service.clone(), hello.clone());
        let (queue, say) = (queue.clone(), say.clone());
        tokio::spawn(async move {
            match accept(&dial, &service, &uuid, &hello).await {
                Ok(stream) => {
                    let peer = format!("{service}:{port} (connection {uuid})");
                    // Too many visitors wait for the layer: this one is dropped.
                    if queue.try_send(Visitor { stream, peer }).is_err() {
                        say(format!("a visitor of the port {port} was dropped: too many wait for the layer"));
                    }
                }
                Err(why) => say(format!("a visitor of the port {port} was not taken: {why}")),
            }
        });
    }
}
