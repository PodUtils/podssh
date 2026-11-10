//! A stand-in of croc's relay and of croc-web's bridge, in the test's own
//! process on the loopback, for the tests of croc's relay road (T-694),
//! each written from croc's source at v11.6.4 (read on 2026-11-10):
//!
//! - the relay (schollz/croc:src/tcp/tcp.go, `clientHandshake`,
//!   `clientCommunication`, `admitToRoom`): a first frame of `ping` is
//!   answered `pong`; else the PAKE as party B, the salt, the password
//!   (`bad password` and the end, for another), `ok|||ADDRESS`, the room;
//!   a new room is `ok` and its member gets a frame of the byte 1 at each
//!   tick while it waits; the second member gets `ok`, then both are piped
//!   until either ends, and the room goes; a third gets `room full`;
//! - the bridge (src/webrelay/webrelay.go, `websocket`): `GET /ws` with
//!   `relay` an index of its relays and `port` in 9009 to 9017, else 403; a
//!   relay that does not answer, 502; an `Origin` of another host, 403, as
//!   coder/websocket's `Accept` refuses one; then each binary message's
//!   bytes to the relay and the relay's bytes back in binary messages.
//!
//! Its PAKE and crypt are podssh's (`podssh_relay::croc`), whose vectors
//! the unit tests hold; the run against croc's own `croc relay` and
//! `croc-web` is T-694's harness (UNVERIFIED until it runs).

// Each test binary uses a part of it.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use podssh_relay::croc::{crypt, pake, wire};
use podssh_relay::session::OsEntropy;
use podssh_ws::http::request::{read_request, refusal};
use podssh_ws::url::WsUrl;
use podssh_ws::{frame, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// A room: whether its second member came, and how the first gets it.
struct Room {
    full: bool,
    second: Option<oneshot::Sender<TcpStream>>,
}

type Rooms = Arc<Mutex<HashMap<String, Room>>>;

/// croc's relay, listening on the loopback.
pub struct Relay {
    pub addr: SocketAddr,
    rooms: Rooms,
    task: JoinHandle<()>,
}

impl Relay {
    /// The relay with `password`, whose waiting members get a frame at each
    /// `tick` (croc's is 1 s).
    pub async fn start(password: &str, tick: Duration) -> Relay {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
        let addr = listener.local_addr().unwrap();
        let rooms: Rooms = Arc::default();
        let (password, kept) = (password.to_string(), rooms.clone());
        let task = tokio::spawn(async move {
            while let Ok((tcp, peer)) = listener.accept().await {
                tokio::spawn(member(tcp, peer, kept.clone(), password.clone(), tick));
            }
        });
        Relay { addr, rooms, task }
    }

    /// The rooms open now.
    pub fn rooms(&self) -> usize {
        self.rooms.lock().unwrap().len()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn read_frame(tcp: &mut TcpStream, most: usize) -> Option<Vec<u8>> {
    let mut header = [0u8; wire::HEADER];
    tcp.read_exact(&mut header).await.ok()?;
    if &header[..4] != wire::MAGIC {
        return None;
    }
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > most {
        return None;
    }
    let mut body = vec![0u8; length];
    tcp.read_exact(&mut body).await.ok()?;
    Some(body)
}

async fn send(tcp: &mut TcpStream, body: &[u8]) -> Option<()> {
    tcp.write_all(&wire::encode(body)).await.ok()
}

async fn sealed(tcp: &mut TcpStream, key: &[u8; 32], text: &str) -> Option<()> {
    send(tcp, &crypt::seal(key, text.as_bytes(), &mut OsEntropy).ok()?).await
}

/// A refusal, then a graceful end: the write half shut, and the peer's bytes
/// read to their end, within 2 s. A drop with unread input is a reset on
/// Windows, and a reset there discards the refusal that the bridge had not
/// read yet, so the client saw "forcibly closed" in place of croc's words.
async fn refused(tcp: &mut TcpStream, key: &[u8; 32], text: &str) -> Option<()> {
    sealed(tcp, key, text).await?;
    let _ = tcp.shutdown().await;
    let mut sink = [0u8; 4096];
    let drain = async { while matches!(tcp.read(&mut sink).await, Ok(n) if n > 0) {} };
    let _ = tokio::time::timeout(Duration::from_secs(2), drain).await;
    None
}

/// One member, as tcp.go serves a connection.
async fn member(mut tcp: TcpStream, peer: SocketAddr, rooms: Rooms, password: String, tick: Duration) -> Option<()> {
    let first = read_frame(&mut tcp, 64 * 1024).await?;
    if first == b"ping" {
        return send(&mut tcp, b"pong").await;
    }
    let mut b = pake::Pake::new(pake::WEAK_KEY, 1, &mut OsEntropy).ok()?;
    b.update(&first).ok()?;
    send(&mut tcp, &b.bytes()).await?;
    let salt = read_frame(&mut tcp, 64).await?;
    let key = crypt::key(&b.session_key()?[..], &salt);
    let given = crypt::open(&key, &read_frame(&mut tcp, 4096).await?)?;
    if String::from_utf8_lossy(&given).trim() != password.trim() {
        return refused(&mut tcp, &key, "bad password").await;
    }
    sealed(&mut tcp, &key, &format!("ok|||{peer}")).await?;
    let room = String::from_utf8(crypt::open(&key, &read_frame(&mut tcp, 1024).await?)?).ok()?;
    // admitToRoom: join a waiting room, refuse a full one, or make one.
    let joined = {
        let mut map = rooms.lock().unwrap();
        match map.get_mut(&room) {
            Some(open) if open.full => Joined::Full,
            Some(open) => {
                open.full = true;
                Joined::Second(open.second.take())
            }
            None => {
                let (tx, rx) = oneshot::channel();
                map.insert(room.clone(), Room { full: false, second: Some(tx) });
                Joined::Made(rx)
            }
        }
    };
    match joined {
        Joined::Full => refused(&mut tcp, &key, "room full").await,
        Joined::Made(second) => {
            if sealed(&mut tcp, &key, "ok").await.is_none() {
                rooms.lock().unwrap().remove(&room);
                return None;
            }
            wait(tcp, second, &rooms, &room, tick).await
        }
        Joined::Second(first) => {
            // The admission first, then the pipe, as tcp.go orders them.
            sealed(&mut tcp, &key, "ok").await?;
            first?.send(tcp).ok()
        }
    }
}

/// What a member found in the room's place.
enum Joined {
    /// A new room, whose second member comes on this channel.
    Made(oneshot::Receiver<TcpStream>),
    /// A room that waited, and how its first member gets this one.
    Second(Option<oneshot::Sender<TcpStream>>),
    Full,
}

/// The first member's wait: the byte 1 at each tick, until the second came;
/// then the pipe, and the room goes when it ends.
async fn wait(
    mut tcp: TcpStream,
    mut second: oneshot::Receiver<TcpStream>,
    rooms: &Rooms,
    room: &str,
    tick: Duration,
) -> Option<()> {
    let mut ticks = tokio::time::interval(tick);
    let joined = loop {
        tokio::select! {
            joined = &mut second => break joined.ok(),
            _ = ticks.tick() => {
                if send(&mut tcp, &[1]).await.is_none() {
                    break None;
                }
            }
        }
    };
    if let Some(mut other) = joined {
        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut other).await;
    }
    rooms.lock().unwrap().remove(room);
    Some(())
}

/// croc-web's bridge, listening on the loopback, to `relays` by index.
pub struct Bridge {
    pub url: WsUrl,
    task: JoinHandle<()>,
}

impl Bridge {
    pub async fn start(relays: Vec<SocketAddr>) -> Bridge {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a port of the loopback");
        let port = listener.local_addr().unwrap().port();
        let relays = Arc::new(relays);
        let task = tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                tokio::spawn(visitor(tcp, relays.clone()));
            }
        });
        Bridge { url: WsUrl::parse(&format!("ws://127.0.0.1:{port}/ws")).unwrap(), task }
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The value of `name` in a query.
fn query<'q>(target: &'q str, name: &str) -> Option<&'q str> {
    let (_, query) = target.split_once('?')?;
    query.split('&').find_map(|pair| pair.strip_prefix(name)?.strip_prefix('='))
}

async fn visitor(mut tcp: TcpStream, relays: Arc<Vec<SocketAddr>>) -> Option<()> {
    let (head, pending) = read_request(&mut tcp, Vec::new()).await.ok()?;
    let refuse = |status: u16, words: &str| refusal(status, words, &[]);
    if head.target.split('?').next() != Some("/ws") {
        return tcp.write_all(&refuse(404, "not found")).await.ok();
    }
    let index = query(&head.target, "relay").and_then(|n| n.trim().parse::<usize>().ok()).filter(|i| *i < relays.len());
    let Some(index) = index else {
        return tcp.write_all(&refuse(403, "relay index is not allowed")).await.ok();
    };
    let port = query(&head.target, "port").and_then(|p| p.trim().parse::<u16>().ok());
    if !port.is_some_and(|p| (9009..=9017).contains(&p)) {
        return tcp.write_all(&refuse(403, "relay port is not allowed")).await.ok();
    }
    // coder/websocket takes no Origin but the request's own host; podssh's
    // client sends none.
    if head.header("origin").is_some_and(|origin| !origin.ends_with(head.header("host").unwrap_or("\u{0}"))) {
        return tcp.write_all(&refuse(403, "origin not allowed")).await.ok();
    }
    // The stand-in's relays listen where the loopback put them: the port
    // that the query names is checked, then each index is its relay.
    let Ok(upstream) = TcpStream::connect(relays[index]).await else {
        return tcp.write_all(&refuse(502, "relay is unavailable")).await.ok();
    };
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return tcp.write_all(&refused.answer()).await.ok(),
    };
    tcp.write_all(&server::switching(&key)).await.ok()?;
    let session = Arc::new(server::session(tcp, pending, None));
    let (mut from_relay, mut to_relay) = upstream.into_split();
    let up = {
        let session = session.clone();
        async move {
            while let Ok(f) = session.read_frame().await {
                match f.opcode {
                    frame::OPCODE_BINARY | frame::OPCODE_TEXT => {
                        if to_relay.write_all(&f.payload).await.is_err() {
                            break;
                        }
                    }
                    frame::OPCODE_CLOSE => break,
                    _ => {}
                }
            }
            let _ = to_relay.shutdown().await;
        }
    };
    let down = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from_relay.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session.send_binary(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = session.send_close(1000, "").await;
    };
    // Either end's close ends both, as the bridge's copies do.
    tokio::select! {
        () = up => {}
        () = down => {}
    }
    let _ = session.send_close(1000, "").await;
    Some(())
}
