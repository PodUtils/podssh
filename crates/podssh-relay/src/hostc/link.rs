//! One socket of the node's tunnel (`packages/client/src/connection.ts` of
//! `akazwz/hostc` at `c19ff67`): the node is the WebSocket's client, so its
//! frames go masked, one message each, never in parts. A writer task owns
//! the socket's sending half and takes [`Out`] from each stream in turn; the
//! reader decodes each message, answers the server's pings, and gives each
//! frame to its stream ([`super::bridge`]). Any message proves the socket
//! alive: the pong of `hostc:ping` may wait behind a window of data, so the
//! socket is dead only when nothing at all came within 10 s of a ping.
//!
//! A frame that breaks the protocol (a short one, an `OPEN` of a stream
//! that is open, more body than the window that the node granted) closes
//! the socket with `1002`, as hostc's client does; a frame of a stream that
//! ended is let go. A stop closes it with `4000`, which frees the tunnel at
//! once.

use std::collections::HashMap;
use std::time::Duration;

use podssh_ws::client::{next_event_capped, Event};
use podssh_ws::frame::{self, Frame as WsFrame, Role};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;

use super::bridge::{self, Given, Stream};
use super::wire::{self, Kind};
use super::{HEARTBEAT, HEARTBEAT_WAIT, MAX_MESSAGE, MAX_STREAMS, PING, PONG};
use crate::opentunnel::dial::BoxIo;
use crate::pinggy::far::Visitor;

/// The largest message read: a whole WebSocket message, its header, and
/// room for the server's own framing.
pub const READ_CAP: usize = MAX_MESSAGE + wire::HEADER + 1024;
/// The messages that wait for the writer, from all the streams.
pub const OUTBOX: usize = 32;
/// The close code of a stop, which frees the tunnel at once.
pub const CLOSE_SHUTDOWN: u16 = 4000;
/// The close code of a broken protocol.
pub const CLOSE_PROTOCOL: u16 = 1002;

/// What goes on the socket.
#[derive(Debug)]
pub enum Out {
    /// A binary message: one frame of the protocol.
    Frame(Vec<u8>),
    /// The heartbeat.
    Ping,
    /// The answer to the server's ping of the WebSocket.
    Pong(Vec<u8>),
    /// The close, then the end of the sending half.
    Close(u16, String),
}

/// Where each stream sends its frames.
pub type Outbox = mpsc::Sender<Out>;

/// The heartbeat's two times: hostc's, or a test's shorter ones.
#[derive(Debug, Clone, Copy)]
pub struct Beat {
    pub every: Duration,
    pub wait: Duration,
}

impl Default for Beat {
    fn default() -> Beat {
        Beat { every: HEARTBEAT, wait: HEARTBEAT_WAIT }
    }
}

/// How a socket ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The node stopped: the tunnel is freed.
    Stopped,
    /// The socket dropped, or the server closed it: the tunnel waits for
    /// another socket for 10 minutes.
    Dropped(String),
    /// The node closed it for a broken protocol.
    Protocol(String),
}

/// Serve the socket `io`, whose first bytes past the 101 are `pending`,
/// until it ends: each stream's pipe goes to `visitors`; the tunnel's name
/// is `name`, the `Host` of a request that names none.
pub async fn serve(
    io: BoxIo,
    pending: Vec<u8>,
    name: String,
    visitors: mpsc::Sender<Visitor>,
    beat: Beat,
    mut stopped: watch::Receiver<bool>,
) -> Ended {
    let (mut from, mut to) = tokio::io::split(io);
    let (outbox, mut queue) = mpsc::channel::<Out>(OUTBOX);
    // The writer: each message masked with a key of its own (RFC 6455, 5.3).
    let writer = tokio::spawn(async move {
        while let Some(out) = queue.recv().await {
            let (opcode, payload, last) = match out {
                Out::Frame(bytes) => (frame::OPCODE_BINARY, bytes, false),
                Out::Ping => (frame::OPCODE_TEXT, PING.as_bytes().to_vec(), false),
                Out::Pong(payload) => (frame::OPCODE_PONG, payload, false),
                Out::Close(code, reason) => (frame::OPCODE_CLOSE, wire::close(code, &reason), true),
            };
            let encoded = frame::encode(&WsFrame { fin: true, opcode, payload }, Role::Client, rand::random());
            if to.write_all(&encoded).await.is_err() {
                return;
            }
            if last {
                let _ = to.shutdown().await;
                return;
            }
        }
    });
    let (done, mut ended_rx) = mpsc::unbounded_channel::<u32>();
    let mut streams: HashMap<u32, Stream> = HashMap::new();
    let (mut buf, mut chunk) = (pending, vec![0u8; 64 * 1024]);
    // A message in parts, where the server sends one so.
    let mut partial: Option<(u8, Vec<u8>)> = None;
    let mut ticks = tokio::time::interval_at(Instant::now() + beat.every, beat.every);
    let mut deadline: Option<Instant> = None;
    let ended = 'socket: loop {
        // Each whole event in the buffer first: one read can carry several.
        loop {
            let event = match next_event_capped(&mut buf, READ_CAP) {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(e) => break 'socket protocol(&outbox, format!("the socket's frame: {e}")).await,
            };
            deadline = None;
            let message = match event {
                Event::Pong(payload) => {
                    let _ = outbox.send(Out::Pong(payload)).await;
                    continue;
                }
                Event::Frame(f) if f.opcode == frame::OPCODE_CLOSE => {
                    break 'socket Ended::Dropped(closed_words(&f.payload));
                }
                Event::Frame(f) => match whole(&mut partial, f) {
                    Some(message) => message,
                    None => continue,
                },
            };
            match message {
                (frame::OPCODE_TEXT, text) if text == PONG.as_bytes() => {}
                (frame::OPCODE_TEXT, _) => {
                    break 'socket protocol(&outbox, "a text message other than the pong".into()).await
                }
                (_, bytes) => {
                    let given = given(&bytes, &name, &outbox, &visitors, &done, &mut streams).await;
                    if let Err(why) = given {
                        break 'socket protocol(&outbox, why).await;
                    }
                }
            }
        }
        let wait_for = deadline.unwrap_or_else(|| Instant::now() + Duration::from_secs(86_400));
        tokio::select! {
            read = from.read(&mut chunk) => match read {
                Ok(0) => break Ended::Dropped("the server ended the socket".into()),
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => break Ended::Dropped(format!("the socket: {e}")),
            },
            _ = ticks.tick() => {
                let _ = outbox.send(Out::Ping).await;
                deadline.get_or_insert(Instant::now() + beat.wait);
            }
            () = tokio::time::sleep_until(wait_for), if deadline.is_some() => {
                break Ended::Dropped(format!("nothing came within {} s of a ping", beat.wait.as_secs()));
            }
            Some(id) = ended_rx.recv() => {
                streams.remove(&id);
            }
            () = stop_of(&mut stopped) => {
                let _ = outbox.send(Out::Close(CLOSE_SHUTDOWN, "the node stopped".into())).await;
                break Ended::Stopped;
            }
        }
    };
    // Each stream ends with its socket: none survives a drop (the protocol's
    // rule); the layer above carries a session to the next socket.
    streams.clear();
    drop(outbox);
    let _ = tokio::time::timeout(Duration::from_secs(1), writer).await;
    ended
}

/// The close's words, for a line.
fn closed_words(payload: &[u8]) -> String {
    match payload {
        [high, low, reason @ ..] => {
            let code = u16::from_be_bytes([*high, *low]);
            let words = match code {
                4001 => " (a newer socket of the same tunnel replaced it)".to_string(),
                _ => String::new(),
            };
            format!("the server closed the socket with {code}{words}: {}", String::from_utf8_lossy(reason))
        }
        _ => "the server closed the socket".into(),
    }
}

/// Close the socket for a broken protocol, and say why.
async fn protocol(outbox: &Outbox, why: String) -> Ended {
    let _ = outbox.send(Out::Close(CLOSE_PROTOCOL, why.clone())).await;
    Ended::Protocol(why)
}

/// A whole message, once its last part came: its opcode and its bytes.
fn whole(partial: &mut Option<(u8, Vec<u8>)>, f: WsFrame) -> Option<(u8, Vec<u8>)> {
    match (f.opcode, partial.take()) {
        (frame::OPCODE_CONTINUATION, Some((opcode, mut bytes))) => {
            bytes.extend_from_slice(&f.payload);
            match f.fin {
                true => Some((opcode, bytes)),
                false => {
                    *partial = Some((opcode, bytes));
                    None
                }
            }
        }
        (frame::OPCODE_CONTINUATION, None) => None,
        (opcode, _) if !f.fin => {
            *partial = Some((opcode, f.payload));
            None
        }
        (opcode, _) => Some((opcode, f.payload)),
    }
}

/// One frame of the protocol, given to its stream; `Err` for a broken
/// protocol, which ends the socket.
async fn given(
    bytes: &[u8],
    name: &str,
    outbox: &Outbox,
    visitors: &mpsc::Sender<Visitor>,
    done: &mpsc::UnboundedSender<u32>,
    streams: &mut HashMap<u32, Stream>,
) -> Result<(), String> {
    let f = wire::decode(bytes)?;
    if f.kind == Kind::Open {
        if streams.contains_key(&f.stream) {
            return Err(format!("an OPEN of the open stream {}", f.stream));
        }
        let open = wire::Open::parse(&f.payload)?;
        // The server's own bound; a stream past it is refused alone.
        if streams.len() >= MAX_STREAMS {
            let words = format!("the node holds {MAX_STREAMS} streams");
            let _ = outbox.send(Out::Frame(wire::encode(Kind::Reset, f.stream, words.as_bytes()))).await;
            return Ok(());
        }
        match bridge::start(f.stream, open, name, outbox.clone(), visitors, done.clone()) {
            Ok(stream) => {
                streams.insert(f.stream, stream);
            }
            Err(why) => {
                let _ = outbox.send(Out::Frame(wire::encode(Kind::Reset, f.stream, why.as_bytes()))).await;
            }
        }
        return Ok(());
    }
    if f.kind == Kind::Head {
        return Err("a HEAD from the server".into());
    }
    let Some(stream) = streams.get(&f.stream) else { return Ok(()) };
    match stream.give(f.kind, f.payload)? {
        Given::Taken => {}
        Given::Ended => {
            streams.remove(&f.stream);
        }
        Given::Overflow(id) => {
            // A WebSocket that the role does not read: its visitor gets 1013,
            // and the other streams go on, as hostc's client does.
            let end = wire::close(1013, "the node is not reading");
            let _ = outbox.send(Out::Frame(wire::encode(Kind::End, id, &end))).await;
            streams.remove(&id);
        }
    }
    Ok(())
}

/// The node's stop: its guard of the value is dropped here, so that a
/// `select!` that waits on it stays `Send`; a sender gone is no stop.
pub(super) async fn stop_of(stopped: &mut tokio::sync::watch::Receiver<bool>) {
    if stopped.wait_for(|stop| *stop).await.is_err() {
        std::future::pending::<()>().await;
    }
}

#[cfg(test)]
#[path = "link_tests.rs"]
mod tests;
