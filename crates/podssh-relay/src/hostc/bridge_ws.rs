//! A stream of a visitor's WebSocket (`WebSocketStream` of hostc's client,
//! `streams.ts` at `c19ff67`), bridged to the pipe: the upgrade's request,
//! with a key of this side's own as the protocol makes each side's
//! handshake headers on its own; the pipe's 101 as `HEAD` with the chosen
//! subprotocol, or its refusal as `HEAD` and the end; then each message both
//! ways. Toward the pipe the bridge is the WebSocket's client, so its frames
//! go masked; the pipe's are the server's, unmasked. A message of the pipe
//! is read only once the one before it went to the socket's writer, so a
//! socket that does not take them holds the node's side back. A binary
//! message longer than hostc passes whole is sent in parts of
//! [`MAX_MESSAGE`]: the node's link carries a stream of bytes, whose
//! messages' edges mean nothing (T-742's Decision); a text one so long
//! closes with `1009`, as hostc's server closes it.

use podssh_ws::frame::{self, Frame, Role};
use podssh_ws::handshake;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use super::bridge::{In, Parts};
use super::wire::{self, Head, Kind};
use super::MAX_MESSAGE;
use crate::quick::origin::{self, Asked, BodyHead};

/// The headers of the handshake that each side makes on its own.
const HANDSHAKE: &[&str] = &[
    "sec-websocket-key",
    "sec-websocket-extensions",
    "sec-websocket-accept",
    "sec-websocket-protocol",
    "sec-websocket-version",
];
/// The headers of a 101 that the server makes itself.
const SWITCHED: &[&str] = &["connection", "upgrade", "sec-websocket-accept", "sec-websocket-extensions"];
/// The largest frame read from the pipe.
const READ_CAP: usize = 16 * 1024 * 1024;

/// The WebSocket of `parts`, bridged until it ends.
pub(super) async fn run(mut parts: Parts) {
    let key = match handshake::generate_key() {
        Ok(key) => key,
        Err(e) => return parts.reset(&format!("a key of the upgrade: {e}")).await,
    };
    let open = &parts.open;
    let mut headers: Vec<(String, String)> =
        open.headers.iter().filter(|(n, _)| !HANDSHAKE.contains(&n.to_ascii_lowercase().as_str())).cloned().collect();
    headers.push(("Sec-WebSocket-Key".into(), key.clone()));
    let offered = open.websocket.clone().unwrap_or_default();
    if !offered.is_empty() {
        headers.push(("Sec-WebSocket-Protocol".into(), offered.join(", ")));
    }
    let host = open.header("host").unwrap_or(&parts.name).to_string();
    let asked = Asked { method: "GET".into(), target: open.path.clone(), host, headers, websocket: true };
    let head = match asked.head_with(BodyHead::Length(0)) {
        Ok(head) => head,
        Err(why) => return parts.reset(&format!("the upgrade: {why}")).await,
    };
    let pipe = std::mem::replace(&mut parts.pipe, tokio::io::duplex(1).0);
    let (mut from_pipe, mut to_pipe) = tokio::io::split(pipe);
    if to_pipe.write_all(&head).await.is_err() {
        return parts.reset("the node took no upgrade").await;
    }
    let read = tokio::time::timeout(origin::ANSWER_WAIT, origin::read_answer(&mut from_pipe)).await;
    let (answer, rest) = match read {
        Ok(Ok(read)) => read,
        Ok(Err(why)) => return parts.reset(&why).await,
        Err(_) => return parts.reset("no answer of the node to the upgrade within its time").await,
    };
    let kept = |set: &[&str]| -> Vec<(String, String)> {
        answer.headers.iter().filter(|(n, _)| !set.contains(&n.as_str())).cloned().collect()
    };
    if !answer.switched() {
        // A refusal passes to the visitor, with no body (as hostc's client).
        let headers = kept(&["content-length", "transfer-encoding", "connection", "keep-alive", "upgrade"]);
        let refused = Head { status: answer.status, headers, body: false, protocol: None };
        parts.send(Kind::Head, &refused.bytes()).await;
        return;
    }
    let protocol = answer.headers.iter().find(|(n, _)| n == "sec-websocket-protocol").map(|(_, v)| v.clone());
    if protocol.as_ref().is_some_and(|p| !offered.contains(p)) {
        return parts.reset("the node chose a subprotocol that the visitor did not offer").await;
    }
    let switched = Head { status: 101, headers: kept(SWITCHED), body: false, protocol };
    if !parts.send(Kind::Head, &switched.bytes()).await {
        return;
    }
    let mut from = std::mem::replace(&mut parts.from, mpsc::unbounded_channel().1);
    // The pipe's pings, answered by the writer of the pipe.
    let (pongs, mut pongs_due) = mpsc::channel::<Vec<u8>>(4);
    let inbound = async {
        loop {
            let (opcode, payload, last) = tokio::select! {
                given = from.recv() => match given {
                    Some(In::Data(bytes)) => (frame::OPCODE_BINARY, bytes, false),
                    Some(In::Text(bytes)) => (frame::OPCODE_TEXT, bytes, false),
                    // The visitor's close, laid out as a close frame already.
                    Some(In::End(payload)) => (frame::OPCODE_CLOSE, close_of(payload), true),
                    Some(In::Window(_)) => continue,
                    Some(In::Reset) | None => return,
                },
                Some(payload) = pongs_due.recv() => (frame::OPCODE_PONG, payload, false),
            };
            let taken = if opcode == frame::OPCODE_BINARY || opcode == frame::OPCODE_TEXT { payload.len() } else { 0 };
            let encoded = frame::encode(&Frame { fin: true, opcode, payload }, Role::Client, rand::random());
            if to_pipe.write_all(&encoded).await.is_err() {
                return;
            }
            parts.taken(taken);
            if last {
                // The node's own close comes back on the pipe, which ends it.
                let _ = to_pipe.flush().await;
                std::future::pending::<()>().await;
            }
        }
    };
    let outbound = async {
        let (mut buf, mut chunk) = (rest, vec![0u8; 64 * 1024]);
        let mut partial: Option<(u8, Vec<u8>)> = None;
        loop {
            let decoded = match frame::decode_capped(&buf, Role::Server, READ_CAP) {
                Ok(decoded) => decoded,
                Err(e) => return wire::close(1002, &format!("the node's frame: {e}")),
            };
            let Some((f, used)) = decoded else {
                match from_pipe.read(&mut chunk).await {
                    Ok(0) | Err(_) => return wire::close(1001, "the node's side ended"),
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
                continue;
            };
            buf.drain(..used);
            match f.opcode {
                frame::OPCODE_PING => {
                    let _ = pongs.try_send(f.payload);
                }
                frame::OPCODE_PONG => {}
                frame::OPCODE_CLOSE => return f.payload,
                opcode => {
                    let (opcode, mut bytes) = match (opcode, partial.take()) {
                        (frame::OPCODE_CONTINUATION, Some((first, mut held))) => {
                            held.extend_from_slice(&f.payload);
                            (first, held)
                        }
                        (frame::OPCODE_CONTINUATION, None) => return wire::close(1002, "a continuation of nothing"),
                        (opcode, _) => (opcode, f.payload),
                    };
                    if opcode == frame::OPCODE_TEXT && bytes.len() > MAX_MESSAGE {
                        return wire::close(1009, "a text message longer than hostc passes");
                    }
                    if !f.fin {
                        // A binary message in parts may go in parts too.
                        if opcode == frame::OPCODE_BINARY && bytes.len() >= MAX_MESSAGE {
                            let rest = bytes.split_off(MAX_MESSAGE);
                            if !parts.send(Kind::Data, &bytes).await {
                                return Vec::new();
                            }
                            bytes = rest;
                        }
                        partial = Some((opcode, bytes));
                        continue;
                    }
                    let kind = if opcode == frame::OPCODE_TEXT { Kind::Text } else { Kind::Data };
                    for piece in pieces(&bytes) {
                        if !parts.send(kind, piece).await {
                            return Vec::new();
                        }
                    }
                }
            }
        }
    };
    tokio::select! {
        () = inbound => {}
        end = outbound => {
            parts.send(Kind::End, &end).await;
        }
    }
}

/// A message's bytes in parts of [`MAX_MESSAGE`] at most; one empty part
/// for an empty message.
pub(super) fn pieces(bytes: &[u8]) -> Vec<&[u8]> {
    match bytes.is_empty() {
        true => vec![bytes],
        false => bytes.chunks(MAX_MESSAGE).collect(),
    }
}

/// The close frame's payload of an `END`: its code and reason, or none.
fn close_of(payload: Vec<u8>) -> Vec<u8> {
    match payload.len() {
        0 | 1 => Vec::new(),
        _ => payload,
    }
}

#[cfg(test)]
#[path = "bridge_ws_tests.rs"]
mod tests;
