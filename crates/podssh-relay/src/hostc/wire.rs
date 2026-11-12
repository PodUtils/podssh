//! The frames of hostc's protocol (version 5, `packages/protocol/src/frame.ts`
//! and `messages.ts` of `akazwz/hostc` at `c19ff67`): each binary message on
//! the node's socket is `u8 type | u32 stream id (big endian) | payload`.
//! The stream ids are the server's, from 1; 0 is reserved. `OPEN` and
//! `HEAD` carry JSON, with headers as a list of `[name, value]` pairs; a
//! WebSocket's `END` is laid out as a close frame, `u16 code | reason`; a
//! `WINDOW` is a `u32` of bytes granted, never 0.

use serde::{Deserialize, Serialize};

/// The bytes before each payload.
pub const HEADER: usize = 5;

/// What a frame is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Server to node: a stream starts.
    Open = 1,
    /// Node to server: an answer's status and headers.
    Head = 2,
    /// An HTTP body's chunk, or a binary WebSocket message.
    Data = 3,
    /// A text WebSocket message.
    Text = 4,
    /// The end of one way.
    End = 5,
    /// The stream is aborted both ways.
    Reset = 6,
    /// Body bytes granted to the peer.
    Window = 7,
}

impl Kind {
    fn of(byte: u8) -> Option<Kind> {
        Some(match byte {
            1 => Kind::Open,
            2 => Kind::Head,
            3 => Kind::Data,
            4 => Kind::Text,
            5 => Kind::End,
            6 => Kind::Reset,
            7 => Kind::Window,
            _ => return None,
        })
    }
}

/// One frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: Kind,
    pub stream: u32,
    pub payload: Vec<u8>,
}

/// A frame's bytes. Stream 0 is never one of the server's, so the node
/// never names it either.
pub fn encode(kind: Kind, stream: u32, payload: &[u8]) -> Vec<u8> {
    debug_assert!(stream != 0, "stream 0 is reserved");
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.push(kind as u8);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

/// A frame of `bytes`, one binary message. A short one, an unknown type or
/// stream 0 breaks the protocol: the socket closes with `1002`.
pub fn decode(bytes: &[u8]) -> Result<Frame, String> {
    if bytes.len() < HEADER {
        return Err("a frame shorter than its header".into());
    }
    let kind = Kind::of(bytes[0]).ok_or_else(|| format!("a frame of the unknown type {}", bytes[0]))?;
    let stream = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
    if stream == 0 {
        return Err("a frame of the reserved stream 0".into());
    }
    Ok(Frame { kind, stream, payload: bytes[HEADER..].to_vec() })
}

/// The payload of `OPEN`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Open {
    pub method: String,
    /// The path and the query, from `/`.
    pub path: String,
    pub headers: Vec<(String, String)>,
    /// Whether `DATA` and an `END` of the request's body follow.
    pub body: bool,
    /// For a WebSocket: the subprotocols that the visitor offered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub websocket: Option<Vec<String>>,
}

impl Open {
    /// `OPEN`'s JSON, checked as the server's client checks it.
    pub fn parse(payload: &[u8]) -> Result<Open, String> {
        let open: Open = serde_json::from_slice(payload).map_err(|_| "an OPEN that is not its JSON".to_string())?;
        if !open.path.starts_with('/') {
            return Err("an OPEN whose path does not start with /".into());
        }
        Ok(open)
    }

    /// The value of the visitor's header `name`, the first of that name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// The payload of `HEAD`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Head {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    /// Whether `DATA` and an `END` of the answer's body follow.
    pub body: bool,
    /// The subprotocol that the node's side chose, for a 101 alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

impl Head {
    pub fn bytes(&self) -> Vec<u8> {
        // A struct of strings, numbers and booleans always serializes.
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// A WebSocket's `END`: `u16 code | UTF-8 reason`, the reason cut to the
/// 123 bytes of a close frame.
pub fn close(code: u16, reason: &str) -> Vec<u8> {
    let mut cut = reason.len().min(123);
    while !reason.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut bytes = code.to_be_bytes().to_vec();
    bytes.extend_from_slice(&reason.as_bytes()[..cut]);
    bytes
}

/// A `WINDOW`'s payload.
pub fn window(granted: u32) -> [u8; 4] {
    granted.to_be_bytes()
}

/// The bytes that a `WINDOW` grants: exactly four, never 0.
pub fn granted(payload: &[u8]) -> Result<u32, String> {
    let bytes: [u8; 4] = payload.try_into().map_err(|_| "a WINDOW that is not four bytes".to_string())?;
    match u32::from_be_bytes(bytes) {
        0 => Err("an empty WINDOW grant".into()),
        n => Ok(n),
    }
}

/// Whether an answer of `status` to `method` has a body (RFC 9110, section
/// 6.4.1), as the protocol's `responseHasBody` reads it.
pub fn has_body(method: &str, status: u16) -> bool {
    method != "HEAD" && status >= 200 && status != 204 && status != 205 && status != 304
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes as hostc's own `encodeFrame` makes them (`frame.ts`): the type,
    /// then the id in big endian, then the payload.
    #[test]
    fn a_frame_is_its_type_its_stream_and_its_payload() {
        let bytes = encode(Kind::Window, 0x0102_0304, &window(262_144));
        assert_eq!(bytes, [7, 1, 2, 3, 4, 0, 4, 0, 0]);
        let frame = decode(&bytes).unwrap();
        assert_eq!((frame.kind, frame.stream, granted(&frame.payload)), (Kind::Window, 0x0102_0304, Ok(262_144)));
        assert!(decode(&[3, 0, 0, 0]).is_err(), "short");
        assert!(decode(&[8, 0, 0, 0, 1]).is_err(), "type 8");
        assert!(decode(&[3, 0, 0, 0, 0]).is_err(), "stream 0");
        assert!(granted(&[0, 0, 0, 0]).is_err() && granted(&[1, 2, 3]).is_err());
    }

    /// An `OPEN` as hostc's server writes one (`JSON.stringify` of
    /// `OpenMessage`), and a `HEAD` as its client writes one.
    #[test]
    fn open_and_head_are_the_json_of_hostc_s_messages() {
        let payload = br#"{"method":"GET","path":"/?a=1","headers":[["host","x.hostc.test"],["upgrade","websocket"]],"body":false,"websocket":["chat"]}"#;
        let open = Open::parse(payload).unwrap();
        assert_eq!(open.websocket.as_deref(), Some(&["chat".to_string()][..]));
        assert_eq!(open.header("Host"), Some("x.hostc.test"));
        let plain = Open::parse(br#"{"method":"POST","path":"/v1/mint","headers":[],"body":true}"#).unwrap();
        assert!(plain.body && plain.websocket.is_none());
        for bad in [&br#"{"method":"GET","path":"x","headers":[],"body":false}"#[..], b"[]", b"{}"] {
            assert!(Open::parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let head = Head { status: 101, headers: vec![("x-a".into(), "1".into())], body: false, protocol: None };
        assert_eq!(String::from_utf8(head.bytes()).unwrap(), r#"{"status":101,"headers":[["x-a","1"]],"body":false}"#);
    }

    #[test]
    fn a_close_is_a_code_and_a_reason_cut_on_a_character() {
        assert_eq!(close(1000, "ok"), [3, 232, b'o', b'k']);
        let long = "é".repeat(100);
        let bytes = close(1013, &long);
        assert!(bytes.len() <= 125 && std::str::from_utf8(&bytes[2..]).is_ok());
        assert!(!has_body("HEAD", 200) && !has_body("GET", 204) && has_body("GET", 200) && !has_body("GET", 101));
    }
}
