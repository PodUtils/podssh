//! croc's frames over the bridge's WebSocket. A frame is `croc`, a 4-byte
//! little-endian length and the body (schollz/croc:src/comm/comm.go at
//! v11.6.4); the bridge copies bytes between its WebSocket and the relay's
//! TCP connection with no regard for where a message ends
//! (src/webrelay/webrelay.go, `websocket.NetConn`), so frames are read from
//! the bytes of the messages as they come, and sent one in each message.

use podssh_ws::session::close_code_and_reason;
use podssh_ws::{frame as ws, RelaySession, SessionError};
use tokio::io::{AsyncRead, AsyncWrite};

/// The first bytes of each frame.
pub const MAGIC: &[u8; 4] = b"croc";
/// The header: the magic and the length.
pub const HEADER: usize = 8;
/// The longest frame that the handshake and the meeting read: their frames
/// are small, and a longer one is a peer that is not podssh's or croc's.
pub const FRAME_MOST: usize = 64 * 1024;

/// `body` as one frame.
pub fn encode(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER + body.len());
    out.extend_from_slice(MAGIC);
    // The handshake's frames are far below 4 GiB.
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// The first frame of `bytes`, taken off them: `Ok(None)` while it has not
/// all come; an error for bytes that are not a frame, or one past `most`.
pub fn take(bytes: &mut Vec<u8>, most: usize) -> Result<Option<Vec<u8>>, String> {
    let seen = bytes.len().min(MAGIC.len());
    if bytes[..seen] != MAGIC[..seen] {
        return Err("bytes that are not croc's frame".into());
    }
    let Some(header) = bytes.get(..HEADER) else { return Ok(None) };
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > most {
        return Err(format!("a frame of {length} bytes, past {most}"));
    }
    if bytes.len() < HEADER + length {
        return Ok(None);
    }
    let body = bytes[HEADER..HEADER + length].to_vec();
    bytes.drain(..HEADER + length);
    Ok(Some(body))
}

/// Why the wire gave no frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cut {
    /// The bridge or the relay ended the connection: a waiting room that the
    /// relay dropped (its 3 h, or its 128 rooms), or a limit of its own.
    Dropped(String),
    /// Bytes that are not croc's, or a failure of the connection.
    Broken(String),
}

impl std::fmt::Display for Cut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Cut::Dropped(why) | Cut::Broken(why) => f.write_str(why),
        }
    }
}

/// The bridge's WebSocket, and the bytes that came on it and are not read.
pub struct Wire<'s, S> {
    session: &'s RelaySession<S>,
    bytes: Vec<u8>,
}

impl<'s, S> Wire<'s, S>
where
    S: AsyncRead + AsyncWrite + Send,
{
    pub fn new(session: &'s RelaySession<S>) -> Wire<'s, S> {
        Wire { session, bytes: Vec::new() }
    }

    /// `body` as one frame, in one message.
    pub async fn send(&self, body: &[u8]) -> Result<(), Cut> {
        self.session.send_binary(&encode(body)).await.map_err(|e| Cut::Broken(e.to_string()))
    }

    /// The next frame, of `most` bytes at most.
    pub async fn frame(&mut self, most: usize) -> Result<Vec<u8>, Cut> {
        loop {
            if let Some(body) = take(&mut self.bytes, most).map_err(Cut::Broken)? {
                return Ok(body);
            }
            self.more().await?;
        }
    }

    /// The bytes that came after the last frame read: the first of a link.
    pub fn rest(self) -> Vec<u8> {
        self.bytes
    }

    /// The next message's bytes; the connection pinged meanwhile, so that a
    /// dead one is found while this end waits in a room.
    async fn more(&mut self) -> Result<(), Cut> {
        let session = self.session;
        let liveness = session.watch_liveness(podssh_ws::LIVENESS_EVERY, podssh_ws::LIVENESS_ALLOWED);
        let read = tokio::select! {
            read = session.read_frame() => read,
            dead = liveness => return Err(Cut::Broken(dead.to_string())),
        };
        let f = match read {
            Ok(f) => f,
            Err(SessionError::ClosedWithoutClose(why)) => return Err(Cut::Dropped(why)),
            Err(e) => return Err(Cut::Broken(e.to_string())),
        };
        match f.opcode {
            ws::OPCODE_BINARY | ws::OPCODE_TEXT => {
                self.bytes.extend_from_slice(&f.payload);
                Ok(())
            }
            ws::OPCODE_CLOSE => {
                let (code, reason) = close_code_and_reason(&f.payload);
                let code = code.map_or_else(|| "no code".to_string(), |c| c.to_string());
                let reason = match reason.is_empty() {
                    true => String::new(),
                    false => format!(" {}", podssh_ws::text::one_line(&reason)),
                };
                Err(Cut::Dropped(format!("a Close ({code}{reason})")))
            }
            other => Err(Cut::Broken(format!("an unexpected frame (opcode {other:#x})"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_croc_its_length_in_little_endian_and_its_body() {
        assert_eq!(encode(b"ping"), b"croc\x04\x00\x00\x00ping".to_vec());
        assert_eq!(encode(&[1]), b"croc\x01\x00\x00\x00\x01".to_vec());
    }

    #[test]
    fn frames_come_out_whole_whatever_the_messages_cut() {
        let stream = [encode(&[1]), encode(b"hello"), b"raw".to_vec()].concat();
        let mut bytes = Vec::new();
        let mut got = Vec::new();
        for byte in &stream[..stream.len() - 3] {
            bytes.push(*byte);
            if let Some(body) = take(&mut bytes, FRAME_MOST).unwrap() {
                got.push(body);
            }
        }
        assert_eq!(got, vec![vec![1], b"hello".to_vec()]);
        bytes.extend_from_slice(b"raw");
        assert_eq!(bytes, b"raw".to_vec(), "what follows the frames stays");
    }

    #[test]
    fn bytes_that_are_not_a_frame_or_a_frame_too_long_are_refused() {
        assert!(take(&mut b"cro".to_vec(), FRAME_MOST).unwrap().is_none());
        assert!(take(&mut b"SSH-2.0-".to_vec(), FRAME_MOST).is_err());
        assert!(take(&mut b"xr".to_vec(), FRAME_MOST).is_err());
        let mut long = encode(&[0; 100]);
        assert!(take(&mut long, 99).unwrap_err().contains("past 99"));
    }
}
