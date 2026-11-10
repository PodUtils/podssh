//! bore's messages, as its `src/shared.rs` defines them at commit
//! `00a735a89917` (read 2026-11-10): serde's JSON of two enums, externally
//! tagged (`{"Hello":0}`, `"Heartbeat"`), each frame ended by a zero byte and
//! at most 256 bytes long (`MAX_FRAME_LENGTH`). A UUID goes as its hyphenated
//! text, and the answer to a `Challenge` is the hex of HMAC-SHA256, keyed by
//! SHA-256 of the secret, over the UUID's 16 bytes (`src/auth.rs`).
//!
//! A frame is read a byte at a time: on a connection that takes `Accept`,
//! the visitor's bytes follow the server's last frame, and none may be read
//! past it.

use hmac::{Hmac, KeyInit, Mac};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The longest frame that bore's codec takes, its zero byte aside.
pub const MAX_FRAME: usize = 256;

/// A message of the node's (bore's `ClientMessage`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientMessage {
    /// The answer to a `Challenge`.
    Authenticate(String),
    /// The port asked for on the control connection, 0 for any.
    Hello(u16),
    /// A visitor taken on this new connection, by its UUID.
    Accept(String),
}

/// A message of the server's (bore's `ServerMessage`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServerMessage {
    /// The first message of a server with a secret.
    Challenge(String),
    /// The public port, the answer to the node's `Hello`.
    Hello(u16),
    /// Sent each 500 ms or so while the control connection lives.
    Heartbeat,
    /// A visitor of the public port, by its UUID.
    Connection(String),
    /// The server's refusal, after which it closes the connection.
    Error(String),
}

/// `message` as one frame: its JSON and the zero byte.
pub fn frame<T: Serialize>(message: &T) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(message).map_err(|e| format!("bore's message: {e}"))?;
    if bytes.len() > MAX_FRAME {
        return Err(format!("a message of bore's protocol is {MAX_FRAME} bytes at most"));
    }
    bytes.push(0);
    Ok(bytes)
}

/// Write `message` as one frame.
pub async fn send<W: AsyncWrite + Unpin, T: Serialize>(to: &mut W, message: &T) -> Result<(), String> {
    let bytes = frame(message)?;
    to.write_all(&bytes).await.map_err(|e| format!("sending to the server: {e}"))?;
    to.flush().await.map_err(|e| format!("sending to the server: {e}"))
}

/// The next frame of `from`, read up to its zero byte and no further; none
/// at the stream's end before a byte of it. An empty frame is passed over.
pub async fn next_frame<R: AsyncRead + Unpin>(from: &mut R) -> Result<Option<Vec<u8>>, String> {
    let mut bytes = Vec::new();
    loop {
        let byte = match from.read_u8().await {
            Ok(byte) => byte,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && bytes.is_empty() => return Ok(None),
            Err(e) => return Err(format!("reading from the server: {e}")),
        };
        match byte {
            0 if bytes.is_empty() => continue,
            0 => return Ok(Some(bytes)),
            _ if bytes.len() == MAX_FRAME => {
                return Err(format!("the server sent a frame longer than bore's {MAX_FRAME} bytes"))
            }
            _ => bytes.push(byte),
        }
    }
}

/// The next message of `from`, as [`next_frame`] reads it.
pub async fn recv<R: AsyncRead + Unpin, T: DeserializeOwned>(from: &mut R) -> Result<Option<T>, String> {
    match next_frame(from).await? {
        Some(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|_| {
            // The server's text is not echoed: it may be anything.
            "the server sent a message that is not of bore's protocol".to_string()
        }),
        None => Ok(None),
    }
}

/// The 16 bytes of a UUID's text: 32 hex digits, hyphens aside, as serde
/// writes a `uuid::Uuid` (8-4-4-4-12); else none.
pub fn uuid_bytes(text: &str) -> Option<[u8; 16]> {
    let digits: Vec<u8> = text.bytes().filter(|b| *b != b'-').collect();
    let hyphens = text.len() - digits.len();
    if digits.len() != 32 || !(hyphens == 0 || hyphens == 4) {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (at, pair) in digits.chunks(2).enumerate() {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes[at] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(bytes)
}

/// The answer of `secret` to the challenge `uuid`, as bore's
/// `Authenticator::answer` makes it; none for a UUID that does not read.
pub fn answer(secret: &str, uuid: &str) -> Option<String> {
    let challenge = uuid_bytes(uuid)?;
    let key = Sha256::digest(secret.as_bytes());
    // HMAC takes a key of each length, so this cannot fail.
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).ok()?;
    mac.update(&challenge);
    Some(mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The forms that bore's serde writes and reads, byte for byte.
    #[test]
    fn the_messages_are_bore_s_json_each_ended_by_a_zero_byte() {
        assert_eq!(frame(&ClientMessage::Hello(0)).unwrap(), b"{\"Hello\":0}\0");
        let id = "67e55044-10b1-426f-9247-bb680e5fe0c8";
        let accept = format!("{{\"Accept\":\"{id}\"}}\0");
        assert_eq!(frame(&ClientMessage::Accept(id.into())).unwrap(), accept.as_bytes());
        assert_eq!(frame(&ServerMessage::Heartbeat).unwrap(), b"\"Heartbeat\"\0");
        let read = |text: &str| serde_json::from_str::<ServerMessage>(text).unwrap();
        assert_eq!(read("{\"Hello\":40123}"), ServerMessage::Hello(40123));
        assert_eq!(read("\"Heartbeat\""), ServerMessage::Heartbeat);
        assert_eq!(read(&format!("{{\"Connection\":\"{id}\"}}")), ServerMessage::Connection(id.into()));
        assert_eq!(read("{\"Error\":\"port already in use\"}"), ServerMessage::Error("port already in use".into()));
        assert!(frame(&ClientMessage::Authenticate("a".repeat(300))).is_err(), "longer than bore's frame");
    }

    #[tokio::test]
    async fn a_frame_is_read_to_its_zero_byte_and_no_further() {
        let mut bytes: &[u8] = b"\0\"Heartbeat\"\0{\"Hello\":7}\0VISITOR";
        assert_eq!(recv::<_, ServerMessage>(&mut bytes).await.unwrap(), Some(ServerMessage::Heartbeat));
        assert_eq!(recv::<_, ServerMessage>(&mut bytes).await.unwrap(), Some(ServerMessage::Hello(7)));
        assert_eq!(bytes, b"VISITOR", "the bytes after the frame are the visitor's, unread");
        let mut ended: &[u8] = b"";
        assert_eq!(recv::<_, ServerMessage>(&mut ended).await.unwrap(), None);
        let mut cut: &[u8] = b"{\"Hel";
        assert!(recv::<_, ServerMessage>(&mut cut).await.is_err(), "a frame cut short");
        let long = [b'a'; 300];
        assert!(next_frame(&mut &long[..]).await.unwrap_err().contains("256"));
        let mut other: &[u8] = b"{\"Nope\":SECRET}\0";
        let why = recv::<_, ServerMessage>(&mut other).await.unwrap_err();
        assert!(!why.contains("SECRET"), "{why}");
    }

    /// A known answer, computed apart from this code (Python's hmac and
    /// hashlib, on 2026-11-10), as bore's `Authenticator` computes it.
    #[test]
    fn the_answer_is_bore_s_hmac_of_the_challenge_s_bytes() {
        let id = "67e55044-10b1-426f-9247-bb680e5fe0c8";
        let want = "58c7053d9b399b587f06f019c9c49d79c1b7c3129455392a25378ae4a1c51d7f";
        assert_eq!(answer("secret", id).as_deref(), Some(want));
        assert_eq!(answer("secret", &id.replace('-', "")).as_deref(), Some(want), "the simple form too");
        assert_ne!(answer("another", id).as_deref(), Some(want));
        for bad in ["", "67e55044", "67e55044-10b1-426f-9247-bb680e5fe0cZ", "67e5-5044-10b1-426f-9247bb680e5fe0c8-"] {
            assert_eq!(answer("secret", bad), None, "{bad}");
        }
    }
}
