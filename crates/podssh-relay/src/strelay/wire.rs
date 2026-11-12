//! Syncthing's relay protocol, version 1 (T-571): each message is a header
//! of three numbers of four bytes in the network's order (the magic, the
//! type, the length of the rest) and the rest in XDR (an opaque is its length
//! and its bytes, padded to four; a number of 16 bits or a boolean takes four
//! bytes). The relay's messages to a client: `Response`, `SessionInvitation`,
//! `Ping`, `Pong`, `RelayFull`; a client's to it: `JoinRelayRequest`,
//! `ConnectRequest`, `JoinSessionRequest`, `Ping`, `Pong`.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The magic of each header.
pub const MAGIC: u32 = 0x9E79_BC40;
/// The protocol's name in TLS's ALPN.
pub const ALPN: &[u8] = b"bep-relay";
/// The largest message that this end reads.
const MOST: usize = 1024;

/// One message of the protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping,
    Pong,
    JoinRelay { token: String },
    JoinSession { key: Vec<u8> },
    Response { code: i32, message: String },
    Connect { id: Vec<u8> },
    Invitation { from: Vec<u8>, key: Vec<u8>, address: Vec<u8>, port: u16, server_socket: bool },
    RelayFull,
}

/// The `Response` of success.
pub const SUCCESS: i32 = 0;
/// The `Response` to a `ConnectRequest` for a device that is not joined.
pub const NOT_FOUND: i32 = 1;
/// The `Response` to a join that the relay could not place at once.
pub const ALREADY_CONNECTED: i32 = 2;

fn opaque(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len() + (4 - bytes.len() % 4) % 4, 0);
}

impl Message {
    fn kind(&self) -> i32 {
        match self {
            Message::Ping => 0,
            Message::Pong => 1,
            Message::JoinRelay { .. } => 2,
            Message::JoinSession { .. } => 3,
            Message::Response { .. } => 4,
            Message::Connect { .. } => 5,
            Message::Invitation { .. } => 6,
            Message::RelayFull => 7,
        }
    }

    /// The message with its header.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        match self {
            Message::Ping | Message::Pong | Message::RelayFull => {}
            Message::JoinRelay { token } => opaque(&mut body, token.as_bytes()),
            Message::JoinSession { key } => opaque(&mut body, key),
            Message::Response { code, message } => {
                body.extend_from_slice(&code.to_be_bytes());
                opaque(&mut body, message.as_bytes());
            }
            Message::Connect { id } => opaque(&mut body, id),
            Message::Invitation { from, key, address, port, server_socket } => {
                opaque(&mut body, from);
                opaque(&mut body, key);
                opaque(&mut body, address);
                body.extend_from_slice(&u32::from(*port).to_be_bytes());
                body.extend_from_slice(&u32::from(*server_socket).to_be_bytes());
            }
        }
        let mut out = Vec::with_capacity(12 + body.len());
        out.extend_from_slice(&MAGIC.to_be_bytes());
        out.extend_from_slice(&self.kind().to_be_bytes());
        out.extend_from_slice(&(body.len() as u32).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// The message of type `kind` and body `body`.
    pub fn decode(kind: i32, body: &[u8]) -> io::Result<Message> {
        let mut at = Reader { rest: body };
        let message = match kind {
            0 => Message::Ping,
            1 => Message::Pong,
            2 => Message::JoinRelay { token: at.text()? },
            3 => Message::JoinSession { key: at.opaque()? },
            4 => Message::Response { code: at.u32()? as i32, message: at.text()? },
            5 => Message::Connect { id: at.opaque()? },
            6 => Message::Invitation {
                from: at.opaque()?,
                key: at.opaque()?,
                address: at.opaque()?,
                port: u16::try_from(at.u32()?).map_err(|_| invalid("a port past 65535"))?,
                server_socket: at.u32()? != 0,
            },
            7 => Message::RelayFull,
            other => return Err(invalid(&format!("a message of type {other}"))),
        };
        Ok(message)
    }
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("Syncthing's relay: {why}"))
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl Reader<'_> {
    fn u32(&mut self) -> io::Result<u32> {
        let (word, rest) = self.rest.split_first_chunk::<4>().ok_or_else(|| invalid("a cut message"))?;
        self.rest = rest;
        Ok(u32::from_be_bytes(*word))
    }

    fn opaque(&mut self) -> io::Result<Vec<u8>> {
        let len = self.u32()? as usize;
        let padded = len + (4 - len % 4) % 4;
        let bytes = self.rest.get(..len).ok_or_else(|| invalid("a cut field"))?.to_vec();
        self.rest = self.rest.get(padded..).unwrap_or_default();
        Ok(bytes)
    }

    fn text(&mut self) -> io::Result<String> {
        String::from_utf8(self.opaque()?).map_err(|_| invalid("a text that is no UTF-8"))
    }
}

/// The next message on `io`.
pub async fn read<R: AsyncRead + Unpin>(io: &mut R) -> io::Result<Message> {
    let mut header = [0u8; 12];
    io.read_exact(&mut header).await?;
    if u32::from_be_bytes([header[0], header[1], header[2], header[3]]) != MAGIC {
        return Err(invalid("no magic: this is no relay of Syncthing's"));
    }
    let kind = i32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    let len = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if len > MOST {
        return Err(invalid("a message too long"));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    Message::decode(kind, &body)
}

/// `message` on `io`.
pub async fn write<W: AsyncWrite + Unpin>(io: &mut W, message: &Message) -> io::Result<()> {
    io.write_all(&message.encode()).await?;
    io.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_message_reads_back_and_pads_to_four() {
        let all = [
            Message::Ping,
            Message::JoinRelay { token: String::new() },
            Message::JoinSession { key: vec![7; 32] },
            Message::Response { code: NOT_FOUND, message: "not found".into() },
            Message::Connect { id: vec![1; 32] },
            Message::Invitation {
                from: vec![2; 32],
                key: vec![3; 32],
                address: vec![],
                port: 443,
                server_socket: true,
            },
            Message::RelayFull,
        ];
        for message in all {
            let bytes = message.encode();
            assert_eq!(&bytes[..4], &MAGIC.to_be_bytes());
            assert_eq!(bytes.len() % 4, 0, "{message:?}");
            let kind = i32::from_be_bytes(bytes[4..8].try_into().unwrap());
            assert_eq!(Message::decode(kind, &bytes[12..]).unwrap(), message);
        }
        // "not found" is 9 bytes: its opaque pads to 12.
        let response = Message::Response { code: 1, message: "not found".into() }.encode();
        assert_eq!(response.len(), 12 + 4 + 4 + 12);
        assert!(Message::decode(6, &[0, 0, 0, 40]).is_err(), "a field past the end");
    }
}
