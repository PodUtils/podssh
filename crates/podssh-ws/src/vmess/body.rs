//! VMess's body in the option S (`common/crypto/auth.go` and
//! `proxy/vmess/encoding/client.go` of Xray-core): chunks, each its sealed
//! length in clear (2 bytes) and the payload sealed with a tag; the nonce
//! is a count of 2 bytes over the IV's next 10; an empty chunk ends the
//! stream. The pump turns the server's bytes into a stream of the target's,
//! once the answer's header opened.

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::oneshot;

use super::header::{self, Keys, ANSWER_LEN};
use crate::crypto::aead::{Aead, AeadId, NONCE_LEN};

/// The tag of each sealed chunk.
pub const TAG: usize = 16;
/// The largest payload of a chunk that podssh sends: Xray-core's own bound
/// (a buffer of 8 KiB less the length and the tag).
pub const MAX_PLAIN: usize = 8192 - 2 - TAG;
/// The largest answer's header taken.
const MAX_ANSWER: usize = 4096;

/// The body's cipher, by the link's `scy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cipher {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl Cipher {
    /// The code in the header's byte of security.
    pub fn code(self) -> u8 {
        match self {
            Cipher::Aes128Gcm => 3,
            Cipher::ChaCha20Poly1305 => 4,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Cipher::Aes128Gcm => "aes-128-gcm",
            Cipher::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// A link's `scy`: `auto` is AES-128-GCM, as Xray-core picks it where
    /// the CPU has AES. A body in clear (`none`, `zero`) is refused: a node
    /// is a stranger, and the target's name is in the body's first bytes
    /// where SSH is not yet up.
    pub fn parse(scy: &str) -> Result<Cipher, String> {
        match scy.trim().to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" => Ok(Cipher::Aes128Gcm),
            "chacha20-poly1305" => Ok(Cipher::ChaCha20Poly1305),
            "none" | "zero" => Err(format!("scy={scy}: a body in clear, which podssh does not send")),
            other => Err(format!("scy={other}: a cipher that VMess's AEAD form does not name")),
        }
    }

    /// The AEAD of a body's key: AES-128-GCM under it, or ChaCha20-Poly1305
    /// under its MD5 and the MD5 of that.
    fn aead(self, key: &[u8; 16]) -> Option<Aead> {
        match self {
            Cipher::Aes128Gcm => Aead::new(AeadId::Aes128Gcm, key).ok(),
            Cipher::ChaCha20Poly1305 => {
                let first = md5::compute(key).0;
                let second = md5::compute(first).0;
                Aead::new(AeadId::ChaCha20Poly1305, &[first, second].concat()).ok()
            }
        }
    }
}

/// One direction's chunks: its AEAD, its IV and its count.
pub struct Chunks {
    aead: Aead,
    iv: [u8; 16],
    count: u16,
}

impl Chunks {
    pub fn new(cipher: Cipher, key: &[u8; 16], iv: &[u8; 16]) -> Option<Chunks> {
        Some(Chunks { aead: cipher.aead(key)?, iv: *iv, count: 0 })
    }

    fn nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&self.iv[..NONCE_LEN]);
        nonce[..2].copy_from_slice(&self.count.to_be_bytes());
        // Go's count of 16 bits wraps, and so does this one.
        self.count = self.count.wrapping_add(1);
        nonce
    }

    /// `plain` (at most [`MAX_PLAIN`]) as a chunk at the end of `out`.
    pub fn seal(&mut self, plain: &[u8], out: &mut Vec<u8>) -> Option<()> {
        let nonce = self.nonce();
        let mut sealed = plain.to_vec();
        self.aead.seal_in_place(&nonce, &[], &mut sealed)?;
        out.extend_from_slice(&u16::try_from(sealed.len()).ok()?.to_be_bytes());
        out.extend_from_slice(&sealed);
        Some(())
    }

    /// A chunk's sealed payload opened in place: its length in clear.
    pub fn open(&mut self, sealed: &mut [u8]) -> Option<usize> {
        let nonce = self.nonce();
        self.aead.open_in_place(&nonce, &[], sealed)
    }
}

/// Why the answer did not come.
#[derive(Debug)]
pub enum Answer {
    /// The server ended the stream before its answer.
    Ended,
    /// The answer's header did not open, or named another byte.
    Wrong(&'static str),
    Io(String),
}

/// The pump of one session over `raw`, the server's stream: `request` goes
/// first, then the user's bytes in chunks; the answer's header is told on
/// the channel, then the target's bytes come out of the stream returned.
pub fn spawn(
    raw: DuplexStream,
    keys: &Keys,
    cipher: Cipher,
    request: Vec<u8>,
) -> Option<(DuplexStream, oneshot::Receiver<Result<(), Answer>>)> {
    let mut up_chunks = Chunks::new(cipher, &keys.request_key, &keys.request_iv)?;
    let mut down_chunks = Chunks::new(cipher, &keys.answer_key, &keys.answer_iv)?;
    let (user, inner) = tokio::io::duplex(64 * 1024);
    let (mut from_user, mut to_user) = tokio::io::split(inner);
    let (mut from_server, mut to_server) = tokio::io::split(raw);
    let (told, told_rx) = oneshot::channel();
    tokio::spawn(async move {
        if to_server.write_all(&request).await.is_err() {
            return;
        }
        let mut buf = vec![0u8; MAX_PLAIN];
        loop {
            let n = match from_user.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => 0,
            };
            let mut out = Vec::with_capacity(n + 2 + TAG);
            if up_chunks.seal(&buf[..n], &mut out).is_none() || to_server.write_all(&out).await.is_err() {
                return;
            }
            if n == 0 {
                // The empty chunk ends the stream; the WebSocket's end
                // follows as the dial's `AtEnd` says.
                let _ = to_server.flush().await;
                let _ = to_server.shutdown().await;
                return;
            }
            let _ = to_server.flush().await;
        }
    });
    let keys = keys.clone();
    tokio::spawn(async move {
        match read_answer(&mut from_server, &keys).await {
            Ok(()) => {
                let _ = told.send(Ok(()));
            }
            Err(why) => {
                let _ = told.send(Err(why));
                let _ = to_user.shutdown().await;
                return;
            }
        }
        let mut size = [0u8; 2];
        let mut buf = vec![0u8; usize::from(u16::MAX)];
        while from_server.read_exact(&mut size).await.is_ok() {
            let n = usize::from(u16::from_be_bytes(size));
            // A chunk of the tag alone is the end, as Xray-core reads it.
            if n <= TAG || from_server.read_exact(&mut buf[..n]).await.is_err() {
                break;
            }
            let Some(plain) = down_chunks.open(&mut buf[..n]) else { break };
            if to_user.write_all(&buf[..plain]).await.is_err() {
                break;
            }
        }
        let _ = to_user.shutdown().await;
    });
    Some((user, told_rx))
}

async fn read_answer(from: &mut (impl AsyncReadExt + Unpin), keys: &Keys) -> Result<(), Answer> {
    let mut len = [0u8; ANSWER_LEN];
    match from.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(Answer::Ended),
        Err(e) => return Err(Answer::Io(e.to_string())),
    }
    let n = header::answer_len(keys, &len).ok_or(Answer::Wrong("its length did not open"))?;
    if n > MAX_ANSWER {
        return Err(Answer::Wrong("its length is too large"));
    }
    let mut sealed = vec![0u8; n + TAG];
    from.read_exact(&mut sealed).await.map_err(|e| Answer::Io(e.to_string()))?;
    match header::answer(keys, &mut sealed) {
        Some(true) => Ok(()),
        Some(false) => Err(Answer::Wrong("it named another byte than the request's")),
        None => Err(Answer::Wrong("it did not open")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A chunk sealed by one end opens at the other with the same count,
    /// for each cipher; the empty chunk is the tag alone.
    #[test]
    fn chunks_open_in_order_and_the_end_is_the_tag_alone() {
        for cipher in [Cipher::Aes128Gcm, Cipher::ChaCha20Poly1305] {
            let (key, iv) = ([3u8; 16], [5u8; 16]);
            let mut send = Chunks::new(cipher, &key, &iv).unwrap();
            let mut take = Chunks::new(cipher, &key, &iv).unwrap();
            let mut wire = Vec::new();
            send.seal(b"first", &mut wire).unwrap();
            send.seal(b"second", &mut wire).unwrap();
            send.seal(b"", &mut wire).unwrap();
            let mut at = 0;
            let mut got = Vec::new();
            while at < wire.len() {
                let n = usize::from(u16::from_be_bytes([wire[at], wire[at + 1]]));
                let plain = take.open(&mut wire[at + 2..at + 2 + n]).unwrap();
                got.push(wire[at + 2..at + 2 + plain].to_vec());
                at += 2 + n;
            }
            assert_eq!(got, vec![b"first".to_vec(), b"second".to_vec(), Vec::new()]);
            // Planted: the chunks taken out of order do not open.
            let mut again = Vec::new();
            let mut a = Chunks::new(cipher, &key, &iv).unwrap();
            a.seal(b"x", &mut again).unwrap();
            a.seal(b"y", &mut again).unwrap();
            let mut b = Chunks::new(cipher, &key, &iv).unwrap();
            let second = 2 + usize::from(u16::from_be_bytes([again[0], again[1]]));
            assert!(b.open(&mut again[second + 2..]).is_none());
        }
    }

    #[test]
    fn a_body_in_clear_is_refused() {
        assert_eq!(Cipher::parse("auto"), Ok(Cipher::Aes128Gcm));
        assert_eq!(Cipher::parse("CHACHA20-POLY1305"), Ok(Cipher::ChaCha20Poly1305));
        assert!(Cipher::parse("none").unwrap_err().contains("in clear"));
        assert!(Cipher::parse("aes-128-cfb").is_err());
    }
}
