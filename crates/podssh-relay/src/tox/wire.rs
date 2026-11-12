//! A client's connection to a Tox TCP relay (T-734), from the protocol's
//! specification (`docs/TCP_Network.txt` of TokTok/c-toxcore), never from
//! its GPL code: the handshake, then packets of a 2-byte length and a box.
//!
//! The handshake: the client sends its key, a nonce, and a box (its key and
//! the relay's) of a key for this connection alone and the base nonce that
//! the relay sends with; the relay answers with a nonce and a box of its own
//! key for the connection and the base nonce that the client sends with.
//! Each packet after it is a box of the two keys of the connection, under
//! the base nonce counted up by one for each packet. What the specification
//! leaves open (the order of the length's bytes and of the count) is the
//! network's order, which the relay of c-toxcore takes (the test).

use std::io;

use crypto_box::aead::Aead;
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A key's bytes.
pub const KEY: usize = 32;
/// A nonce's bytes.
pub const NONCE: usize = 24;
/// A box's tag.
pub const MAC: usize = 16;
/// The most bytes of a packet's box, its tag in it.
pub const MAX_BOX: usize = 2048;
/// The most bytes of a data packet's payload: a box of the id and them.
pub const MAX_DATA: usize = MAX_BOX - MAC - 1;

/// The packet ids of the protocol.
pub mod id {
    pub const ROUTE_REQUEST: u8 = 0;
    pub const ROUTE_RESPONSE: u8 = 1;
    pub const CONNECTED: u8 = 2;
    pub const DISCONNECTED: u8 = 3;
    pub const PING: u8 = 4;
    pub const PONG: u8 = 5;
    pub const OOB_SEND: u8 = 6;
    pub const OOB_RECV: u8 = 7;
    /// The first id of a routed connection's data; 255 is the last.
    pub const DATA: u8 = 16;
}

/// A long-term key pair of an end: from a seed, so that both ends of a pair
/// can make the other's public key from what they share.
pub struct Keys {
    secret: SecretKey,
    public: [u8; KEY],
}

impl Keys {
    pub fn of_seed(seed: [u8; KEY]) -> Keys {
        let secret = SecretKey::from(seed);
        let public = *secret.public_key().as_bytes();
        Keys { secret, public }
    }

    pub fn fresh() -> Keys {
        Keys::of_seed(rand::random())
    }

    pub fn public(&self) -> [u8; KEY] {
        self.public
    }
}

/// What the relay sent, opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Packet {
    /// The answer to a routing request: the connection's id, 0 when refused.
    Routed {
        id: u8,
        key: [u8; KEY],
    },
    Connected(u8),
    Disconnected(u8),
    Ping([u8; 8]),
    Pong([u8; 8]),
    /// A packet of another client of this relay, by its key.
    Oob {
        from: [u8; KEY],
        data: Vec<u8>,
    },
    /// Data of the routed connection `id`.
    Data {
        id: u8,
        data: Vec<u8>,
    },
    /// An id that this client does not use (the onion's).
    Other(u8),
}

impl Packet {
    fn parse(plain: &[u8]) -> Result<Packet, String> {
        let (&first, rest) = plain.split_first().ok_or("an empty packet")?;
        let key = |bytes: &[u8]| -> Result<[u8; KEY], String> {
            bytes.get(..KEY).and_then(|k| k.try_into().ok()).ok_or_else(|| format!("packet {first} is short"))
        };
        let eight = |bytes: &[u8]| -> Result<[u8; 8], String> {
            bytes.try_into().map_err(|_| format!("packet {first} is not 9 bytes"))
        };
        let one = |bytes: &[u8]| -> Result<u8, String> {
            match bytes {
                [b] => Ok(*b),
                _ => Err(format!("packet {first} is not 2 bytes")),
            }
        };
        Ok(match first {
            id::ROUTE_RESPONSE => {
                let (&routed, rest) = rest.split_first().ok_or("a short routing response")?;
                Packet::Routed { id: routed, key: key(rest)? }
            }
            id::CONNECTED => Packet::Connected(one(rest)?),
            id::DISCONNECTED => Packet::Disconnected(one(rest)?),
            id::PING => Packet::Ping(eight(rest)?),
            id::PONG => Packet::Pong(eight(rest)?),
            id::OOB_RECV => Packet::Oob { from: key(rest)?, data: rest[KEY..].to_vec() },
            n if n >= id::DATA => Packet::Data { id: n, data: rest.to_vec() },
            n => Packet::Other(n),
        })
    }
}

/// One count up of a nonce, its last byte first (the network's order).
fn count(nonce: &mut [u8; NONCE]) {
    for b in nonce.iter_mut().rev() {
        let (next, carry) = b.overflowing_add(1);
        *b = next;
        if !carry {
            return;
        }
    }
}

/// The connection's sending half.
pub struct Sender<W> {
    io: W,
    sealer: SalsaBox,
    nonce: [u8; NONCE],
}

/// The connection's receiving half.
pub struct Receiver<R> {
    io: R,
    opener: SalsaBox,
    nonce: [u8; NONCE],
}

impl<W: AsyncWrite + Unpin> Sender<W> {
    /// One packet, boxed under the next nonce.
    pub async fn send(&mut self, plain: &[u8]) -> io::Result<()> {
        if plain.len() + MAC > MAX_BOX {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a packet past the protocol's 2048 bytes"));
        }
        let sealed = self
            .sealer
            .encrypt(&crypto_box::Nonce::from(self.nonce), plain)
            .map_err(|_| io::Error::other("a box of a packet"))?;
        count(&mut self.nonce);
        let mut frame = Vec::with_capacity(2 + sealed.len());
        frame.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        frame.extend_from_slice(&sealed);
        self.io.write_all(&frame).await?;
        self.io.flush().await
    }

    pub async fn route(&mut self, to: &[u8; KEY]) -> io::Result<()> {
        let mut packet = vec![id::ROUTE_REQUEST];
        packet.extend_from_slice(to);
        self.send(&packet).await
    }

    pub async fn pong(&mut self, ping: [u8; 8]) -> io::Result<()> {
        let mut packet = vec![id::PONG];
        packet.extend_from_slice(&ping);
        self.send(&packet).await
    }

    pub async fn ping(&mut self, ping: [u8; 8]) -> io::Result<()> {
        let mut packet = vec![id::PING];
        packet.extend_from_slice(&ping);
        self.send(&packet).await
    }

    /// A packet to another client of this relay, by its key; the relay
    /// says nothing of its delivery.
    pub async fn oob(&mut self, to: &[u8; KEY], data: &[u8]) -> io::Result<()> {
        let mut packet = vec![id::OOB_SEND];
        packet.extend_from_slice(to);
        packet.extend_from_slice(data);
        self.send(&packet).await
    }

    pub async fn data(&mut self, id: u8, data: &[u8]) -> io::Result<()> {
        let mut packet = Vec::with_capacity(1 + data.len());
        packet.push(id);
        packet.extend_from_slice(data);
        self.send(&packet).await
    }
}

impl<R: AsyncRead + Unpin> Receiver<R> {
    /// The next packet; an error for a box that does not open, which no
    /// relay of the protocol sends.
    pub async fn recv(&mut self) -> io::Result<Packet> {
        let mut length = [0u8; 2];
        self.io.read_exact(&mut length).await?;
        let length = u16::from_be_bytes(length) as usize;
        if !(MAC + 1..=MAX_BOX).contains(&length) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, format!("a packet of {length} bytes")));
        }
        let mut sealed = vec![0u8; length];
        self.io.read_exact(&mut sealed).await?;
        let plain = self
            .opener
            .decrypt(&crypto_box::Nonce::from(self.nonce), sealed.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a packet that does not open"))?;
        count(&mut self.nonce);
        Packet::parse(&plain).map_err(|why| io::Error::new(io::ErrorKind::InvalidData, why))
    }
}

/// The handshake with the relay whose key is `relay`, as `keys`: the two
/// halves of the connection.
pub async fn connect<R, W>(
    mut read: R,
    mut write: W,
    relay: &[u8; KEY],
    keys: &Keys,
) -> io::Result<(Sender<W>, Receiver<R>)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let temporary = Keys::fresh();
    let ours: [u8; NONCE] = rand::random();
    let nonce: [u8; NONCE] = rand::random();
    let long = SalsaBox::new(&PublicKey::from(*relay), &keys.secret);
    let mut plain = temporary.public.to_vec();
    plain.extend_from_slice(&ours);
    let sealed = long
        .encrypt(&crypto_box::Nonce::from(nonce), plain.as_slice())
        .map_err(|_| io::Error::other("a box of the handshake"))?;
    let mut hello = Vec::with_capacity(KEY + NONCE + sealed.len());
    hello.extend_from_slice(&keys.public);
    hello.extend_from_slice(&nonce);
    hello.extend_from_slice(&sealed);
    write.write_all(&hello).await?;
    write.flush().await?;
    let mut answer = [0u8; NONCE + KEY + NONCE + MAC];
    read.read_exact(&mut answer).await?;
    let (their_nonce, sealed) = answer.split_at(NONCE);
    let their_nonce: [u8; NONCE] = their_nonce.try_into().unwrap_or([0; NONCE]);
    let opened = long
        .decrypt(&crypto_box::Nonce::from(their_nonce), sealed)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "the relay's answer does not open: another key"))?;
    let their_key: [u8; KEY] = opened[..KEY].try_into().unwrap_or([0; KEY]);
    let theirs: [u8; NONCE] = opened[KEY..KEY + NONCE].try_into().unwrap_or([0; NONCE]);
    let session = || SalsaBox::new(&PublicKey::from(their_key), &temporary.secret);
    // Each end sends under the base nonce that it chose and opens under the
    // other's: c-toxcore's relay drops a client that sends under the
    // relay's (measured, the test), where the specification's words read
    // the other way.
    Ok((Sender { io: write, sealer: session(), nonce: ours }, Receiver { io: read, opener: session(), nonce: theirs }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_nonce_counts_up_its_last_byte_first_with_its_carry() {
        let mut nonce = [0u8; NONCE];
        nonce[NONCE - 1] = 0xff;
        count(&mut nonce);
        assert_eq!((nonce[NONCE - 2], nonce[NONCE - 1]), (1, 0));
        let mut all = [0xffu8; NONCE];
        count(&mut all);
        assert_eq!(all, [0u8; NONCE]);
    }

    #[test]
    fn the_packets_parse_and_a_short_one_does_not() {
        let key = [7u8; KEY];
        let mut routed = vec![id::ROUTE_RESPONSE, 16];
        routed.extend_from_slice(&key);
        assert_eq!(Packet::parse(&routed), Ok(Packet::Routed { id: 16, key }));
        assert_eq!(Packet::parse(&[id::CONNECTED, 17]), Ok(Packet::Connected(17)));
        assert_eq!(Packet::parse(&[20, 1, 2]), Ok(Packet::Data { id: 20, data: vec![1, 2] }));
        assert_eq!(Packet::parse(&[id::PING, 1, 2, 3, 4, 5, 6, 7, 8]), Ok(Packet::Ping([1, 2, 3, 4, 5, 6, 7, 8])));
        assert!(Packet::parse(&[id::ROUTE_RESPONSE, 16, 1]).is_err());
        assert!(Packet::parse(&[id::PING, 1]).is_err());
        assert!(Packet::parse(&[]).is_err());
    }
}
