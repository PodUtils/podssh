//! Salamander, Hysteria 2's obfuscation of each UDP datagram (its protocol's
//! "Salamander" section, `extras/obfs/salamander.go`): 8 bytes of salt, then
//! the QUIC packet XORed with BLAKE2b-256 of the pre-shared key and the
//! salt, repeated. A datagram that is no longer than its salt is dropped, as
//! the server drops one. [`Salamander`] wraps any way of datagrams, so that
//! QUIC (pod-quic's endpoint over it) and the probe of UDP both speak it.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::task::{Context, Poll};

use blake2::{Blake2b256, Digest};
use pod_core::entropy::{Entropy, OsEntropy};
use pod_core::{Datagrams, RecvMeta, Transmit};
use zeroize::Zeroizing;

/// The salt before each packet.
pub const SALT: usize = 8;

/// The key of one salt: BLAKE2b-256 of the pre-shared key, then the salt.
fn key(psk: &[u8], salt: &[u8]) -> [u8; 32] {
    let digest = Blake2b256::new().chain_update(psk).chain_update(salt).finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

/// `packet` as it goes on the wire, with `salt`.
pub fn obfuscate(psk: &[u8], salt: [u8; SALT], packet: &[u8]) -> Vec<u8> {
    let key = key(psk, &salt);
    let mut out = Vec::with_capacity(SALT + packet.len());
    out.extend_from_slice(&salt);
    out.extend(packet.iter().enumerate().map(|(i, b)| b ^ key[i % 32]));
    out
}

/// A datagram of the wire, in place: its packet moved to the front, and its
/// length; none when it is no longer than its salt.
pub fn deobfuscate(psk: &[u8], datagram: &mut [u8]) -> Option<usize> {
    let len = datagram.len().checked_sub(SALT).filter(|n| *n > 0)?;
    let key = key(psk, &datagram[..SALT]);
    datagram.copy_within(SALT.., 0);
    for (i, b) in datagram[..len].iter_mut().enumerate() {
        *b ^= key[i % 32];
    }
    Some(len)
}

/// A fresh salt from the system's source, as Hysteria draws one for each
/// packet.
pub fn salt() -> io::Result<[u8; SALT]> {
    let mut salt = [0u8; SALT];
    OsEntropy.fill(&mut salt).map_err(|_| io::Error::other("no random salt for Salamander"))?;
    Ok(salt)
}

/// A way of datagrams whose each datagram is Salamander's.
pub struct Salamander<D> {
    inner: D,
    psk: Zeroizing<Vec<u8>>,
}

impl<D> Salamander<D> {
    pub fn new(inner: D, psk: &[u8]) -> Salamander<D> {
        Salamander { inner, psk: Zeroizing::new(psk.to_vec()) }
    }
}

impl<D: fmt::Debug> fmt::Debug for Salamander<D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Salamander").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl<D: Datagrams> Datagrams for Salamander<D> {
    fn poll_writable(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.inner.poll_writable(cx)
    }

    /// Each segment as a datagram of its own, with its own salt.
    fn try_send(&self, t: &Transmit<'_>) -> io::Result<()> {
        let size = t.segment_size.filter(|s| *s > 0).unwrap_or(t.contents.len().max(1));
        for segment in t.contents.chunks(size) {
            let wire = obfuscate(&self.psk, salt()?, segment);
            let one = Transmit { destination: t.destination, contents: &wire, segment_size: None, src_ip: t.src_ip };
            self.inner.try_send(&one)?;
        }
        Ok(())
    }

    /// One datagram at a time, into the first buffer; one no longer than its
    /// salt is dropped, and the next is read. Salamander has no tag: a
    /// stranger's datagram reads as noise, which QUIC drops.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let (Some(buf), Some(m)) = (bufs.first_mut(), meta.first_mut()) else {
            return Poll::Ready(Ok(0));
        };
        loop {
            let got = self.inner.poll_recv(cx, std::slice::from_mut(&mut *buf), std::slice::from_mut(&mut *m));
            match got {
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(_)) => {
                    // A batch of several datagrams in one buffer is not
                    // asked for (one segment at most): it is dropped whole.
                    if m.stride != m.len {
                        continue;
                    }
                    if let Some(len) = deobfuscate(&self.psk, &mut buf[..m.len]) {
                        *m = RecvMeta { len, stride: len, ..*m };
                        return Poll::Ready(Ok(1));
                    }
                }
                other => return other,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Each datagram is a salt longer than QUIC's packet.
    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A vector made with Python's `hashlib.blake2b(psk + salt,
    /// digest_size=32)`, a packet of 34 bytes so that the key wraps.
    #[test]
    fn a_packet_goes_as_hysteria_s_salamander_makes_it_and_comes_back() {
        let psk = b"cry_me_a_r1ver";
        let salt = [1, 2, 3, 4, 5, 6, 7, 8];
        let packet = b"a QUIC packet, 34 bytes long......";
        let wire = obfuscate(psk, salt, packet);
        let want = "01020304050607080581dabd9ed3de6e790939dd63ed7c6eeeb414fb797af1bbe9f01558b5d627c74a8f";
        assert_eq!(crate::hysteria::link::hex(&wire), want);
        let mut back = wire.clone();
        assert_eq!(deobfuscate(psk, &mut back), Some(packet.len()));
        assert_eq!(&back[..packet.len()], packet);
        let mut other = wire;
        deobfuscate(b"another key", &mut other);
        assert_ne!(&other[..packet.len()], packet, "another key reads noise");
    }

    #[test]
    fn a_datagram_no_longer_than_its_salt_is_dropped_and_salts_differ() {
        assert_eq!(deobfuscate(b"key!", &mut [0u8; SALT]), None);
        assert_eq!(deobfuscate(b"key!", &mut [0u8; 3]), None);
        assert_ne!(salt().unwrap(), salt().unwrap(), "a salt for each packet");
    }

    /// Through the wrapper on the loopback: a datagram sent by one end comes
    /// out of the other's whole, and a stranger's never reads as it.
    #[tokio::test]
    async fn the_wrapper_carries_a_datagram_whole() {
        use pod_core::datagrams::{recv_from, send_to};
        use pod_core::SystemDatagrams;
        let lo: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let a = Salamander::new(SystemDatagrams::bind(lo).await.unwrap(), b"shared key");
        let b = Salamander::new(SystemDatagrams::bind(lo).await.unwrap(), b"shared key");
        let stranger = Salamander::new(SystemDatagrams::bind(lo).await.unwrap(), b"other key!");
        let to = b.local_addr().unwrap();
        send_to(&stranger, b"not for b", to).await.unwrap();
        send_to(&a, b"for b", to).await.unwrap();
        let mut buf = [0u8; 64];
        let wait = std::time::Duration::from_secs(5);
        let (n, from) = tokio::time::timeout(wait, recv_from(&b, &mut buf)).await.unwrap().unwrap();
        // The stranger's datagram may decode to noise of its length, which
        // QUIC drops as a packet it cannot open; the shared one comes whole.
        let (n, from) = match &buf[..n] == b"for b" {
            true => (n, from),
            false => tokio::time::timeout(wait, recv_from(&b, &mut buf)).await.unwrap().unwrap(),
        };
        assert_eq!((&buf[..n], from), (&b"for b"[..], a.local_addr().unwrap()));
    }
}
