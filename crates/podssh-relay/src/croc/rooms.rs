//! The words of a pair at croc's relay (T-694), from the pair's secret: the
//! base of its rooms, each a slot of it, the relay of croc's pool that the
//! base picks, and the key of podssh's own proof of the pair, each by
//! HKDF-SHA256 from the pair's connect token and name, which both ends hold.
//! The rooms are the relay's to see (and the bridge's, whose handshake key
//! is public): a room lets a peer meet the node and no more, as the proof
//! key cannot be had from it.
//!
//! A room of croc's relay holds two members and pipes them until either
//! ends (schollz/croc:src/tcp/tcp.go at v11.6.4, `admitToRoom`), so a pair
//! has [`SLOTS`] rooms, one for each link that its node carries at once.

use std::fmt;

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The salt of each derivation: a new version of the words is a new salt.
pub const SALT: &[u8] = b"podssh croc, version 1";
const BASE_LABEL: &[u8] = b"podssh croc room";
const PROOF_KEY_LABEL: &[u8] = b"podssh croc proof key";
const PROOF_LABEL: &[u8] = b"podssh croc proof";
/// The rooms of a pair: the links that its node carries at once over croc's
/// relay. Each try of one is a join, which the relay limits for each source
/// (30 a minute by croc's defaults), and the bridge is one source for all
/// its users, so a client tries few.
pub const SLOTS: usize = 4;
/// The bytes of a proof: HMAC-SHA256.
pub const PROOF_BYTES: usize = 32;

/// The pair's words at croc's relay.
#[derive(Clone)]
pub struct Rooms {
    /// 64 hex digits, as croc's code names a room's relay.
    base: String,
    proof: Zeroizing<[u8; 32]>,
}

impl Rooms {
    /// The words of the pair `name` whose connect token is `connect_token`:
    /// the node's whole pair and the operator's part give the same.
    pub fn of_pair(name: &str, connect_token: &str) -> Rooms {
        let hkdf = Hkdf::<Sha256>::new(Some(SALT), connect_token.as_bytes());
        let mut base = [0u8; 32];
        let mut proof = Zeroizing::new([0u8; 32]);
        // 32 bytes is far below HKDF-SHA256's 8160, so neither can fail; a
        // failure would leave zeros, which meet nobody's proof.
        let _ = hkdf.expand(&info(BASE_LABEL, name), &mut base);
        let _ = hkdf.expand(&info(PROOF_KEY_LABEL, name), &mut proof[..]);
        Rooms { base: hex(&base), proof }
    }

    /// A peer that knows the rooms alone, as the relay does: its proof key
    /// is none of the pair's. For a test of the door.
    pub fn knowing_only(base: &str) -> Rooms {
        Rooms { base: base.to_string(), proof: Zeroizing::new([0u8; 32]) }
    }

    /// The base of the rooms, which is never printed.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// The room of `slot`, which the relay's handshake carries encrypted.
    pub fn room(&self, slot: usize) -> String {
        format!("{}-{slot}", self.base)
    }

    /// The relay of a pool of `count` that the base picks, as croc picks a
    /// code's: the SHA-256 of its text, a big-endian number, modulo `count`
    /// (schollz/croc:src/codephrase/codephrase.go at v11.6.4, `RelayIndex`).
    pub fn relay(&self, count: usize) -> usize {
        relay_index(&self.base, count)
    }

    /// The proof of the end whose part is `part`, which sent `sender`'s
    /// nonce and got `receiver`'s: each part and each order is its own, so
    /// the relay cannot send a proof back to the one who made it.
    pub fn prove(&self, part: u8, sender: &[u8], receiver: &[u8]) -> [u8; PROOF_BYTES] {
        self.mac(part, sender, receiver).finalize().into_bytes().into()
    }

    /// Whether `proof` is [`Rooms::prove`]'s, compared in constant time.
    pub fn verify(&self, part: u8, sender: &[u8], receiver: &[u8], proof: &[u8]) -> bool {
        self.mac(part, sender, receiver).verify_slice(proof).is_ok()
    }

    fn mac(&self, part: u8, sender: &[u8], receiver: &[u8]) -> Hmac<Sha256> {
        // A key of any length is valid for HMAC; 32 bytes always are.
        let mut mac = match Hmac::<Sha256>::new_from_slice(&self.proof[..]) {
            Ok(mac) => mac,
            Err(_) => <Hmac<Sha256> as KeyInit>::new(&Default::default()),
        };
        mac.update(PROOF_LABEL);
        mac.update(&[0, part]);
        mac.update(sender);
        mac.update(receiver);
        mac
    }
}

impl fmt::Debug for Rooms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Neither the rooms nor the key go into a line.
        f.write_str("Rooms(..)")
    }
}

/// croc's `RelayIndex`: SHA-256 of `code`, as a big-endian number, modulo
/// `count`; 0 for an empty pool.
pub fn relay_index(code: &str, count: usize) -> usize {
    if count == 0 {
        return 0;
    }
    let digest = Sha256::digest(code.as_bytes());
    let count = count as u128;
    // Horner's rule, each step below count · 256, which fits.
    digest.iter().fold(0u128, |rest, b| (rest * 256 + u128::from(*b)) % count) as usize
}

fn info(label: &[u8], name: &str) -> Vec<u8> {
    [label, &[0], name.as_bytes()].concat()
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "0123456789abcdef0123456789abcdef";
    const CONNECT: &str = "connect-token-of-a-test-0123456789abcdef";

    // Computed with Python's hmac and hashlib (HKDF by RFC 5869 written out),
    // software that podssh did not write.
    const BASE: &str = "7269f1542c0892755005d5fcd2ef3e942bbc8e3dd1d275fc30c8a20c2e1c1504";
    const PROOF_KEY: &str = "6687989bd6584ce2852b73a38ede6c15cd277afcaea06d15cb3cd6855e1cf420";
    const PROOF_OF_C: &str = "c6ed5705dfeaf901f0c0fbe1632cda1e2e30e08dd7c538b869a47ca93e49253d";

    #[test]
    fn the_rooms_and_the_proof_key_are_hkdf_sha256_of_the_pair_as_python_computes_them() {
        let rooms = Rooms::of_pair(NAME, CONNECT);
        assert_eq!(rooms.base(), BASE);
        assert_eq!(hex(&rooms.proof[..]), PROOF_KEY);
        assert_eq!(rooms.room(0), format!("{BASE}-0"));
        assert_eq!(rooms.room(SLOTS - 1), format!("{BASE}-3"));
        let proof = rooms.prove(b'C', &[1; 32], &[2; 32]);
        assert_eq!(hex(&proof), PROOF_OF_C);
        assert!(rooms.verify(b'C', &[1; 32], &[2; 32], &proof));
        assert!(!format!("{rooms:?}").contains(BASE));
    }

    // Python: int.from_bytes(sha256(code).digest(), 'big') % count.
    #[test]
    fn the_relay_is_croc_s_relay_index_of_the_base() {
        assert_eq!(relay_index("abc", 4), 1);
        assert_eq!(relay_index("abc", 3), 1);
        assert_eq!(relay_index("podssh", 4), 0);
        assert_eq!(relay_index("podssh", 3), 1);
        assert_eq!(Rooms::of_pair(NAME, CONNECT).relay(4), 1);
        assert_eq!(relay_index("abc", 0), 0);
        assert_eq!(relay_index("abc", 1), 0);
    }

    #[test]
    fn a_proof_holds_for_its_part_and_order_alone_and_never_for_the_rooms_alone() {
        let rooms = Rooms::of_pair(NAME, CONNECT);
        let proof = rooms.prove(b'N', &[1; 32], &[2; 32]);
        assert!(!rooms.verify(b'C', &[1; 32], &[2; 32], &proof), "another part");
        assert!(!rooms.verify(b'N', &[2; 32], &[1; 32], &proof), "the nonces swapped");
        assert!(!rooms.verify(b'N', &[1; 32], &[2; 32], &proof[..31]), "a proof cut short");
        let stranger = Rooms::knowing_only(rooms.base());
        assert_eq!(stranger.room(1), rooms.room(1));
        assert!(!rooms.verify(b'N', &[1; 32], &[2; 32], &stranger.prove(b'N', &[1; 32], &[2; 32])));
        assert_ne!(Rooms::of_pair(NAME, "another connect token").base(), rooms.base());
        assert_ne!(Rooms::of_pair("another-name", CONNECT).base(), rooms.base());
        // The transit road's token of the same pair is another (T-436).
        assert_ne!(crate::transit::Keys::of_pair(NAME, CONNECT).token(), rooms.base());
    }
}
