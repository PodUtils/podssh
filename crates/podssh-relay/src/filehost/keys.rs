//! The keys, the topics and the seals of the road, from the pair's secret.
//! A board's topics are public and a file host serves each upload to anyone
//! with its URL, so nothing that leaves an end is in clear: each piece, each
//! note of a piece's URL and each hello is AES-256-GCM under a key of the
//! pair, with a random nonce, and with what it is (its kind, its way, its
//! link and its number) as associated data, so that a host or a board that
//! swaps two of them, or plays one back in another place, is caught when
//! it is opened. A topic is a MAC of the same key: it names neither the
//! pair nor the token, and only the pair's two ends can find it.
//!
//! The end-to-end channel runs above the resumable layer and is not up when
//! a link opens, so the seal here is the pair's, as the paths of the Piping
//! Server road are; the channel still checks each end's identity above it.

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, KeyInit as MacInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::session::{Entropy, NoRandom};

const KEY_LABEL: &[u8] = b"podssh filehost v1 key";
const SEAL_LABEL: &[u8] = b"podssh filehost v1 seal";
const TOPIC_LABEL: &[u8] = b"podssh filehost v1 topic";
const DOOR_LABEL: &[u8] = b"podssh filehost v1 door";
const AAD_LABEL: &[u8] = b"podssh filehost v1";
/// AES-GCM's nonce and tag.
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
/// The bytes that a seal adds.
pub const OVERHEAD: usize = NONCE_BYTES + TAG_BYTES;
/// A topic: two letters, then 40 hex digits of a MAC. Letters and digits
/// alone, and far under the 128 characters of a public broker's topic.
const TOPIC_PREFIX: &str = "pf";
const TOPIC_DIGITS: usize = 40;

/// A way of a link: up from the client to the node, or down.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Way {
    Up,
    Down,
}

impl Way {
    fn byte(self) -> u8 {
        match self {
            Way::Up => b'u',
            Way::Down => b'd',
        }
    }

    /// The other way: what an end reads when it sends this one.
    pub fn other(self) -> Way {
        match self {
            Way::Up => Way::Down,
            Way::Down => Way::Up,
        }
    }
}

/// A link's id, which a client draws for each link, so that the pieces of
/// two links, or of a link and the next, never share a topic.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LinkId(pub [u8; 16]);

impl LinkId {
    pub fn random(entropy: &mut dyn Entropy) -> Result<LinkId, NoRandom> {
        let mut bytes = [0u8; 16];
        entropy.fill(&mut bytes)?;
        Ok(LinkId(bytes))
    }

    /// Its first 8 hex digits, for a line.
    pub fn short(&self) -> String {
        hex(&self.0[..4])
    }
}

impl fmt::Debug for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LinkId({})", self.short())
    }
}

/// What a seal holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A piece of a way: the layer's bytes.
    Piece,
    /// The note of a piece on the board: its host, URL and delete token.
    Note,
    /// A client's hello at the node's door: the id of a new link.
    Hello,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Piece => b'p',
            Kind::Note => b'n',
            Kind::Hello => b'h',
        }
    }
}

/// The road's key for one pair. Never shown.
pub struct Keys(Zeroizing<[u8; 32]>);

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Keys(<redacted>)")
    }
}

impl Keys {
    /// The key of the pair `name`, whose two ends hold `connect_token`. The
    /// token keys the MAC, so that nothing derived from it shows it.
    pub fn of_pair(name: &str, connect_token: &str) -> Keys {
        Keys(Zeroizing::new(mac(connect_token.as_bytes(), KEY_LABEL, &[name.as_bytes()])))
    }

    /// A key of these bytes, for a test.
    pub fn from_bytes(bytes: [u8; 32]) -> Keys {
        Keys(Zeroizing::new(bytes))
    }

    fn mac(&self, label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        mac(&self.0[..], label, parts)
    }

    /// The topic where a client's hello waits for the node.
    pub fn door(&self) -> String {
        topic_of(&self.mac(DOOR_LABEL, &[]))
    }

    /// The topic of the note of piece `n` of `way` of `link`.
    pub fn topic(&self, way: Way, link: &LinkId, n: u64) -> String {
        topic_of(&self.mac(TOPIC_LABEL, &[&[way.byte()], &link.0, &n.to_be_bytes()]))
    }

    /// `plain` sealed as `kind` of piece `n` of `way` of `link`: a random
    /// nonce, then the ciphertext and its tag.
    pub fn seal(
        &self,
        kind: Kind,
        way: Way,
        link: &LinkId,
        n: u64,
        plain: &[u8],
        entropy: &mut dyn Entropy,
    ) -> Result<Vec<u8>, NoRandom> {
        let mut nonce = [0u8; NONCE_BYTES];
        entropy.fill(&mut nonce)?;
        let aad = aad(kind, way, link, n);
        let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
        // AES-GCM seals each message under 64 GiB; a piece is 4 MiB at most,
        // so a failure would be the crate's bug. An empty seal never opens.
        let sealed = self.cipher().encrypt(&gcm, Payload { msg: plain, aad: &aad }).unwrap_or_default();
        Ok([nonce.as_slice(), sealed.as_slice()].concat())
    }

    /// What [`Keys::seal`] sealed as the same `kind`, `way`, `link` and `n`;
    /// `None` for bytes that are too short, of another key, or of another
    /// place.
    pub fn open(&self, kind: Kind, way: Way, link: &LinkId, n: u64, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < OVERHEAD {
            return None;
        }
        let (nonce, body) = sealed.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().ok()?;
        let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
        let aad = aad(kind, way, link, n);
        self.cipher().decrypt(&gcm, Payload { msg: body, aad: &aad }).ok()
    }

    fn cipher(&self) -> Aes256Gcm {
        let key = Zeroizing::new(self.mac(SEAL_LABEL, &[]));
        // A key of 32 bytes is AES-256's length, so this cannot fail.
        match Aes256Gcm::new_from_slice(&key[..]) {
            Ok(cipher) => cipher,
            Err(_) => Aes256Gcm::new(&[0u8; 32].into()),
        }
    }
}

/// The associated data of a seal: the label, then what the seal holds and
/// where it belongs.
fn aad(kind: Kind, way: Way, link: &LinkId, n: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AAD_LABEL.len() + 2 + 16 + 8);
    aad.extend_from_slice(AAD_LABEL);
    aad.push(kind.byte());
    aad.push(way.byte());
    aad.extend_from_slice(&link.0);
    aad.extend_from_slice(&n.to_be_bytes());
    aad
}

fn topic_of(mac: &[u8; 32]) -> String {
    let digits = hex(mac);
    format!("{TOPIC_PREFIX}{}", &digits[..TOPIC_DIGITS])
}

/// HMAC-SHA256 under `key` of `label`, a 0 byte, and each part after its
/// length, so that two lists of parts never give one input.
fn mac(key: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC takes a key of each length, so `new_from_slice` cannot fail.
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => <Hmac<Sha256> as MacInit>::new(&Default::default()),
    };
    mac.update(label);
    mac.update(&[0]);
    for part in parts {
        mac.update(&(part.len() as u32).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// Lower-case hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 15)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::OsEntropy;

    const TOKEN: &str = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr";
    const LINK: LinkId = LinkId([7; 16]);

    fn keys() -> Keys {
        Keys::of_pair("relay-pair-name", TOKEN)
    }

    #[test]
    fn a_topic_is_letters_and_digits_of_the_pair_the_way_the_link_and_the_number() {
        let topic = keys().topic(Way::Up, &LINK, 0);
        assert_eq!(topic.len(), TOPIC_PREFIX.len() + TOPIC_DIGITS);
        assert!(topic.bytes().all(|b| b.is_ascii_alphanumeric()), "{topic}");
        assert_eq!(topic, keys().topic(Way::Up, &LINK, 0), "both ends find one topic");
        assert_ne!(topic, keys().topic(Way::Down, &LINK, 0), "another way");
        assert_ne!(topic, keys().topic(Way::Up, &LinkId([8; 16]), 0), "another link");
        assert_ne!(topic, keys().topic(Way::Up, &LINK, 1), "another piece");
        assert_ne!(topic, Keys::of_pair("relay-pair-name", "another token").topic(Way::Up, &LINK, 0));
        assert_ne!(topic, Keys::of_pair("another-pair", TOKEN).topic(Way::Up, &LINK, 0));
        assert_ne!(topic, keys().door());
        assert!(!topic.contains(&TOKEN[..8]) && !topic.contains("relay"), "a topic names neither");
    }

    #[test]
    fn a_seal_opens_only_with_its_key_its_kind_and_its_place() {
        let plain = b"the layer's bytes";
        let sealed = keys().seal(Kind::Piece, Way::Up, &LINK, 3, plain, &mut OsEntropy).unwrap();
        assert_eq!(sealed.len(), plain.len() + OVERHEAD);
        assert!(!sealed.windows(plain.len()).any(|w| w == plain), "no plaintext in the seal");
        assert_eq!(keys().open(Kind::Piece, Way::Up, &LINK, 3, &sealed).as_deref(), Some(&plain[..]));
        assert!(keys().open(Kind::Note, Way::Up, &LINK, 3, &sealed).is_none(), "another kind");
        assert!(keys().open(Kind::Piece, Way::Down, &LINK, 3, &sealed).is_none(), "another way");
        assert!(keys().open(Kind::Piece, Way::Up, &LinkId([8; 16]), 3, &sealed).is_none(), "another link");
        assert!(keys().open(Kind::Piece, Way::Up, &LINK, 4, &sealed).is_none(), "another number");
        assert!(Keys::from_bytes([1; 32]).open(Kind::Piece, Way::Up, &LINK, 3, &sealed).is_none(), "another key");
        let mut changed = sealed.clone();
        changed[NONCE_BYTES] ^= 1;
        assert!(keys().open(Kind::Piece, Way::Up, &LINK, 3, &changed).is_none(), "a changed byte");
        assert!(keys().open(Kind::Piece, Way::Up, &LINK, 3, &sealed[..OVERHEAD - 1]).is_none());
        let empty = keys().seal(Kind::Piece, Way::Up, &LINK, 9, b"", &mut OsEntropy).unwrap();
        assert_eq!(keys().open(Kind::Piece, Way::Up, &LINK, 9, &empty), Some(Vec::new()), "the end of a way");
        let again = keys().seal(Kind::Piece, Way::Up, &LINK, 3, plain, &mut OsEntropy).unwrap();
        assert_ne!(again, sealed, "a fresh nonce for each seal");
    }

    #[test]
    fn nothing_shows_the_key() {
        assert_eq!(format!("{:?}", keys()), "Keys(<redacted>)");
        assert_eq!(format!("{LINK:?}"), "LinkId(07070707)");
        assert_eq!(hex(&[0x00, 0x7f, 0xff]), "007fff");
    }
}
