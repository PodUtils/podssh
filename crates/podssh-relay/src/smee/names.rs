//! The channels of the road, from the pair's secret. A channel of smee.io is
//! any name of 1 to 128 characters of `[a-zA-Z0-9-_]` that its first use
//! makes, and anyone who knows a name reads and writes it, so a name is the
//! road's only meeting point: each comes from a key that the pair's two ends
//! alone hold, the HMAC of the connect token over the pair's name, under
//! labels of this road's own, so that no name is ever a path of the Piping
//! Server road's. The node reads its door; a client's hello there names a
//! random link id, and each way of that link has a channel of its own, as
//! smee.io gives no poster its own events back and a channel serves one way.
//! Each way begins with a mark of its link and its way, which the reader
//! checks before the layer reads a byte: an end that read its own way, or a
//! stranger's frames, ends the link there.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

pub use crate::piping::paths::LinkId;
use crate::piping::paths::{hex, same};

const KEY_LABEL: &[u8] = b"podssh smee v1 key";
const DOOR_LABEL: &[u8] = b"podssh smee v1 door";
const UP_LABEL: &[u8] = b"podssh smee v1 up";
const DOWN_LABEL: &[u8] = b"podssh smee v1 down";
const UP_MARK_LABEL: &[u8] = b"podssh smee v1 mark up";
const DOWN_MARK_LABEL: &[u8] = b"podssh smee v1 mark down";
const HELLO_LABEL: &[u8] = b"podssh smee v1 hello";
/// The first word of a hello.
pub const HELLO_WORD: &str = "podssh-smee";
/// The version of the hello, the channels and the marks.
pub const VERSION: &str = "1";
/// A channel's name: 128 bits of a MAC, as 32 hex digits, well within
/// smee.io's 128 characters.
const NAME_BYTES: usize = 16;
/// The mark that begins each way.
pub const MARK_BYTES: usize = 16;
const TAG_BYTES: usize = 16;
/// The longest hello that a node reads.
pub const HELLO_MAX: usize = 256;
/// smee.io's bound of a channel's name (`lib/server.js`, its schema).
pub const NAME_MAX: usize = 128;

/// A way of a link: up from the client to the node, or down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Way {
    Up,
    Down,
}

/// The road's key for one pair. Never shown.
pub struct Secret(Zeroizing<[u8; 32]>);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Secret {
    /// The key of the pair `name`, whose two ends hold `connect_token`. The
    /// token keys the MAC, so that nothing derived from it shows it.
    pub fn of_pair(name: &str, connect_token: &str) -> Secret {
        Secret(Zeroizing::new(mac(connect_token.as_bytes(), KEY_LABEL, &[name.as_bytes()])))
    }

    /// A key of these bytes, for a test.
    pub fn from_bytes(bytes: [u8; 32]) -> Secret {
        Secret(Zeroizing::new(bytes))
    }

    fn mac(&self, label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        mac(&self.0[..], label, parts)
    }

    /// The channel of the node's door.
    pub fn door(&self) -> String {
        hex(&self.mac(DOOR_LABEL, &[])[..NAME_BYTES])
    }

    /// The channel of `way` of `link`.
    pub fn channel(&self, way: Way, link: &LinkId) -> String {
        let label = match way {
            Way::Up => UP_LABEL,
            Way::Down => DOWN_LABEL,
        };
        hex(&self.mac(label, &[&link.0])[..NAME_BYTES])
    }

    /// The mark that begins `way` of `link`.
    pub fn mark(&self, way: Way, link: &LinkId) -> [u8; MARK_BYTES] {
        let label = match way {
            Way::Up => UP_MARK_LABEL,
            Way::Down => DOWN_MARK_LABEL,
        };
        let mut mark = [0u8; MARK_BYTES];
        mark.copy_from_slice(&self.mac(label, &[&link.0])[..MARK_BYTES]);
        mark
    }

    fn tag(&self, link: &LinkId) -> [u8; 32] {
        self.mac(HELLO_LABEL, &[&link.0])
    }

    /// A client's hello at the door: the version, the link's id and a tag of
    /// the key, so that the node opens no link for a hello of another pair's
    /// or a stranger's, who can read and write the door as well.
    pub fn hello(&self, link: &LinkId) -> String {
        let tag = self.tag(link);
        format!("{HELLO_WORD} {VERSION} {} {}", hex(&link.0), hex(&tag[..TAG_BYTES]))
    }

    /// The link of a hello that this key's [`Secret::hello`] wrote; else why
    /// not.
    pub fn read_hello(&self, text: &str) -> Result<LinkId, String> {
        if text.len() > HELLO_MAX {
            return Err(format!("a hello of {} bytes", text.len()));
        }
        let words: Vec<&str> = text.split_ascii_whitespace().collect();
        let &[word, version, link, tag] = words.as_slice() else {
            return Err(format!("a hello of {} words, not 4", words.len()));
        };
        if word != HELLO_WORD {
            return Err("not a hello of podssh's smee.io road".into());
        }
        if version != VERSION {
            let shown = podssh_ws::text::one_line(&version.chars().take(16).collect::<String>());
            return Err(format!("a hello of version {shown}, which this podssh does not read"));
        }
        let link = unhex(link).filter(|b| b.len() == 16).ok_or("a hello whose link is not 32 hex digits")?;
        let tag = unhex(tag).filter(|b| b.len() == TAG_BYTES).ok_or("a hello whose tag is not 32 hex digits")?;
        let mut id = [0u8; 16];
        id.copy_from_slice(&link);
        let id = LinkId(id);
        if !same(&self.tag(&id)[..TAG_BYTES], &tag) {
            return Err("a hello of another key: another pair's client, or a stranger's".into());
        }
        Ok(id)
    }
}

/// What one end of a link posts and reads: the channel of its own way, the
/// channel of the far end's, the mark that it sends first, and the one that
/// it must read first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ends {
    pub send: String,
    pub recv: String,
    pub mine: [u8; MARK_BYTES],
    pub theirs: [u8; MARK_BYTES],
}

impl Ends {
    /// The client's: it posts up, and reads down.
    pub fn client(secret: &Secret, link: &LinkId) -> Ends {
        Ends::of(secret, link, Way::Up, Way::Down)
    }

    /// The node's: it posts down, and reads up.
    pub fn node(secret: &Secret, link: &LinkId) -> Ends {
        Ends::of(secret, link, Way::Down, Way::Up)
    }

    fn of(secret: &Secret, link: &LinkId, send: Way, recv: Way) -> Ends {
        Ends {
            send: secret.channel(send, link),
            recv: secret.channel(recv, link),
            mine: secret.mark(send, link),
            theirs: secret.mark(recv, link),
        }
    }
}

/// Whether `name` is a channel that smee.io takes: 1 to 128 characters of
/// `[a-zA-Z0-9-_]`.
pub fn is_channel(name: &str) -> bool {
    (1..=NAME_MAX).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// HMAC-SHA256 under `key` of `label`, a 0 byte, and each part after its
/// length, so that two lists of parts never give one input.
fn mac(key: &[u8], label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // HMAC takes a key of each length, so `new_from_slice` cannot fail.
    let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
        Ok(mac) => mac,
        Err(_) => <Hmac<Sha256> as KeyInit>::new(&Default::default()),
    };
    mac.update(label);
    mac.update(&[0]);
    for part in parts {
        mac.update(&(part.len() as u32).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The bytes of hex in either case; `None` for another character or an odd
/// length.
fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    text.as_bytes().chunks(2).map(|pair| Some((digit(pair[0])? << 4) | digit(pair[1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::piping::paths::Secret as PipingSecret;

    const TOKEN: &str = "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr";
    const LINK: LinkId = LinkId([7; 16]);

    fn secret() -> Secret {
        Secret::of_pair("relay-pair-name", TOKEN)
    }

    #[test]
    fn the_client_posts_where_the_node_reads_and_reads_where_the_node_posts() {
        let (client, node) = (Ends::client(&secret(), &LINK), Ends::node(&secret(), &LINK));
        assert_eq!(client.send, node.recv, "the up way: the client's POST is the node's stream");
        assert_eq!(client.recv, node.send, "the down way: the node's POST is the client's stream");
        assert_eq!((client.mine, client.theirs), (node.theirs, node.mine));
        assert_ne!(client.send, client.recv, "the two ways never share a channel");
        assert_ne!(client.mine, client.theirs, "nor a mark");
    }

    #[test]
    fn each_channel_is_one_that_smee_io_takes_and_names_neither_the_token_nor_the_pair() {
        let door = secret().door();
        for name in [door.clone(), secret().channel(Way::Up, &LINK), secret().channel(Way::Down, &LINK)] {
            assert!(is_channel(&name) && name.len() == 32, "{name}");
            assert!(!name.contains(&TOKEN[..8]) && !name.contains("relay"), "{name}");
        }
        assert_eq!(door, secret().door(), "a node and a client find one door");
        assert_ne!(door, Secret::of_pair("relay-pair-name", "another token").door());
        assert_ne!(door, Secret::of_pair("another-pair", TOKEN).door());
        assert_ne!(secret().channel(Way::Up, &LINK), secret().channel(Way::Up, &LinkId([8; 16])));
        assert!(!is_channel("") && !is_channel(&"a".repeat(129)) && !is_channel("a/b") && !is_channel("a.b"));
    }

    #[test]
    fn no_channel_of_this_road_is_a_path_of_the_piping_server_road() {
        let piping = PipingSecret::of_pair("relay-pair-name", TOKEN);
        assert_ne!(secret().door(), piping.door(), "the labels differ");
        let ways = [crate::piping::paths::Way::Up, crate::piping::paths::Way::Down];
        for way in ways {
            let path = piping.path(way, &LINK);
            assert_ne!(path, secret().channel(Way::Up, &LINK));
            assert_ne!(path, secret().channel(Way::Down, &LINK));
        }
    }

    #[test]
    fn a_hello_comes_back_as_it_went_and_one_of_another_key_or_shape_is_refused() {
        let hello = secret().hello(&LINK);
        assert!(hello.len() <= HELLO_MAX, "{hello}");
        assert_eq!(secret().read_hello(&hello), Ok(LINK));
        assert_eq!(secret().read_hello(&hello.to_uppercase().replace("PODSSH-SMEE", HELLO_WORD)), Ok(LINK));
        let stranger = Secret::from_bytes([1; 32]);
        assert!(stranger.read_hello(&hello).unwrap_err().contains("another key"));
        assert!(secret().read_hello(&hello.replace(" 1 ", " 2 ")).unwrap_err().contains("version 2"));
        for bad in ["", "podssh-smee 1", "podssh-piping 1 00 00", "podssh-smee 1 zz 00"] {
            assert!(secret().read_hello(bad).is_err(), "{bad:?}");
        }
        assert!(secret().read_hello(&"a".repeat(HELLO_MAX + 1)).is_err());
        assert_eq!(format!("{:?}", secret()), "Secret(<redacted>)");
    }
}
