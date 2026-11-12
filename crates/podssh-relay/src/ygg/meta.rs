//! Yggdrasil's `meta` handshake, the first bytes each way of a link: `meta`,
//! the length of the rest in two bytes of the network's order, fields of a
//! type and a length in two bytes each (the major and the minor version,
//! the Ed25519 key, the priority), then an Ed25519 signature of the BLAKE2b-512
//! of the key, so that an end proves the key that it names. A field of a type
//! that this end does not know is skipped, as a newer end may send one. No
//! password: the public network has none.

use std::io;

use blake2::{Blake2b512, Digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// The protocol's version that this end speaks: 0.5, as yggdrasil-go's.
pub const MAJOR: u16 = 0;
pub const MINOR: u16 = 5;
const PREAMBLE: &[u8; 4] = b"meta";
const SIGNATURE: usize = 64;
/// The fields' types.
const FIELD_MAJOR: u16 = 0;
const FIELD_MINOR: u16 = 1;
const FIELD_KEY: u16 = 2;
const FIELD_PRIORITY: u16 = 3;
/// The longest handshake that this end reads.
const MOST: usize = 1024;

/// What an end said of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub major: u16,
    pub minor: u16,
    pub key: [u8; 32],
    pub priority: u8,
}

fn digest(key: &[u8; 32]) -> [u8; 64] {
    Blake2b512::digest(key).into()
}

fn field(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// This end's handshake, signed with `secret`.
pub fn encode(secret: &SigningKey, priority: u8) -> Vec<u8> {
    let key = secret.verifying_key().to_bytes();
    let mut out = PREAMBLE.to_vec();
    out.extend_from_slice(&[0, 0]);
    field(&mut out, FIELD_MAJOR, &MAJOR.to_be_bytes());
    field(&mut out, FIELD_MINOR, &MINOR.to_be_bytes());
    field(&mut out, FIELD_KEY, &key);
    field(&mut out, FIELD_PRIORITY, &[priority]);
    out.extend_from_slice(&secret.sign(&digest(&key)).to_bytes());
    let len = (out.len() - 6) as u16;
    out[4..6].copy_from_slice(&len.to_be_bytes());
    out
}

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("the peer's handshake: {why}"))
}

/// The fields and the signature after the header, checked.
pub fn decode(body: &[u8]) -> io::Result<Meta> {
    if body.len() < SIGNATURE {
        return Err(invalid("too short"));
    }
    let (mut fields, signature) = body.split_at(body.len() - SIGNATURE);
    let mut meta = Meta { major: u16::MAX, minor: 0, key: [0; 32], priority: 0 };
    let mut keyed = false;
    while !fields.is_empty() {
        let (Some(kind), Some(len)) = (fields.get(..2), fields.get(2..4)) else { return Err(invalid("a cut field")) };
        let (kind, len) = (u16::from_be_bytes([kind[0], kind[1]]), usize::from(u16::from_be_bytes([len[0], len[1]])));
        let value = fields.get(4..4 + len).ok_or_else(|| invalid("a field past the end"))?;
        match (kind, len) {
            (FIELD_MAJOR, 2) => meta.major = u16::from_be_bytes([value[0], value[1]]),
            (FIELD_MINOR, 2) => meta.minor = u16::from_be_bytes([value[0], value[1]]),
            (FIELD_KEY, 32) => {
                meta.key.copy_from_slice(value);
                keyed = true;
            }
            (FIELD_PRIORITY, 1) => meta.priority = value[0],
            (FIELD_MAJOR | FIELD_MINOR | FIELD_KEY | FIELD_PRIORITY, _) => {
                return Err(invalid("a field of a wrong length"))
            }
            _ => {}
        }
        fields = &fields[4 + len..];
    }
    if !keyed {
        return Err(invalid("no key"));
    }
    if meta.major != MAJOR || meta.minor < MINOR {
        return Err(invalid(&format!("the version {}.{}, not {MAJOR}.{MINOR}", meta.major, meta.minor)));
    }
    if !ironwood::is_public_key_valid(&meta.key) {
        return Err(invalid("a key of a low order"));
    }
    let verifying = VerifyingKey::from_bytes(&meta.key).map_err(|_| invalid("no Ed25519 key"))?;
    let signature = Signature::from_bytes(signature.try_into().map_err(|_| invalid("no signature"))?);
    verifying.verify(&digest(&meta.key), &signature).map_err(|_| invalid("its signature does not hold"))?;
    Ok(meta)
}

/// The handshake both ways on `io`: this end's, then the peer's, checked;
/// a peer of this end's own key is refused, as a link to oneself.
pub async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
    secret: &SigningKey,
    priority: u8,
) -> io::Result<Meta> {
    io.write_all(&encode(secret, priority)).await?;
    io.flush().await?;
    let mut header = [0u8; 6];
    io.read_exact(&mut header).await?;
    if &header[..4] != PREAMBLE {
        return Err(invalid("no preamble"));
    }
    let len = usize::from(u16::from_be_bytes([header[4], header[5]]));
    if len > MOST {
        return Err(invalid("too long"));
    }
    let mut body = vec![0u8; len];
    io.read_exact(&mut body).await?;
    let meta = decode(&body)?;
    if meta.key == secret.verifying_key().to_bytes() {
        return Err(invalid("this end's own key"));
    }
    Ok(meta)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_handshake_reads_back_and_a_changed_one_does_not() {
        let secret = SigningKey::from_bytes(&[7; 32]);
        let bytes = encode(&secret, 3);
        assert_eq!(&bytes[..4], b"meta");
        assert_eq!(usize::from(u16::from_be_bytes([bytes[4], bytes[5]])), bytes.len() - 6);
        let meta = decode(&bytes[6..]).unwrap();
        assert_eq!((meta.major, meta.minor, meta.priority), (MAJOR, MINOR, 3));
        assert_eq!(meta.key, secret.verifying_key().to_bytes());
        // Another key in the field, under the first key's signature.
        let mut forged = bytes.clone();
        let other = SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes();
        let at = forged.windows(32).position(|w| w == meta.key).unwrap();
        forged[at..at + 32].copy_from_slice(&other);
        assert!(decode(&forged[6..]).unwrap_err().to_string().contains("signature"));
        // A field of an unknown type is skipped.
        let mut newer = bytes[..6].to_vec();
        field(&mut newer, 9, b"later");
        newer.extend_from_slice(&bytes[6..]);
        assert_eq!(decode(&newer[6..]).unwrap().key, meta.key);
        assert!(decode(&bytes[6..40]).is_err());
    }
}
