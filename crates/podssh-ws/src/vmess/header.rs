//! VMess's request header in the AEAD form, and its answer
//! (`proxy/vmess/encoding/client.go`, `aead/encrypt.go` of Xray-core): the
//! header names the body's keys, the cipher and the target, ends in its
//! FNV-1a, and goes sealed under keys from the user's key, the auth ID and a
//! nonce of the connection. The answer's header is sealed under keys from
//! the body's keys, and repeats the byte that the request chose.

use sha2::{Digest, Sha256};

use super::body::Cipher;
use super::kdf::{self, kdf12, kdf16};
use crate::crypto::aead::{Aead, AeadId};

const VERSION: u8 = 1;
/// The option S: the body in chunks, each with its length in clear. No M
/// (the length masked by SHAKE-128, which no crate of the workspace has),
/// no P, no authenticated length.
const OPTION_CHUNK_STREAM: u8 = 0x01;
const COMMAND_TCP: u8 = 1;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_NAME: u8 = 2;
const ADDRESS_IPV6: u8 = 3;
/// The sealed length of the answer's header: 2 bytes and a tag.
pub const ANSWER_LEN: usize = 2 + 16;

/// The keys of one session: the request's, chosen at random, and the
/// answer's, their SHA-256 (the AEAD form's rule); the byte that the answer
/// must repeat.
#[derive(Clone)]
pub struct Keys {
    pub request_key: [u8; 16],
    pub request_iv: [u8; 16],
    pub answer_key: [u8; 16],
    pub answer_iv: [u8; 16],
    pub check: u8,
}

impl Keys {
    /// From 33 random bytes: the key, the IV and the byte.
    pub fn new(random: &[u8; 33]) -> Keys {
        let mut request_key = [0u8; 16];
        let mut request_iv = [0u8; 16];
        request_key.copy_from_slice(&random[..16]);
        request_iv.copy_from_slice(&random[16..32]);
        let mut answer_key = [0u8; 16];
        let mut answer_iv = [0u8; 16];
        answer_key.copy_from_slice(&Sha256::digest(request_key)[..16]);
        answer_iv.copy_from_slice(&Sha256::digest(request_iv)[..16]);
        Keys { request_key, request_iv, answer_key, answer_iv, check: random[32] }
    }
}

/// The request header in clear: for TCP to `host:port`, with `padding`
/// (at most 15 bytes) before the checksum.
pub fn request(keys: &Keys, cipher: Cipher, host: &str, port: u16, padding: &[u8]) -> Result<Vec<u8>, String> {
    let pad = u8::try_from(padding.len()).ok().filter(|n| *n < 16).ok_or("padding of 16 bytes or more")?;
    let mut out = vec![VERSION];
    out.extend_from_slice(&keys.request_iv);
    out.extend_from_slice(&keys.request_key);
    out.extend_from_slice(&[keys.check, OPTION_CHUNK_STREAM, (pad << 4) | cipher.code(), 0, COMMAND_TCP]);
    out.extend_from_slice(&port.to_be_bytes());
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            out.push(ADDRESS_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            out.push(ADDRESS_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let len = u8::try_from(bare.len()).ok().filter(|n| *n > 0).ok_or("a name of 1 to 255 bytes")?;
            out.push(ADDRESS_NAME);
            out.push(len);
            out.extend_from_slice(bare.as_bytes());
        }
    }
    out.extend_from_slice(padding);
    let check = kdf::fnv1a(&out);
    out.extend_from_slice(&check.to_be_bytes());
    Ok(out)
}

/// The header sealed for the user's key: the auth ID (the time `unix` and
/// 4 random bytes), the sealed length, the connection's nonce, the sealed
/// header. Each seal's associated data is the auth ID.
pub fn seal(cmd_key: &[u8; 16], plain: &[u8], unix: u64, random: [u8; 4], nonce: [u8; 8]) -> Option<Vec<u8>> {
    let auth = kdf::auth_id(cmd_key, unix, random);
    let len = u16::try_from(plain.len()).ok()?.to_be_bytes();
    let path = |label: &'static [u8]| -> [&[u8]; 3] { [label, &auth[..], &nonce[..]] };
    let len_aead = Aead::new(AeadId::Aes128Gcm, &kdf16(cmd_key, &path(kdf::HEADER_LEN_KEY))).ok()?;
    let mut sealed_len = len.to_vec();
    len_aead.seal_in_place(&kdf12(cmd_key, &path(kdf::HEADER_LEN_IV)), &auth, &mut sealed_len)?;
    let aead = Aead::new(AeadId::Aes128Gcm, &kdf16(cmd_key, &path(kdf::HEADER_KEY))).ok()?;
    let mut sealed = plain.to_vec();
    aead.seal_in_place(&kdf12(cmd_key, &path(kdf::HEADER_IV)), &auth, &mut sealed)?;
    Some([&auth[..], &sealed_len, &nonce[..], &sealed].concat())
}

/// The length of the answer's header from its first 18 bytes, or `None`
/// where they do not open under the session's keys.
pub fn answer_len(keys: &Keys, sealed: &[u8; ANSWER_LEN]) -> Option<usize> {
    let aead = Aead::new(AeadId::Aes128Gcm, &kdf16(&keys.answer_key, &[kdf::RESP_LEN_KEY])).ok()?;
    let mut buf = *sealed;
    let n = aead.open_in_place(&kdf12(&keys.answer_iv, &[kdf::RESP_LEN_IV]), &[], &mut buf)?;
    (n == 2).then(|| usize::from(u16::from_be_bytes([buf[0], buf[1]])))
}

/// The answer's header opened (its length and a tag), and whether it
/// repeats the request's byte: `None` where it does not open, `Some(false)`
/// where the byte is another.
pub fn answer(keys: &Keys, sealed: &mut [u8]) -> Option<bool> {
    let aead = Aead::new(AeadId::Aes128Gcm, &kdf16(&keys.answer_key, &[kdf::RESP_KEY])).ok()?;
    let n = aead.open_in_place(&kdf12(&keys.answer_iv, &[kdf::RESP_IV]), &[], sealed)?;
    (n >= 4).then(|| sealed[0] == keys.check)
}

#[cfg(test)]
#[path = "header_tests.rs"]
mod tests;
