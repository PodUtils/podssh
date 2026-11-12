//! TURN's messages on STUN's codec (`pod_proxy::stun`): the methods and
//! attributes of RFC 8656 and RFC 6062, the long-term credential's key, and
//! MESSAGE-INTEGRITY and FINGERPRINT, written and checked here because the
//! codec of pod-proxy reads and writes attributes alone. Pure Rust, no I/O.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::stun::{self, TransactionId, HEADER};

/// The methods (RFC 8656, 17; RFC 6062, 6.1). A request's type is the
/// method itself, as each is below 0x10.
pub const ALLOCATE: u16 = 0x0003;
pub const REFRESH: u16 = 0x0004;
pub const CONNECT: u16 = 0x000a;
pub const CONNECTION_BIND: u16 = 0x000b;
pub const CONNECTION_ATTEMPT: u16 = 0x000c;

/// The classes of a type, for a method below 0x10 (RFC 8489, 5).
pub const SUCCESS: u16 = 0x0100;
pub const ERROR: u16 = 0x0110;
pub const INDICATION: u16 = 0x0010;

/// The attributes (RFC 8489, 18.3; RFC 8656, 18; RFC 6062, 6.2).
pub const USERNAME: u16 = 0x0006;
pub const MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ERROR_CODE: u16 = stun::ERROR_CODE;
pub const LIFETIME: u16 = 0x000d;
pub const XOR_PEER_ADDRESS: u16 = 0x0012;
pub const REALM: u16 = 0x0014;
pub const NONCE: u16 = 0x0015;
pub const XOR_RELAYED_ADDRESS: u16 = 0x0016;
pub const REQUESTED_ADDRESS_FAMILY: u16 = 0x0017;
pub const REQUESTED_TRANSPORT: u16 = 0x0019;
pub const CONNECTION_ID: u16 = 0x002a;
pub const SOFTWARE: u16 = stun::SOFTWARE;
pub const FINGERPRINT: u16 = 0x8028;

/// TCP's protocol number in REQUESTED-TRANSPORT (RFC 6062, 4.1).
pub const TCP: u8 = 6;
/// The length of MESSAGE-INTEGRITY's value: HMAC-SHA1.
const MAC: usize = 20;
/// FINGERPRINT's XOR, "STUN" (RFC 8489, 14.7).
const FINGERPRINT_XOR: u32 = 0x5354_554e;

/// The type of `method`'s success and error responses.
pub fn success(method: u16) -> u16 {
    method | SUCCESS
}

pub fn error(method: u16) -> u16 {
    method | ERROR
}

/// The long-term credential's key (RFC 8489, 9.2.2):
/// MD5(username ":" realm ":" password). The password is taken as its
/// bytes: SASLprep changes no ASCII password, and coturn applies none.
pub fn long_term_key(user: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut ctx = md5::Context::new();
    ctx.consume(user.as_bytes());
    ctx.consume(b":");
    ctx.consume(realm.as_bytes());
    ctx.consume(b":");
    ctx.consume(password.as_bytes());
    ctx.finalize().0
}

/// A message of `kind` with `attributes`, then MESSAGE-INTEGRITY over it
/// with `key` when one is given: the header's length counts the MAC's
/// attribute before the HMAC is taken (RFC 8489, 14.5).
pub fn signed(kind: u16, id: &TransactionId, attributes: &[(u16, &[u8])], key: Option<&[u8]>) -> Vec<u8> {
    let Some(key) = key else { return stun::message(kind, id, attributes) };
    let mut all: Vec<(u16, &[u8])> = attributes.to_vec();
    let blank = [0u8; MAC];
    all.push((MESSAGE_INTEGRITY, &blank));
    let mut out = stun::message(kind, id, &all);
    let at = out.len() - MAC;
    let mac = hmac(key, &out[..at - 4]);
    out[at..].copy_from_slice(&mac);
    out
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; MAC] {
    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// The offset in `bytes` of the first attribute of `kind`'s header, read
/// as `stun::parse` reads: the caller parsed the message first.
fn offset_of(bytes: &[u8], kind: u16) -> Option<usize> {
    let mut at = HEADER;
    while at + 4 <= bytes.len() {
        let attribute = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        if attribute == kind {
            return Some(at);
        }
        let len = usize::from(u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]));
        at += 4 + len + (4 - len % 4) % 4;
    }
    None
}

/// Whether `bytes`, a whole message, carries a MESSAGE-INTEGRITY that `key`
/// signed: the HMAC over the message up to the attribute, with the header's
/// length as if the message ended after it (RFC 8489, 14.5). `None` with
/// no MESSAGE-INTEGRITY.
pub fn integrity(bytes: &[u8], key: &[u8]) -> Option<bool> {
    let at = offset_of(bytes, MESSAGE_INTEGRITY)?;
    if bytes.len() < at + 4 + MAC {
        return Some(false);
    }
    let mut head = bytes[..at].to_vec();
    let length = (at + 4 + MAC - HEADER) as u16;
    head[2..4].copy_from_slice(&length.to_be_bytes());
    let want = hmac(key, &head);
    // A comparison in constant time, as the HMAC's own verify would make.
    let got = &bytes[at + 4..at + 4 + MAC];
    Some(want.iter().zip(got).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0)
}

/// Whether `bytes` carries a FINGERPRINT that matches it (RFC 8489, 14.7);
/// `None` with none. A server may add one; podssh sends none.
pub fn fingerprint_ok(bytes: &[u8]) -> Option<bool> {
    let at = offset_of(bytes, FINGERPRINT)?;
    if bytes.len() < at + 8 {
        return Some(false);
    }
    let want = crc32(&bytes[..at]) ^ FINGERPRINT_XOR;
    Some(bytes[at + 4..at + 8] == want.to_be_bytes())
}

/// CRC-32 of ISO 3309, as FINGERPRINT takes it: a few bytes of a message,
/// not worth a crate.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let low = crc & 1;
            crc >>= 1;
            if low == 1 {
                crc ^= 0xedb8_8320;
            }
        }
    }
    !crc
}

/// REQUESTED-TRANSPORT's value for TCP: the protocol, then RFFU zeros.
pub fn requested_tcp() -> [u8; 4] {
    [TCP, 0, 0, 0]
}

/// REQUESTED-ADDRESS-FAMILY's value for IPv6 (RFC 8656, 18.11); IPv4 is
/// the default, and no attribute asks it.
pub fn family_v6() -> [u8; 4] {
    [0x02, 0, 0, 0]
}

/// A 32-bit attribute's value: LIFETIME's seconds, CONNECTION-ID's id.
pub fn u32_of(value: &[u8]) -> Option<u32> {
    <[u8; 4]>::try_from(value).ok().map(u32::from_be_bytes)
}

/// The credential of coturn's `use-auth-secret` (its "TURN REST API"): the
/// user `EXPIRY:podssh`, EXPIRY in seconds since 1970, and the password
/// base64(HMAC-SHA1(secret, user)), as coturn checks it.
pub fn rest_credential(secret: &[u8], expiry: u64) -> (String, String) {
    use base64::Engine as _;
    let user = format!("{expiry}:podssh");
    let mac = hmac(secret, user.as_bytes());
    (user, base64::engine::general_purpose::STANDARD.encode(mac))
}

#[cfg(test)]
#[path = "msg_tests.rs"]
mod tests;
