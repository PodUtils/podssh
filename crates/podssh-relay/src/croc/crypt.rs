//! croc's crypt of the relay's handshake (schollz/croc:src/crypt/crypt.go at
//! v11.6.4): the key is PBKDF2-HMAC-SHA256 of the PAKE's key, with a salt of
//! 8 random bytes that the client sends, 100 rounds, 32 bytes; each message
//! is AES-256-GCM, its 12-byte nonce first, then the ciphertext and the tag,
//! with no associated data.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, KeyInit as MacInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::session::secret::{Entropy, NoRandom};

/// croc's rounds of PBKDF2 (`crypt.New`).
pub const ROUNDS: u32 = 100;
/// The bytes of the salt that croc's client draws.
pub const SALT_BYTES: usize = 8;
/// AES-GCM's nonce and tag.
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;

/// PBKDF2-HMAC-SHA256 of `password` and `salt`, `rounds` rounds, one block
/// of 32 bytes (RFC 8018 section 5.2), which is all that croc takes.
pub fn pbkdf2(password: &[u8], salt: &[u8], rounds: u32) -> Zeroizing<[u8; 32]> {
    let prf = || -> Hmac<Sha256> {
        // A key of any length is valid for HMAC.
        match Hmac::<Sha256>::new_from_slice(password) {
            Ok(mac) => mac,
            Err(_) => <Hmac<Sha256> as MacInit>::new(&Default::default()),
        }
    };
    let mut mac = prf();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u = Zeroizing::new([0u8; 32]);
    u.copy_from_slice(mac.finalize().into_bytes().as_slice());
    let mut out = Zeroizing::new(*u);
    for _ in 1..rounds.max(1) {
        let mut mac = prf();
        mac.update(&u[..]);
        u.copy_from_slice(mac.finalize().into_bytes().as_slice());
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    out
}

/// The key of the relay's messages, from the PAKE's key and the salt.
pub fn key(pake_key: &[u8], salt: &[u8]) -> Zeroizing<[u8; 32]> {
    pbkdf2(pake_key, salt, ROUNDS)
}

/// `plain` sealed under `key`: a random nonce, then the ciphertext and tag.
pub fn seal(key: &[u8; 32], plain: &[u8], entropy: &mut dyn Entropy) -> Result<Vec<u8>, NoRandom> {
    let mut nonce = [0u8; NONCE_BYTES];
    entropy.fill(&mut nonce)?;
    Ok(seal_with(key, &nonce, plain))
}

/// The same with a nonce given: for the vectors of a test.
pub fn seal_with(key: &[u8; 32], nonce: &[u8; NONCE_BYTES], plain: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(&(*key).into());
    let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = (*nonce).into();
    // AES-GCM seals any message below 64 GiB; a failure would be a bug of
    // the crate, and an empty message is refused at the far end.
    let sealed = cipher.encrypt(&gcm, plain).unwrap_or_default();
    [nonce.as_slice(), sealed.as_slice()].concat()
}

/// A message of croc's opened under `key`; `None` when it is too short or
/// its tag is not the key's.
pub fn open(key: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return None;
    }
    let (nonce, body) = sealed.split_at(NONCE_BYTES);
    let nonce: [u8; NONCE_BYTES] = nonce.try_into().ok()?;
    let gcm: aes_gcm::Nonce<aes_gcm::aead::consts::U12> = nonce.into();
    Aes256Gcm::new(&(*key).into()).decrypt(&gcm, body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // Python's hashlib.pbkdf2_hmac (software that podssh did not write): the
    // common vectors of 1 and 2 rounds, and croc's 100.
    #[test]
    fn pbkdf2_is_rfc_8018_s_as_hashlib_computes_it() {
        assert_eq!(
            hex(&pbkdf2(b"password", b"salt", 1)[..]),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        assert_eq!(
            hex(&pbkdf2(b"password", b"salt", 2)[..]),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        let pake = [
            0x30, 0xd6, 0x49, 0x76, 0x89, 0xdd, 0x7a, 0xa3, 0x74, 0x01, 0x19, 0xe8, 0x5e, 0x9f, 0xa6, 0x1b, 0x3c, 0x96,
            0x77, 0xed, 0xf1, 0x13, 0x00, 0x2e, 0x46, 0xbb, 0xd0, 0xca, 0x78, 0x3f, 0xc0, 0x58,
        ];
        let salt = [0, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(hex(&key(&pake, &salt)[..]), "a1cf8718f4873853d4d11f406d35b2c7ecc4cc98c07c926384c38f5bed421ef7");
    }

    // The GCM paper's test cases 13 and 14 (AES-256, a key and a nonce of
    // zeros), and Python's `cryptography` for the password's message.
    #[test]
    fn a_message_is_its_nonce_then_aes_256_gcm() {
        let zeros = [0u8; 32];
        assert_eq!(hex(&seal_with(&zeros, &[0; 12], b"")[12..]), "530f8afbc74536b9a963b4f1c4cb738b");
        assert_eq!(
            hex(&seal_with(&zeros, &[0; 12], &[0; 16])[12..]),
            "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"
        );
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let nonce: [u8; 12] = std::array::from_fn(|i| 100 + i as u8);
        let sealed = seal_with(&key, &nonce, b"pass123");
        assert_eq!(hex(&sealed), "6465666768696a6b6c6d6e6f387aad1548db650da67bdbe7fc76fba3ee90efaf82b8c2");
        assert_eq!(open(&key, &sealed).as_deref(), Some(&b"pass123"[..]));
    }

    #[test]
    fn a_message_cut_short_or_of_another_key_does_not_open() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"room", &mut crate::session::OsEntropy).unwrap();
        assert_eq!(open(&key, &sealed).as_deref(), Some(&b"room"[..]));
        assert!(open(&[8u8; 32], &sealed).is_none());
        assert!(open(&key, &sealed[..sealed.len() - 1]).is_none());
        assert!(open(&key, &sealed[..NONCE_BYTES + TAG_BYTES - 1]).is_none());
    }
}
