//! The keys of VMess's AEAD form, as v2fly wrote them and Xray-core keeps
//! them (`proxy/vmess/aead/kdf.go`, `authid.go`): a nested HMAC-SHA-256
//! whose innermost key is a constant and whose each label keys one more HMAC
//! over the one inside; the auth ID, which holds the time and a CRC-32 under
//! AES; and FNV-1a, the request header's checksum. The two checksums are a
//! few lines each, as no crate of the workspace has them.

use aes::cipher::BlockCipherEncrypt;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The innermost HMAC's key.
const ROOT: &[u8] = b"VMess AEAD KDF";
/// SHA-256's block, which each HMAC of the nest pads its key to.
const BLOCK: usize = 64;

pub const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
pub const RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
pub const RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
pub const RESP_KEY: &[u8] = b"AEAD Resp Header Key";
pub const RESP_IV: &[u8] = b"AEAD Resp Header IV";
pub const HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
pub const HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
pub const HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
pub const HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

/// The constant that the user's key is the MD5 of, after the UUID.
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";

/// KDF(key, path...): the HMAC keyed by the path's last label, over a hash
/// that is the same nest of the labels before it.
pub fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    nested(path, key)
}

/// The first 16 bytes of [`kdf`]: an AES-128 key.
pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, path)[..16]);
    out
}

/// The first 12 bytes of [`kdf`]: a nonce.
pub fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&kdf(key, path)[..12]);
    out
}

fn nested(path: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((label, inside)) = path.split_last() else {
        // HMAC takes a key of any length, so this never fails.
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(ROOT)
            .unwrap_or_else(|_| <Hmac<Sha256> as KeyInit>::new(&Default::default()));
        mac.update(msg);
        let mut out = [0u8; 32];
        out.copy_from_slice(&mac.finalize().into_bytes());
        return out;
    };
    // HMAC's own rule: a key longer than the block is hashed first, by the
    // hash that it keys. No label of VMess's is.
    let hashed;
    let label: &[u8] = if label.len() > BLOCK {
        hashed = nested(inside, label);
        &hashed
    } else {
        label
    };
    let mut padded = [0u8; BLOCK];
    padded[..label.len()].copy_from_slice(label);
    let first: Vec<u8> = padded.iter().map(|b| b ^ 0x36).chain(msg.iter().copied()).collect();
    let inner = nested(inside, &first);
    let second: Vec<u8> = padded.iter().map(|b| b ^ 0x5c).chain(inner).collect();
    nested(inside, &second)
}

/// The user's key: MD5 of the UUID's 16 bytes and a constant.
pub fn cmd_key(id: &[u8; 16]) -> [u8; 16] {
    let mut hash = md5::Context::new();
    hash.consume(id);
    hash.consume(CMD_KEY_SALT);
    hash.finalize().0
}

/// The auth ID of a request sent at `unix` seconds with `random`: the time,
/// the 4 bytes and their CRC-32, under AES-128 keyed from the user's key.
/// A server takes it within 120 s of its own clock, and once.
pub fn auth_id(cmd_key: &[u8; 16], unix: u64, random: [u8; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&unix.to_be_bytes());
    block[8..12].copy_from_slice(&random);
    let check = crc32(&block[..12]);
    block[12..].copy_from_slice(&check.to_be_bytes());
    let aes = aes::Aes128::new(&kdf16(cmd_key, &[AUTH_ID_KEY]).into());
    let mut sealed = block.into();
    aes.encrypt_block(&mut sealed);
    sealed.into()
}

/// CRC-32 of IEEE 802.3, reflected, as Go's `crc32.ChecksumIEEE`.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// FNV-1a of 32 bits, as Go's `fnv.New32a`.
pub fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn the_checksums_are_go_s() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(fnv1a(b""), 0x811c_9dc5);
        assert_eq!(fnv1a(b"a"), 0xe40c_292c);
    }

    /// With no label the KDF is HMAC-SHA-256 under the constant; with one,
    /// an HMAC whose hash is that HMAC, which a plain HMAC-SHA-256 under the
    /// label is not.
    #[test]
    fn the_kdf_nests_one_hmac_for_each_label() {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(ROOT).unwrap();
        mac.update(b"key");
        assert_eq!(kdf(b"key", &[]).to_vec(), mac.finalize().into_bytes().to_vec());
        let mut plain = <Hmac<Sha256> as KeyInit>::new_from_slice(b"label").unwrap();
        plain.update(b"key");
        assert_ne!(kdf(b"key", &[b"label"]).to_vec(), plain.finalize().into_bytes().to_vec());
        assert_ne!(kdf(b"key", &[b"a", b"b"]), kdf(b"key", &[b"b", b"a"]));
        assert_eq!(hex(&kdf16(b"key", &[b"x"])), hex(&kdf(b"key", &[b"x"])[..16]));
    }

    /// The auth ID opens under the same key to the time, the random bytes
    /// and their CRC-32.
    #[test]
    fn the_auth_id_holds_the_time_and_its_checksum() {
        use aes::cipher::BlockCipherDecrypt;
        let key = cmd_key(&[7u8; 16]);
        let sealed = auth_id(&key, 1_700_000_000, [1, 2, 3, 4]);
        let aes = aes::Aes128::new(&kdf16(&key, &[AUTH_ID_KEY]).into());
        let mut block = sealed.into();
        aes.decrypt_block(&mut block);
        let plain: [u8; 16] = block.into();
        assert_eq!(u64::from_be_bytes(plain[..8].try_into().unwrap()), 1_700_000_000);
        assert_eq!(&plain[8..12], &[1, 2, 3, 4]);
        assert_eq!(u32::from_be_bytes(plain[12..].try_into().unwrap()), crc32(&plain[..12]));
    }
}
