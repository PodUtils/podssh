//! The arithmetic of a one-time code (T-115): RFC 4648's base32 for the
//! secret, RFC 4226's HOTP (HMAC-SHA-1, dynamic truncation) and RFC 6238's
//! TOTP over it, as authenticator apps and `oathtool --totp -b` compute
//! them. No I/O and no clock here: the caller gives the time.

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

/// RFC 6238's time step, the one each authenticator app uses.
pub const STEP: u64 = 30;

/// The digits of a code, as each authenticator app shows them.
pub const DIGITS: u32 = 6;

/// The fewest bytes of a secret: RFC 4226 asks for 128 bits; 80, the length
/// that many apps make, is taken, and less is refused.
pub const LEAST_SECRET: usize = 10;

/// The most bytes of a secret: an HMAC key past SHA-1's block is hashed
/// first, so more adds nothing.
pub const MOST_SECRET: usize = 64;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The bytes of a secret written in base32, as an app shows it: case,
/// spaces, dashes and the padding `=` do not count. Err names what is wrong,
/// never the secret.
pub fn decode_base32(text: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bits: u64 = 0;
    let mut held = 0u32;
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8));
    for c in text.bytes() {
        if c.is_ascii_whitespace() || c == b'-' || c == b'=' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let Some(value) = ALPHABET.iter().position(|&a| a == up) else {
            return Err("it is not base32 (A to Z and 2 to 7)".into());
        };
        bits = (bits << 5) | value as u64;
        held += 5;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    if out.len() < LEAST_SECRET {
        return Err(format!("it holds {} bytes, fewer than {LEAST_SECRET} (80 bits)", out.len()));
    }
    if out.len() > MOST_SECRET {
        return Err(format!("it holds {} bytes, more than {MOST_SECRET}", out.len()));
    }
    Ok(out)
}

/// `bytes` in base32 with no padding, as an app takes it.
pub fn encode_base32(bytes: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(bytes.len().div_ceil(5) * 8));
    let (mut bits, mut held) = (0u64, 0u32);
    for &b in bytes {
        bits = (bits << 8) | u64::from(b);
        held += 8;
        while held >= 5 {
            held -= 5;
            out.push(ALPHABET[((bits >> held) & 31) as usize] as char);
        }
        bits &= (1 << held) - 1;
    }
    if held > 0 {
        out.push(ALPHABET[((bits << (5 - held)) & 31) as usize] as char);
    }
    out
}

/// RFC 4226's HOTP of `counter` under `secret`, `digits` long (6 to 9);
/// None where HMAC refuses the key, which it never does for these lengths.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> Option<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let hash = mac.finalize().into_bytes();
    let offset = usize::from(hash.last()? & 0x0f);
    let part = hash.get(offset..offset + 4)?;
    let number = u32::from_be_bytes([part[0] & 0x7f, part[1], part[2], part[3]]);
    Some(number % 10u32.checked_pow(digits)?)
}

/// The time step of `unix` seconds.
pub fn step_of(unix: u64) -> u64 {
    unix / STEP
}

/// The code of `step`, as its six digits with the zeros in front.
pub fn code_of(secret: &[u8], step: u64) -> Option<Zeroizing<String>> {
    hotp(secret, step, DIGITS).map(|n| Zeroizing::new(format!("{n:06}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238, appendix B: the SHA-1 rows, eight digits, the secret
    /// "12345678901234567890".
    #[test]
    fn the_vectors_of_rfc_6238_pass() {
        let secret = b"12345678901234567890";
        let rows: [(u64, u32); 6] = [
            (59, 94287082),
            (1111111109, 7081804),
            (1111111111, 14050471),
            (1234567890, 89005924),
            (2000000000, 69279037),
            (20000000000, 65353130),
        ];
        for (time, code) in rows {
            assert_eq!(hotp(secret, step_of(time), 8), Some(code), "T = {time}");
        }
    }

    /// RFC 4226, appendix D: the HOTP values of the counts 0 to 9.
    #[test]
    fn the_vectors_of_rfc_4226_pass() {
        let secret = b"12345678901234567890";
        let codes = [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489];
        for (count, code) in codes.into_iter().enumerate() {
            assert_eq!(hotp(secret, count as u64, 6), Some(code), "count {count}");
        }
    }

    /// RFC 4648's base32, both ways, as apps write it; a secret too short
    /// or not base32 is refused, and the words never hold it.
    #[test]
    fn base32_reads_as_apps_write_it() {
        let secret = b"12345678901234567890";
        let text = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(encode_base32(secret).as_str(), text);
        let spaced = "gezd gnbv gy3t qojq-gezd gnbv gy3t qojq==";
        for written in [text, spaced] {
            assert_eq!(decode_base32(written).unwrap().as_slice(), secret, "{written}");
        }
        for (bad, words) in [("GEZDGNBV", "fewer than 10"), ("GEZDGNBVGY3TQOJ1GEZD", "not base32")] {
            let said = decode_base32(bad).expect_err(bad);
            assert!(said.contains(words) && !said.contains(bad), "{bad}: {said}");
        }
        let long = encode_base32(&[7u8; MOST_SECRET + 1]);
        assert!(decode_base32(&long).is_err());
    }
}
