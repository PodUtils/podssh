//! The messages against RFC 5769's test vectors, which other STUN stacks
//! wrote, and against the long-term credential as RFC 8489 derives it.

use super::*;
use crate::stun::{parse, BINDING_REQUEST};

fn hex(text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
    digits.chunks(2).map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap()).collect()
}

/// RFC 5769, 2.1: a request with a short-term credential, padded with
/// spaces, MESSAGE-INTEGRITY then FINGERPRINT.
const SAMPLE_REQUEST: &str = "
    00 01 00 58 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
    80 22 00 10 53 54 55 4e 20 74 65 73 74 20 63 6c 69 65 6e 74
    00 24 00 04 6e 00 01 ff
    80 29 00 08 93 2f f9 b1 51 26 3b 36
    00 06 00 09 65 76 74 6a 3a 68 36 76 59 20 20 20
    00 08 00 14 9a ea a7 0c bf d8 cb 56 78 1e f2 b5 b2 d3 f2 49 c1 b5 71 a2
    80 28 00 04 e5 7a 3b cf";

/// RFC 5769, 2.2: the IPv4 response to it.
const SAMPLE_RESPONSE: &str = "
    01 01 00 3c 21 12 a4 42 b7 e7 a7 01 bc 34 d6 86 fa 87 df ae
    80 22 00 0b 74 65 73 74 20 76 65 63 74 6f 72 20
    00 20 00 08 00 01 a1 47 e1 12 a6 43
    00 08 00 14 2b 91 f5 99 fd 9e 90 c3 8c 74 89 f9 2a f9 ba 53 f0 6b e7 d7
    80 28 00 04 c0 7d 4c 96";

/// RFC 5769, 2.4: a request with the long-term credential, padded with
/// zeros, as podssh pads.
const LONG_TERM: &str = "
    00 01 00 60 21 12 a4 42 78 ad 34 33 c6 ad 72 c0 29 da 41 2e
    00 06 00 12 e3 83 9e e3 83 88 e3 83 aa e3 83 83 e3 82 af e3 82 b9 00 00
    00 15 00 1c 66 2f 2f 34 39 39 6b 39 35 34 64 36 4f 4c 33 34 6f 4c 39 46 53 54 76 79 36 34 73 41
    00 14 00 0b 65 78 61 6d 70 6c 65 2e 6f 72 67 00
    00 08 00 14 f6 70 24 65 6d d6 4a 3e 02 b8 e0 71 2e 85 c9 a2 8c a8 96 66";

const SHORT_TERM: &[u8] = b"VOkJxbRl1RmTxUk/WvJxBt";

#[test]
fn rfc_5769_s_short_term_messages_check_and_a_changed_byte_fails() {
    for vector in [SAMPLE_REQUEST, SAMPLE_RESPONSE] {
        let bytes = hex(vector);
        parse(&bytes).expect("the vector is a message");
        assert_eq!(integrity(&bytes, SHORT_TERM), Some(true));
        assert_eq!(fingerprint_ok(&bytes), Some(true));
        assert_eq!(integrity(&bytes, b"another password"), Some(false));
        let mut changed = bytes.clone();
        changed[HEADER + 5] ^= 1;
        assert_eq!(integrity(&changed, SHORT_TERM), Some(false));
        assert_eq!(fingerprint_ok(&changed), Some(false));
    }
}

#[test]
fn rfc_5769_s_long_term_request_is_written_byte_for_byte() {
    let want = hex(LONG_TERM);
    let message = parse(&want).unwrap();
    // The password after SASLprep, as the vector gives it.
    let key = long_term_key("\u{30DE}\u{30C8}\u{30EA}\u{30C3}\u{30AF}\u{30B9}", "example.org", "TheMatrIX");
    assert_eq!(integrity(&want, &key), Some(true));
    let attrs = [
        (USERNAME, message.attribute(USERNAME).unwrap()),
        (NONCE, message.attribute(NONCE).unwrap()),
        (REALM, message.attribute(REALM).unwrap()),
    ];
    assert_eq!(signed(BINDING_REQUEST, &message.id, &attrs, Some(&key)), want);
}

#[test]
fn a_message_with_no_integrity_says_none_and_an_unsigned_one_is_the_codec_s() {
    let id = [7u8; 12];
    let plain = signed(ALLOCATE, &id, &[(REQUESTED_TRANSPORT, &requested_tcp())], None);
    assert_eq!(plain, crate::stun::message(ALLOCATE, &id, &[(REQUESTED_TRANSPORT, &requested_tcp())]));
    assert_eq!(integrity(&plain, b"k"), None);
    assert_eq!(fingerprint_ok(&plain), None);
    let cut = &signed(ALLOCATE, &id, &[], Some(b"k"))[..HEADER + 10];
    assert_eq!(integrity(cut, b"k"), Some(false));
}

#[test]
fn crc_32_is_iso_3309_s() {
    // The check value of CRC-32 in each catalogue of CRCs.
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
}

#[test]
fn the_types_and_values_are_rfc_6062_s() {
    assert_eq!(success(CONNECT), 0x010a);
    assert_eq!(error(CONNECTION_BIND), 0x011b);
    assert_eq!(CONNECTION_ATTEMPT | INDICATION, 0x001c);
    assert_eq!(u32_of(&[0, 0, 2, 88]), Some(600));
    assert_eq!(u32_of(&[1, 2, 3]), None);
}

#[test]
fn coturn_s_rest_credential_is_its_hmac_in_base64() {
    // The user of an expiry, and a password of 20 bytes in base64.
    let (user, password) = rest_credential(b"north", 1_700_000_000);
    assert_eq!(user, "1700000000:podssh");
    assert_eq!(password.len(), 28);
    assert_ne!(rest_credential(b"south", 1_700_000_000).1, password);
}
