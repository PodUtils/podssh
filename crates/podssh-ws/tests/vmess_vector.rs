//! VEC-6 (T-760): VMess's request header against an authored vector, at two
//! ends of the same decoder. The fixture `tests/fixtures/vmess-request.hex`
//! is a fixed vector of the form, with its bytes held here; this file's
//! decoder opens it, and opens what podssh's road sends at a stand-in
//! server. The decoder here is written from the AEAD form's rule, in this
//! file, and uses none of `pod-egress`'s private header code, so a mistake
//! shared between the road and its reader would have to be made twice, from
//! two texts, to pass.
//!
//! What these tests do not prove: that a live Xray-core server accepts the
//! session, or that any server wrote the fixture. The stand-in is not a
//! VMess server and answers nothing; a run of Xray-core itself is
//! `scripts/interop-vless.sh`'s neighbour work, and the vector is authored,
//! not a capture.

mod vmess_support;

use std::time::Duration;

use aes::cipher::{BlockCipherDecrypt, KeyInit};
use pod_tls::crypto::aead::{Aead, AeadId};
use podssh_ws::vmess::{self, AtEnd, Dial, Server};
use podssh_ws::ProxyChoice;
use tokio::io::AsyncWriteExt;

/// The fixture's account, and its bytes.
const ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const ID_BYTES: [u8; 16] =
    [0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00];
/// The time that the fixture's auth ID holds.
const FIXTURE_UNIX: u64 = 1_795_186_764;
/// The constant of the command key's MD5, `proxy/vmess/encoding`'s.
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
/// `proxy/vmess/aead/kdf.go`'s innermost key.
const ROOT: &[u8] = b"VMess AEAD KDF";
const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";
const HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";

const LIMIT: Duration = Duration::from_secs(20);

// --- the decoder, from the form's rule ---------------------------------

fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes any key");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// `KDF(key, path…)` of `proxy/vmess/aead/kdf.go`: the labels nest, each
/// keying an HMAC over the one inside, and the innermost is keyed by the
/// constant. Written as the nest it is rather than with a counter.
fn nest(path: &[&[u8]], msg: &[u8]) -> [u8; 32] {
    let Some((label, inside)) = path.split_last() else {
        return mac(ROOT, msg);
    };
    assert!(label.len() <= 64, "no label of the form is longer than SHA-256's block");
    let mut key = [0u8; 64];
    key[..label.len()].copy_from_slice(label);
    let mut inner = key.map(|b| b ^ 0x36).to_vec();
    inner.extend_from_slice(msg);
    let sealed = nest(inside, &inner);
    let mut outer = key.map(|b| b ^ 0x5c).to_vec();
    outer.extend_from_slice(&sealed);
    nest(inside, &outer)
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    nest(path, key)[..16].try_into().expect("16 of 32")
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    nest(path, key)[..12].try_into().expect("12 of 32")
}

/// Open one sealed field: its key from `key_label`, its nonce from
/// `iv_label`, each over the auth ID and the connection's nonce.
fn opus(
    key: &[u8],
    key_label: &'static [u8],
    iv_label: &'static [u8],
    nonce: &[u8; 8],
    sealed: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    let key_path: [&[u8]; 3] = [key_label, aad, nonce];
    let iv_path: [&[u8]; 3] = [iv_label, aad, nonce];
    let aead = Aead::new(AeadId::Aes128Gcm, &kdf16(key, &key_path)).ok()?;
    let mut buf = sealed.to_vec();
    let n = aead.open_in_place(&kdf12(key, &iv_path), aad, &mut buf)?;
    Some(buf[..n].to_vec())
}

/// A request's header decoded, with the session's keys for what follows it.
#[derive(Debug)]
struct Request {
    unix: u64,
    version: u8,
    option: u8,
    cipher: u8,
    command: u8,
    host: String,
    port: u16,
    padding: usize,
    key: [u8; 16],
    iv: [u8; 16],
    /// The header's plaintext length.
    plain: usize,
    /// The bytes of the header on the wire.
    consumed: usize,
}

/// Open the header at the front of `wire` with the account's command key.
/// The auth ID's CRC and the header's FNV-1a are checked, so the answer is
/// either the fields that the sender sealed or an error naming where it
/// stopped.
fn decode(wire: &[u8]) -> Result<Request, String> {
    if wire.len() < 16 + 18 + 8 {
        return Err(format!("{} bytes is less than the auth ID, the length and the nonce", wire.len()));
    }
    let cmd_key = md5::compute([&ID_BYTES[..], CMD_KEY_SALT].concat()).0;
    let auth: [u8; 16] = wire[..16].try_into().expect("16");
    let nonce: [u8; 8] = wire[34..42].try_into().expect("8");

    // The auth ID: the time, four bytes and their CRC-32 under AES.
    let block = aes::Aes128::new(&kdf16(&cmd_key, &[AUTH_ID_KEY]).into());
    let mut opened = auth.into();
    block.decrypt_block(&mut opened);
    let plain: [u8; 16] = opened.into();
    let mut time = [0u8; 8];
    time.copy_from_slice(&plain[..8]);
    let unix = u64::from_be_bytes(time);
    let crc = u32::from_be_bytes(plain[12..16].try_into().expect("4"));
    if crc != crc32(&plain[..12]) {
        return Err("the auth ID's CRC-32 is not its time and random bytes".into());
    }

    let len = opus(&cmd_key, HEADER_LEN_KEY, HEADER_LEN_IV, &nonce, &wire[16..34], &auth)
        .ok_or("the sealed length did not open")?;
    if len.len() != 2 {
        return Err(format!("the sealed length opened to {} bytes", len.len()));
    }
    let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    let end = 42 + len + 16;
    if wire.len() < end {
        return Err(format!("{} bytes is less than the header's {end}", wire.len()));
    }
    let plain =
        opus(&cmd_key, HEADER_KEY, HEADER_IV, &nonce, &wire[42..end], &auth).ok_or("the header did not open")?;
    if plain.len() != len {
        return Err(format!("the header opened to {} bytes, not {len}", plain.len()));
    }
    let sum = fnv1a(&plain[..plain.len() - 4]);
    if u32::from_be_bytes(plain[plain.len() - 4..].try_into().expect("4")) != sum {
        return Err("the header's FNV-1a is not its own bytes".into());
    }
    if plain.len() < 41 {
        return Err(format!("a plaintext of {} bytes is short of the fixed fields", plain.len()));
    }

    let option = plain[34];
    let security = plain[35];
    let command = plain[37];
    let port = u16::from_be_bytes([plain[38], plain[39]]);
    let padding = usize::from(security >> 4);
    let mut at = 40;
    let host = match plain[at] {
        1 if plain.len() >= at + 5 => {
            let host = format!("{}.{}.{}.{}", plain[at + 1], plain[at + 2], plain[at + 3], plain[at + 4]);
            at += 5;
            host
        }
        3 if plain.len() >= at + 17 => {
            at += 17;
            "<ipv6>".to_string()
        }
        2 if plain.len() >= at + 2 => {
            let n = usize::from(plain[at + 1]);
            let host = String::from_utf8(plain[at + 2..at + 2 + n].to_vec())
                .map_err(|_| "the target's name is not UTF-8".to_string())?;
            at += 2 + n;
            host
        }
        other => return Err(format!("the address is of kind {other}, or is cut short")),
    };
    if at + padding + 4 != plain.len() {
        return Err(format!("a padding of {padding} does not fill the {} bytes after {at}", plain.len()));
    }
    Ok(Request {
        unix,
        version: plain[0],
        option,
        cipher: security & 0x0f,
        command,
        host,
        port,
        padding,
        key: plain[17..33].try_into().expect("16"),
        iv: plain[1..17].try_into().expect("16"),
        plain: plain.len(),
        consumed: end,
    })
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

fn fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0x811c_9dc5u32, |h, &b| (h ^ u32::from(b)).wrapping_mul(0x0100_0193))
}

fn fixture() -> Vec<u8> {
    let text = include_str!("fixtures/vmess-request.hex");
    let hex: String = text.lines().filter(|l| !l.trim_start().starts_with('#')).collect();
    let hex = hex.trim();
    (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex")).collect()
}

// --- the vector, from the form's rule ----------------------------------

/// VEC-6: the authored vector opens to the fields that it holds, under this
/// file's own decoder.
#[test]
fn the_authored_vector_opens_to_its_recorded_fields() {
    let wire = fixture();
    assert_eq!(wire.len(), 129, "the fixed wire is the form's 129 bytes");
    let request = decode(&wire).expect("the vector opens");
    assert_eq!(request.consumed, wire.len(), "the header is the whole wire");
    assert_eq!(request.version, 1, "VMess's version");
    assert_eq!(request.option, 0x01, "the option S alone: chunk-stream");
    assert_eq!(request.cipher, 3, "aes-128-gcm");
    assert_eq!(request.command, 1, "TCP");
    assert_eq!(request.host, "www.example.com");
    assert_eq!(request.port, 443);
    assert_eq!(request.padding, 10, "the vector's padding");
    assert_eq!(request.plain, 71, "the plaintext that the vector holds");
    assert_eq!(request.unix, FIXTURE_UNIX, "the auth ID's clock");
    assert_ne!(request.key, [0u8; 16], "the vector holds a key");
    assert_ne!(request.iv, [0u8; 16], "and an IV");
}

/// Planted: a changed byte of the sealed header does not open, so the pass
/// above is the auth ID's and the tag's, not any bytes'.
#[test]
fn a_changed_byte_of_the_fixture_does_not_open() {
    for at in [0usize, 3, 20, 40, 60, 100, 128] {
        let mut wire = fixture();
        wire[at] ^= 0x01;
        assert!(decode(&wire).is_err(), "a change at byte {at} opened");
    }
}

// --- the road's own header, at a stand-in server -----------------------

fn link(port: u16) -> String {
    let json = format!(
        r#"{{"add":"127.0.0.1","port":"{port}","id":"{ID}","aid":"0","scy":"auto","net":"ws","tls":"","path":"/vm"}}"#
    );
    use base64::Engine as _;
    format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(json))
}

/// VEC-6 at the road: the header that podssh sends opens, under the same
/// decoder, to the target and the form that the fixture has, and the key and
/// IV it names are the ones the first chunk of the body is sealed with.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_road_s_header_opens_to_the_target_and_keys_its_first_chunk() {
    let (port, seen) = vmess_support::ws_server().await;
    let server = Server::parse(&link(port)).expect("the link");
    let dial = Dial {
        trust: podssh_ws::Trust::Default,
        way: podssh_ws::client::way(&ProxyChoice::Direct),
        timeout: LIMIT,
        answer: Duration::from_millis(300),
        silence_is_ready: true,
        at_end: AtEnd::Now,
        early: None,
    };
    let mut opened = vmess::open_at(&server, "www.example.com", 443, &dial, FIXTURE_UNIX)
        .await
        .unwrap_or_else(|e| panic!("{}", e.line("vmess", "www.example.com:443")));
    // The header waits in the session's buffer until the first write flushes.
    opened.stream.write_all(b"x").await.expect("the first write");
    opened.stream.flush().await.expect("the flush");

    let first = seen.message(0).await;
    let request = decode(&first).unwrap_or_else(|e| panic!("the road's header: {e} ({first:02x?})"));
    assert_eq!(request.consumed, first.len(), "the first message is the header alone");
    assert_eq!(request.unix, FIXTURE_UNIX, "the clock that `open_at` was given");
    assert_eq!(request.version, 1);
    assert_eq!(request.option, 0x01, "chunk-stream");
    assert_eq!(request.cipher, 3, "aes-128-gcm, from `scy` auto");
    assert_eq!(request.command, 1, "TCP");
    assert_eq!(request.host, "www.example.com");
    assert_eq!(request.port, 443);

    // The next message is the first chunk, sealed with the header's key and
    // IV: the header named the keys that the body really uses. The pump
    // writes the header before it reads the user's first bytes, and a write
    // is a message, so the two are two messages and not one.
    let chunk = seen.message(1).await;
    assert!(chunk.len() >= 2, "a chunk's length follows the header");
    let len = usize::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    assert_eq!(chunk.len(), 2 + len, "one chunk of the first write, and nothing more");
    let aead = Aead::new(AeadId::Aes128Gcm, &request.key).expect("the header's key");
    let mut nonce = [0u8; 12];
    nonce[2..].copy_from_slice(&request.iv[2..12]);
    let mut sealed = chunk[2..].to_vec();
    let n = aead.open_in_place(&nonce, &[], &mut sealed).expect("the first chunk opens");
    assert_eq!(&sealed[..n], b"x", "the first chunk is the write that followed the header");

    // The upgrade went to the link's path, so the header came from this link.
    assert!(seen.heads.lock().unwrap()[0].starts_with("GET /vm HTTP/1.1\r\n"), "the link's path");
}
