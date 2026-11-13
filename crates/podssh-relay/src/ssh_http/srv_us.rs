//! The name of a node's tunnel at srv.us (T-566), a function of the key
//! that the node's leg logs in with and of the forward's port, as srv.us's
//! server computes it (`endpointURLs` of `backend/main.go`, xmit-dev/srv.us
//! at c153c354, 0BSD, read 2026-11-13):
//!
//! ```go
//! hasher := sha256.New()
//! hasher.Write((*key).Marshal())   // the key's SSH wire form
//! hasher.Write([]byte{0})
//! hasher.Write([]byte(strconv.Itoa(int(port))))
//! b32 := b32encoder.EncodeToString(hasher.Sum(nil)[:16])
//! result := []string{fmt.Sprintf("%s.%s", b32, *domain)}
//! ```
//!
//! with `b32encoder` RFC 4648's base32 in lower case with no padding
//! (`base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567")`), and the
//! domain the server's own (`srv.us`). So a client that pins the node's key
//! knows the name with no meeting point, and the node can check the name
//! that the server writes against it. The server lets in a key only once it
//! signed (`golang.org/x/crypto` v0.41.0 of its `go.mod`, after the fix of
//! CVE-2024-45337), so a stranger cannot take the name; and the end-to-end
//! channel refuses one that the server gave it all the same.

use sha2::{Digest, Sha256};

use crate::identity::PublicKey;

/// The port of the node's remote forward: the README's `-R 1:...`. The
/// name hashes it, so the node and the client must agree on it.
pub const FORWARD_PORT: u32 = 1;

/// RFC 4648's base32 alphabet in lower case: srv.us's `b32encoder`.
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// The SSH wire form of an Ed25519 key, as Go's `ssh.PublicKey.Marshal`
/// writes it: the string `ssh-ed25519`, then the string of its 32 bytes,
/// each after its length in four bytes.
pub fn wire(key: &PublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(51);
    for part in [&b"ssh-ed25519"[..], &key.0[..]] {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part);
    }
    out
}

/// `bytes` in base32 with no padding, in lower case.
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// The label of the tunnel of `key`'s forward of `port`: 26 characters.
pub fn label(key: &PublicKey, port: u32) -> String {
    let digest =
        Sha256::new().chain_update(wire(key)).chain_update([0u8]).chain_update(port.to_string().as_bytes()).finalize();
    base32(&digest[..16])
}

/// The tunnel's name of `key` at the server whose domain is `zone`, for the
/// node's forward of [`FORWARD_PORT`].
pub fn name(key: &PublicKey, zone: &str) -> String {
    format!("{}.{}", label(key, FORWARD_PORT), zone.trim_end_matches('.').to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh_http::{name as lines, Service, SRV_US};

    /// The public key of RFC 8032's first test of Ed25519, a key that each
    /// reader can look up.
    const RFC8032_1: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// RFC 8032's second test.
    const RFC8032_2: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";

    fn key(hex: &str) -> PublicKey {
        PublicKey::parse(hex).expect("64 hex digits")
    }

    /// srv.us's source holds no test of `endpointURLs` and its README's
    /// sample names no key, so these vectors were computed by its exact
    /// steps, read from `backend/main.go`, with Python's `hashlib` and
    /// `base64` on 2026-11-13 (`docs/carriers.md`, [R566-2]): SHA-256 of the
    /// wire form, a zero byte and the port in decimal; the first 16 bytes;
    /// base32 in lower case with no padding.
    #[test]
    fn the_name_is_srv_us_s_own_derivation_on_vectors_of_its_steps() {
        let one = key(RFC8032_1);
        assert_eq!(one.fingerprint(), "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8", "the wire form");
        assert_eq!(label(&one, 1), "zzrmnvgfo2simj7f57nztj24qq");
        assert_eq!(label(&one, 2), "7lldg6kmotnncjmueo4qatleyu");
        assert_eq!(label(&one, 80), "xkh7fetlfo3lkk2thdhv6tnd2u");
        assert_eq!(label(&key(RFC8032_2), 1), "pfc7mvo4oo3wytfj2bxhu7tvva");
        assert_eq!(name(&one, "srv.us"), "zzrmnvgfo2simj7f57nztj24qq.srv.us");
        assert_eq!(name(&one, "SRV.us."), "zzrmnvgfo2simj7f57nztj24qq.srv.us", "the zone as DNS reads it");
    }

    #[test]
    fn the_label_has_the_shape_of_the_readme_s_names() {
        // The README's sample: https://qp556ma755ktlag5b2xyt334ae.srv.us/.
        let sample = "qp556ma755ktlag5b2xyt334ae";
        let ours = label(&key(RFC8032_1), FORWARD_PORT);
        assert_eq!(ours.len(), sample.len(), "16 bytes are 26 characters of base32");
        assert!(ours.bytes().all(|b| ALPHABET.contains(&b)), "{ours}");
        assert_eq!(base32(b"f"), "my");
        assert_eq!(base32(b"foobar"), "mzxw6ytboi", "RFC 4648's test, in lower case and with no padding");
    }

    #[test]
    fn the_server_s_line_names_the_tunnel_and_the_derived_name_is_it() {
        let service = Service { word: SRV_US, host: "srv.us".into(), ports: vec![22], host_key: None };
        let derived = name(&key(RFC8032_1), &service.host);
        let line = format!("1: https://{derived}/, https://someone.gh.srv.us/");
        let found = lines::of_line(&line, &SRV_US, &|host| service.own(host));
        assert_eq!(found.as_deref(), Some(derived.as_str()), "the first name, the key's");
        assert_eq!(lines::of_line("Usage: ssh srv.us -R 1:localhost:3000", &SRV_US, &|h| service.own(h)), None);
        assert!(service.own("srv.us") && !service.own(&derived), "only the server is its own");
    }
}
