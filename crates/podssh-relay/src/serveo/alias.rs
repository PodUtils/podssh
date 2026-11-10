//! The alias of a node at Serveo (T-549), derived from its key, so that a
//! client that holds the key computes it and no name passes between them.
//! The alias is of the key's fingerprint, the text that podssh shows a key
//! by (`SHA256:` and base64): `--node-key` may name a fingerprint alone, and
//! the pins of a label hold fingerprints, so each of them gives the alias.
//! Knowing the alias lets a stranger hold it or reach the node's door, as
//! Serveo's documents warn ("a routing name rather than an authentication
//! secret"); the end-to-end channel and the node's allowlist are the door.

use std::path::PathBuf;

use pod_core::files::{read_own, Others};
use pod_identity::KeyName;
use sha2::{Digest, Sha256};

/// The context of the hash: the alias is this road's alone, and of no other
/// use of the same fingerprint.
const CONTEXT: &[u8] = b"podssh serveo alias v1\0";
/// The bytes of the hash that the alias keeps: 160 bits, as nobody guesses
/// an alias of a key that they do not know.
const KEPT: usize = 20;

/// The alias `k` of the series of the node whose key's fingerprint is
/// `fingerprint`: `p`, then the hex of the first [`KEPT`] bytes of SHA-256
/// over [`CONTEXT`], the fingerprint and `k`. 41 characters of `[a-z0-9]`,
/// one label of a host name that begins with a letter, as Serveo reads the
/// alias in the place of a host name.
pub fn alias(fingerprint: &str, k: u8) -> String {
    let mut bytes = Vec::with_capacity(CONTEXT.len() + fingerprint.len() + 1);
    bytes.extend_from_slice(CONTEXT);
    bytes.extend_from_slice(fingerprint.as_bytes());
    bytes.push(k);
    let digest = Sha256::digest(&bytes);
    let hex: String = digest[..KEPT].iter().map(|byte| format!("{byte:02x}")).collect();
    format!("p{hex}")
}

/// The keys that the pins of `label` name, in their order: the keys whose
/// aliases a client tries. None where the pins name none, or cannot be read
/// (the end-to-end channel then refuses the session on its own).
pub fn pinned(label: &str) -> Vec<KeyName> {
    pinned_in(&crate::cache::pod_places().read(), label)
}

/// [`pinned`], with `dirs` as the cache's directories (for tests): the
/// first that holds the pins' file, as the pins' own check reads them.
pub fn pinned_in(dirs: &[PathBuf], label: &str) -> Vec<KeyName> {
    for dir in dirs {
        // Others may read the pins, which are public keys, as the check does.
        let text = match read_own(&dir.join(pod_identity::pins::FILE), Others::Read) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(_) => return Vec::new(),
        };
        let named = |line: &str| {
            let mut words = line.split_whitespace();
            (words.next() == Some(label)).then(|| words.next().and_then(KeyName::parse)).flatten()
        };
        return text.lines().filter(|line| !line.trim_start().starts_with('#')).filter_map(named).collect();
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A known answer, computed apart from this code (Python's hashlib, on
    /// 2026-11-10): a change of the derivation is a change of each node's
    /// alias, which its clients would no longer find.
    #[test]
    fn the_alias_is_of_the_key_s_fingerprint_and_its_place_in_the_series() {
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        assert_eq!(alias(&fingerprint, 0), "pe5e9904d763989a2a1aa8a21d16842c6bba55730");
        assert_eq!(alias(&fingerprint, 1), "pc41f8ed4c8293563e1765682dee6180cd9a76ebf");
        let other = format!("SHA256:{}", "B".repeat(43));
        assert_ne!(alias(&other, 0), alias(&fingerprint, 0), "another key, another alias");
        let each = alias(&fingerprint, 3);
        assert_eq!(each.len(), 41);
        assert!(each.starts_with('p') && each.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    #[test]
    fn the_pins_of_a_label_name_its_keys_in_their_order() {
        let dir = std::env::temp_dir().join(format!("podssh-serveo-pins-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::cache::private_dir(&dir).unwrap();
        // A fingerprint's last character holds 2 bits of padding, which must be
        // zero for a strict decoder: "B" there is no fingerprint, so B's ends in "A".
        let (a, b) = (format!("SHA256:{}", "A".repeat(43)), format!("SHA256:{}A", "B".repeat(42)));
        let text = format!("# the pins\nother {b}\nlab {a}\n# lab {b}\nlab {b}\n");
        std::fs::write(dir.join(pod_identity::pins::FILE), text).unwrap();
        let dirs = std::slice::from_ref(&dir);
        let named: Vec<String> = pinned_in(dirs, "lab").iter().map(KeyName::fingerprint).collect();
        assert_eq!(named, vec![a, b]);
        assert!(pinned_in(dirs, "none").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
