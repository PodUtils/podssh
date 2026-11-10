//! A node's name at ssh-j.com, derived from its key: the user (the page's
//! "unique namespace for your hosts") and the forward's address (its
//! "device name"). The node derives it from its own key, and a client from
//! the key it expects, so neither says it to the other.
//!
//! Each half is SHA-256 over a label of this road and the key's fingerprint
//! (`SHA256:...`, the form that `--node-key`, the net and the pins all give,
//! even where they hold the fingerprint alone), cut short and written in
//! hex: a word that SSH's user and Dropbear's 64-byte address both take, and
//! that a person can read. 64 bits a half: a stranger who wants the name
//! takes it from the key, which is public, so the hash hides nothing and
//! needs no more; the end-to-end channel is what refuses that stranger.

use sha2::{Digest, Sha256};

/// The label of the derivation, so that the name is this road's alone.
const LABEL: &[u8] = b"podssh ssh-j name v1\0";
/// What each half begins with, so that a line or a log shows whose it is.
const USER_PREFIX: &str = "podssh-";
const ADDRESS_PREFIX: &str = "n";

/// The user and the forward's address of a node at ssh-j.com.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JumpName {
    pub user: String,
    pub address: String,
}

impl JumpName {
    /// The name of the node whose key has the fingerprint `fingerprint`
    /// (`SHA256:` and its base64, as `PublicKey::fingerprint` and
    /// `KeyName::fingerprint` write it).
    pub fn of_fingerprint(fingerprint: &str) -> JumpName {
        let digest: [u8; 32] = Sha256::new().chain_update(LABEL).chain_update(fingerprint.as_bytes()).finalize().into();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let address = format!("{ADDRESS_PREFIX}{}", hex(&digest[8..16]));
        // The server keeps no longer address (its `MAX_HOST_LEN`).
        debug_assert!(address.len() <= super::MOST_ADDRESS);
        JumpName { user: format!("{USER_PREFIX}{}", hex(&digest[..8])), address }
    }

    /// The name of the node whose key `key` names.
    pub fn of(key: &podssh_relay::identity::KeyName) -> JumpName {
        JumpName::of_fingerprint(&key.fingerprint())
    }
}

impl std::fmt::Display for JumpName {
    /// `USER@ADDRESS`, as the page's `ssh -J USER@ssh-j.com ADDRESS` pairs them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.user, self.address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use podssh_relay::identity::{Identity, KeyName};

    #[test]
    fn the_name_is_the_key_s_whichever_form_names_it_and_another_key_has_another() {
        let node = Identity::from_seed(&[7; 32]).public();
        let by_key = JumpName::of(&KeyName::Key(node));
        let by_print = JumpName::of(&KeyName::parse(&node.fingerprint()).expect("a fingerprint"));
        assert_eq!(by_key, by_print, "a key and its fingerprint give one name");
        assert_eq!(by_key, JumpName::of_fingerprint(&node.fingerprint()));
        let other = JumpName::of(&KeyName::Key(Identity::from_seed(&[8; 32]).public()));
        assert_ne!(by_key.user, other.user, "another key, another user");
        assert_ne!(by_key.address, other.address, "another key, another address");
    }

    #[test]
    fn each_half_is_a_short_word_that_ssh_and_the_server_take() {
        let name = JumpName::of_fingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU");
        assert_eq!(name.user.len(), USER_PREFIX.len() + 16, "{name}");
        assert_eq!(name.address.len(), ADDRESS_PREFIX.len() + 16, "{name}");
        assert!(name.address.len() <= super::super::MOST_ADDRESS);
        for half in [&name.user, &name.address] {
            assert!(half.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'), "{half}");
        }
        assert_eq!(name.to_string(), format!("{}@{}", name.user, name.address));
        // The derivation is fixed: a node and a client of other versions meet.
        assert_eq!(name, JumpName::of_fingerprint("SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU"));
    }
}
