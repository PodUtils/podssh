//! The algorithms that `podssh serve` offers (T-841): one stated set, in
//! podssh's record, in the place of russh's default. A russh update that
//! adds or drops a name of its own default changes nothing here; a change
//! of this set is a change of this file, which `tests/serve_algorithms.rs`
//! holds against its own table of names.
//!
//! The set is the one that serve offered before it was stated (russh
//! 0.65.2's default), less nothing and plus nothing: the entry states the
//! present set, it does not choose a new one. Never `none`: no list here
//! carries the bytes in the clear.

use std::borrow::Cow;

use russh::keys::{Algorithm, EcdsaCurve, HashAlg};
use russh::{cipher, compression, kex, mac, Preferred};

/// The key exchanges, in the order that serve prefers, and the extensions
/// that ride in the same list (RFC 8308's `ext-info`, OpenSSH's strict key
/// exchange against Terrapin), which are no exchange and never chosen.
pub const KEX: &[kex::Name] = &[
    kex::MLKEM768X25519_SHA256,
    kex::CURVE25519,
    kex::CURVE25519_PRE_RFC_8731,
    kex::DH_GEX_SHA256,
    kex::DH_G18_SHA512,
    kex::DH_G17_SHA512,
    kex::DH_G16_SHA512,
    kex::DH_G15_SHA512,
    kex::DH_G14_SHA256,
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// The names of [`KEX`] that are extensions, not exchanges.
pub const KEX_EXTENSIONS: &[kex::Name] = &[
    kex::EXTENSION_SUPPORT_AS_CLIENT,
    kex::EXTENSION_SUPPORT_AS_SERVER,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
    kex::EXTENSION_OPENSSH_STRICT_KEX_AS_SERVER,
];

/// The host key algorithms. A connection is offered those that the host
/// key serves (an Ed25519 key: `ssh-ed25519` alone); the list is also the
/// `server-sig-algs` that serve tells a client (RFC 8308).
pub const HOST_KEYS: &[Algorithm] = &[
    Algorithm::Ed25519,
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP256 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP384 },
    Algorithm::Ecdsa { curve: EcdsaCurve::NistP521 },
    Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
    Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
    Algorithm::Rsa { hash: None },
];

/// The ciphers, each way.
pub const CIPHERS: &[cipher::Name] =
    &[cipher::CHACHA20_POLY1305, cipher::AES_256_GCM, cipher::AES_256_CTR, cipher::AES_192_CTR, cipher::AES_128_CTR];

/// The MACs, each way, where the cipher needs one (an AEAD cipher does not).
pub const MACS: &[mac::Name] = &[mac::HMAC_SHA512_ETM, mac::HMAC_SHA256_ETM, mac::HMAC_SHA512, mac::HMAC_SHA256];

/// The compressions, each way: none first, so that a client that asks
/// nothing gets none.
pub const COMPRESSION: &[compression::Name] = &[compression::NONE, compression::ZLIB, compression::ZLIB_LEGACY];

/// The whole set, as russh's server takes it. A server offers no host
/// certificate: the list of certificates is the client's alone.
pub const SERVED: Preferred = Preferred {
    kex: Cow::Borrowed(KEX),
    key: Cow::Borrowed(HOST_KEYS),
    host_key_certificates: Cow::Borrowed(&[]),
    cipher: Cow::Borrowed(CIPHERS),
    mac: Cow::Borrowed(MACS),
    compression: Cow::Borrowed(COMPRESSION),
};

/// The names of one list of the set, as the wire spells them: for the
/// manual, `docs/cli.md` and a test.
pub fn names<N: AsRef<str>>(list: &[N]) -> Vec<String> {
    list.iter().map(|name| name.as_ref().to_string()).collect()
}

/// The host key algorithms by name.
pub fn host_key_names() -> Vec<String> {
    HOST_KEYS.iter().map(|a| a.as_str().to_string()).collect()
}

/// The key exchanges by name, without the extensions.
pub fn kex_names() -> Vec<String> {
    KEX.iter().filter(|k| !KEX_EXTENSIONS.contains(*k)).map(|k| k.as_ref().to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_list_of_the_set_is_empty_or_carries_none() {
        let lists = [kex_names(), host_key_names(), names(CIPHERS), names(MACS)];
        for list in &lists {
            assert!(!list.is_empty());
            assert!(!list.iter().any(|n| n == "none" || n == "clear"), "{list:?}");
        }
        // Compression's `none` is no clear text: it is the default.
        assert_eq!(names(COMPRESSION).first().map(String::as_str), Some("none"));
    }

    #[test]
    fn each_extension_of_the_kex_list_is_in_it() {
        for name in KEX_EXTENSIONS {
            assert!(KEX.contains(name), "{}", name.as_ref());
        }
    }
}
