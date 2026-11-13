//! The flag rows of `serve` (T-107): podssh's own SSH server, over stdin
//! and stdout, its host key, and the keys that may log in.

use super::{row, FlagKind, FlagRow};

/// `serve`.
#[rustfmt::skip]
pub const SERVE_FLAGS: &[FlagRow] = &[
    row(None, "stdio", None, FlagKind::Supported,
        "serve one SSH connection on stdin and stdout, as sshd -i, for a ProxyCommand; nothing listens", None),
    row(None, "host-key", Some("FILE"), FlagKind::Supported,
        "the host key: an OpenSSH private key with no passphrase, made there (Ed25519, mode 0600) when missing, never overwritten (default: serve_host_ed25519_key in the cache)", None),
    row(None, "authorized-key", Some("KEY"), FlagKind::Supported,
        "a public key that may log in, as a line of authorized_keys: TYPE BASE64 [COMMENT]; may be repeated", None),
    row(None, "authorized-keys", Some("FILE"), FlagKind::Supported,
        "a file of authorized_keys lines; may be repeated (default, with no key flag: ~/.ssh/authorized_keys)", None),
];
