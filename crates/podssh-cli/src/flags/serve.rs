//! The flag rows of `serve` (T-107): podssh's own SSH server, over stdin
//! and stdout, its host key, and the keys that may log in; what a session
//! runs (T-108) and its shell (T-222); whether a client may forward (T-109).

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
    row(None, "accept-env", Some("PATTERN"), FlagKind::Supported,
        "the names of a client's env requests that a session takes, with * and ?; may be repeated (default: LANG and LC_*); never LD_*, PATH, HOME, SHELL, ENV, BASH_ENV or IFS", None),
    row(None, "shell", Some("PATH"), FlagKind::Supported,
        "the shell of each session and command, the only one tried: a start where it does not run is refused (default: SHELL, then /bin/sh, /usr/bin/sh, /bin/bash, /usr/bin/bash, /bin/ash, /bin/dash)", None),
    row(None, "no-shell", None, FlagKind::Supported,
        "run no command and no shell: each such request is refused, and no shell is looked for", None),
    row(None, "pty", Some("MODE"), FlagKind::Supported,
        "what a pty request meets where no pty opens: auto, a devpts instance of serve's own and then serve as the line discipline on pipes (echo, editing, Ctrl-C to the command); line, the line discipline with no pty tried; no, the request refused (default: auto)", None),
    row(None, "no-forwarding", None, FlagKind::Supported,
        "open no forward: each direct-tcpip channel that a client opens is refused (default: each forward dials its host and port from this host)", None),
];
