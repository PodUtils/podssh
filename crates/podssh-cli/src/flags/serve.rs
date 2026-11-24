//! The flag rows of `serve` (T-107): podssh's own SSH server, over stdin
//! and stdout, its host key, and the keys that may log in; what a session
//! runs (T-108) and its shell (T-222); whether a client may forward (T-109);
//! whether a reload that takes a key out ends its sessions (T-842); a client
//! policy (T-838); a shell shared by name (T-837); a unit of systemd that
//! runs it (T-709); the message of the day (T-119).

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
        "what a pty request meets where no pty opens: auto, a devpts instance of serve's own, then a tty whose calls serve answers (Linux); then serve as the line discipline on pipes (echo, editing, Ctrl-C to the command); notify, the tty that serve answers with no pty tried, else the request refused; line, the line discipline with no pty tried; no, the request refused (default: auto)", None),
    // The message of the day of a login shell on a tty (T-119).
    row(None, "motd", Some("FILE"), FlagKind::Supported,
        "the message of the day: shown before each login shell on a tty, never for a command, and not when ~/.hushlogin exists; at most 64 KiB, with no control character but tab and newline (default: /etc/motd, where it is there)", None),
    row(None, "no-forwarding", None, FlagKind::Supported,
        "open no forward: each direct-tcpip channel that a client opens is refused (default: each forward dials its host and port from this host)", None),
    row(None, "revoke-ends-sessions", None, FlagKind::Supported,
        "a SIGHUP that takes a key out of the authorized keys ends that key's open sessions, and a key's expiry-time= ends them at its time; one line names each key (default: a session goes on under the rules it logged in with)", None),
    // A login shell offered by two names, typed in or watched (T-837).
    row(None, "share", None, FlagKind::Supported,
        "offer each login shell on a pty by two names told once to its owner: one types in it, one watches it; each dies with the shell", None),
    // A client policy on each client's KEXINIT (T-838).
    super::policy::SERVE_POLICY,
    // A unit of systemd that runs serve NAME, printed (T-709).
    row(None, "print-unit", None, FlagKind::Supported,
        "with NAME: print a unit of systemd that runs serve NAME with these flags, on stdout, and write nothing: a user unit, or with --system --run-as USER a system unit", None),
    row(None, "system", None, FlagKind::Supported,
        "with --print-unit: a system unit, /etc/systemd/system/podssh-serve-NAME.service, that runs as the user of --run-as, with the hardening that leaves its sessions as sshd's", None),
    row(None, "run-as", Some("USER"), FlagKind::Supported,
        "with --system: the user that serve runs as, a user of /etc/passwd other than root; the unit names its HOME and its login shell", None),
];
