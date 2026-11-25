//! The flag rows of `serve` (T-107): podssh's own SSH server, over stdin
//! and stdout, its host key, and the keys that may log in; what a session
//! runs (T-108) and its shell (T-222); whether a client may forward (T-109);
//! whether a reload that takes a key out ends its sessions (T-842); a client
//! policy (T-838); a shell shared by name (T-837); a shell kept for a lease
//! (T-159); a unit of systemd that runs it (T-709); the message of the day
//! (T-119); the marks of a shell (T-120); listeners that the user asks for
//! (T-124); an audit log (T-116); a one-time code (T-115); a gateway to
//! private hosts by the login name (T-836).

use super::{row, FlagKind, FlagRow};

/// `serve`.
#[rustfmt::skip]
pub const SERVE_FLAGS: &[FlagRow] = &[
    row(None, "stdio", None, FlagKind::Supported,
        "serve one SSH connection on stdin and stdout, as sshd -i, for a ProxyCommand; nothing listens", None),
    // A listener that the user asks for, after a bind that the host allows (T-124).
    row(None, "listen", Some("ADDR"), FlagKind::Supported,
        "serve each SSH connection that comes on ADDR: PORT on 127.0.0.1, ADDR:PORT on an address of this host ([::1]:PORT for IPv6), or unix:PATH, a socket of mode 0600; may be repeated; never with PODSSH_LISTEN=no", None),
    row(None, "max-connections", Some("N"), FlagKind::Supported,
        "with --listen: the connections at once, logged in or not; one more is refused with a disconnect, too many connections (default: 64)", None),
    // A deadline from the accept, and a cap on the clients not logged in (T-631).
    row(None, "pending-max", Some("N"), FlagKind::Supported,
        "with --listen: the connections at once that have not logged in; one more is refused as with --max-connections (default: 16)", None),
    row(None, "login-timeout", Some("SECS"), FlagKind::Supported,
        "with --listen: the seconds from a connection to its login, 1 to 3600; past them it ends, told why, however busy the client is (default: 60)", None),
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
    // The marks of OSC 133 and OSC 7 for a terminal (T-120).
    row(None, "shell-integration", None, FlagKind::Supported,
        "mark each login shell's prompts and commands for the terminal (OSC 133) and its directory (OSC 7): bash and zsh on a pty by a start file of serve's own that reads the user's, which serve never writes; the prompts and lines of serve's line discipline (default: no marks)", None),
    // A client's -R published at the relay, a pair for each (T-123, Q108).
    row(None, "publish-remote", None, FlagKind::Supported,
        "answer a client's -R (tcpip-forward) with a pair of the relay for each, at most 8 a connection, with no bind here (default: each -R is refused)", None),
    // A client's -R on a listener of the loopback, which the user asks for (T-123).
    row(None, "remote-listen", None, FlagKind::Supported,
        "answer a client's -R with a listener on this host's 127.0.0.1, at the port asked or one the system picks; where the bind fails, --publish-remote's pair if it is on (default: no listener)", None),
    row(None, "no-forwarding", None, FlagKind::Supported,
        "open no forward: each direct-tcpip channel that a client opens is refused (default: each forward dials its host and port from this host)", None),
    row(None, "revoke-ends-sessions", None, FlagKind::Supported,
        "a SIGHUP that takes a key out of the authorized keys ends that key's open sessions, and a key's expiry-time= ends them at its time; one line names each key (default: a session goes on under the rules it logged in with)", None),
    // A login shell offered by two names, typed in or watched (T-837).
    row(None, "share", None, FlagKind::Supported,
        "offer each login shell on a pty by two names told once to its owner: one types in it, one watches it; each dies with the shell", None),
    // A shell kept after its client detached, for a lease (T-159).
    row(None, "keep-lease", Some("TIME"), FlagKind::Supported,
        "with NAME: how long a shell that its client detached (~d of podssh ssh) waits for a client, as 90s, 30m or 8h, 30 days at most; 0 keeps no shell (default: 24h)", None),
    // A client policy on each client's KEXINIT (T-838).
    super::policy::SERVE_POLICY,
    // The audit log, chained JSON lines (T-116).
    row(None, "audit-log", Some("FILE"), FlagKind::Supported,
        "append one JSON line for each login, session, forward, start and stop to FILE, mode 0600, each line chained to the one before by SHA-256; never a key, a token, the environment or session data", None),
    row(None, "audit-commands", None, FlagKind::Supported,
        "with --audit-log: also record each command line, which can hold a password (default: a command is recorded without its words)", None),
    // A one-time code after the key (T-115).
    row(None, "totp", Some("FILE"), FlagKind::Supported,
        "after a key, ask for the one-time code of the secret in FILE (base32, mode 0600) by keyboard-interactive: RFC 6238, 30 s, six digits, each code taken once", None),
    row(None, "totp-new", Some("FILE"), FlagKind::Supported,
        "make a new secret in FILE, mode 0600, never over a file that is there, print its path alone, and exit", None),
    // A gateway: the login name picks an upstream, logged in by a certificate (T-836).
    row(None, "gateway", Some("FILE"), FlagKind::Supported,
        "serve as a gateway: the login name picks a route of FILE, whose keys may take it. serve logs in at the route's pinned upstream by a certificate of its CA, and carries each session and forward there; nothing runs here", None),
    row(None, "audit-verify", Some("FILE"), FlagKind::Supported,
        "check the chain of the audit log FILE, print what it found and the last line's SHA-256, and exit: 0 when it holds, 65 when a line was changed, 66 when FILE cannot be read", None),
    // A unit of systemd that runs serve NAME, printed (T-709).
    row(None, "print-unit", None, FlagKind::Supported,
        "with NAME: print a unit of systemd that runs serve NAME with these flags, on stdout, and write nothing: a user unit, or with --system --run-as USER a system unit", None),
    row(None, "system", None, FlagKind::Supported,
        "with --print-unit: a system unit, /etc/systemd/system/podssh-serve-NAME.service, that runs as the user of --run-as, with the hardening that leaves its sessions as sshd's", None),
    row(None, "run-as", Some("USER"), FlagKind::Supported,
        "with --system: the user that serve runs as, a user of /etc/passwd other than root; the unit names its HOME and its login shell", None),
];
