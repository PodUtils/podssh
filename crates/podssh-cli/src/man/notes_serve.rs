//! The notes of `podssh serve` (T-107; a command, a shell and the
//! environment, T-108; the shell, T-222; direct-tcpip, T-109), and the row
//! of its host key's file.

pub const SERVE: &[&str] = &[
    "podssh serve --stdio is an SSH server for one connection on stdin and stdout, as sshd -i: OpenSSH's \
     ssh, or podssh ssh, reaches it through its ProxyCommand, on this host or at the other end of any pipe. \
     Nothing listens. It runs as the user that started it, with no passwd entry, setgroups or chroot. At its \
     start it gives up each capability of the process, before it reads a file; a capability that stays is \
     a refusal (78).",
    "Only public keys log in. The keys are each --authorized-key, and the lines of each --authorized-keys \
     file; with neither, ~/.ssh/authorized_keys. A key is compared by its key alone: the login name selects \
     nothing. A line with options before its key (command=, from=, restrict) is not used yet, and is said \
     with its number; a line that is no key is passed over, and said. A file that is a symbolic link, \
     another user's, or one that others can change is refused (78). With no key at all, the start is \
     refused (78): no setting lets each key in.",
    "The host key is --host-key FILE, else serve_host_ed25519_key in the cache (see FILES): made at the \
     first start, an Ed25519 key of mode 0600, and read at each later one, never overwritten; of two \
     starts at once, one makes it and the other reads it. Its fingerprint goes to stderr at each start, \
     with a warning when the file is in a temporary directory, which a reboot can empty: each client would \
     then meet a new host key. A key file with a passphrase is refused (78).",
    "A command (exec) runs as SHELL -c COMMAND, and a shell request runs the shell as a login shell \
     (its argv[0] the shell's name after a dash), as the user that runs serve, on three pipes: stdout comes as data and stderr as \
     extended data, apart. Each child leads a session of its own (setsid), in HOME when it is a \
     directory, else /; a signal request goes to its process group. When it ends, its pipes are read \
     to their end, for 2 s of silence at most (30 s in all), as a job that it put in the background can \
     hold them; then exit-status, or exit-signal with the signal's name and the core flag, always before \
     EOF and close. A pty request is refused (the command runs without one; OpenSSH says PTY allocation \
     request failed); a subsystem such as SFTP, X11 or a Unix socket's forward is refused with its answer.",
    "A client's forward (direct-tcpip: OpenSSH's -W, -L and -J) is a TCP connection that serve opens from \
     its own host to the host and port asked, any of them, as sshd allows by default: a name is resolved \
     there, or given to the proxy of serve's HTTPS_PROXY, and the loopback and the names of NO_PROXY go \
     directly, as podssh's own dials go. The dial has 20 s. One that fails is refused as connect failed, \
     with its reason in words, the system's error or the proxy's status and reason (OpenSSH: open failed: \
     connect failed: podssh serve: could not connect to 127.0.0.1:1: Connection refused); a port of 0 or \
     past 65535 too. The bytes go both ways, an end of one way keeps the other open, and the TCP \
     connection ends with its channel. At most 256 forwards are open at once on one connection, and one \
     more is refused as a resource shortage. --no-forwarding refuses each forward, administratively \
     prohibited, with the flag named.",
    "The environment of a child is serve's own, as the cage gave it (PATH, HTTPS_PROXY and the rest stay), \
     without podssh's credentials (PODSSH_RELAY_TOKEN, the secrets of Cloudflare Access, and each variable \
     of podssh whose name holds TOKEN, SECRET, PASSWORD or PASSPHRASE, but those that name a file), plus USER and LOGNAME \
     (serve's, else the uid's number: no passwd entry is read), HOME (/ with none), SHELL and PATH (sshd's \
     /usr/local/bin:/usr/bin:/bin with none). A client's env request (OpenSSH's SetEnv and SendEnv) is \
     taken when its name matches an --accept-env pattern (default LANG and LC_*), never for LD_*, PATH, \
     HOME, SHELL, ENV, BASH_ENV, IFS, USER or LOGNAME, whatever the pattern; --accept-env '' takes none.",
    "The shell is found with no passwd entry and no /etc/shells: --shell PATH alone when it is given; else \
     SHELL, then /bin/sh, /usr/bin/sh, /bin/bash, /usr/bin/bash, /bin/ash and /bin/dash. A candidate \
     passes when it is an absolute path to a regular file that this user may execute, and when a real run \
     of -c 'exit 0' ends with 0 within 5 s: a noexec mount, a data file with its mode bits set or a missing \
     loader fail there. The search runs at the start and again at each session, with no cache. At the \
     start, a candidate passed over is said with its reason (not executable (noexec mount), for one), \
     and no shell at all refuses the start (78), as does a --shell that does not run; --no-shell skips \
     the search, and refuses each command and shell. In a session, the same line goes to the channel's \
     stderr, and the request fails (OpenSSH: exec request failed). podssh doctor's line shell names the \
     shell that serve would run, and each candidate passed over.",
    "The connection ends when the client leaves: exit 0, else 255 when it failed. Without --stdio the run \
     is a usage error (64), and so are --shell with --no-shell; on Windows it exits 70.",
];

/// The host key's file, for FILES.
pub fn file() -> (Vec<String>, String) {
    (
        vec![podssh_ssh::server::host_key::FILE.to_string()],
        "The host key of podssh serve, in the cache, when no --host-key names one: an OpenSSH private key \
         (Ed25519) that the first start makes, mode 0600 (on Windows, the access list of the cache), and \
         that each later start reads; podssh never writes over it. Remove it to make a new host key, which \
         each client then sees as a changed one."
            .to_string(),
    )
}
