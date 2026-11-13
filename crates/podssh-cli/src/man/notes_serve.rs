//! The notes of `podssh serve` (T-107), and the row of its host key's file.

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
    "This version serves the login alone: a request for a shell, a command, a pty, the environment, a \
     subsystem such as SFTP, a forward or X11 is refused with its answer, so a client says so at once \
     (OpenSSH: exec request failed) instead of waiting; -N stays connected. The connection ends when the \
     client leaves: exit 0, else 255 when it failed. Without --stdio the run is a usage error (64); on \
     Windows it exits 70.",
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
