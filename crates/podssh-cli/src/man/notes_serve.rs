//! The notes of `podssh serve` (T-107; a command, a shell and the
//! environment, T-108; the shell, T-222; direct-tcpip, T-109; a pty,
//! T-110; SFTP, T-112; the options of a key line, T-114; the stop and
//! SIGHUP, T-117), and the row of its host key's file.

pub const SERVE: &[&str] = &[
    "podssh serve --stdio is an SSH server for one connection on stdin and stdout, as sshd -i: OpenSSH's \
     ssh, or podssh ssh, reaches it through its ProxyCommand, on this host or at the other end of any pipe. \
     Nothing listens. It runs as the user that started it, with no passwd entry, setgroups or chroot. At its \
     start it gives up each capability of the process, before it reads a file; a capability that stays is \
     a refusal (78).",
    "Only public keys log in. The keys are each --authorized-key, and the lines of each --authorized-keys \
     file; with neither, ~/.ssh/authorized_keys. A key is compared by its key alone: the login name selects \
     nothing. The options before a key are its rules (below); a line whose options serve cannot all \
     honour, and a line that is no key, are passed over, and said with their number and why. A file that \
     is a symbolic link, another user's, or one that others can change is refused (78). With no key at \
     all, the start is refused (78): no setting lets each key in.",
    "The options of a key line are OpenSSH's (the format of the authorized_keys file in sshd(8)), read as \
     sshd reads them: separated by commas, names in any case, a value in double quotes where a backslash before a \
     quote is a quote. command=\"...\" runs in place of each command, shell and sftp request, as SHELL -c, \
     with the client's command in SSH_ORIGINAL_COMMAND (not set for a shell; internal-sftp for sftp); \
     command=\"internal-sftp\" serves SFTP alone, and refuses one with arguments. no-pty refuses a pty \
     (OpenSSH, with -tt, ends with PTY allocation request failed). no-port-forwarding refuses each forward, \
     and each permitopen=\"host:port\" (an IPv6 address in brackets; * for any port) lets in that target \
     alone, the host compared as written, with no lookup. restrict turns off the pty and forwarding, and a \
     later pty or port-forwarding turns one on again. expiry-time=\"YYYYMMDD[HHMM[SS]]\" (local time, or \
     UTC with Z) refuses the key after it. from=\"patterns\" lets the key in from a matching address \
     alone: addresses with * and ?, blocks such as 10.0.0.0/8, and ! to refuse; serve looks up no name, so \
     a host name matches nothing. serve knows an address only when its stdin is a TCP socket (as from \
     inetd): on a pipe, as from a ProxyCommand or the relay, no from= matches, and the key is refused. \
     no-agent-forwarding, no-X11-forwarding, no-user-rc and no-touch-required change nothing (serve offers \
     none of them). environment=, permitlisten=, tunnel=, principals=, cert-authority, touch-required, \
     verify-required and any option that serve does not know make the line unused, named. Of the lines \
     of one key, the first that lets it in now holds. Each refusal by a rule goes to the client (a forward \
     refused as administratively prohibited, a pty or a command with its line on the channel's stderr) \
     and to serve's stderr, with the key's fingerprint and the option; a key refused at login is said \
     there alone, as the client hears Permission denied.",
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
     EOF and close. X11, a Unix socket's forward and each subsystem but sftp are refused with their answer.",
    "A pty request (OpenSSH's -t and -tt) is granted where a pty opens at that moment: serve tries \
     /dev/ptmx, then /dev/pts/ptmx, at each request, and keeps nothing for the next one. The command or \
     the shell then has the pty's slave as its stdin, stdout and stderr and as its controlling terminal, \
     in a session of its own, so Ctrl-C and the job control of a shell work as under sshd; TERM is the \
     request's (xterm-256color when it is empty), and the variable of the slave's path is set as sshd \
     sets it. The size is the request's (80x24 when it is zero) and follows each window change; the \
     request's terminal modes are set where termios has them, and a mode that it lacks or that the \
     kernel refuses is passed over. On a pty, stdout and stderr come as one stream of data, and the \
     client's EOF ends its input alone. Where no pty opens (a cage with no /dev/ptmx), the request is \
     refused with its answer, and a command runs on pipes (OpenSSH, with -tt, ends with PTY allocation \
     request failed); podssh doctor's line pty says which of the two a client meets. On Windows the \
     request is refused.",
    "The sftp subsystem is served in the process: SFTP version 3 as OpenSSH's sftp-server speaks it, so \
     that OpenSSH's sftp, its scp (SFTP is its mode since OpenSSH 9.0) and podssh cp reach a cage that has \
     no sftp-server, scp or rsync. The files are reached as the user that runs serve, with no chroot: what \
     that user may read and write, a client may. A path is taken as the client gives it, and a relative \
     one starts at HOME (/ with none). Served: open, read, write, close, stat, lstat, fstat, setstat, \
     fsetstat, opendir, readdir, remove, rename (never over a name that exists), mkdir, rmdir, realpath, \
     readlink and symlink, and the extensions posix-rename@openssh.com (a rename over a name), \
     fsync@openssh.com and limits@openssh.com. A failure is its status code with the path and the \
     system's words (no such file, permission denied, failure). Each call on the file system has 20 s: \
     past it the reply is a failure that says so, the handle that it used is closed, and the session goes \
     on, so a FIFO with no writer or a dead mount cannot stop it; a session that left 8 such calls ends. \
     At most 256 handles are open in a session, a read is 255 KiB at most and a request 256 KiB. A \
     listing names owners by number, as serve reads no passwd entry. scp in its legacy mode runs scp by \
     exec, and exits 127 in a cage that has none. --no-shell leaves SFTP served, as it runs no program.",
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
     HOME, SHELL, ENV, BASH_ENV, IFS, USER, LOGNAME or SSH_ORIGINAL_COMMAND, whatever the pattern; \
     --accept-env '' takes none.",
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
    "SIGTERM or SIGINT stops serve cleanly: it takes no new session or forward, sends the client a \
     disconnect with the reason podssh serve is stopping (OpenSSH prints it), and hangs up the process \
     group of each command, shell and pty child (SIGHUP, then SIGCONT, as the kernel does when a terminal \
     goes away). A group that still runs 5 s later is killed with SIGKILL; a second SIGTERM or SIGINT \
     kills at once. Then serve exits 0. A client that closes its channel, or a connection that ends, \
     hangs up that channel's child the same way, so nothing of a session that is gone runs on unless it \
     asked to (nohup).",
    "SIGHUP reads the authorized keys again: each --authorized-keys file, or ~/.ssh/authorized_keys; each \
     --authorized-key stays. Each line is read as at the start, its options its rules: a line that is \
     not used is passed over and said. The next login meets the new set; a session that logged in goes \
     on, under the rules it logged in with. A file that is gone or cannot be read, or no key at all, \
     keeps the set before, and one line on stderr says why; a reload that took says how many lines are \
     used now. The other settings are the command line's, and a restart changes them.",
    "The connection ends when the client leaves: exit 0, else 255 when it failed; a stop exits 0. Without \
     --stdio the run is a usage error (64), and so are --shell with --no-shell; on Windows it exits 70.",
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
