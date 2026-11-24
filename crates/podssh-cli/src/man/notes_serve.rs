//! The notes of `podssh serve` (T-107; a command, a shell and the
//! environment, T-108; the shell, T-222; direct-tcpip, T-109; a pty,
//! T-110; SFTP, T-112; the options of a key line, T-114; the stop and
//! SIGHUP, T-117; a slow client, T-118; the algorithms, T-841; the end of
//! a removed key's sessions, T-842; a shell shared by name, T-837; a shell
//! kept for a lease, T-159; the message of the day, T-119; the marks of a
//! shell, T-120; the scope of a pty child, T-122; a listener, T-124,
//! `notes_serve_listen`; the audit log, T-116; a one-time code, T-115), and
//! the row of its host key's file.

pub const SERVE: &[&str] = &[
    "podssh serve --stdio is an SSH server for one connection on stdin and stdout, as sshd -i: OpenSSH's \
     ssh, or podssh ssh, reaches it through its ProxyCommand, on this host or at the other end of any pipe. \
     Nothing listens. It runs as the user that started it, with no passwd entry, setgroups or chroot. At its \
     start it gives up each capability of the process, before it reads a file; a capability that stays is \
     a refusal (78).",
    "podssh serve NAME is the node of the pair NAME (podssh relay pair NAME) whose sessions serve answers itself, in \
     its process: no TARGET is dialled, and nothing listens. An operator reaches it as any node: podssh ssh \
     node://user@NAME, podssh cp or sftp to node://NAME. That goes through the relay, with the node's end-to-end \
     channel and resumable layer. A host with no sshd, which may not listen, gives a shell and its files this way. The \
     keys, the host key and the other flags are those of --stdio; --stdio and NAME are one of the two (64). The node's \
     lines say serving podssh serve, in this process. Whoever holds the pair's connect token reaches serve, whose \
     authorized keys alone guard each login. SIGHUP reads the keys again for each session of the node, as \
     with --stdio, and --revoke-ends-sessions ends a removed key's sessions there too.",
    "Only public keys log in, with a one-time code after the key where --totp asks for one (below). The keys \
     are each --authorized-key, and the lines of each --authorized-keys file; with neither, \
     ~/.ssh/authorized_keys. A key is compared by its key alone: the login name selects \
     nothing, but a name of --share (below). The options before a key are its rules (below); a line whose options serve cannot all \
     honour, and a line that is no key, are passed over, and said with their number and why. A file that \
     is a symbolic link, another user's, or one that others can change is refused (78). With no key at \
     all, the start is refused (78): no setting lets each key in.",
    // A listener that the user asks for (T-124).
    super::notes_serve_listen::LISTEN,
    super::notes_serve_listen::BIND,
    super::notes_serve_listen::CAPS,
    super::notes_serve_listen::DEADLINE,
    // The algorithms (T-841): the test below holds each name against the
    // server's constant, so the note and the set cannot part.
    "The algorithms are one stated set, the same at each start, never russh's default of the day. Key exchanges: \
     mlkem768x25519-sha256, curve25519-sha256, curve25519-sha256@libssh.org, diffie-hellman-group-exchange-sha256, \
     diffie-hellman-group18-sha512, diffie-hellman-group17-sha512, diffie-hellman-group16-sha512, \
     diffie-hellman-group15-sha512 and diffie-hellman-group14-sha256. Host key algorithms: ssh-ed25519, \
     ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, rsa-sha2-512 and rsa-sha2-256. Of \
     those, a client is offered the ones that the host key serves. Ciphers: chacha20-poly1305@openssh.com, \
     aes256-gcm@openssh.com, aes256-ctr, aes192-ctr and aes128-ctr. MACs: hmac-sha2-512-etm@openssh.com, \
     hmac-sha2-256-etm@openssh.com, hmac-sha2-512 and hmac-sha2-256. Compression: none, zlib and \
     zlib@openssh.com. A client that offers no name of a list is refused in the handshake (OpenSSH: no matching \
     cipher found, and the set as Their offer).",
    "The options of a key line are OpenSSH's (the format of the authorized_keys file in sshd(8)), read as sshd reads \
     them: separated by commas, names in any case, a value in double quotes where a backslash before a quote is a \
     quote. command=\"...\" runs in place of each command, shell and sftp request, as SHELL -c, with the client's \
     command in SSH_ORIGINAL_COMMAND (not set for a shell; internal-sftp for sftp); command=\"internal-sftp\" serves \
     SFTP alone, and refuses one with arguments. no-pty refuses a pty (OpenSSH, with -tt, ends with PTY allocation \
     request failed). no-port-forwarding refuses each forward, and each permitopen=\"host:port\" (an IPv6 address in \
     brackets; * for any port) lets in that target alone, the host compared as written, with no lookup. restrict turns \
     off the pty and forwarding, and a later pty or port-forwarding turns one on again. \
     expiry-time=\"YYYYMMDD[HHMM[SS]]\" (local time, or UTC with Z) refuses the key after it. from=\"patterns\" lets \
     the key in from a matching address alone: addresses with * and ?, blocks such as 10.0.0.0/8, and ! to refuse; \
     serve looks up no name, so a host name matches nothing. serve knows an address only when its stdin is a TCP \
     socket (as from inetd): on a pipe, as from a ProxyCommand or the relay, no from= matches, and the key is refused. \
     no-agent-forwarding, no-X11-forwarding and no-user-rc change nothing (serve offers none of them). A security key \
     (sk-ssh-ed25519, sk-ecdsa-sha2-nistp256) logs in only with a signature whose flag of presence is set (the key was \
     touched), as sshd checks it: no-touch-required takes one without, and verify-required also asks for the flag that \
     the key verified the user (a PIN); restrict changes neither, and serve's stderr names the flag that was missing. \
     environment=, permitlisten=, tunnel=, principals=, cert-authority and any option that serve does not know make \
     the line unused, named. Of the lines of one key, the first that lets it in now holds. Each refusal by a rule goes \
     to the client: a forward refused as administratively prohibited, a pty or a command with its line on the \
     channel's stderr. It also goes to serve's stderr, with the key's fingerprint and the option; a key refused at \
     login is said there alone, as the client hears Permission denied.",
    "The host key is --host-key FILE, else serve_host_ed25519_key in the cache (see FILES): made at the \
     first start, an Ed25519 key of mode 0600, and read at each later one, never overwritten; of two \
     starts at once, one makes it and the other reads it. Its fingerprint goes to stderr at each start, \
     with a warning when the file is in a temporary directory, which a reboot can empty: each client would \
     then meet a new host key. A key file with a passphrase is refused (78). An RSA key signs through \
     aws-lc-rs, whose RSA is constant-time, with SHA-2 alone (rsa-sha2-512, rsa-sha2-256), never through \
     russh's rsa crate. An RSA key outside 2048 to 8192 bits, or a key that is not Ed25519, ECDSA or RSA, \
     is refused (78).",
    "A command (exec) runs as SHELL -c COMMAND. A shell request runs the shell as a login shell (its argv[0] the \
     shell's name after a dash). Each runs as the user that runs serve, on three pipes: stdout comes as data and \
     stderr as extended data, apart. Each child leads a session of its own (setsid), in HOME when it is a directory, \
     else /; a signal request goes to its process group. When it ends, its pipes are read to their end, for 2 s of \
     silence at most (30 s in all): a job that it put in the background can hold them. Then comes exit-status, or \
     exit-signal with the signal's name and the core flag, always before EOF and close. X11, a Unix socket's forward \
     and each subsystem but sftp are refused with their answer.",
    "A pty request (OpenSSH's -t and -tt) is granted where a pty opens at that moment: serve tries /dev/ptmx, then \
     /dev/pts/ptmx, at each request, and keeps nothing for the next one. The command or the shell then has the pty's \
     slave as its stdin, stdout and stderr and as its controlling terminal. It runs in a session of its own, so Ctrl-C \
     and the job control of a shell work as under sshd; TERM is the request's (xterm-256color when it is empty), and \
     the variable of the slave's path is set as sshd sets it. The size is the request's (80x24 when it is zero) and \
     follows each window change; the request's terminal modes are set where termios has them, and a mode that it lacks \
     or that the kernel refuses is passed over. On a pty, stdout and stderr come as one stream of data, and the \
     client's EOF ends its input alone. On Linux, where neither master opens, serve makes a pty of its own: a helper \
     process makes a user and a mount namespace, mounts a new devpts instance, and gives back its master and its \
     slave. The slave has no path, so the variable of the slave's path is not set; a host that refuses unshare or \
     mount refuses this too (podssh doctor's line pty devpts). Where no pty opens, on Linux (x86_64 and aarch64), \
     serve gives the program a tty that it answers itself: the program's stdin, stdout and stderr are one socket. A \
     seccomp filter of the program's own, set before it starts, sends its tty calls and its opens to serve. The tty \
     calls are the ioctl requests of termios, the window size and the foreground group. serve answers them from one \
     termios state, and gives a copy of the socket for /dev/tty; each other call goes to the kernel. The program sees \
     a tty: test -t 0, stty, a shell's job control, vi, less and top; the keys go through a line discipline in serve \
     that follows the state that the program set. That state is echo, editing, Ctrl-C, Ctrl-Z and Ctrl-\\ to the \
     foreground group, and the window size with SIGWINCH. On a socket, Ctrl-D on an empty line ends the program's \
     input for good. A program that reads two lines quickly may get both in one read. Where the host's own filter \
     already holds a listener, so that a second is refused, serve answers the same calls by ptrace: the program's \
     filter stops it at each tty call and open, and serve's thread answers from the same state. It follows each \
     process that the program starts, and an open of /dev/tty becomes a copy of a descriptor that holds the socket. \
     The program and its children can then use no ptrace of their own (gdb, strace); serve says so. A host that \
     refuses both, or the program's memory to serve, refuses this (podssh doctor's lines pty notify and pty ptrace); \
     --pty notify takes it with no pty tried, and refuses the request where it fails. Where none of these opens (a \
     cage with no /dev/ptmx), serve is the line discipline itself (--pty auto): the command or the shell runs on \
     pipes, and each key is echoed and edited in serve. A line goes to the program when Enter submits it. Ctrl-C and \
     Ctrl-\\ go to the program's process group as SIGINT and SIGQUIT. Its output comes around the line under edit, \
     with each line ending CR LF. A login shell runs with no prompt of its own and a trap of SIGINT and SIGQUIT. So \
     Ctrl-C ends the command and not the shell; serve draws the prompt $. A program that draws on a tty (vi, less, \
     top) gets a line that says so, then runs. --pty line takes the line discipline with no pty tried; --pty no \
     refuses such a request with its answer, and a command then runs on pipes (OpenSSH, with -tt, ends with PTY \
     allocation request failed); podssh doctor's lines pty, pty devpts and pty notify say which a client meets. On \
     Windows the request is refused.",
    // The message of the day (T-119).
    "A login shell on a tty, of any of the kinds above, is shown the message of the day first, as sshd shows it. The \
     file is --motd FILE, else /etc/motd where it is there. A command, a forced command= and a subsystem are shown \
     none. A user with ~/.hushlogin is shown none; serve takes the home from HOME. At most 64 KiB of the file is shown, \
     and serve's stderr says when the rest was cut. Each control character but tab and newline is dropped, so the \
     file cannot drive the terminal. The file is read again at each login. A --motd FILE that cannot be read refuses \
     the start (78); later, a login goes on without it, and stderr says why.",
    // The marks of a shell (T-120).
    "With --shell-integration, a login shell on a tty is marked for the terminal: OSC 133 marks each prompt, command \
     and output, and OSC 7 names the directory. A terminal then jumps between commands, and opens a tab in the same \
     directory. On a pty, or a tty that serve answers, bash and zsh take the marks from their start. bash runs with \
     an rc file of serve's own that reads the files of a login, then adds hooks. It is no login shell then, so \
     logout refuses; exit ends it. zsh runs with ZDOTDIR at a directory of serve's own. Its .zshenv gives ZDOTDIR \
     back, reads the user's .zshenv, and adds hooks. The files are in TMPDIR, else /tmp, and go when the session \
     ends. serve never writes a file of the user's. Another shell gets no marks, and stderr says so. On the line \
     discipline, serve marks its own prompt and each line submitted. It cannot see a command end, so the output's \
     end comes at once, with no status. A command gets no marks.",
    // Each pty child in a transient scope (T-122).
    "Where systemd is this host's service manager, each child on a pty runs in a transient scope of its own, as sshd \
     moves each session. A stop of serve's unit then leaves each user's shell, and its memory counts against the \
     scope. At its start, serve checks /run/systemd/system, busctl and systemctl on PATH, and that the user's manager \
     says running or degraded within 2 s. Where that fails, stderr says so once, and each child \
     starts where serve is. With systemd, the child waits between its fork and its exec until the user's manager has \
     moved it into podssh-serve-PID-N.scope. A move that fails, or takes past 2 s, lets the child go on where serve \
     is, with one line on stderr. No session fails because systemd is absent or slow. The user's manager lists \
     each open session's scope as podssh-serve-*. On another system there is no probe and no line.",
    "The sftp subsystem is served in the process: SFTP version 3 as OpenSSH's sftp-server speaks it. So OpenSSH's \
     sftp, its scp (SFTP is its mode since OpenSSH 9.0) and podssh cp reach a cage that has no sftp-server, scp or \
     rsync. The files are reached as the user that runs serve, with no chroot: what that user may read and write, a \
     client may. A path is taken as the client gives it, and a relative one starts at HOME (/ with none). Served: \
     open, read, write, close, stat, lstat, fstat, setstat, fsetstat, opendir, readdir, remove, and rename (never over \
     a name that exists). Served too: mkdir, rmdir, realpath, readlink and symlink, and the extensions \
     posix-rename@openssh.com (a rename over a name), fsync@openssh.com and limits@openssh.com. Two more are \
     podssh's own: sha256@podssh, the SHA-256 of a byte range of an open file, and sha256-blocks@podssh, that of \
     each block. So podssh cp checks a copy with no second read and no exec; other clients pass them by. \
     A digest has 20 s, and one second more for each 32 MiB of its range. A failure is its \
     status code with the path and the system's words (no such file, permission denied, failure). Each call on the \
     file system has 20 s: past it the reply is a failure that says so, and the handle that it used is closed. The \
     session goes on, so a FIFO with no writer or a dead mount cannot stop it; a session that left 8 such calls ends. \
     At most 256 handles are open in a session, a read is 255 KiB at most and a request 256 KiB. A listing names \
     owners by number, as serve reads no passwd entry. scp in its legacy mode runs scp by exec, and exits 127 in a \
     cage that has none. --no-shell leaves SFTP served, as it runs no program.",
    "A client's forward (direct-tcpip, from OpenSSH's -W, -L and -J) is a TCP connection that serve opens from its own \
     host. It goes to the host and port asked, any of them, as sshd allows by default: a name is resolved there, or \
     given to the proxy of serve's HTTPS_PROXY. The loopback and the names of NO_PROXY go directly, as podssh's own \
     dials go. The dial has 20 s. One that fails is refused as connect failed, with its reason in words, the system's \
     error or the proxy's status and reason (OpenSSH: open failed: connect failed: podssh serve: could not connect to \
     127.0.0.1:1: Connection refused); a port of 0 or past 65535 too. The bytes go both ways, an end of one way keeps \
     the other open, and the TCP connection ends with its channel. At most 256 forwards are open at once on one \
     connection, and one more is refused as a resource shortage. --no-forwarding refuses each forward, \
     administratively prohibited, with the flag named. A client's -R (tcpip-forward) is refused, and serve's stderr \
     says why: serve binds no socket for it (OpenSSH: remote port forwarding failed).",
    "The environment of a child is serve's own, as the cage gave it (PATH, HTTPS_PROXY and the rest stay). It goes \
     without podssh's credentials: PODSSH_RELAY_TOKEN, the secrets of Cloudflare Access, and each variable of podssh \
     whose name holds TOKEN, SECRET, PASSWORD or PASSPHRASE. Of those, the ones that name a file stay. It adds USER \
     and LOGNAME (serve's, else the uid's number: no passwd entry is read), HOME (/ with none), SHELL and PATH (sshd's \
     /usr/local/bin:/usr/bin:/bin with none). A client's env request (OpenSSH's SetEnv and SendEnv) is taken when its \
     name matches an --accept-env pattern (default LANG and LC_*). It is never taken for LD_*, PATH, HOME, SHELL, ENV, \
     BASH_ENV, IFS, USER, LOGNAME or SSH_ORIGINAL_COMMAND, whatever the pattern; --accept-env '' takes none.",
    "The shell is found with no passwd entry and no /etc/shells: --shell PATH alone when it is given; else SHELL, then \
     /bin/sh, /usr/bin/sh, /bin/bash, /usr/bin/bash, /bin/ash and /bin/dash. A candidate passes when it is an absolute \
     path to a regular file that this user may execute. A real run of -c 'exit 0' must also end with 0 within 5 s: a \
     noexec mount, a data file with its mode bits set or a missing loader fail there. The search runs at the start and \
     again at each session, with no cache. At the start, a candidate passed over is said with its reason (not \
     executable (noexec mount), for one). No shell at all refuses the start (78), as does a --shell that does not run; \
     --no-shell skips the search, and refuses each command and shell. In a session, the same line goes to the \
     channel's stderr, and the request fails (OpenSSH: exec request failed). podssh doctor's line shell names the \
     shell that serve would run, and each candidate passed over.",
    "A client that reads slowly slows the child: its output is read 32 KiB at a time, and read again only once that \
     went out within the client's window. So a client that stops reading leaves the pipe or the pty full and the child \
     waiting in its write. serve's memory does not grow; the session goes on when the client reads again. The other \
     way, each channel's window (512 KiB) opens as the child, the SFTP server or a forward's target takes the bytes. \
     So a child that reads nothing of its stdin holds its own channel alone, never the other channels of the \
     connection.",
    "SIGTERM or SIGINT stops serve cleanly: it takes no new session or forward, and sends the client a disconnect with \
     the reason podssh serve is stopping (OpenSSH prints it). It hangs up the process group of each command, shell and \
     pty child (SIGHUP, then SIGCONT, as the kernel does when a terminal goes away). A group that still runs 5 s later \
     is killed with SIGKILL; a second SIGTERM or SIGINT kills at once. Then serve exits 0. A client that closes its \
     channel, or a connection that ends, hangs up that channel's child the same way. So nothing of a session that is \
     gone runs on unless it asked to (nohup).",
    "SIGHUP reads the authorized keys again: each --authorized-keys file, or ~/.ssh/authorized_keys; each \
     --authorized-key stays. Each line is read as at the start, its options its rules: a line that is \
     not used is passed over and said. The next login meets the new set; a session that logged in goes \
     on, under the rules it logged in with. A file that is gone or cannot be read, or no key at all, \
     keeps the set before, and one line on stderr says why; a reload that took says how many lines are \
     used now. The other settings are the command line's, and a restart changes them. Under --stdio, a SIGHUP \
     that comes with the end of the input is the client's end, as OpenSSH hangs up its ProxyCommand when it \
     exits: it reads nothing and says nothing. A client that closes the connection after its login, with or \
     without a disconnect, ends it with no line.",
    "With --revoke-ends-sessions, a reload that takes a key out also ends that key's open sessions. A key whose \
     line now refuses it (from=, expiry-time=) counts as out. The client gets a disconnect that names the key \
     (OpenSSH prints it), and its children are hung up as at a stop. One line on stderr names each key. A key's \
     expiry-time= then ends its sessions at that second too. A reload that keeps the set before ends nothing. \
     Without the flag, no session ends by a reload.",
    // A shell shared by name (T-837).
    "With --share, each login shell on a pty is shared by two names, told once to its owner on stderr. A name is 128 \
     random bits in hex, after rw- (it types) or ro- (it watches). ssh NAME@HOST, by the same road, attaches to the \
     shell with any key. A name that serve does not hold reads as a wrong key. A watcher's input never reaches the \
     pty: it may send only its window size. Writers, the owner among them, take turns: one writer's bytes reach the \
     pty until 200 ms of its silence. The pty's size is the least of each attached window. A seat sees the output \
     from its attach on, and one that falls behind skips ahead. A name opens no forward and runs no command. The \
     names die with the shell, and each seat then exits 0. A shell on serve's own tty (--pty line or notify) is \
     shared the same way: each seat sees the screen that serve draws. There, the EOF of the owner's channel no longer \
     ends the shell's input: Ctrl-D or exit does.",
    // The owner's word to its shared shell (T-860).
    "The owner deletes or rotates a name from a new channel of the same connection: the subsystem share@podssh reads \
     one line. The line is rotate WHICH or delete WHICH, where WHICH is rw, ro or a whole name. rotate prints the new \
     name, and the old one lets nobody in; delete prints what it deleted. Each seat that a name opened stays. A \
     refusal is one line on stderr and exit status 1. Only the connection that holds the owner's shell may ask; a \
     login under a name may not. With OpenSSH, open the first login with ControlMaster, then: echo rotate rw | ssh \
     -S SOCKET -s HOST share@podssh.",
    // A shell kept after its client leaves (T-159).
    "Under NAME, a login shell on a pty can outlive its client. podssh ssh's ~d keeps it under a name, and \
     --attach NAME joins it again from a new login. Only the key that kept it finds it, by that name. serve's layer \
     then names keep.v1, and podssh ssh offers ~d only where it does. env keep@podssh NAME before the shell keeps \
     it as NAME if its client is lost with no ~d. Only a shell on a pty of the kernel is kept, and none with \
     --share. A kept shell waits --keep-lease for a client (24 h by default, 30 days at most); env lease@podssh \
     SECONDS asks for less. Its output with no client goes to a ring of 256 KiB, and an attach gets what came since \
     the detach. A ring that dropped a part says how many bytes, and gives the rest from a clean boundary. One \
     client has the shell at a time; --take takes it, and the other client's channel ends with a line. A key keeps \
     4 shells at most, and serve 32. At the end of a lease, serve hangs up the shell's process group, and kills it \
     10 s later. A job in a process group of its own, as job control makes, is the user's to leave behind, as under \
     sshd. A shell that its client leaves with no ~d and no keep@podssh is hung up, as before.",
    // Who may join a kept shell, and replay or reset (T-833).
    "A kept shell's ticket is its key and its name: another key, or a name that this key does not keep, is refused \
     alike. shells@podssh gives each shell's offset, the bytes of its output so far. Before an attach, env \
     count@podssh OFFSET replays from the offset that the client has. An offset that the ring no longer holds, or env \
     reset@podssh yes, gives a reset. serve says so on stderr, then gives the last output from a clean boundary. \
     serve decides the reset itself, so a gap never repeats. One attach at a time: a second one while the first \
     catches up is refused with a line.",
    "A stop or a restart of serve, or of its host, ends each kept shell: a process does not outlive either. serve \
     writes the names of its kept shells to serve-NAME.kept beside its host key, mode 0600. The next start says \
     which shells ended with the last run, and shells@podssh lists them as lost. Under --stdio no shell is kept: \
     serve ends with its one connection. Under --listen none is kept either. --keep-lease with either is a usage \
     error (64).",
    // A client policy (T-838).
    super::notes_policy::SERVE_JUDGE,
    // The audit log (T-116).
    super::notes_serve_audit::AUDIT,
    // A one-time code after the key (T-115).
    super::notes_serve_totp::TOTP,
    // A unit of systemd that runs serve NAME (T-709).
    super::notes_unit::SERVE,
    "The connection ends when the client leaves: exit 0, else 255 when it failed; a stop exits 0, as does a session \
     that a reload ended. Without --stdio, NAME or --listen the run is a usage error (64). So are two of them, and \
     --shell with --no-shell. On Windows it exits 70.",
];

/// The host key's file, for FILES.
pub fn file() -> (Vec<String>, String) {
    (
        vec![podssh_ssh::server::host_key::FILE.to_string()],
        "The host key of podssh serve, in the cache, when no --host-key names one: an OpenSSH private key \
         (Ed25519) that the first start makes, mode 0600 (on Windows, the access list of the cache); \
         each later start reads it; podssh never writes over it. Remove it to make a new host key, which \
         each client then sees as a changed one."
            .to_string(),
    )
}

/// The message of the day and `~/.hushlogin` (T-119), for FILES.
pub fn motd_file() -> (Vec<String>, String) {
    (
        vec![podssh_ssh::server::motd::DEFAULT.to_string(), "~/.hushlogin".to_string()],
        "The message of the day that podssh serve shows before a login shell on a tty, when no --motd names \
         another file; a missing file shows none. A ~/.hushlogin in the user's home (HOME) shows none either."
            .to_string(),
    )
}

/// The record of the kept shells, for FILES (T-159).
pub fn kept_file() -> (Vec<String>, String) {
    (
        vec![crate::serve_keep::record_name("NAME")],
        "The names of the shells that podssh serve NAME keeps, beside its host key: on each line, the fingerprint \
         of the key that kept one and its name. Mode 0600, replaced whole at each change. The next start reads it, \
         says which shells ended with the last run, and lists them as lost. It holds no output."
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use podssh_ssh::server::algorithms;

    /// The note of the algorithms names each name of the server's set
    /// (T-841): a name added to the set and not to the note fails here.
    #[test]
    fn the_note_names_each_algorithm_of_the_set() {
        let note = super::SERVE.iter().find(|n| n.starts_with("The algorithms are one stated set")).expect("the note");
        let set = [
            algorithms::kex_names(),
            algorithms::host_key_names(),
            algorithms::names(algorithms::CIPHERS),
            algorithms::names(algorithms::MACS),
            algorithms::names(algorithms::COMPRESSION),
        ];
        // A name holds dots (zlib@openssh.com): only the end of a sentence
        // and the punctuation around a word are cut.
        let cut = |c: char| ".():".contains(c);
        let words: Vec<&str> =
            note.split(|c: char| c.is_whitespace() || c == ',').map(|w| w.trim_matches(cut)).collect();
        for name in set.iter().flatten() {
            assert!(words.contains(&name.as_str()), "the note does not name {name}");
        }
        // And its host key algorithms are the set's, no more (T-856 took
        // ssh-rsa out of the set).
        let (_, rest) = note.split_once("Host key algorithms: ").expect("the host key algorithms");
        let (list, _) = rest.split_once(". ").expect("the end of the sentence");
        let named: Vec<&str> = list.split(", ").flat_map(|part| part.split(" and ")).collect();
        assert_eq!(named, algorithms::host_key_names(), "the note's host key algorithms");
    }
}
