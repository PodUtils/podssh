//! The FILES and EXIT STATUS tables, as data: the text, the man page and
//! `podssh man --json` read them, so the renderers cannot differ. Each number,
//! name and path comes from the constant that the code uses.

use crate::exitmap::sysexits;

/// An exit code: a number, or the status of the remote command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Value(i32),
    /// `N`: the remote command's status, which `podssh ssh` passes on.
    Remote,
}

/// Each exit code and what it means, from the constants that the commands
/// return.
pub fn exit_codes() -> Vec<(Code, String)> {
    let row = |code: i32, what: &str| (Code::Value(code), what.to_string());
    super::notes_policy::exit_words(vec![
        row(
            0,
            "Success. For podssh ssh: the remote command exited 0. For podssh chat: each message was \
             acknowledged, and the one thing of --send or --file is done; with --listen --linger, also when \
             the --timeout passed, the run's planned end. For podssh ping: a relay host \
             gave its measures, or with a destination each measure has its number. For podssh health: the \
             facts came, or the host has no /proc and gave its system's name; with --preflight, also no \
             check failed.",
        ),
        row(
            crate::doctor::EXIT_FAILED,
            "podssh doctor: a check failed. podssh relay spec: a fact of the relay's document disagrees. \
             podssh relay conform: a check of the relay failed. podssh keygen: a key could not be made or read. podssh health --preflight: after the login, a \
             check failed or the facts did not come. podssh play: the recording cannot be read, or its version is \
             not one that it plays. podssh ping --nodes: some nodes answered and some did not (69 when none did).",
        ),
        row(
            crate::exit_codes::EXIT_USAGE,
            "A usage error: an unknown command or flag, a bad value, a missing argument. podssh did nothing.",
        ),
        row(
            sysexits::EX_DATAERR,
            "podssh agent add-passphrase: the passphrase does not open the key file, or the file needs none; \
             nothing is kept. podssh pipe: the bytes of a udp: address are not each datagram after its \
             length. podssh containers: a tool listed a name that podssh does not take, which is left out. \
             podssh net: a file or a document that cannot be used, nothing kept. Such a file is not UTF-8, not \
             JSON, too large, a policy or a gateway that is not valid, or a signature that fails; add of a key that another member \
             has; take of a document that the rule of the store refuses; policy test: a case is false; policy diff \
             --exit-code: the new policy widens the old. podssh agent: a key file that is no key, or lock \
             passwords that differ. podssh sftp: the file of -b is not UTF-8 text.",
        ),
        row(
            sysexits::EX_NOINPUT,
            "podssh cp and mv: a source is missing or cannot be read. podssh mv: a source that changed \
             during the move, which stays. podssh chat: the file of --file or --sendfile cannot be read. podssh edit: the file is not on the host. podssh sftp: the file of -b cannot be read, or a path that a \
             command names is not on the server. \
             podssh net: the FILE of take, policy set, test or diff, or gateway set is missing or cannot be read. \
             podssh agent: a key file is missing or cannot be read, or no passphrase or password came.",
        ),
        row(
            sysexits::EX_UNAVAILABLE,
            "podssh proxy: no relay host could be reached, or the relay ended the session abnormally. \
             podssh node, operator and relay: the relay or TARGET could not be reached, the node did not take \
             the session, the pair was stopped, or another node serves it; with --sshd, a TARGET that sent \
             no line within 10 s, or closed first; with --publish-tls and --acme, the first order of the \
             certificate failed; with --run-as, no such user. podssh cp and mv: no connection to \
             the server, or it has neither SFTP nor the sh and the tools of a copy by exec. podssh chat: \
             the same of the relay and the pair, or a message went with no acknowledgement; each is said. \
             podssh ping: no relay host answered, the relay refused its default target, or PODSSH_OFFLINE is set. podssh relay status: no relay \
             host answered; podssh relay trace: the relay would not dial the target. podssh agent: no agent \
             answers at SSH_AUTH_SOCK, or it keeps no passwords. podssh agent: the agent refused a key, a list, a \
             removal or a lock; a locked agent refuses each. podssh containers: the host has \
             none of docker, podman and kubectl, one of them failed, or --exec names no container that a \
             list has. podssh session: no session of that name answers, or its session ended (and the \
             status that it ended with is said). podssh detached status and stop: no run of that name \
             runs. podssh relay serve: the port of --listen is in use. podssh keygen -t ecdsa-tpm: no TPM \
             that podssh may reach.",
        ),
        row(
            crate::exit_codes::EXIT_NOT_IMPLEMENTED,
            "The command is not implemented yet, or podssh failed inside. podssh node and operator: the \
             relay closed the node or the session for a fault (1003, 1008 or 1009); or the end-to-end \
             channel failed (a peer with no channel, a message that failed its check). podssh cp and mv: the \
             digests of a copy differ, or the session broke; the destination was not changed. podssh mv: \
             the copy is verified and its source could not be removed; the data is in both places. podssh \
             chat: the peer broke the protocol, the channel failed, or the file of --file arrived with \
             another SHA-256.",
        ),
        row(
            sysexits::EX_CANTCREAT,
            "podssh cp and mv: the destination cannot be written. podssh edit: the far file changed since \
             it was fetched, so nothing was sent and the copy here stays, or no cache directory takes the copy. \
             podssh chat: the path of --accept-dir is not there, or is no directory. podssh each: a file of --output-dir \
             cannot be made; no host has run.",
        ),
        row(
            sysexits::EX_IOERR,
            "The output of a command could not be written, as to a full disk or a device that refuses it. That holds \
             for podssh keygen, doctor, man, status, config, agent and update, and for podssh node --print-unit and \
             podssh serve --print-unit. The line says so, and the command's own code stays when it failed first. A \
             reader that went away, as head does, is no failure.",
        ),
        row(
            sysexits::EX_TEMPFAIL,
            "podssh cp and mv: the --timeout passed before the copy ended; a later try can work. podssh \
             chat: the --timeout passed, or the peer talks with another peer; a later try can work. podssh \
             session start and wait: the --timeout passed first. podssh job wait: the --timeout passed \
             before the job ended, which runs on; podssh job fetch: the job is queued or running, so its \
             output is not whole yet. podssh node --quick-tunnel: api.trycloudflare.com refused for now \
             (429 or a 5xx) and asked for a wait past 5 minutes, which the line names, or refused for 5 \
             minutes; a later run can work. --detach and -f: a run of the same --detach-name runs, and its \
             pid is said. podssh detached stop: the run still holds its lock after it was killed.",
        ),
        row(
            sysexits::EX_NOPERM,
            "podssh proxy: the relay or the proxy refused (a token, or each as a relay that issues none answers 503; \
             a blocked address; a proxy's 403 or 407). \
             podssh node, operator and relay: the relay refused the pair, or the pair expired; for relay \
             trace, the token. podssh operator and pipe node:: the node's key is not the one pinned in known-nodes or named by \
             --node-key; or the node's allowlist refused this client's key, its grant, or its route. podssh cp \
             and mv: the server refused the login, or podssh did not accept its host key. podssh chat: the same of the pair \
             and of the keys, or the peer declined the file of --file. podssh session start: this host refuses \
             the bind of the session's socket. podssh net policy check: the policy does not let FROM reach TO. \
             podssh agent: a wrong passphrase, or a wrong lock password.",
        ),
        row(
            sysexits::EX_CONFIG,
            "A setting of the environment cannot be used: PODSSH_RELAY or PODSSH_RELAY_ADDR (podssh ssh, cp, proxy and \
             doctor). For podssh proxy also a proxy URL of another scheme than http://, socks5:// or socks5h://, \
             or a PODSSH_RELAY_TOKEN that is no token. The same value as a flag is a usage error \
             (64). A line that podssh cannot use, with its file and line named: in the settings file (see FILES), \
             or in an ssh_config file (-F, ~/.ssh/config, the system's, \
             or one that Include reads). Also such a file that cannot be read or that others can change; the same \
             keyword with -o on the command line is a usage error (64). podssh node, operator, relay and chat: no pair \
             is stored under the label, the pair cannot be read or stored, or a node cannot connect as it is set up; \
             podssh node and operator: the relay speaks a dialect of the reverse road that this podssh does not read, \
             or does not read its own (its hello, or 426); the line names the side to update. podssh edit: VISUAL, \
             EDITOR and PATH give no editor, the editor does not start, or PODSSH_CACHE_DIR is none. podssh node \
             --sshd: a TARGET that sends lines and no version line of SSH 2, which is another service. podssh node: \
             this host refuses UDP for a udp: TARGET. podssh each --interactive: the emergency stop cannot be armed. \
             podssh session start and serve: PODSSH_LISTEN is no, or no directory takes the session's socket. podssh \
             serve: no authorized key, or a key file or the host key that cannot be used, or no shell that runs. \
             podssh agent: no terminal and no SSH_ASKPASS that runs, to ask a passphrase or a password.",
        ),
        row(
            podssh_ssh::EXIT_FAILURE,
            "podssh ssh: the connection, the host key, a node's key or the authentication failed; or the \
             server refused a session or ended the connection before one opened (the line says which); or the \
             session ended with no exit status (also when stdout closed and none came within 5 s); or the \
             connection was lost after the exit status and before the end of the output, which may be cut \
             (the line says the status); or the server ended a run of -N. OpenSSH uses the same code, but \
             for a cut, where it gives the status. A node://NAME with no pair stored under NAME is 255 too, as a \
             host that cannot be reached; podssh operator and proxy give 78. podssh ping: the destination could \
             not be reached or logged in to, or a measure broke. podssh each: a host could not be reached \
             or logged in to, or its session ended with no exit status. podssh health: the host could not \
             be reached or logged in to, or it has no sh; or its answer had none of the lines of the script \
             (with --preflight, the login alone). \
             podssh containers: the host could not be reached or logged in to, or its list did not end \
             within 60 s. podssh session start: the connection or the login failed. podssh job: the host \
             could not be reached or logged in to, has no tmux, has no such job, or gave no answer; for \
             wait, also a job that is lost. podssh run: the copy failed, and the command did not run.",
        ),
        (
            Code::Remote,
            "podssh ssh: the exit status of the remote command, unchanged. When signal N stopped the \
             command, 128 + N. podssh ping: the status of the remote program of a measure that failed, \
             127 when the host lacks it. podssh edit: the status of an editor that failed; nothing was sent. \
             podssh each: the largest status of the hosts, 0 only when each gave 0; with --interactive, of their \
             shells, and 130 for a host whose shell Ctrl-C cut after the end of the input. podssh containers \
             --exec: the status of the session in the container. podssh job wait: the exit status of the job. \
             podssh run: the status of the command, as podssh ssh gives it."
                .to_string(),
        ),
    ])
}

// The FILES table lives beside this file, which the EXIT STATUS table fills.
#[path = "data_files.rs"]
mod files_table;
pub use files_table::files;
