//! The FILES table, as data: its names and what podssh does with each,
//! from the constants that the code uses (split from `data.rs`).

use std::path::Path;

fn paths(list: Vec<std::path::PathBuf>) -> Vec<String> {
    list.iter().map(|p| p.display().to_string()).collect()
}

/// Each file that podssh reads or writes: its names, and what podssh does
/// with it. The home directory is written `~`, so the table is the same for
/// each user.
pub fn files() -> Vec<(Vec<String>, String)> {
    let home = Path::new("~");
    let global_kh: Vec<String> = if cfg!(windows) {
        vec![r"%ProgramData%\ssh\ssh_known_hosts".to_string()]
    } else {
        paths(podssh_ssh::options::default_global_known_hosts())
    };
    let cache = if cfg!(windows) {
        "%PODSSH_CACHE_DIR%, else %LOCALAPPDATA%\\podssh, else podssh-USER in the temporary directory (%TMP%, \
         %TEMP%, else the one Windows gives), else .podssh in the working directory"
    } else {
        "$PODSSH_CACHE_DIR, else $XDG_CACHE_HOME/podssh (else ~/.cache/podssh; when it is in another \
         user's tree, the .cache/podssh of the home of your uid's entry in /etc/passwd); else \
         $XDG_RUNTIME_DIR/podssh; else podssh-UID in $TMPDIR (else $TMP, $TEMP, and only then /tmp and \
         /dev/shm); else ./.podssh"
    };
    let mut rows = vec![
        (
            paths(podssh_ssh::options::default_identity_files(home)),
            "The identity files tried, in this order, when no -i or IdentityFile is given.".to_string(),
        ),
        (
            paths(podssh_ssh::options::default_user_known_hosts(home)),
            "The user's known hosts. podssh records a new host key in the first file (mode 0600, in a \
             directory of mode 0700). With no home directory, a new key is accepted but not recorded."
                .to_string(),
        ),
        (global_kh, "The system's known hosts. podssh only reads them.".to_string()),
        (
            vec!["~/.ssh/config".to_string()],
            "The user's ssh_config, read by podssh ssh, cp, mv, scp and sftp unless -F or PODSSH_SSH_CONFIG \
             names another file, or none. A missing file is no error. A file that another user than you or \
             root owns (on Windows, than you, SYSTEM or the Administrators) is refused. So is a file that others \
             can change (on Windows, as its access list says), and so is each file that an Include reads. The file \
             that -F or PODSSH_SSH_CONFIG names is your choice, and is not checked, as OpenSSH does not check \
             it. Match \
             is read as OpenSSH 10.3p1 reads it, but for Match exec and Match localnetwork. These are refused by \
             name, with the file and the line, where they would decide, and run nothing. Each hop of \
             -J reads the blocks of its own name, as OpenSSH's jump host does; it logs in as its user@, its \
             User, else the local user. The first ProxyCommand holds, as in OpenSSH: none, or podssh proxy %h \
             %p, on the command line or in an earlier block, goes past a later block's command. So -o \
             ProxyCommand=none goes past a Host * that names a jump host for OpenSSH, and keeps the file's \
             other settings. A later ProxyJump is not read, as OpenSSH does not read it then; a \
             command with no value before it is refused with its file and line (exit 78)."
                .to_string(),
        ),
        (
            vec![if cfg!(windows) { r"%ProgramData%\ssh\ssh_config" } else { "/etc/ssh/ssh_config" }.to_string()],
            "The system's ssh_config, read after the user's, and not when -F or PODSSH_SSH_CONFIG names a \
             file. A relative Include in it starts from its directory."
                .to_string(),
        ),
        (
            vec![cache.to_string()],
            format!(
                "The cache: the first of these directories that podssh can use. It holds one relay token for \
                 each relay deployment, with the host that minted it ({} for the default relay). It holds the \
                 relay's list of hosts ({}). It holds the last addresses that carried a session to each relay host \
                 ({}), which a run whose resolver fails asks before DNS over HTTPS. It holds the key exchange \
                 group that each TLS server took ({}), which the next run offers first. For each host \
                 that took a key, it holds that key's fingerprint by a hash of its host key and the user ({}): the \
                 next login sends that key's signature in its first request, with no query before it. It does so \
                 when the key is a file that opens with no question and is not RSA or a security key's. Neither \
                 holds a secret. It holds each pair of the \
                 reverse road under its label ({}), \
                 as podssh relay pair writes it. Until a copy that broke is done, it holds its side file \
                 (podssh-cp-*.resume: the offset, the temporary file's name and the source's state, never a \
                 byte of the file). While podssh edit runs, a directory edit-RANDOM of mode 0700 holds the \
                 copy of the far file; it goes after the edit, and stays, named, after a failure when the copy \
                 holds a change. Each file has mode 0600; on Windows, an access list that lets in only \
                 you, SYSTEM and the Administrators. podssh ignores a cache file that is a symbolic link, \
                 that belongs to another user, or that others can read. On Unix, $XDG_CACHE_HOME, ~/.cache \
                 and $XDG_RUNTIME_DIR count only in your own tree: each of their directories that exists, up \
                 to the home (else up to /), is yours or root's. One in another user's tree, as when root runs \
                 with the HOME of another account, is passed over: podssh writes nothing more there, and \
                 makes no directory there, so a missing .cache stays its owner's to make. It still reads a \
                 key, the pins, a pair or a token that an earlier run kept there, after your own places; it \
                 says once of a key where to move it; it moves nothing. podssh status and podssh doctor name \
                 each place passed over, and why. Above the cache's own directory, podssh makes a missing \
                 one only in a directory of yours or of root.",
                podssh_relay::cache::file_name(podssh_relay::default_relay_host()),
                podssh_relay::pool::file_name(podssh_relay::default_relay_host()),
                podssh_relay::addresses::FILE,
                podssh_relay::tls_groups::FILE,
                podssh_ssh::accepted::FILE,
                podssh_relay::pair::file_name("LABEL").unwrap_or_default()
            ),
        ),
        (
            vec![podssh_relay::pair::part::file_name("NAME").unwrap_or_default()],
            "The operator's part of a pair that podssh relay join NAME took by a code, in the cache: the \
             relay, the pair's name, its connect token and its expiry, as JSON with mode 0600, replaced by the \
             next join under NAME. podssh operator, podssh ssh node:// and podssh relay status find it by NAME \
             where no pair is stored under it."
                .to_string(),
        ),
        // The offsets of kept shells (T-895).
        (
            vec![podssh_ssh::keep_record::FILE.to_string()],
            "The offsets of kept shells that this client has, in the cache. For each far end and shell name, it \
             holds the bytes of output that a session got. A session to a far end that keeps shells writes it at \
             its end, while the shell may still be kept. The next --attach NAME gives that offset, and the far \
             end replays what this client missed. A far end is named by a hash of its host key and the user. The \
             file has mode 0600, holds no secret, and forgets an offset after 30 days."
                .to_string(),
        ),
        (
            vec![
                podssh_relay::identity::file::node_file("NAME"),
                podssh_relay::identity::file::CLIENT_FILE.to_string(),
            ],
            "The keys of the ends of a road between two podssh ends, in the cache, the same on each \
             road: a node's under its NAME, and this user's as a client; --key and --client-key name other \
             files. Each holds the secret key in hex, has mode 0600, and is made when it is missing. podssh \
             refuses one that is a symbolic link, another user's, or that others can read, and never \
             replaces it: a new key would change the node's identity, which operators pinned, and its \
             ticket. The names of an earlier podssh, iroh-node-NAME.key and iroh-client.key, are still read."
                .to_string(),
        ),
        (
            vec![podssh_relay::pool::kept::FILE.to_string(), podssh_relay::pool::signed::ROLE_KEY_FILE.to_string()],
            "The signed lists of relay deployments, in the cache: the newest list of each trusted key, its exact text \
             and its signature, as JSON with mode 0600. It is checked again at each read, so that a run keeps the \
             other deployments when the default's domain is gone; and the key with which podssh relay serve \
             --deployment signs its list, in hex with mode 0600. The key is made when it is missing, unless --list-key \
             names another file."
                .to_string(),
        ),
        (
            vec!["grants-NAME/".to_string()],
            "The grants used once that the node NAME let in, in the cache: a private directory with a file of mode \
             0600 for each grant. Each file is made create-new and synced before the session comes in. It is named by \
             the end of the grant's window and the digest of what its issuer signed, and removed once that end passed. \
             A grant whose file is there is refused; a directory that cannot take a file refuses each grant. It holds \
             no secret: a serial and an issuer's fingerprint."
                .to_string(),
        ),
        (
            vec![crate::net::reached::FILE.to_string()],
            format!(
                "The road that last reached each node from this host, in the cache: by the node's label, the \
                 road that answered first, its time and when, and why the last race that found no road ended so. It is \
                 JSON with mode 0600, at most {} nodes, the oldest going first. Each race of podssh ssh, of the \
                 copies and of podssh ping to node://NAME writes it, and podssh status --net reads it. It holds no \
                 secret; a record that does not read is none.",
                crate::net::reached::MOST
            ),
        ),
        (
            vec![crate::ssh::cloud::warp::DEVICE_FILE.to_string(), crate::ssh::cloud::warp::DOOR_FILE.to_string()],
            "WARP's road (warp://, in a build with the feature warp), in the cache: the device, pod-warp's identity \
             file of mode 0600, JSON with its record of WARP's API, its certificate and its P-256 key. It is written \
             once as it registers, and again when WARP's API gives the front door a new key; and the door that opened \
             and the API's base that answered last, which a run tries first. A record that cannot be read is a \
             configuration error (78), never a new registration: remove it to register again."
                .to_string(),
        ),
        (
            vec![format!("{}/HOST-DIGEST/", crate::acme::store::DIR)],
            "The state of podssh relay serve --acme NAME, in the cache, mode 0700, for each CA: HOST is the host of \
             its directory, and DIGEST 8 hex digits of the SHA-256 of its URL. account.key, the account's P-256 key, \
             made once and never replaced; NAME.pem, the certificate's own P-256 key and its chain in one file. It is \
             replaced whole by a rename at each renewal, so that the key of one certificate is never read with the \
             chain of another. Each has mode 0600; podssh refuses one that is a symbolic link, another user's, or that \
             others can read."
                .to_string(),
        ),
        (
            vec!["detached/".to_string()],
            "The runs that --detach and -f sent into the background, in the cache, mode 0700: \
             VERB-PID.log, mode 0600, which takes the run's stdout and stderr once it is ready; past 1 MiB it is \
             renamed VERB-PID.log.1, which takes the lines written until the run writes the new one, so none is \
             lost. NAME.lock, which the run of the name NAME (or its supervisor \
             of --restart) holds for its life, with its pid in it. NAME.run.lock, which a supervisor's run \
             holds: a second start of the name refuses while either is held, and podssh detached reads them. \
             NAME.json, the run's record: its pid, the pid of a supervisor's run, its words, its log and its \
             start. NAME.alive, whose time each run of --restart sets each 10 s, and which its supervisor reads \
            . Each start of --detach or -f removes each of them older than 30 days whose run runs no \
             more: no lock of its name is held, and the process of a log's PID is gone."
                .to_string(),
        ),
        (
            vec!["node-NAME.env".to_string(), "ssh-NAME.env".to_string(), "node-NAME.env.lock".to_string()],
            "The service of podssh node NAME --install, or of podssh ssh --install NAME, in the \
             cache: the private file of the variables that it reads (the file of --env-file), with no token; \
             FILE.lock beside it, which its run holds with its pid in it, so that a second start of the service \
             ends at once; and a LaunchAgent's log, node-NAME.log, made with mode 0600 before launchd opens it. \
             --uninstall removes them, with the unit, the LaunchAgent \
             (~/Library/LaunchAgents/dev.podssh.VERB.NAME.plist), the lines of the crontab or the task."
                .to_string(),
        ),
        (
            vec!["node-NAME.shares".to_string(), "node-NAME.shares.lock".to_string()],
            "The shares of podssh node NAME, in the cache beside its key, or the file of podssh node --shares \
             FILE: one name=HOST:PORT on each line, which the node reads again for each session. podssh \
             share changes it under the lock of FILE.lock beside it, the file replaced whole. Mode 0600; the node \
             refuses one that others may change, as it names what the node dials."
                .to_string(),
        ),
        (
            vec![format!("{}/", crate::ssh::cloud::tor::DIR_NAME)],
            "The Tor road's directory (tor://, in a build with the feature tor), in the cache, mode 0700: \
             Arti's state (its guards, which Tor asks a client to keep) in state/. Its copy of Tor's \
             directory in cache/, which a later run reads to start sooner. Arti checks that no other user \
             can write them; where a sandbox's mounts fail that check on a directory above, podssh made \
             these private itself and tries once more without it. The same pair for another network of \
             PODSSH_TOR_NETWORK goes in networks/, by a digest of its file. Removing it costs the next run a \
             new bootstrap."
                .to_string(),
        ),
        (
            vec![podssh_relay::identity::pins::FILE.to_string()],
            "The node keys that an operator has met, in the cache: one line for each key of a label, LABEL \
             KEY, the key as its fingerprint (SHA256:...) or itself. The first sight of a label's node \
             writes its line; a node whose key matches no line of its label is refused, and no line is ever \
             replaced: remove one, or add one for a new key. A file of the user that others cannot change. A \
             member of the net is checked by the key that the net names, and its line is not written."
                .to_string(),
        ),
        (
            vec![crate::net::store::FILE.to_string()],
            "The net's document (podssh net), in the cache, or the file of PODSSH_NET: one line of JSON, \
             then the owner's signature as ssh-keygen -Y sign writes it, replaced whole by each document taken. \
             A file of the user that others cannot change; a node of the net reads it again for each session."
                .to_string(),
        ),
        (
            vec!["the file of --shadowsocks".to_string()],
            "The Shadowsocks servers of --shadowsocks: ss:// lines, subscription lines and access keys (see podssh \
             ssh). Its keys hold passwords. So podssh reads it as it reads a pair file: only as a regular file of \
             yours that others cannot read (on Windows, as its access list says); else, and for a line that cannot be \
             read, the run is refused (78). podssh never writes it."
                .to_string(),
        ),
        (
            vec!["the file of --via-auth-file".to_string()],
            "The Basic credentials of the forward proxy of --via: one line, USER:PASSWORD, or the password alone \
             when the URL names USER; # starts a comment. podssh reads it only as a regular file of yours that \
             others cannot read (on Windows, as its access list says), as a pair file; else, and for a line that \
             cannot be read, the run is refused (78), and no message shows the line. podssh never writes it."
                .to_string(),
        ),
        (
            ["the file of --vless", "the file of --trojan", "the file of --tuic"].map(String::from).to_vec(),
            "The VLESS servers of --vless, the Trojan servers of --trojan, or the TUIC servers of --tuic: a \
             vless://, trojan:// or tuic:// share link on each line (see podssh ssh); # starts a comment. Each link \
             holds its user's ID or password. So podssh reads it as it reads a pair file: only as a regular file of \
             yours that others cannot read (on Windows, as its access list says); else, and for a line that \
             cannot be read, the run is refused (78), by the line's number, never its text. podssh never writes \
             it."
            .to_string(),
        ),
        (
            vec!["the file of --wstunnel-secret-file".to_string()],
            "What the wstunnel server of --wstunnel checks of a client: path-prefix PREFIX, the prefix that it \
             restricts its clients to, as letters, digits and -._~!$&'()*+,;=:@; credentials USER[:PASSWORD], \
             sent as Basic, or authorization VALUE, sent as it is, the Authorization that its restrictions match; \
             each once, and one of the last two; or one line, the prefix alone. # starts a comment. podssh reads \
             it only as a regular file of yours that others cannot read (on Windows, as its access list says), as \
             a pair file; else, and for a line that cannot be read, the run is refused (78), by the line's number \
             and never its text. podssh never writes it."
                .to_string(),
        ),
        (
            vec!["shadowsocks-HASH.json".to_string()],
            "The list of each subscription and access key of --shadowsocks, in the cache, under a hash of its \
             URL, which it does not show: the time it came and its ss:// lines, with a WebSocket's URL beside \
             each server in one; they hold passwords; mode 0600. Read for a day, then fetched again, and fetched \
             again too when each of its servers failed."
                .to_string(),
        ),
        (
            vec!["the file of --allow".to_string()],
            "The operator keys that may come in to podssh node, on each road: one key on each line, as the line \
             that podssh keygen -y prints (ssh-ed25519 BASE64), its fingerprint (SHA256:...), or its hex or \
             base32. Then routes=ROUTE,... for the routes that it may use, and those alone (routes=* for each, and \
             the TARGET with no route); a line with no routes= reaches the TARGET with no route. Then a comment if \
             any; # starts a comment line. Read again for each session. A file of the user that others cannot \
             change; others may read it."
                .to_string(),
        ),
        (
            vec![podssh_ws::bundle::BUNDLE_FILE_NAME.to_string()],
            "CA certificates in the directory of the podssh binary, added to the trust store.".to_string(),
        ),
        (
            if cfg!(windows) {
                vec![r"%APPDATA%\podssh\settings".to_string(), crate::settings::BESIDE_BINARY.to_string()]
            } else {
                vec!["$XDG_CONFIG_HOME/podssh/settings".to_string(), crate::settings::BESIDE_BINARY.to_string()]
            },
            "podssh's own settings: RelayHost, RelayAddr (each line adds), RelayFailover, CaFile, SessionLog, \
             Forwarder, ForwarderFallback; DoctorJobs (the sections of podssh doctor at once), RelayKeys (the keys of \
             a signed list of relay deployments; each line adds), ECH (as PODSSH_ECH), AccessHost (each line \
             adds), AccessClientIdFile and AccessClientSecretFile (see podssh pipe). NetUrl and NetOwner are \
             --net-url and --net-owner of podssh node. They are Keyword value lines, below the flags and the \
             variables. The file of PODSSH_SETTINGS, else the first of these that exists \
             (~/.config/podssh/settings with no XDG_CONFIG_HOME; the second beside the podssh binary); never one of \
             the working directory. A symbolic link, a file of another user than you or root, one that others can \
             change, and a bad line are refused (78). Each command that reaches the relay refuses them. podssh never \
             writes it, and no keyword holds a token. After a line [groups], each line is NAME HOSTS: a group of \
             hosts, parted by commas or blanks (by commas alone on the command line), which podssh each takes as \
             @NAME. After a line [snippets], each line is NAME COMMAND: a command that podssh ssh --snippet NAME and \
             podssh each run, with its placeholders (see podssh ssh). A COMMAND in double quotes, with none inside, \
             loses them, and a # in it is no comment."
                .to_string(),
        ),
        (
            vec![crate::session_log::FILE.to_string(), crate::session_log::OLD_FILE.to_string()],
            "The log of the sessions of this host, in the cache, when PODSSH_SESSION_LOG or SessionLog asks for \
             it: a JSON line for each run of podssh ssh and podssh proxy that named a destination, at its end. \
             The line holds its start, duration, verb, host, port, relay host or road, end, exit code, bytes and the \
             relay's close code; never a command, an environment value, a token or a password. Mode 0600, \
             opened to append with no symbolic link followed, a line in one write; at 1 MiB it becomes the \
             second name, and a new file starts. podssh status shows the last line."
                .to_string(),
        ),
        (
            vec![format!("sessions{}NAME.sock", std::path::MAIN_SEPARATOR)],
            "The socket of each session of podssh session, in the cache: the directory sessions has mode 0700, \
             and each socket mode 0600 (on Windows, the access list of the cache); it goes when its session's \
             podssh ends. A socket that nobody serves is replaced by the next start of its name. Beside a \
             socket's file, NAME.sock.lock, which its podssh holds for its life. So a second one of the \
             name is refused (69), and it never removes the first one's socket. The lock's file stays after its \
             session ends or fails to start: the system's lock, not the file, holds the name. The next start of \
             NAME takes it again. podssh never removes it, as a removal could let two starts hold one name."
                .to_string(),
        ),
        (
            podssh_ws::tls::SYSTEM_BUNDLES.iter().map(|s| s.to_string()).collect(),
            "The system CA bundles. The first one that podssh can read is added to the trust store.".to_string(),
        ),
        (
            vec![
                ".podssh.update-RANDOM".to_string(),
                "podssh.prev".to_string(),
                "podssh.prev.exe".to_string(),
                "podssh.exe.old".to_string(),
            ],
            "In the directory of the podssh binary, while podssh update runs: the new binary, written beside the old \
             one with its mode and run once with --version. Then it is renamed over the old one, or removed when a \
             step fails. The binary before the last update stays as podssh.prev (podssh.prev.exe on Windows, where the \
             running binary is renamed to it); a move over it or update --rollback puts it back; on Windows, when that \
             name is taken by a running one, the running binary is renamed to podssh.exe.old instead. The next run of \
             podssh removes it."
                .to_string(),
        ),
    ];
    rows.extend([
        super::super::notes_roads::chisel_file(),
        super::super::notes_hysteria::file(),
        super::super::notes_turn::file(),
    ]);
    rows.extend([
        super::super::notes_devtunnel::file(),
        super::super::notes_serve::file(),
        super::super::notes_serve::motd_file(),
        super::super::notes_doctor::http_road_file(),
    ]);
    rows.push(super::super::notes_serve::kept_file());
    rows.push(super::super::notes_gsr::file());
    rows.push(super::super::notes_bucket::file());
    rows.push(super::super::notes_dns::file());
    rows
}
