//! `podssh serve --stdio` (T-107, milestone M5): podssh's own SSH server
//! for one connection on stdin and stdout, as `sshd -i`, so that OpenSSH's
//! client reaches it through a ProxyCommand and nothing listens (rule 2 of
//! `AGENTS.md`). The server is `podssh_ssh::server`; this file is the
//! command line: the authorized keys, the shell that sessions run (T-222),
//! the host key in its state file, the drop of each capability of the start
//! (T-698), then the connection, whose forwards the server dials (T-109),
//! until the client leaves or a signal stops it; SIGHUP reads the keys
//! again (T-117, `serve_keys.rs`), also under NAME (T-855).
//! The options of each key line are its rules (T-114): a line whose options
//! cannot all be honoured is passed over, and said. `--policy FILE` judges
//! each client's KEXINIT before authentication (T-838). `--share` offers
//! each login shell on a pty by two names (T-837). Under NAME, a shell that
//! its client detached is kept for `--keep-lease` (T-159, `serve_keep.rs`).
//! `--motd FILE` is the message of the day of a login shell on a tty
//! (T-119); `--shell-integration` marks its prompts and commands (T-120).
//! Where a probe finds systemd, each pty child runs in a transient scope of
//! its own (T-122). `--listen ADDR` serves each connection of a listener
//! that the user asks for (T-124, `serve_listen.rs`). `--audit-log FILE`
//! records each login, session and forward (T-116, `serve_audit.rs`).
//! `--totp FILE` asks each key for a one-time code (T-115, `serve_totp.rs`).
//! A client's `-R` is a pair of the relay, whose node runs here, with no
//! bind (T-123, `serve_forward.rs`).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::ArgMatches;
use podssh_relay::cache::{self, Others};
use podssh_ssh::server::motd::{self, Motd};
use podssh_ssh::server::{host_key, HostKey, Keys, PtyMode, Say, Settings, StateFiles};

use crate::exit_codes::{EXIT_NOT_IMPLEMENTED, EXIT_USAGE};
use crate::relay_settings::Refusal;
use crate::serve_keys::{self, Sources};

/// Every value `podssh serve` accepts, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServeArgs {
    pub stdio: bool,
    /// `podssh serve NAME`: the label of a pair, whose node this serves
    /// (T-107, Approach item 5).
    pub name: Option<String>,
    /// `--listen ADDR`, each one bound (T-124).
    pub listen: Vec<String>,
    /// `--max-connections N` (T-124).
    pub max_connections: Option<String>,
    /// `--pending-max N` and `--login-timeout SECS` (T-631).
    pub pending_max: Option<String>,
    pub login_timeout: Option<String>,
    pub host_key: Option<String>,
    pub authorized_key: Vec<String>,
    pub authorized_keys: Vec<String>,
    pub accept_env: Vec<String>,
    pub shell: Option<String>,
    pub no_shell: bool,
    pub no_forwarding: bool,
    /// `--revoke-ends-sessions` (T-842).
    pub revoke_ends_sessions: bool,
    /// `--policy FILE`: a client policy (T-838).
    pub policy: Option<String>,
    /// `--share`: a login shell offered by name (T-837).
    pub share: bool,
    /// `--keep-lease TIME`: how long a detached shell waits (T-159).
    pub keep_lease: Option<String>,
    /// `--audit-log FILE`, `--audit-commands` and `--audit-verify FILE`
    /// (T-116).
    pub audit_log: Option<String>,
    pub audit_commands: bool,
    pub audit_verify: Option<String>,
    /// `--totp FILE` and `--totp-new FILE` (T-115).
    pub totp: Option<String>,
    pub totp_new: Option<String>,
    pub pty: Option<String>,
    /// `--motd FILE`: the message of the day (T-119).
    pub motd: Option<String>,
    /// `--shell-integration`: the marks of a login shell (T-120).
    pub shell_integration: bool,
    /// `--publish-remote`: a client's -R as a pair of the relay (T-123, Q108).
    pub publish_remote: bool,
    /// `--print-unit`, `--system` and `--run-as USER`: a unit of systemd
    /// that runs serve NAME, printed (T-709).
    pub print_unit: bool,
    pub system: bool,
    pub run_as: Option<String>,
    pub refused: Vec<(String, &'static str, &'static str)>,
}

impl ServeArgs {
    pub fn from_matches(matches: &ArgMatches, refused: Vec<(String, &'static str, &'static str)>) -> Self {
        let many = |id: &str| matches.get_many::<String>(id).map(|v| v.cloned().collect()).unwrap_or_default();
        ServeArgs {
            stdio: matches.get_flag("stdio"),
            name: matches.get_one::<String>("name").cloned(),
            listen: many("listen"),
            max_connections: matches.get_one::<String>("max-connections").cloned(),
            pending_max: matches.get_one::<String>("pending-max").cloned(),
            login_timeout: matches.get_one::<String>("login-timeout").cloned(),
            host_key: matches.get_one::<String>("host-key").cloned(),
            authorized_key: many("authorized-key"),
            authorized_keys: many("authorized-keys"),
            accept_env: many("accept-env"),
            shell: matches.get_one::<String>("shell").cloned(),
            no_shell: matches.get_flag("no-shell"),
            no_forwarding: matches.get_flag("no-forwarding"),
            revoke_ends_sessions: matches.get_flag("revoke-ends-sessions"),
            policy: matches.get_one::<String>("policy").cloned(),
            share: matches.get_flag("share"),
            keep_lease: matches.get_one::<String>("keep-lease").cloned(),
            audit_log: matches.get_one::<String>("audit-log").cloned(),
            audit_commands: matches.get_flag("audit-commands"),
            audit_verify: matches.get_one::<String>("audit-verify").cloned(),
            totp: matches.get_one::<String>("totp").cloned(),
            totp_new: matches.get_one::<String>("totp-new").cloned(),
            pty: matches.get_one::<String>("pty").cloned(),
            motd: matches.get_one::<String>("motd").cloned(),
            shell_integration: matches.get_flag("shell-integration"),
            publish_remote: matches.get_flag("publish-remote"),
            print_unit: matches.get_flag("print-unit"),
            system: matches.get_flag("system"),
            run_as: matches.get_one::<String>("run-as").cloned(),
            refused,
        }
    }
}

/// The host key's file, read with no link followed and closed to others,
/// and made whole by the cache, never over one that is there.
const FILES: StateFiles = StateFiles { read: read_secret, create: cache::create_private, dir: cache::private_dir };

fn read_secret(path: &Path) -> Result<Option<String>, String> {
    cache::read_own(path, Others::NoAccess)
}

pub fn run(args: &ServeArgs, err: &mut dyn Write) -> i32 {
    // The server's later parts, a shell and a pty, are Unix's.
    if cfg!(windows) {
        let _ = writeln!(err, "podssh serve: not on Windows: it serves a Unix host");
        return EXIT_NOT_IMPLEMENTED;
    }
    if let Err(refusal) = one_mode(args) {
        return refused(err, refusal);
    }
    // The addresses and the caps are checked before anything binds or reads.
    let caps = crate::serve_listen::Caps {
        max_connections: args.max_connections.as_deref(),
        pending_max: args.pending_max.as_deref(),
        login_timeout: args.login_timeout.as_deref(),
    };
    let listening = match crate::serve_listen::Plan::of(&args.listen, &caps) {
        Ok(plan) => plan,
        Err(refusal) => return refused(err, refusal),
    };
    let pty = match args.pty.as_deref().map(|v| (v, PtyMode::parse(v))) {
        None => PtyMode::Auto,
        Some((_, Some(mode))) => mode,
        Some((value, None)) => {
            let _ = writeln!(err, "podssh serve: --pty takes auto, notify, line or no, not {value:?}");
            return EXIT_USAGE;
        }
    };
    let keep_lease = match crate::serve_keep::lease(args.keep_lease.as_deref(), args.name.is_some()) {
        Ok(lease) => lease,
        Err(refusal) => return refused(err, refusal),
    };
    if args.no_shell && args.shell.is_some() {
        let _ = writeln!(err, "podssh serve: --shell and --no-shell: give one of them");
        return EXIT_USAGE;
    }
    if args.stdio && std::io::stdin().is_terminal() {
        let _ = writeln!(
            err,
            "podssh serve: --stdio speaks SSH on stdin, which is a terminal here: run it as a client's ProxyCommand"
        );
        return EXIT_USAGE;
    }
    // A listener binds first, as the relay role does: a port under 1024
    // needs the one capability that the drop takes (T-124).
    let bound = match listening.as_ref().map(crate::serve_listen::Bound::all).transpose() {
        Ok(bound) => bound,
        Err((code, line)) => {
            let _ = writeln!(err, "podssh serve: {line}");
            return code;
        }
    };
    let moment = if bound.is_some() { crate::harden::Moment::AfterBind } else { crate::harden::Moment::AtStart };
    // Nothing else of the start needs a privilege: each one held is dropped
    // before a file is read and before the runtime makes its threads.
    match crate::harden::give_up_at(&[], moment) {
        // The words are the tail of a line: here they stand alone.
        Ok(Some(line)) => {
            let line = line.trim_start_matches([',', ' ']);
            let _ = writeln!(err, "podssh serve: {line}");
        }
        Ok(None) => {}
        Err(refusal) => return refused(err, refusal),
    }
    let sources = match Sources::of(&args.authorized_key, &args.authorized_keys, default_file()) {
        Ok(sources) => sources,
        Err(refusal) => return refused(err, refusal),
    };
    let keys = match sources.read(err) {
        Ok(authorized) => Keys::new(authorized),
        Err(refusal) => return refused(err, refusal),
    };
    let policy = match args.policy.as_deref().map(client_policy).transpose() {
        Ok(policy) => policy.map(Arc::new),
        Err(refusal) => return refused(err, refusal),
    };
    let audit = match crate::serve_audit::open(args) {
        Ok(audit) => audit,
        Err(refusal) => return refused(err, refusal),
    };
    let totp = match crate::serve_totp::open(args) {
        Ok(totp) => totp,
        Err(refusal) => return refused(err, refusal),
    };
    let mut settings = Settings {
        accept_env: args.accept_env.clone(),
        shell: args.shell.as_ref().map(PathBuf::from),
        no_shell: args.no_shell,
        base_env: None,
        no_forwarding: args.no_forwarding,
        max_forwards: None,
        ptmx: None,
        devpts: None,
        pty,
        sftp_limit: None,
        // A listener's connection gets its own peer at its accept.
        peer: if args.stdio { peer_of_stdin() } else { None },
        // A refusal by a key's rules is said where serve's other lines go.
        say: Some(Say(Arc::new(|line: &str| {
            let _ = writeln!(std::io::stderr(), "podssh serve: {line}");
        }))),
        revoke_ends_sessions: args.revoke_ends_sessions,
        policy,
        share: args.share,
        motd: Some(args.motd.as_ref().map_or_else(Motd::default_file, Motd::named)),
        shell_integration: args.shell_integration,
        scope: None,
        // A client's -R: a pair of the relay for each, with no bind (T-123),
        // only where serve's user asks: each pair is a connection out (Q108).
        remote: args.publish_remote.then(crate::serve_forward::publisher),
        keep_lease,
        audit: audit.clone(),
        totp,
    };
    // Before the host key, so a start that cannot serve makes none.
    if let Err(refusal) = crate::serve_shell::at_start(&settings, err) {
        return refused(err, refusal);
    }
    // A named message of the day that cannot be read is a mistake of the
    // setup (78), said before a client comes; /etc/motd may be missing.
    if let Some(file) = args.motd.as_deref()
        && let Err(why) = motd::check(Path::new(file))
    {
        return refused(err, Refusal::config(format!("--motd {why}")));
    }
    // Each pty child in a transient scope of its own, where a probe finds
    // systemd (T-122); else each stays in serve's cgroup, said once.
    if cfg!(target_os = "linux") && !settings.no_shell {
        match podssh_ssh::server::scope::probe() {
            Ok(tool) => settings.scope = Some(tool),
            Err(why) => {
                let _ = writeln!(err, "podssh serve: each session stays in serve's own cgroup: {why}");
            }
        }
    }
    let found = match args.host_key.as_deref() {
        Some(file) => host_key::at(Path::new(file), &FILES),
        None => host_key::in_first(&cache::read_dirs(), &cache::candidate_dirs(), &FILES),
    };
    let HostKey { key, path, made } = match found {
        Ok(found) => found,
        Err(why) => return refused(err, Refusal::config(format!("the host key: {why}"))),
    };
    say_host_key(err, &key, &path, made);
    // The run's first line, once it can serve; its last at each end below.
    if let Some(audit) = &audit {
        let mode = match (args.stdio, bound.is_some()) {
            (true, _) => "stdio",
            (false, true) => "listen",
            (false, false) => "node",
        };
        audit.started(mode);
    }
    let stopped = |outcome: &str| {
        if let Some(audit) = &audit {
            audit.stopped(outcome);
        }
    };
    // NAME: a node of the pair, whose sessions this process answers.
    if let Some(name) = &args.name {
        let control = podssh_ssh::server::Control::new();
        if !keep_lease.is_zero() {
            crate::serve_keep::at_start(&control, &path, name, err);
        }
        let served = crate::node_serve::Served { key, keys, settings: Arc::new(settings), control, sources };
        if !crate::node_serve::set(served) {
            let _ = writeln!(err, "podssh serve: one node of serve in a process");
            stopped("failed");
            return podssh_ssh::EXIT_FAILURE;
        }
        let node = crate::node::NodeArgs { name: Some(name.clone()), ..Default::default() };
        let code = crate::node::run_node(&node, err);
        stopped(if code == 0 { "ok" } else { "failed" });
        return code;
    }
    if let Some(bound) = bound {
        // serve_listen's runtime ends inside it: each connection's last
        // lines are queued before the run's.
        let code = crate::serve_listen::run(bound, key, keys, settings, &sources, err);
        stopped(if code == 0 { "ok" } else { "failed" });
        return code;
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(e) => {
            let _ = writeln!(err, "podssh serve: no runtime: {e}");
            stopped("failed");
            return EXIT_NOT_IMPLEMENTED;
        }
    };
    // Its end tells OpenSSH's SIGHUP at a logout from an operator's (T-869).
    let (stdin, input) = crate::serve_end::watch(tokio::io::stdin(), true);
    let stream = tokio::io::join(stdin, crate::flushing::stdout());
    let serving = serve_keys::serve_until_stopped(stream, input, key, keys, Arc::new(settings), &sources, err);
    let served = runtime.block_on(serving);
    // Each -R's pair is stopped at the relay while the runtime runs (T-123).
    runtime.block_on(crate::serve_forward::end_all());
    // The runtime goes first: each connection's last lines are queued
    // before the run's.
    drop(runtime);
    match served {
        Ok(()) => {
            stopped("ok");
            0
        }
        Err(why) => {
            let _ = writeln!(err, "podssh serve: {why}");
            stopped("failed");
            podssh_ssh::EXIT_FAILURE
        }
    }
}

/// One of `--stdio`, NAME and `--listen` (T-124), else a usage error.
fn one_mode(args: &ServeArgs) -> Result<(), Refusal> {
    let listen = !args.listen.is_empty();
    match (args.stdio, &args.name, listen) {
        (false, None, false) => Err(Refusal::usage(
            "give --stdio, one SSH connection on stdin and stdout as the ProxyCommand of a client; NAME, the label of \
             a pair whose node this serves; or --listen ADDR",
        )),
        (true, Some(name), _) => Err(Refusal::usage(format!("--stdio and NAME {name:?}: give one of them"))),
        (true, None, true) => Err(Refusal::usage("--stdio and --listen: give one of them")),
        (false, Some(name), true) => Err(Refusal::usage(format!("NAME {name:?} and --listen: give one of them"))),
        _ if listen => Ok(()),
        _ => match [
            ("--max-connections", &args.max_connections),
            ("--pending-max", &args.pending_max),
            ("--login-timeout", &args.login_timeout),
        ]
        .into_iter()
        .find(|(_, value)| value.is_some())
        {
            Some((flag, _)) => Err(Refusal::usage(format!("{flag} bounds a listener: give --listen ADDR with it"))),
            None => Ok(()),
        },
    }
}

/// The client policy of `--policy FILE` (T-838). A policy of a server
/// would find a mismatch on each client, so it is refused at the start (78).
fn client_policy(path: &str) -> Result<podssh_ssh::policy::Policy, Refusal> {
    let policy = crate::policy::load(path)?;
    if !policy.client_policy {
        return Err(Refusal::config(format!(
            "--policy {path}: the policy {:?} judges a server; serve judges clients: give a file with client policy \
             = true",
            policy.name
        )));
    }
    Ok(policy)
}

fn refused(err: &mut dyn Write, refusal: Refusal) -> i32 {
    let _ = writeln!(err, "podssh serve: {}", refusal.message);
    refusal.code
}

/// The keys that may log in: each `--authorized-key`, each line of each
/// `--authorized-keys` file, else of `~/.ssh/authorized_keys`, each with
/// its rules (T-114). None at all refuses the start (78).
#[cfg(test)]
fn authorized(args: &ServeArgs, err: &mut dyn Write) -> Result<podssh_ssh::server::Authorized, Refusal> {
    Sources::of(&args.authorized_key, &args.authorized_keys, default_file())?.read(err)
}

/// The address of the client where stdin is a TCP socket (an inetd or a
/// socket of systemd, as `sshd -i` takes one), for the `from=` of a key
/// line; None for a pipe, which a ProxyCommand and the relay give.
#[cfg(unix)]
fn peer_of_stdin() -> Option<std::net::IpAddr> {
    use std::os::fd::FromRawFd;
    // SAFETY: descriptor 0 is open for the whole run, and ManuallyDrop
    // never closes it; getpeername on a pipe fails with ENOTSOCK.
    let stdin = std::mem::ManuallyDrop::new(unsafe { std::net::TcpStream::from_raw_fd(0) });
    stdin.peer_addr().ok().map(|addr| addr.ip().to_canonical())
}

#[cfg(not(unix))]
fn peer_of_stdin() -> Option<std::net::IpAddr> {
    None
}

/// `~/.ssh/authorized_keys`, as sshd reads it; none with no home.
fn default_file() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty());
    let home = var("HOME").or_else(|| if cfg!(windows) { var("USERPROFILE") } else { None })?;
    Some(PathBuf::from(home).join(".ssh").join("authorized_keys"))
}

/// The host key's fingerprint and its file, for the client's
/// `known_hosts`; a warning when the file may not outlive a reboot, as a
/// new key would then meet each client's old one.
fn say_host_key(err: &mut dyn Write, key: &podssh_ssh::russh::keys::PrivateKey, path: &Path, made: bool) {
    let fingerprint = podssh_ssh::known_hosts::fingerprint(key.public_key());
    let now = if made { ", made now" } else { "" };
    let _ = writeln!(err, "podssh serve: host key {fingerprint} ({}{now})", path.display());
    if podssh_ssh::tpm::host::is_stand_in(key) {
        let _ = writeln!(err, "podssh serve: the host key is sealed to the TPM, which signs each key exchange");
    }
    if temporary(path) {
        let _ = writeln!(
            err,
            "podssh serve: {} is in a temporary directory: a reboot can take it, and each client then meets a new \
             host key; --host-key FILE keeps it where you choose",
            path.display()
        );
    }
    if let Some(note) = cache::places().kept_note(path) {
        let _ = writeln!(err, "podssh serve: {note}");
    }
}

/// Whether `path` is in a directory that a reboot or a logout empties.
fn temporary(path: &Path) -> bool {
    let mut places = vec![std::env::temp_dir(), PathBuf::from("/tmp"), PathBuf::from("/dev/shm")];
    places.extend(std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()).map(PathBuf::from));
    places.iter().any(|place| path.starts_with(place))
}

#[cfg(test)]
#[path = "serve_tests.rs"]
mod tests;
