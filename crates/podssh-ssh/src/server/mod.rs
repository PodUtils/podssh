//! The SSH server of `podssh serve` (T-107, milestone M5): russh's server
//! over one stream that the caller gives, its host key in a state file, and
//! public-key authentication against the authorized keys.
//!
//! It never listens: the stream is the caller's (stdin and stdout for
//! `--stdio`, as `sshd -i`; a node's session; a connection that the
//! listener of `--listen` accepted, under the caps and the deadline of
//! `listen.rs`, T-124 and T-631). A command and a shell
//! run on pipes (T-108), with the shell that T-222 finds, or on a pty where
//! a master opens at the request (T-110); direct-tcpip dials from this host
//! (T-109); the `sftp` subsystem is served in the process (T-112). Where no
//! pty opens (T-111), the request is refused with the reply that the client
//! waits for. The options of each key line (`command=`, `no-pty`,
//! `permitopen=`, `from=`, `restrict`...) limit what it may do (T-114).
//! A stop says why to each client and hangs up each child, and the keys
//! can be read again while it serves (T-117, `stop.rs`); a reload that takes
//! a key out ends its sessions when asked (T-842, `live.rs`). The algorithms
//! that it offers are one stated set (T-841, `algorithms.rs`); an RSA host
//! key signs through aws-lc-rs, never russh's `rsa` (T-856, `host_sign.rs`);
//! a client policy refuses a client by its KEXINIT before authentication
//! (T-838, `policy_gate.rs`). With `--share`, a login shell on a pty or on
//! serve's own tty (T-861) is offered by two names, one that types and one that watches (T-837,
//! `share.rs`); its owner deletes or rotates a name by the subsystem
//! `share@podssh` (T-860, `share_ctl.rs`). A login shell on a pty can
//! outlive its channel when its client asks: it is kept for a lease, and a
//! later login of the same key joins it by name (T-159, `kept.rs`). A login
//! shell on a tty is shown the message of the day first (T-119, `motd.rs`),
//! and with `--shell-integration` its prompts and commands are marked
//! (T-120, `marks.rs`). Where systemd is there, each pty child runs in a
//! transient scope of its own (T-122, `scope.rs`). A client's `-R` is
//! published with no bind where the settings give a way (T-123,
//! `remote_forward.rs`). `--audit-log FILE` records the logins, sessions
//! and forwards as chained JSON lines (T-116, `audit/`); `--totp FILE` asks
//! each key for a one-time code after it (T-115, `totp/`).

pub mod algorithms;
pub mod audit;
mod authorized;
mod channel;
#[cfg(unix)]
mod child;
mod direct;
pub mod env;
mod handler;
pub mod host_key;
mod host_sign;
mod kept;
mod kept_ask;
mod kept_join;
mod kept_record;
mod kept_replay;
#[cfg(unix)]
mod kept_run;
mod kept_shelf;
#[cfg(unix)]
mod line;
pub mod listen;
pub mod live;
pub mod marks;
pub mod motd;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub mod notify;
pub mod options;
mod policy_gate;
mod program;
// The reports of local echo, from a pty's channel (T-160).
#[cfg(unix)]
mod predict;
#[cfg(unix)]
pub mod pty;
#[cfg(unix)]
mod pty_child;
#[cfg(target_os = "linux")]
pub mod pty_devpts;
mod pty_grant;
pub mod remote_forward;
pub mod rules;
pub mod scope;
#[cfg(unix)]
pub mod sftp;
pub mod share;
mod share_ctl;
#[doc(hidden)]
pub mod share_measure;
mod share_view;
#[cfg(unix)]
pub mod shell;
mod start;
pub mod stop;
pub mod totp;

use std::borrow::Cow;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::{MethodKind, MethodSet, SshId};
use tokio::io::{AsyncRead, AsyncWrite};

pub use authorized::{parse_line, Admission, Authorized, Line, Read};
pub use direct::{DIAL_LIMIT, MAX_FORWARDS};
pub use host_key::{HostKey, StateFiles};
pub use kept::{KILL_AFTER, PER_KEY, RING, TOTAL};
pub use live::{Ended, Reloaded};
pub use options::{Permit, Rules};
pub use rules::Context;
pub use stop::{Control, Keys, Stage};

/// How often the server asks a silent client whether it is there, as the
/// relay's own keepalive does (`docs/relay.md`).
pub const KEEPALIVE: Duration = Duration::from_secs(60);

/// The server's settings: public keys alone (russh's default also offers
/// passwords), the window of podssh's client, no cut of an idle session
/// (russh's default cuts at 600 s), a keepalive, the algorithms of
/// podssh's own stated set, never russh's default of the day (T-841), and
/// the signer of the host key, which keeps an RSA key from russh (T-856).
pub fn config(host_key: PrivateKey) -> russh::server::Config {
    let signer = host_sign::HostSigner::of(&host_key);
    russh::server::Config {
        server_id: SshId::Standard(Cow::Owned(server_id())),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        keys: vec![host_key],
        preferred: algorithms::SERVED,
        window_size: crate::run::WINDOW,
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        // OpenSSH's client asks with `none` first, to learn the methods: an
        // answer to it tells nothing, so it need not wait.
        auth_rejection_time_initial: Some(Duration::ZERO),
        host_key_signer: Some(Arc::new(signer)),
        ..russh::server::Config::default()
    }
}

/// serve's version line, without its CR LF: russh's and a listener's
/// refusal say the same (T-124).
fn server_id() -> String {
    format!("SSH-2.0-podssh_{}", env!("CARGO_PKG_VERSION").replace('-', "_"))
}

/// What a session may run (T-108, T-222): the `env` requests let in, the
/// shell, and the environment that each child starts from; and whether a
/// client may forward (T-109).
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// `--accept-env`'s patterns; none takes [`env::DEFAULT_ACCEPT`].
    pub accept_env: Vec<String>,
    /// `--shell`: the one shell, strict; none searches (T-222).
    pub shell: Option<PathBuf>,
    /// `--no-shell`: no command and no shell run.
    pub no_shell: bool,
    /// The environment of each child before its own variables; None reads
    /// this process's at each start, as a test gives one of its own.
    pub base_env: Option<Vec<(OsString, OsString)>>,
    /// `--no-forwarding`: each direct-tcpip channel is refused.
    pub no_forwarding: bool,
    /// The most forwards open at once on one connection; None is
    /// [`MAX_FORWARDS`], as a test gives a smaller bound.
    pub max_forwards: Option<usize>,
    /// The masters that a `pty-req` tries; None is `pty::PTMX`, as a test
    /// names a missing one to see the refusal on a host that has a pty.
    pub ptmx: Option<Vec<PathBuf>>,
    /// Whether a `pty-req` that no master of `ptmx` serves tries a devpts
    /// instance of podssh's own (T-775); None is yes with the default
    /// masters and no with a test's, so that a test's missing master
    /// still sees the refusal.
    pub devpts: Option<bool>,
    /// Where a `pty-req` meets no pty: `Auto` makes serve the line
    /// discipline (T-111) with the default masters, and with a test's
    /// `ptmx` refuses as before; `Line` always does, with no pty tried;
    /// `No` refuses (`--pty`).
    pub pty: PtyMode,
    /// The time limit of each file-system call of the SFTP server (T-112);
    /// None is `sftp::CALL_LIMIT`, as a test gives a shorter one.
    pub sftp_limit: Option<Duration>,
    /// The client's address, for the `from=` of a key line (T-114): a TCP
    /// socket's peer where serve's stream is one; None for a pipe, where
    /// no `from=` matches.
    pub peer: Option<IpAddr>,
    /// Where serve says a line for its operator: a key that a line refused,
    /// a request that a key's rules refused. None says nothing.
    pub say: Option<Say>,
    /// `--revoke-ends-sessions` (T-842): a reload that takes a key out ends
    /// that key's sessions, and a key's `expiry-time=` ends them at its
    /// time. Off, a session goes on under the rules it logged in with.
    pub revoke_ends_sessions: bool,
    /// `--policy FILE` (T-838): a client whose first KEXINIT the policy
    /// does not pass is refused before authentication. None judges nothing.
    pub policy: Option<Arc<crate::policy::Policy>>,
    /// `--share` (T-837): each login shell on a pty is offered by two names,
    /// told once to its owner. Off, the login name selects nothing.
    pub share: bool,
    /// The message of the day of a login shell on a tty (T-119): the CLI's
    /// `--motd FILE`, else `/etc/motd`. None shows none, as a test needs on
    /// a host whose `/etc/motd` it does not know.
    pub motd: Option<motd::Motd>,
    /// `--shell-integration` (T-120): a login shell on a tty gets the marks
    /// of OSC 133 and OSC 7. Off, nothing is added.
    pub shell_integration: bool,
    /// What moves each pty child into a transient scope of its own (T-122):
    /// found by the CLI's probe of systemd at the start. None starts each
    /// child where serve is, as on a host with no systemd.
    pub scope: Option<scope::Tool>,
    /// What publishes a client's `-R` with no bind (T-123); None refuses
    /// each `tcpip-forward`, as russh's default did.
    pub remote: Option<remote_forward::Publisher>,
    /// `--keep-lease` (T-159): how long a login shell on a pty that its
    /// client detached waits for a client; zero keeps no shell.
    pub keep_lease: Duration,
    /// `--audit-log FILE` (T-116): each login, session and forward as a
    /// chained JSON line. None records nothing.
    pub audit: Option<Arc<audit::Audit>>,
    /// `--totp FILE` (T-115): a key that passed must give a one-time code
    /// by keyboard-interactive. None asks for none.
    pub totp: Option<Arc<totp::Totp>>,
}

/// `--pty`: what a pty request that no pty serves meets (T-111).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PtyMode {
    /// A real pty, then a devpts instance of serve's own, then a tty that
    /// serve answers (Linux), then serve as the line discipline on pipes.
    #[default]
    Auto,
    /// Serve as the line discipline, with no pty tried.
    Line,
    /// A tty that serve answers by seccomp's user notification, with no pty
    /// tried; else the request is refused (Linux on x86_64 and aarch64).
    Notify,
    /// A real pty or a devpts instance; else the request is refused.
    No,
}

impl PtyMode {
    /// The mode of `--pty`'s value.
    pub fn parse(value: &str) -> Option<PtyMode> {
        match value {
            "auto" => Some(PtyMode::Auto),
            "line" => Some(PtyMode::Line),
            "notify" => Some(PtyMode::Notify),
            "no" => Some(PtyMode::No),
            _ => None,
        }
    }
}

/// A sink for serve's lines (its stderr, for the CLI).
#[derive(Clone)]
pub struct Say(pub Arc<dyn Fn(&str) + Send + Sync>);

impl std::fmt::Debug for Say {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Say")
    }
}

impl Settings {
    /// The environment that each child starts from.
    pub fn base(&self) -> Vec<(OsString, OsString)> {
        self.base_env.clone().unwrap_or_else(|| std::env::vars_os().collect())
    }

    /// Say `line` where the settings say lines.
    pub fn say(&self, line: &str) {
        if let Some(Say(say)) = self.say.as_ref() {
            say(line);
        }
    }
}

/// Serve one SSH connection over `stream` until the client leaves, with
/// the default [`Settings`]. `Err` is why the connection failed, in words
/// for a line of the caller.
pub async fn serve<S>(stream: S, host_key: PrivateKey, authorized: Arc<Authorized>) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_with(stream, host_key, authorized, Arc::new(Settings::default())).await
}

/// [`serve`] with the settings of the command line.
pub async fn serve_with<S>(
    stream: S,
    host_key: PrivateKey,
    authorized: Arc<Authorized>,
    settings: Arc<Settings>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_under(stream, host_key, Keys::from(authorized), settings, Control::new()).await
}

/// [`serve_with`] under the caller's `control` (T-117): its stop ends the
/// connection with a reason and hangs up each child, and `keys` is the set
/// that a reload replaces, shared with each other connection of the server.
/// A stop is a clean end: `Ok`.
pub async fn serve_under<S>(
    stream: S,
    host_key: PrivateKey,
    keys: Keys,
    settings: Arc<Settings>,
    control: Control,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_inner(stream, host_key, keys, settings, control, None).await
}

/// [`serve_under`] for a connection that a listener let in (T-124,
/// T-631): its places under the caps are held for its life, and with no
/// login by its deadline it ends, the client told why. That end is `Err`,
/// a line for serve's log.
pub async fn serve_admitted<S>(
    stream: S,
    host_key: PrivateKey,
    keys: Keys,
    settings: Arc<Settings>,
    control: Control,
    admitted: listen::Admitted,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let listen::Admitted { all, login } = admitted;
    let ended = serve_inner(stream, host_key, keys, settings, control, Some(login)).await;
    drop(all);
    ended
}

async fn serve_inner<S>(
    stream: S,
    host_key: PrivateKey,
    keys: Keys,
    settings: Arc<Settings>,
    control: Control,
    login: Option<listen::Login>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // No key, no login: the caller refuses the start first, and this holds
    // it for each other caller.
    if keys.is_empty() {
        return Err("no authorized key: nobody could log in".into());
    }
    let mut stage = control.watch();
    if *stage.borrow() != Stage::Serving {
        return Ok(());
    }
    let config = Arc::new(config(host_key));
    // In the server's table from the first byte: a reload that comes during
    // the login still finds the connection (T-842).
    let conn = control.live.join(settings.peer);
    let mut revoked = conn.watch();
    // A client policy judges the client's KEXINIT as it passes (T-838); a
    // refusal ends the connection as a revoke does.
    let stream = policy_gate::Gated::new(stream, &conn, &settings);
    let served = handler::Served::new(keys, settings, control.clone(), conn.clone());
    let started = russh::server::run_stream(config, stream, served);
    // A listener's deadline holds from the accept: russh waits for the
    // client's version line with no bound of its own here (T-631).
    let started = match login.as_ref().map(|login| (login.at, login.silent())) {
        None => started.await,
        Some((at, silent)) => tokio::time::timeout_at(at, started).await.map_err(|_| silent)?,
    };
    let mut running = started.map_err(|e| ended(&e))?;
    let handle = running.handle();
    let reaped = listen::reaped(login, conn.logged_in());
    let result = tokio::select! {
        result = &mut running => result,
        () = stop::reached(&mut stage, Stage::Stopping) => {
            stop::wind_down(handle, &control, &control.groups, stop::STOPPING, running).await;
            return Ok(());
        }
        // The key was taken out by a reload, or expired: this connection
        // alone ends, as a stop ends each.
        told = live::ended(&mut revoked) => {
            stop::wind_down(handle, &control, conn.groups(), &told, running).await;
            return Ok(());
        }
        // No login by the listener's deadline: the client hears the limit,
        // and serve's log gets the same line.
        told = reaped => {
            stop::wind_down(handle, &control, conn.groups(), &told, running).await;
            return Err(format!("{}: closed", told.trim_start_matches("podssh serve: ")));
        }
    };
    match result {
        Ok(()) => Ok(()),
        // The client's own end of the connection.
        Err(russh::Error::Disconnect | russh::Error::HUP) => Ok(()),
        Err(russh::Error::IO(e)) => closed(&e, conn.accepted()),
        Err(e) => Err(ended(&e)),
    }
}

/// An I/O error at the end of a connection (T-869). A client that closed
/// the stream after its login ended it: OpenSSH closes with no DISCONNECT
/// after a refused forward (`early eof`), and leaves before reading serve's
/// last bytes (`Broken pipe`), each at a normal end. Before a login it is
/// one true line; any other error is a failure.
fn closed(e: &std::io::Error, accepted: bool) -> Result<(), String> {
    use std::io::ErrorKind::{BrokenPipe, ConnectionAborted, ConnectionReset, UnexpectedEof};
    match e.kind() {
        BrokenPipe | ConnectionAborted | ConnectionReset | UnexpectedEof if accepted => Ok(()),
        BrokenPipe | ConnectionAborted | ConnectionReset | UnexpectedEof => {
            Err(format!("the client closed the connection before it logged in ({e})"))
        }
        _ => Err(format!("the SSH connection failed: {e}")),
    }
}

/// The words of a connection that failed.
fn ended(e: &russh::Error) -> String {
    format!("the SSH connection failed: {e}")
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::closed;

    /// Each kind of a client's close, after a login and before one; any
    /// other error stays a failure (T-869).
    #[test]
    fn a_close_by_the_client_after_its_login_is_its_end() {
        let kinds =
            [ErrorKind::UnexpectedEof, ErrorKind::BrokenPipe, ErrorKind::ConnectionReset, ErrorKind::ConnectionAborted];
        for kind in kinds {
            let e = Error::new(kind, "the words");
            assert_eq!(closed(&e, true), Ok(()), "{kind:?}");
            let said = closed(&e, false).expect_err("before a login");
            assert!(said.starts_with("the client closed the connection before it logged in"), "{kind:?}: {said}");
        }
        for accepted in [true, false] {
            let said = closed(&Error::new(ErrorKind::InvalidData, "bad mac"), accepted).expect_err("a failure");
            assert_eq!(said, "the SSH connection failed: bad mac");
        }
    }
}
