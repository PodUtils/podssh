//! The SSH server of `podssh serve` (T-107, milestone M5): russh's server
//! over one stream that the caller gives, its host key in a state file, and
//! public-key authentication against the authorized keys.
//!
//! It never listens: the stream is the caller's (stdin and stdout for
//! `--stdio`, as `sshd -i`; a node's session later). A command and a shell
//! run on pipes (T-108), with the shell that T-222 finds, or on a pty where
//! a master opens at the request (T-110); direct-tcpip dials from this host
//! (T-109); the `sftp` subsystem is served in the process (T-112). Where no
//! pty opens (T-111), the request is refused with the reply that the client
//! waits for. The options of each key line (`command=`, `no-pty`,
//! `permitopen=`, `from=`, `restrict`...) limit what it may do (T-114).
//! A stop says why to each client and hangs up each child, and the keys
//! can be read again while it serves (T-117, `stop.rs`).

mod authorized;
mod channel;
#[cfg(unix)]
mod child;
mod direct;
pub mod env;
mod handler;
pub mod host_key;
pub mod options;
#[cfg(unix)]
pub mod pty;
#[cfg(unix)]
mod pty_child;
mod pty_grant;
pub mod rules;
#[cfg(unix)]
pub mod sftp;
#[cfg(unix)]
pub mod shell;
pub mod stop;

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
pub use options::{Permit, Rules};
pub use rules::Context;
pub use stop::{Control, Keys, Stage};

/// How often the server asks a silent client whether it is there, as the
/// relay's own keepalive does (`docs/relay.md`).
pub const KEEPALIVE: Duration = Duration::from_secs(60);

/// The server's settings: public keys alone (russh's default also offers
/// passwords), the window of podssh's client, no cut of an idle session
/// (russh's default cuts at 600 s), and a keepalive.
pub fn config(host_key: PrivateKey) -> russh::server::Config {
    russh::server::Config {
        server_id: SshId::Standard(Cow::Owned(format!(
            "SSH-2.0-podssh_{}",
            env!("CARGO_PKG_VERSION").replace('-', "_")
        ))),
        methods: MethodSet::from(&[MethodKind::PublicKey][..]),
        keys: vec![host_key],
        window_size: crate::run::WINDOW,
        inactivity_timeout: None,
        keepalive_interval: Some(KEEPALIVE),
        // OpenSSH's client asks with `none` first, to learn the methods: an
        // answer to it tells nothing, so it need not wait.
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..russh::server::Config::default()
    }
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
    let served = handler::Served::new(keys, settings, control.clone());
    let mut running = russh::server::run_stream(config, stream, served).await.map_err(|e| ended(&e))?;
    let handle = running.handle();
    let result = tokio::select! {
        result = &mut running => result,
        () = stop::reached(&mut stage, Stage::Stopping) => {
            stop::wind_down(handle, &control, running).await;
            return Ok(());
        }
    };
    match result {
        Ok(()) => Ok(()),
        // The client's own end of the connection.
        Err(russh::Error::Disconnect | russh::Error::HUP) => Ok(()),
        Err(e) => Err(ended(&e)),
    }
}

/// The words of a connection that failed.
fn ended(e: &russh::Error) -> String {
    format!("the SSH connection failed: {e}")
}
