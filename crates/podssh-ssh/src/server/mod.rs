//! The SSH server of `podssh serve` (T-107, milestone M5): russh's server
//! over one stream that the caller gives, its host key in a state file, and
//! public-key authentication against the authorized keys.
//!
//! It never listens: the stream is the caller's (stdin and stdout for
//! `--stdio`, as `sshd -i`; a node's session later). Exec, a shell, a pty,
//! SFTP and direct-tcpip come with T-108 to T-112; until then each such
//! request is refused with the reply that the client waits for.

mod authorized;
mod handler;
pub mod host_key;

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::PrivateKey;
use russh::{MethodKind, MethodSet, SshId};
use tokio::io::{AsyncRead, AsyncWrite};

pub use authorized::{parse_line, Authorized, Line, Read};
pub use host_key::{HostKey, StateFiles};

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

/// Serve one SSH connection over `stream` until the client leaves. `Err`
/// is why the connection failed, in words for a line of the caller.
pub async fn serve<S>(stream: S, host_key: PrivateKey, authorized: Arc<Authorized>) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // No key, no login: the caller refuses the start first, and this holds
    // it for each other caller.
    if authorized.is_empty() {
        return Err("no authorized key: nobody could log in".into());
    }
    let config = Arc::new(config(host_key));
    let served = handler::Served { authorized };
    let running = russh::server::run_stream(config, stream, served).await.map_err(|e| ended(&e))?;
    match running.await {
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
