//! The Dev Tunnels forward road (T-755, feature `devtunnel`): a
//! `direct-tcpip` channel to a port of the host of a Microsoft Dev Tunnels
//! tunnel, through the service's relay on port 443, with no relay of
//! podssh's. The protocol is `pod-devtunnel` of PodUtils/podcrates (the
//! management API, the relay WebSocket, SSH with no user authentication to
//! the tunnel's host, the channels and a bounded reconnect); this module
//! gives it podssh's parts: the way out through `HTTPS_PROXY` with
//! podssh's TLS, its SSH name, the user's token from a private file
//! ([`token`]), and its lines ([`lines`]).
//!
//! No token goes in argv, a line, an event, the journal or `--json`: the
//! file's path is the only thing that the user gives, and each type of the
//! crate hides its token in `Debug`.

pub mod lines;
pub mod token;

use std::fmt;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};

pub use pod_core::{Class, Failure, Report};
pub use pod_devtunnel::stream::SESSION_ENDED;
pub use pod_devtunnel::{step_of, steps_of, Base, Locator, Relay, Scheme, Settings, Step, Stream, UserToken, Way};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use token::{parse_token, read_token_file};

/// The variable that names the private file of the user's token.
pub const TOKEN_FILE_ENV: &str = "PODSSH_DEVTUNNEL_TOKEN_FILE";
/// Another base of the management API, `https://HOST[:PORT]`: another
/// environment of the service, or a stand-in on the loopback (`http://`).
pub const API_ENV: &str = "PODSSH_DEVTUNNEL_API";

/// The word of a step, as `podssh doctor` names the stage that failed.
pub fn step_word(step: Step) -> &'static str {
    match step {
        Step::Management => "management",
        Step::WebSocket => "websocket",
        Step::Ssh => "ssh",
        Step::Channel => "channel",
        Step::Reconnect => "reconnect",
    }
}

/// The word of the step that `failure` names, or `setup` for a failure of
/// podssh's own parts (the token file, a setting).
pub fn stage_of(failure: &Failure) -> &'static str {
    step_of(failure).map_or("setup", step_word)
}

/// The settings of the crate as podssh runs it: its own SSH name, and the
/// base of `api` (from [`API_ENV`]) when one is given.
pub fn settings(api: Option<&str>) -> Result<Settings, Failure> {
    let version = env!("CARGO_PKG_VERSION").replace('-', "_");
    let mut settings = Settings { ssh_id: format!("SSH-2.0-podssh_{version}"), ..Settings::default() };
    if let Some(api) = api.map(str::trim).filter(|a| !a.is_empty()) {
        settings.management = Base::parse(api)?;
    }
    Ok(settings)
}

/// podssh's way out for `proxy`: the HTTP client of the management API and
/// the WebSocket of the relay on one dial, with the process's TLS and
/// `trust` for the relay's certificate.
pub fn way(proxy: &ProxyChoice, trust: Trust) -> Way {
    Way { http: podssh_ws::client::getter(proxy), ws: podssh_ws::client::way(proxy), trust }
}

/// A tunnel, the user's token for it, and how to reach it.
#[derive(Clone)]
pub struct Road {
    pub locator: Locator,
    user: UserToken,
    pub settings: Settings,
    pub trust: Trust,
    pub proxy: ProxyChoice,
}

impl fmt::Debug for Road {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Road")
            .field("locator", &self.locator)
            .field("user", &self.user)
            .field("management", &self.settings.management)
            .finish_non_exhaustive()
    }
}

impl Road {
    /// The road to `tunnel` (`NAME` or `ID.CLUSTER`), with the token of
    /// `user`.
    pub fn new(
        tunnel: &str,
        user: UserToken,
        settings: Settings,
        trust: Trust,
        proxy: ProxyChoice,
    ) -> Result<Road, Failure> {
        Ok(Road { locator: Locator::parse(tunnel)?, user, settings, trust, proxy })
    }

    /// The road as the environment gives it: the token of the file of
    /// [`TOKEN_FILE_ENV`] and the base of [`API_ENV`]. No file named is a
    /// configuration failure that names the variable.
    pub fn from_env(tunnel: &str, trust: Trust, proxy: ProxyChoice) -> Result<Road, Failure> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
        let Some(file) = var(TOKEN_FILE_ENV) else {
            let why = format!(
                "Dev Tunnels asks the user's token: set {TOKEN_FILE_ENV} to a private file with one line \
                 SCHEME TOKEN (github, aad or bearer)"
            );
            return Err(Failure::new(pod_core::Stage::Host, pod_core::Class::Config, why));
        };
        let user = read_token_file(Path::new(&file))
            .map_err(|f| Failure::new(f.stage, f.class, format!("{TOKEN_FILE_ENV}: {}", f.text())))?;
        let settings = settings(var(API_ENV).as_deref())
            .map_err(|f| Failure::new(f.stage, f.class, format!("{API_ENV}: {}", f.chain())))?;
        Road::new(tunnel, user, settings, trust, proxy)
    }

    /// The tunnel as messages and `known_hosts` show it.
    pub fn shown(&self) -> String {
        format!("devtunnel://{}", self.locator)
    }

    /// The connect information, then one relay session; its events go to
    /// `report`.
    pub async fn connect(&self, report: Report) -> Result<Relay, Failure> {
        let way = way(&self.proxy, self.trust.clone());
        Relay::connect(way, self.settings.clone(), self.locator.clone(), self.user.clone(), report).await
    }

    /// A stream to `port` of the tunnel's host on a session of its own: the
    /// session lives as long as the stream.
    pub async fn open(&self, port: u16, report: Report) -> Result<Tunneled, Failure> {
        let relay = self.connect(report).await?;
        open(&relay, port).await
    }
}

/// A stream to `port` on the session of `relay`; the stream keeps the
/// session.
pub async fn open(relay: &Relay, port: u16) -> Result<Tunneled, Failure> {
    let stream = relay.open(port).await?;
    Ok(Tunneled { stream, relay: relay.clone() })
}

/// A stream of the road, with the client of its tunnel: the SSH session
/// under the channel ends when the last clone of the client goes, so the
/// stream holds one.
pub struct Tunneled {
    stream: Stream,
    relay: Relay,
}

impl Tunneled {
    /// The client of the tunnel: its sessions so far, a reconnect.
    pub fn relay(&self) -> &Relay {
        &self.relay
    }

    pub fn stream(&self) -> &Stream {
        &self.stream
    }
}

impl fmt::Debug for Tunneled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tunneled").field("stream", &self.stream).field("relay", &self.relay).finish()
    }
}

impl AsyncRead for Tunneled {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tunneled {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// True when `e`, of a read or a write of a [`Tunneled`], is the end of its
/// relay session (a reconnect, a relay that went away), not the far end's.
pub fn session_ended(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::ConnectionAborted && e.to_string() == SESSION_ENDED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devtunnel_the_settings_name_podssh_and_take_another_base() {
        let plain = settings(None).unwrap();
        assert!(plain.ssh_id.starts_with("SSH-2.0-podssh_"), "{}", plain.ssh_id);
        assert_eq!(plain.management, Settings::default().management);
        let local = settings(Some("http://127.0.0.1:8080")).unwrap();
        assert_eq!((local.management.tls, local.management.port), (false, 8080));
        assert!(settings(Some("http://tunnels.example")).is_err(), "plain HTTP is for the loopback alone");
        assert_eq!(settings(Some("  ")).unwrap().management, Settings::default().management);
    }

    #[test]
    fn devtunnel_a_road_shows_its_tunnel_and_no_token() {
        let user = parse_token("github made-up-token-of-a-road").unwrap();
        let road = Road::new("Box-1", user, Settings::default(), Trust::Default, ProxyChoice::Direct).unwrap();
        assert_eq!(road.shown(), "devtunnel://box-1");
        assert!(!format!("{road:?}").contains("made-up"));
        let user = parse_token("github made-up").unwrap();
        assert!(Road::new("not a tunnel", user, Settings::default(), Trust::Default, ProxyChoice::Direct).is_err());
        let words: Vec<_> = [Step::Management, Step::WebSocket, Step::Ssh, Step::Channel, Step::Reconnect]
            .into_iter()
            .map(step_word)
            .collect();
        assert_eq!(words, ["management", "websocket", "ssh", "channel", "reconnect"]);
    }
}
