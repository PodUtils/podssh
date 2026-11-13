//! The server's answers (T-107): public-key authentication against the
//! authorized keys; a command, a shell and the environment on a session
//! channel (T-108); direct-tcpip (T-109); a pty where one opens (T-110);
//! and a clean refusal of each request that a later entry serves. russh's
//! defaults send no reply to a channel request, and a client then waits
//! (podssh's own for 30 s): each request here is answered, in the order the
//! requests came, as the handler answers each before russh reads the next.

use std::collections::HashMap;
use std::sync::Arc;

use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty, Sig};

use super::channel::{Open, Program};
use super::direct::{self, Slots};
use super::{env, Authorized, Settings};

/// The most session channels open at once on one connection, as OpenSSH's
/// `MaxSessions` bounds them.
pub const MAX_SESSIONS: usize = 64;

/// What a `pty-req` asked for.
#[cfg_attr(not(unix), allow(dead_code))]
struct Asked<'a> {
    term: &'a str,
    cols: u32,
    rows: u32,
    pix_width: u32,
    pix_height: u32,
    modes: &'a [(Pty, u32)],
}

/// One connection's handler.
pub struct Served {
    authorized: Arc<Authorized>,
    settings: Arc<Settings>,
    channels: HashMap<ChannelId, Open>,
    forwards: Slots,
}

impl Served {
    pub(super) fn new(authorized: Arc<Authorized>, settings: Arc<Settings>) -> Served {
        let forwards = Slots::new(settings.max_forwards.unwrap_or(direct::MAX_FORWARDS));
        Served { authorized, settings, channels: HashMap::new(), forwards }
    }

    /// Refuse a request on `channel`, with the reply that the client waits
    /// for when it asked for one.
    fn refuse(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        session.channel_failure(channel)
    }

    /// Run `program` on the channel `id`: success once it runs; else its
    /// line on the channel's stderr, then failure, so the client says why.
    async fn start(&mut self, id: ChannelId, program: Program<'_>, session: &mut Session) -> Result<(), russh::Error> {
        let settings = self.settings.clone();
        let Some(open) = self.channels.get_mut(&id) else { return Self::refuse(id, session) };
        // A channel runs one program, as RFC 4254 has it.
        if open.started() {
            return Self::refuse(id, session);
        }
        let started = if settings.no_shell {
            Err("--no-shell: this server runs no command and no shell".to_string())
        } else {
            start_program(open, id, &settings, program).await
        };
        match started {
            Ok(()) => session.channel_success(id),
            // A channel whose program did not start can run nothing else,
            // so it ends here: the client waits for no close of its own.
            Err(line) => {
                session.extended_data(id, 1, format!("podssh serve: {line}\n").into_bytes())?;
                Self::refuse(id, session)?;
                session.eof(id)?;
                session.close(id)
            }
        }
    }
}

/// Find the shell (T-222), at each start and with no cache, then start the
/// program with it. The search runs programs and waits for them, so it
/// runs on a blocking thread.
#[cfg(unix)]
async fn start_program(
    open: &mut Open,
    id: ChannelId,
    settings: &Settings,
    program: Program<'_>,
) -> Result<(), String> {
    use super::{child, shell};
    let base = settings.base();
    let candidates = shell::candidates(settings.shell.as_deref(), env::lookup(&base, "SHELL"));
    let probe_env = env::without_credentials(&base);
    let found = tokio::task::spawn_blocking(move || shell::find(&candidates, &probe_env))
        .await
        .map_err(|e| format!("the search for a shell failed: {e}"))?
        .map_err(|none| none.to_string())?;
    let child_env = env::child_env(&base, &found.path, &open.env);
    child::spawn(open, id, &found.path, program, child_env)
}

#[cfg(not(unix))]
async fn start_program(_: &mut Open, _: ChannelId, _: &Settings, _: Program<'_>) -> Result<(), String> {
    Err("not on this system: podssh serve runs programs on a Unix host".into())
}

/// Grant a pty to `open` when a master opens now, before its program and
/// once; nothing is kept for the next request.
#[cfg(unix)]
fn grant_pty(open: &mut Open, settings: &Settings, asked: &Asked<'_>) -> bool {
    use super::{pty, pty_child::Granted};
    if open.started() || open.pty.is_some() {
        return false;
    }
    let paths = settings.ptmx.clone().unwrap_or_else(|| pty::PTMX.iter().map(std::path::PathBuf::from).collect());
    let Ok(pair) = pty::open_from(&paths) else { return false };
    let size = pty::size_of(asked.cols, asked.rows, asked.pix_width, asked.pix_height);
    match Granted::new(pair, asked.term, size, asked.modes) {
        Ok(granted) => {
            open.pty = Some(granted);
            true
        }
        Err(_) => false,
    }
}

/// On Windows a pty request fails: serve runs no program there.
#[cfg(not(unix))]
fn grant_pty(_: &mut Open, _: &Settings, _: &Asked<'_>) -> bool {
    false
}

#[cfg(unix)]
fn resize_pty(open: &Open, cols: u32, rows: u32, pix_width: u32, pix_height: u32) {
    if let Some(granted) = open.pty.as_ref() {
        granted.resize(super::pty::size_of(cols, rows, pix_width, pix_height));
    }
}

#[cfg(not(unix))]
fn resize_pty(_: &Open, _: u32, _: u32, _: u32, _: u32) {}

impl russh::server::Handler for Served {
    type Error = russh::Error;

    // A key that is not listed is refused before the client signs with it.
    async fn auth_publickey_offered(&mut self, _user: &str, offer: PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        Ok(if self.authorized.allows(offer.public_key) { Auth::Accept } else { Auth::reject() })
    }

    // The login name selects nothing: the key alone decides.
    async fn auth_publickey(&mut self, _user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        Ok(if self.authorized.allows(key.public_key) { Auth::Accept } else { Auth::reject() })
    }

    // A session channel opens, and a task reads it from now on: russh
    // holds the whole connection while a channel's messages wait unread.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if self.channels.len() >= MAX_SESSIONS {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        }
        self.channels.insert(channel.id(), Open::new(channel, session.handle()));
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    // A TCP connection from this host (T-109): checked here, dialed on a
    // task of its own, so the answer to the open comes with the dial's.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _from: &str,
        _from_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        let port = match direct::check(self.settings.no_forwarding, host, port) {
            Ok(port) => port,
            Err(refusal) => {
                reply.reject(refusal).await;
                return Ok(());
            }
        };
        let Some(slot) = self.forwards.take() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        direct::open(channel, host.to_string(), port, reply, slot);
        Ok(())
    }

    async fn channel_open_x11(
        &mut self,
        _channel: Channel<Msg>,
        _from: &str,
        _from_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    // A Unix socket in the cage stays refused: T-040 is the client's side.
    async fn channel_open_direct_streamlocal(
        &mut self,
        _channel: Channel<Msg>,
        _path: &str,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
        Ok(())
    }

    // A pty where a master opens now (T-110); else refused, and the
    // command runs on pipes (T-111 is the line discipline for that case).
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        cols: u32,
        rows: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let asked = Asked { term, cols, rows, pix_width, pix_height, modes };
        let settings = self.settings.clone();
        let granted = self.channels.get_mut(&channel).is_some_and(|open| grant_pty(open, &settings, &asked));
        if granted {
            session.channel_success(channel)
        } else {
            Self::refuse(channel, session)
        }
    }

    // A new size for the pty; the request has no reply.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(open) = self.channels.get(&channel) {
            resize_pty(open, cols, rows, pix_width, pix_height);
        }
        Ok(())
    }

    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Self::refuse(channel, session)
    }

    // A variable for the program to come: only a name that --accept-env
    // lets in, never one that changes what runs, and before the start.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let patterns = env::patterns(&self.settings.accept_env);
        let taken = match self.channels.get_mut(&channel) {
            Some(open)
                if !open.started()
                    && open.env.len() < env::MAX_REQUESTS
                    && env::refused(&patterns, name, value).is_none() =>
            {
                open.env.push((name.to_string(), value.to_string()));
                true
            }
            _ => false,
        };
        if taken {
            session.channel_success(channel)
        } else {
            Self::refuse(channel, session)
        }
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        self.start(channel, Program::Login, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.start(channel, Program::Command(data), session).await
    }

    // To the child's process group; the request has no reply.
    async fn signal(&mut self, channel: ChannelId, signal: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        if let Some(open) = self.channels.get(&channel) {
            open.signal(&signal);
        }
        Ok(())
    }

    // SFTP in the process (T-112); each other name is refused. A channel
    // that runs a program, or SFTP already, takes no second one.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(open) = self.channels.get_mut(&channel) else { return Self::refuse(channel, session) };
        if name != "sftp" || open.started() {
            return Self::refuse(channel, session);
        }
        #[cfg(unix)]
        let started = super::sftp::start(open, &self.settings);
        #[cfg(not(unix))]
        let started: Result<(), String> = Err("not on this system: podssh serve serves SFTP on a Unix host".into());
        match started {
            Ok(()) => session.channel_success(channel),
            Err(line) => {
                session.extended_data(channel, 1, format!("podssh serve: {line}\n").into_bytes())?;
                Self::refuse(channel, session)
            }
        }
    }
}
