//! The server's answers (T-107): public-key authentication against the
//! authorized keys; a command, a shell and the environment on a session
//! channel (T-108); and a clean refusal of each request that a later entry
//! serves. russh's defaults send no reply to a channel request, and a client
//! then waits (podssh's own for 30 s): each request here is answered, in
//! the order the requests came, as the handler answers each before russh
//! reads the next.

use std::collections::HashMap;
use std::sync::Arc;

use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty, Sig};

use super::channel::{Open, Program};
use super::{env, Authorized, Settings};

/// The most session channels open at once on one connection, as OpenSSH's
/// `MaxSessions` bounds them.
pub const MAX_SESSIONS: usize = 64;

/// One connection's handler.
pub struct Served {
    authorized: Arc<Authorized>,
    settings: Arc<Settings>,
    channels: HashMap<ChannelId, Open>,
}

impl Served {
    pub(super) fn new(authorized: Arc<Authorized>, settings: Arc<Settings>) -> Served {
        Served { authorized, settings, channels: HashMap::new() }
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

    // direct-tcpip is T-109's.
    async fn channel_open_direct_tcpip(
        &mut self,
        _channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _from: &str,
        _from_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
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

    // A pty is T-110's and T-111's.
    async fn pty_request(
        &mut self,
        channel: ChannelId,
        _term: &str,
        _cols: u32,
        _rows: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Self::refuse(channel, session)
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

    // SFTP is T-112's.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Self::refuse(channel, session)
    }
}
