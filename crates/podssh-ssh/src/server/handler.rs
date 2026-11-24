//! The server's answers (T-107): public-key authentication against the
//! authorized keys; a command, a shell and the environment on a session
//! channel (T-108); direct-tcpip (T-109) and `-R` (T-123); a pty where one opens (T-110);
//! the rules of the key that logged in (T-114: `command=`, `no-pty`,
//! `permitopen=` and the rest, each refusal with its reason on the channel);
//! a login under a shared shell's name, which attaches under its right
//! (T-837); the requests of the kept shells (T-159, `kept_asks.rs`); and a
//! clean refusal of each request that a later entry serves.
//! The logins are `handler/auth.rs`; the audit log's lines (T-116),
//! `handler/record.rs`.
//! russh's defaults send no reply to a channel request, and a client then
//! waits (podssh's own for 30 s): each request here is answered, in the
//! order the requests came, as the handler answers each before russh reads
//! the next.

mod auth;
mod record;

use std::collections::HashMap;
use std::sync::Arc;

use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty, Sig};

use super::audit::Trail;
use super::channel::{Open, Program};
use super::direct::{self, Slots};
use super::live::Conn;
use super::program::{self, start_program};
use super::pty_grant::{grant_pty, resize_pty, Asked};
use super::remote_forward::Forwards;
use super::rules::{Asked as Wanted, Plan};
use super::share::Pass;
use super::stop::{Control, Keys, Stage};
use super::{env, share_ctl, share_view, Rules, Settings};

#[path = "handler_forward.rs"]
mod forward;
#[path = "handler_gate.rs"]
mod gate;
#[path = "kept_asks.rs"]
mod kept_asks;

/// The most session channels open at once on one connection, as OpenSSH's
/// `MaxSessions` bounds them.
pub const MAX_SESSIONS: usize = 64;

/// One connection's handler.
pub struct Served {
    /// The server's keys, read at each attempt: a reload is seen by the
    /// next login (T-117); a login keeps the rules it got.
    authorized: Keys,
    settings: Arc<Settings>,
    channels: HashMap<ChannelId, Open>,
    forwards: Slots,
    /// The client's forwards of `-R`, published with no bind (T-123).
    remote: Forwards,
    /// The rules of the key that logged in; None before a login, which
    /// refuses each request.
    rules: Option<Arc<Rules>>,
    /// That key's fingerprint, for serve's log.
    who: String,
    /// The server's stop (T-117): no new session or request once it stops.
    control: Control,
    /// This connection in the server's table (T-842): its key, its
    /// children, and its end by a reload that took the key out.
    conn: Conn,
    /// The timer of the key's `expiry-time=`, with `--revoke-ends-sessions`.
    expiry: Option<tokio::task::AbortHandle>,
    /// A login under a shared shell's name (T-837): it attaches, and no key
    /// rules it.
    viewer: Option<Pass>,
    /// The audit log's lines of this connection (T-116); last, so that the
    /// end of each session is written before the connection's.
    trail: Trail,
}

impl Drop for Served {
    // A connection that ends first leaves no timer behind.
    fn drop(&mut self) {
        if let Some(timer) = self.expiry.take() {
            timer.abort();
        }
    }
}

impl Served {
    pub(super) fn new(authorized: Keys, settings: Arc<Settings>, control: Control, conn: Conn) -> Served {
        let forwards = Slots::new(settings.max_forwards.unwrap_or(direct::MAX_FORWARDS));
        let (rules, who, channels, expiry, viewer) = (None, String::new(), HashMap::new(), None, None);
        let (remote, trail) = (Forwards::default(), Trail::open(&settings));
        Served { authorized, settings, channels, forwards, remote, rules, who, control, conn, expiry, viewer, trail }
    }

    /// Refuse a request on `channel` for a key's rule: `why` on the
    /// channel's stderr and in serve's log, then the failure.
    fn refuse_for(&self, channel: ChannelId, why: &str, session: &mut Session) -> Result<(), russh::Error> {
        self.settings.say(&format!("key {}: refused: {why}", self.who));
        if self.channels.contains_key(&channel) {
            session.extended_data(channel, 1, format!("podssh serve: {why}\n").into_bytes())?;
        }
        Self::refuse(channel, session)
    }

    /// Answer `wanted` on `channel` under the key's rules: run what they
    /// say, serve SFTP, or refuse with the reason.
    async fn answer(
        &mut self,
        channel: ChannelId,
        wanted: Wanted<'_>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        // A shell request that joins a kept shell (T-158, T-159).
        if matches!(wanted, Wanted::Shell) && self.viewer.is_none() && self.joins(channel) {
            let answered = self.join_kept(channel, session);
            // In the audit log as a shell's session, or as one that did not
            // start, whose line went to the client (T-116).
            self.record(channel, wanted, &Plan::Shell);
            return answered;
        }
        let plan = match (self.rules(), self.viewer.clone()) {
            // The one gate of a name's right (T-837): its shell request
            // attaches, under that right; each other request is refused.
            (Err(_), Some(pass)) if matches!(wanted, Wanted::Shell) && self.serving() => {
                let attached = self.channels.get_mut(&channel).map(|open| share_view::attach(open, &pass));
                match attached {
                    Some(Ok(())) => return session.channel_success(channel),
                    Some(Err(why)) => Plan::Refuse(why),
                    None => return Self::refuse(channel, session),
                }
            }
            (Ok(rules), _) => rules.plan(wanted),
            (Err(why), _) => Plan::Refuse(why),
        };
        let answered = match &plan {
            Plan::Command(command, original) => {
                self.start(channel, Program::Command(command), original.clone(), session).await
            }
            Plan::Shell => self.start(channel, Program::Login, None, session).await,
            Plan::Sftp => program::sftp(self.channels.get_mut(&channel), &self.settings, channel, session),
            // As a program that did not start: the channel runs nothing
            // else, so it ends here.
            Plan::Refuse(why) => {
                self.refuse_for(channel, why, session)?;
                if self.channels.get(&channel).is_some_and(|open| !open.started()) {
                    session.eof(channel)?;
                    session.close(channel)?;
                }
                Ok(())
            }
        };
        self.record(channel, wanted, &plan);
        answered
    }

    /// Refuse a request on `channel`, with the reply that the client waits
    /// for when it asked for one.
    fn refuse(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        session.channel_failure(channel)
    }

    /// Run `program` on the channel `id`: success once it runs; else its
    /// line on the channel's stderr, then failure, so the client says why.
    /// `original` is the client's command where a forced one replaced it.
    async fn start(
        &mut self,
        id: ChannelId,
        program: Program<'_>,
        original: Option<Vec<u8>>,
        session: &mut Session,
    ) -> Result<(), russh::Error> {
        let settings = self.settings.clone();
        let shares = self.control.live.shares.clone();
        // A login shell on a pty may be kept (T-159).
        let keeper = if matches!(program, Program::Login) { self.keeper(id) } else { None };
        let Some(open) = self.channels.get_mut(&id) else { return Self::refuse(id, session) };
        // A channel runs one program, as RFC 4254 has it.
        if open.started() {
            return Self::refuse(id, session);
        }
        // With --share, the login shell on a pty is offered by name (T-837).
        if settings.share && matches!(program, Program::Login) {
            open.offer = Some(shares);
        }
        open.keeper = keeper;
        let started = if settings.no_shell {
            Err("--no-shell: this server runs no command and no shell".to_string())
        } else {
            start_program(open, id, &settings, program, original).await
        };
        let told = share_view::told(open);
        match started {
            Ok(()) => {
                session.channel_success(id)?;
                told.map_or(Ok(()), |told| session.extended_data(id, 1, told.into_bytes()))
            }
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

impl russh::server::Handler for Served {
    type Error = russh::Error;

    // A key that is not listed, or that its lines refuse now (from=,
    // expiry-time=), is refused before the client signs with it; so is
    // each key of a connection that a client policy ended (T-838).
    async fn auth_publickey_offered(&mut self, user: &str, offer: PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        Ok(self.offered(user, offer))
    }

    // The key decides, or a shared shell's name (T-837): `handler/auth.rs`.
    async fn auth_publickey(&mut self, user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        Ok(self.verified(user, key))
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
        // A server that stops takes no new session (T-117), nor does a
        // connection that a reload ended (T-842).
        if self.control.stage() != Stage::Serving || self.conn.ended().is_some() {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        let group = self.control.groups.slot();
        self.conn.groups().adopt(&group);
        self.channels.insert(channel.id(), Open::new(channel, session.handle(), group));
        reply.accept().await;
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        self.channels.remove(&channel);
        Ok(())
    }

    // Each channel that serve takes (a session, a forward) opens its window
    // as its reader takes the bytes, and grants them back (T-118): a child
    // or a target that reads slowly holds its own channel alone, never the
    // connection, and serve holds no more than a window for it.
    fn window_on_read(&mut self, _channel: ChannelId) -> bool {
        true
    }

    // A TCP connection from this host (T-109), `handler_forward.rs`.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        _from: &str,
        _from_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.direct_tcpip(channel, host, port, reply, session).await
    }

    // A stock `ssh -R` (T-123): published with no bind where the settings
    // give a way, else refused as before.
    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let rules = self.rules();
        Ok(self.remote.ask(&self.settings, rules, &self.who, address, port, session.handle()).await)
    }

    async fn cancel_tcpip_forward(&mut self, address: &str, port: u32, _: &mut Session) -> Result<bool, Self::Error> {
        Ok(self.remote.cancel(address, port))
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
        // A name's pty is the shared shell's: its size counts (T-837).
        if self.viewer.is_some() && self.serving() {
            let open = self.channels.get_mut(&channel);
            let asked = share_view::ask_pty(open, cols, rows, pix_width, pix_height);
            return if asked { session.channel_success(channel) } else { Self::refuse(channel, session) };
        }
        let refused = match self.rules() {
            Ok(rules) => rules.pty_refusal(),
            Err(why) => Some(why),
        };
        if let Some(why) = refused {
            return self.refuse_for(channel, &why, session);
        }
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
        // podssh's own names of the kept shells, before --accept-env (T-159).
        if let Some(answered) = self.keep_env(channel, name, value, session) {
            return answered;
        }
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
        self.answer(channel, Wanted::Shell, session).await
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.answer(channel, Wanted::Exec(data), session).await
    }

    // To the child's process group; the request has no reply.
    async fn signal(&mut self, channel: ChannelId, signal: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        if let Some(open) = self.channels.get(&channel) {
            open.signal(&signal);
        }
        Ok(())
    }

    // SFTP in the process (T-112), or a key's forced command in its place
    // (T-114); the owner's word to its shared shell (T-860), only from the
    // connection that holds the shell; each other name is refused.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == share_ctl::SUBSYSTEM {
            let (shares, settings, who) = (self.control.live.shares.clone(), self.settings.clone(), self.who.clone());
            let owned = self.rules().map(|_| share_ctl::owned(self.channels.values()));
            let job = owned.map(|owned| share_ctl::Job { shares, owned, settings, who });
            return share_ctl::answer(self.channels.get_mut(&channel), job, channel, session);
        }
        // The kept shells of this key (T-158, T-159).
        if name == crate::keep::LIST {
            return self.list_kept(channel, session);
        }
        if name != "sftp" {
            return Self::refuse(channel, session);
        }
        self.answer(channel, Wanted::Sftp, session).await
    }
}
