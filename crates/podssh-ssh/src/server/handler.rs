//! The server's answers (T-107): public-key authentication against the
//! authorized keys; a command, a shell and the environment on a session
//! channel (T-108); direct-tcpip (T-109); a pty where one opens (T-110);
//! the rules of the key that logged in (T-114: `command=`, `no-pty`,
//! `permitopen=` and the rest, each refusal with its reason on the channel);
//! and a clean refusal of each request that a later entry serves. russh's
//! defaults send no reply to a channel request, and a client then waits
//! (podssh's own for 30 s): each request here is answered, in the order the
//! requests came, as the handler answers each before russh reads the next.

use std::collections::HashMap;
use std::sync::Arc;

use russh::keys::Algorithm;
use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty, Sig};

use super::authorized::Admission;
use super::channel::{Open, Program};
use super::direct::{self, Slots};
use super::pty_grant::{grant_pty, resize_pty, Asked};
use super::rules::{Asked as Wanted, Context, Plan};
use super::stop::{Control, Keys, Stage};
use super::{env, Rules, Settings};

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
    /// The rules of the key that logged in; None before a login, which
    /// refuses each request.
    rules: Option<Arc<Rules>>,
    /// That key's fingerprint, for serve's log.
    who: String,
    /// The server's stop (T-117): no new session or request once it stops.
    control: Control,
}

impl Served {
    pub(super) fn new(authorized: Keys, settings: Arc<Settings>, control: Control) -> Served {
        let forwards = Slots::new(settings.max_forwards.unwrap_or(direct::MAX_FORWARDS));
        let (rules, who) = (None, String::new());
        Served { authorized, settings, channels: HashMap::new(), forwards, rules, who, control }
    }

    /// The rules under which `key` logs in now, or None; a key that lines
    /// name and refuse is said with each line's reason, as the client hears
    /// only "Permission denied".
    fn admit(&self, key: &russh::keys::PublicKey) -> Option<Arc<Rules>> {
        match self.authorized.admit(key, &Context::now(self.settings.peer)) {
            Admission::Admitted(rules) => Some(rules),
            Admission::Unlisted => None,
            Admission::Refused(reasons) => {
                let who = crate::known_hosts::fingerprint(key);
                for why in reasons {
                    self.settings.say(&format!("key {who} refused: {why}"));
                }
                None
            }
        }
    }

    /// The rules in force, or the words of a refusal: before a login, or
    /// once the server stops (T-117), which takes no new request.
    fn rules(&self) -> Result<Arc<Rules>, String> {
        if self.control.stage() != Stage::Serving {
            return Err(super::stop::STOPPING.to_string());
        }
        self.rules.clone().ok_or_else(|| "no key logged in".to_string())
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
        let plan = match self.rules() {
            Ok(rules) => rules.plan(wanted),
            Err(why) => Plan::Refuse(why),
        };
        match plan {
            Plan::Command(command, original) => {
                self.start(channel, Program::Command(&command), original, session).await
            }
            Plan::Shell => self.start(channel, Program::Login, None, session).await,
            Plan::Sftp => self.sftp(channel, session),
            // As a program that did not start: the channel runs nothing
            // else, so it ends here.
            Plan::Refuse(why) => {
                self.refuse_for(channel, &why, session)?;
                if self.channels.get(&channel).is_some_and(|open| !open.started()) {
                    session.eof(channel)?;
                    session.close(channel)?;
                }
                Ok(())
            }
        }
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
        let Some(open) = self.channels.get_mut(&id) else { return Self::refuse(id, session) };
        // A channel runs one program, as RFC 4254 has it.
        if open.started() {
            return Self::refuse(id, session);
        }
        let started = if settings.no_shell {
            Err("--no-shell: this server runs no command and no shell".to_string())
        } else {
            start_program(open, id, &settings, program, original).await
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

    /// Serve SFTP in the process on `channel` (T-112). A channel that runs
    /// a program, or SFTP already, takes no second one.
    fn sftp(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        let Some(open) = self.channels.get_mut(&channel) else { return Self::refuse(channel, session) };
        if open.started() {
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

/// Find the shell (T-222), at each start and with no cache, then start the
/// program with it. The search runs programs and waits for them, so it
/// runs on a blocking thread.
#[cfg(unix)]
async fn start_program(
    open: &mut Open,
    id: ChannelId,
    settings: &Settings,
    program: Program<'_>,
    original: Option<Vec<u8>>,
) -> Result<(), String> {
    use super::{child, shell};
    use std::os::unix::ffi::OsStringExt;
    let base = settings.base();
    let candidates = shell::candidates(settings.shell.as_deref(), env::lookup(&base, "SHELL"));
    let probe_env = env::without_credentials(&base);
    let found = tokio::task::spawn_blocking(move || shell::find(&candidates, &probe_env))
        .await
        .map_err(|e| format!("the search for a shell failed: {e}"))?
        .map_err(|none| none.to_string())?;
    let child_env = env::child_env(&base, &found.path, &open.env);
    let child_env = env::with_original(child_env, original.map(std::ffi::OsString::from_vec));
    child::spawn(open, id, &found.path, program, child_env)
}

#[cfg(not(unix))]
async fn start_program(
    _: &mut Open,
    _: ChannelId,
    _: &Settings,
    _: Program<'_>,
    _: Option<Vec<u8>>,
) -> Result<(), String> {
    Err("not on this system: podssh serve runs programs on a Unix host".into())
}

impl russh::server::Handler for Served {
    type Error = russh::Error;

    // A key that is not listed, or that its lines refuse now (from=,
    // expiry-time=), is refused before the client signs with it.
    async fn auth_publickey_offered(&mut self, _user: &str, offer: PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        Ok(if self.admit(offer.public_key).is_some() { Auth::Accept } else { Auth::reject() })
    }

    // The login name selects nothing: the key alone decides, and its line's
    // rules hold for the whole connection. A security key's signature must
    // carry the flags that its line asks for (T-774), as sshd checks them:
    // the line that admitted the key decides, and no later line is tried.
    async fn auth_publickey(&mut self, _user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        let Some(rules) = self.admit(key.public_key) else { return Ok(Auth::reject()) };
        let sk = matches!(key.public_key.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256);
        if let Some(why) = rules.sk_refusal(sk, key.sk_flags) {
            let who = crate::known_hosts::fingerprint(key.public_key);
            self.settings.say(&format!("key {who} refused: {why}"));
            return Ok(Auth::reject());
        }
        self.rules = Some(rules);
        self.who = crate::known_hosts::fingerprint(key.public_key);
        Ok(Auth::Accept)
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
        // A server that stops takes no new session (T-117).
        if self.control.stage() != Stage::Serving {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        let group = self.control.groups.slot();
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
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let port = match direct::check(self.settings.no_forwarding, host, port) {
            Ok(port) => port,
            Err(refusal) => {
                reply.reject(refusal).await;
                return Ok(());
            }
        };
        // The key's own limits (no-port-forwarding, permitopen=).
        let refused = match self.rules() {
            Ok(rules) => rules.forward_refusal(host, port),
            Err(why) => Some(why),
        };
        if let Some(why) = refused {
            self.settings.say(&format!("key {}: refused: {why}", self.who));
            reply.reject(direct::prohibited(&why)).await;
            return Ok(());
        }
        let Some(slot) = self.forwards.take() else {
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        direct::open(channel, host.to_string(), port, reply, slot, session.handle());
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
    // (T-114); each other name is refused.
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "sftp" {
            return Self::refuse(channel, session);
        }
        self.answer(channel, Wanted::Sftp, session).await
    }
}
