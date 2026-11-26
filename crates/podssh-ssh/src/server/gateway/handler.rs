//! The handler of one connection to a gateway (T-836): the login by the
//! route of the login name, and each channel of the client carried to the
//! upstream. The upstream is dialed in `auth_publickey` alone, after russh
//! verified the client's signature: a key that is only offered
//! (`auth_publickey_offered`, which also runs for a signed request that no
//! probe came before) proves nothing, and a client that offers many keys
//! must not cause many logins upstream. A login with no upstream is
//! refused; nothing here ever lets a client in on the gateway's own word.
//!
//! Each request of a session channel is sent to the upstream's channel and
//! answered with the upstream's own reply, in the order the requests came,
//! as russh reads the next request only once the handler answered.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::Algorithm;
use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{client, Channel, ChannelId, ChannelOpenFailure, Pty, Sig};

use super::pump::{self, Pair, Reply};
use super::upstream::{self, Pinned};
use super::{Route, Table};
use crate::known_hosts::fingerprint;
use crate::server::audit::{Trail, Verdict};
use crate::server::direct::{self, Slots};
use crate::server::live::Conn;
use crate::server::stop::{Control, Stage};
use crate::server::{env, Settings};

/// The longest that the opening of a channel at the upstream may take.
const OPEN_LIMIT: Duration = Duration::from_secs(20);

/// The method of a gateway's login in the audit log.
const METHOD: &str = "publickey,gateway";

/// The bit of a security key's flags that says it was touched.
const USER_PRESENT: u8 = 0x01;

/// One connection's handler.
pub struct Gateway {
    table: Arc<Table>,
    settings: Arc<Settings>,
    control: Control,
    conn: Conn,
    /// The upstream once a login passed; None refuses each channel.
    up: Option<Up>,
    /// The fingerprint of the key that logged in, for serve's log.
    who: String,
    pairs: HashMap<ChannelId, Pair>,
    forwards: Slots,
    /// The task that ends this connection when the upstream's ends.
    watch: Option<tokio::task::AbortHandle>,
    trail: Trail,
    /// Whether serve said why an offered key was refused: once for a
    /// connection, as a client offers many keys.
    told_offer: bool,
}

/// A logged-in upstream, and the route it came by.
struct Up {
    handle: Arc<client::Handle<Pinned>>,
    route: Arc<Route>,
}

impl Drop for Gateway {
    // The client left: so does the gateway, at the upstream.
    fn drop(&mut self) {
        if let Some(watch) = self.watch.take() {
            watch.abort();
        }
        let (Some(up), Ok(runtime)) = (self.up.take(), tokio::runtime::Handle::try_current()) else { return };
        runtime.spawn(async move {
            let bye = up.handle.disconnect(russh::Disconnect::ByApplication, "the client left the gateway", "");
            let _ = tokio::time::timeout(Duration::from_secs(5), bye).await;
        });
    }
}

impl Gateway {
    pub(in crate::server) fn new(table: Arc<Table>, settings: Arc<Settings>, control: Control, conn: Conn) -> Gateway {
        let forwards = Slots::new(settings.max_forwards.unwrap_or(direct::MAX_FORWARDS));
        let trail = Trail::open(&settings);
        Gateway {
            table,
            settings,
            control,
            conn,
            up: None,
            who: String::new(),
            pairs: HashMap::new(),
            forwards,
            watch: None,
            trail,
            told_offer: false,
        }
    }

    /// Whether new channels are taken: logged in, serving, not ended.
    fn open(&self) -> Option<&Up> {
        let serving = self.control.stage() == Stage::Serving && self.conn.ended().is_none();
        self.up.as_ref().filter(|_| serving)
    }

    /// Refuse a login, said on serve's stderr and in the audit log.
    fn refuse(&self, user: &str, who: &str, why: &str) -> Auth {
        self.settings.say(&format!("key {who}: refused as {}: {why}", printable(user)));
        self.trail.auth(Verdict::Refused, user, Some(who), METHOD, Some(why));
        Auth::reject()
    }

    /// Answer a request of the client with the upstream's reply; a lost
    /// reply closes the pair, as no later reply could be matched.
    async fn answer(&mut self, channel: ChannelId, reply: Reply, session: &mut Session) -> Result<(), russh::Error> {
        match reply {
            Reply::Yes => session.channel_success(channel),
            Reply::No => session.channel_failure(channel),
            Reply::Lost(why) => {
                self.settings.say(&format!("key {}: a channel closed: {why}", self.who));
                if let Some(pair) = self.pairs.remove(&channel) {
                    let _ = pair.up.close().await;
                }
                session.channel_failure(channel)?;
                session.close(channel)
            }
        }
    }
}

/// A login name as serve's log shows it: printable ASCII alone.
fn printable(user: &str) -> String {
    user.chars().take(64).map(|c| if c.is_ascii_graphic() { c } else { '?' }).collect()
}

/// Send one request of the client on its pair, and wait for the reply. A
/// channel with no pair is refused.
macro_rules! ask {
    ($self:ident, $channel:expr, $session:ident, |$up:ident| $send:expr) => {{
        let reply = match $self.pairs.get_mut(&$channel) {
            Some(pair) => {
                pair.forget_stray();
                let $up = pair.up.clone();
                let sent = $send.await;
                pair.reply(sent).await
            }
            None => Reply::No,
        };
        $self.answer($channel, reply, $session).await
    }};
}

impl russh::server::Handler for Gateway {
    type Error = russh::Error;

    // A probe: the route of the name, and its list of keys. Never a dial.
    async fn auth_publickey_offered(&mut self, user: &str, offer: PublicKeyOffer<'_>) -> Result<Auth, Self::Error> {
        if self.conn.ended().is_some() {
            return Ok(Auth::reject());
        }
        // A net's document past its end lets no route in (T-902).
        let why = match (self.table.closed(), self.table.now().route(user)) {
            (Some(why), _) => why,
            (None, Some(route)) if route.admits(offer.public_key) => return Ok(Auth::Accept),
            (None, Some(route)) => format!("not a key of the route {} (line {})", route.pattern, route.line),
            (None, None) => "no route of --gateway matches the login name".to_string(),
        };
        // A refused offer is never signed, so its line is said here, once.
        if std::mem::replace(&mut self.told_offer, true) {
            return Ok(Auth::reject());
        }
        Ok(self.refuse(user, &fingerprint(offer.public_key), &why))
    }

    // The signature is verified: the route decides, then the upstream's
    // login, within its time limit.
    async fn auth_publickey(&mut self, user: &str, key: VerifiedPublicKey<'_>) -> Result<Auth, Self::Error> {
        let who = fingerprint(key.public_key);
        if self.conn.ended().is_some() {
            return Ok(self.refuse(user, &who, "the connection was ended"));
        }
        if let Some(why) = self.table.closed() {
            return Ok(self.refuse(user, &who, &why));
        }
        let Some(route) = self.table.now().route(user) else {
            return Ok(self.refuse(user, &who, "no route of --gateway matches the login name"));
        };
        if !route.admits(key.public_key) {
            let why = format!("not a key of the route {} (line {})", route.pattern, route.line);
            return Ok(self.refuse(user, &who, &why));
        }
        // A security key that was not touched did not sign for a person.
        let sk = matches!(key.public_key.algorithm(), Algorithm::SkEd25519 | Algorithm::SkEcdsaSha2NistP256);
        if sk && key.sk_flags.is_none_or(|flags| flags & USER_PRESENT == 0) {
            return Ok(self.refuse(user, &who, "a security key that was not touched"));
        }
        let up = match upstream::log_in(&route, user, &who).await {
            Ok(up) => up,
            Err(why) => return Ok(self.refuse(user, &who, &format!("route {}: {why}", route.pattern))),
        };
        self.settings.say(&format!(
            "key {who}: logged in as {} by the route {} to {}:{} as {}",
            printable(user),
            route.pattern,
            route.host,
            route.port,
            route.principal
        ));
        self.trail.auth(Verdict::Accepted, user, Some(&who), METHOD, None);
        // The upstream's end is this connection's end.
        let (conn, mut gone) = (self.conn.clone(), up.gone);
        let watch = tokio::spawn(async move {
            while gone.changed().await.is_ok() {}
            let _ = conn.end("podssh serve: the upstream closed the connection".into());
        });
        self.watch = Some(watch.abort_handle());
        self.up = Some(Up { handle: Arc::new(up.handle), route });
        self.who = who;
        self.conn.accept();
        Ok(Auth::Accept)
    }

    // A session channel: its twin opens at the upstream first, so that the
    // client's open has the upstream's answer.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let room = self.pairs.len() < crate::server::handler::MAX_SESSIONS;
        let Some(handle) = self.open().filter(|_| room).map(|up| up.handle.clone()) else {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        let opened = tokio::time::timeout(OPEN_LIMIT, handle.channel_open_session()).await;
        match opened {
            Ok(Ok(twin)) => {
                let id = channel.id();
                reply.accept().await;
                self.pairs.insert(id, pump::session(channel, twin, session.handle()));
            }
            refused => {
                let why = match refused {
                    Ok(Err(e)) => format!("the upstream refused a session: {}", podssh_ws::text::said(&e)),
                    _ => format!("the upstream opened no session within {} s", OPEN_LIMIT.as_secs()),
                };
                self.settings.say(&format!("key {}: {why}", self.who));
                reply.reject(direct::connect_failed(&why)).await;
            }
        }
        Ok(())
    }

    async fn channel_close(&mut self, channel: ChannelId, _session: &mut Session) -> Result<(), Self::Error> {
        if let Some(pair) = self.pairs.remove(&channel) {
            let _ = pair.up.close().await;
        }
        Ok(())
    }

    // The client's window opens as the upstream takes its bytes (`pump.rs`).
    fn window_on_read(&mut self, _channel: ChannelId) -> bool {
        true
    }

    // A forward, opened by the upstream from its own host: the route's
    // host is the one that the client reaches the private side through.
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host: &str,
        port: u32,
        from: &str,
        from_port: u32,
        reply: ChannelOpenHandle,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let Some(up) = self.open() else {
            reply.reject(ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        let port = match direct::check(self.settings.no_forwarding, host, port) {
            Ok(port) => port,
            Err(refusal) => {
                self.trail.forward_refused(&self.who, host, port, refusal.description());
                reply.reject(refusal).await;
                return Ok(());
            }
        };
        let Some(slot) = self.forwards.take() else {
            self.trail.forward_refused(&self.who, host, port.into(), direct::FULL);
            reply.reject(ChannelOpenFailure::ResourceShortage).await;
            return Ok(());
        };
        let mut mark = self.trail.forward(&self.who, host, port.into());
        let (handle, down) = (up.handle.clone(), session.handle());
        let (host, from) = (host.to_string(), from.to_string());
        let at = format!("{}:{}", up.route.host, up.route.port);
        tokio::spawn(async move {
            let _slot = slot;
            let opened = handle.channel_open_direct_tcpip(host.as_str(), port.into(), from, from_port);
            let why = match tokio::time::timeout(OPEN_LIMIT, opened).await {
                Ok(Ok(twin)) => {
                    reply.accept().await;
                    let tally = match mark.as_mut() {
                        Some(mark) => {
                            mark.opened();
                            mark.tally()
                        }
                        None => Arc::default(),
                    };
                    // The mark, and its end in the audit log, last as long
                    // as the forward does.
                    pump::forward(channel, twin, down, tally).await;
                    return;
                }
                Ok(Err(e)) => format!("the upstream {at} did not open {host}:{port}: {}", podssh_ws::text::said(&e)),
                Err(_) => format!("the upstream {at} did not open {host}:{port} within {} s", OPEN_LIMIT.as_secs()),
            };
            if let Some(mark) = mark.as_mut() {
                mark.refused(&why);
            }
            reply.reject(direct::connect_failed(&why)).await;
        });
        Ok(())
    }

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
        ask!(self, channel, session, |up| up.request_pty(true, term, cols, rows, pix_width, pix_height, modes))
    }

    // No reply is asked for, nor given.
    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        cols: u32,
        rows: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(pair) = self.pairs.get(&channel) {
            let _ = pair.up.window_change(cols, rows, pix_width, pix_height).await;
        }
        Ok(())
    }

    // --accept-env here first, then the upstream's own AcceptEnv.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if env::refused(&env::patterns(&self.settings.accept_env), name, value).is_some() {
            return session.channel_failure(channel);
        }
        ask!(self, channel, session, |up| up.set_env(true, name, value))
    }

    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        ask!(self, channel, session, |up| up.request_shell(true))
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        ask!(self, channel, session, |up| up.exec(true, data))
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        ask!(self, channel, session, |up| up.request_subsystem(true, name))
    }

    // No reply is asked for, nor given.
    async fn signal(&mut self, channel: ChannelId, signal: Sig, _session: &mut Session) -> Result<(), Self::Error> {
        if let Some(pair) = self.pairs.get(&channel) {
            let _ = pair.up.signal(signal).await;
        }
        Ok(())
    }

    // X11 and a Unix socket are not carried: refused with the reply that
    // the client waits for.
    async fn x11_request(
        &mut self,
        channel: ChannelId,
        _single: bool,
        _protocol: &str,
        _cookie: &str,
        _screen: u32,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.channel_failure(channel)
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
}
