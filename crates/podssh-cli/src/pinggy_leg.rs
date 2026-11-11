//! The node's leg of the Pinggy road (T-548): SSH to Pinggy's server on
//! port 443, through `HTTPS_PROXY`. Raw SSH first, as `ssh -p 443` reaches
//! it; where that fails before SSH's version line (a proxy that passes TLS
//! alone), SSH inside TLS, as Pinggy documents it for a host behind such a
//! proxy (<https://pinggy.io/docs/client_behind_proxy/>, read 2026-11-09),
//! verified by this host's trust, as a relay host's TLS is: a proxy that
//! ends TLS with a CA that the host trusts passes, and nothing else does. A
//! line says which way carried. The user is `tls`, the keyword of a TLS
//! tunnel, with no account: no authentication first, then an empty password
//! or keyboard-interactive, as Pinggy's documents say to press Enter at a
//! prompt (<https://pinggy.io/docs/>, read 2026-11-09). One remote forward
//! of port 0, as `ssh -R0:...` asks it; each `forwarded-tcpip` channel is a
//! visitor, handed to `podssh_relay::pinggy::far`. The session channel takes
//! a shell with no terminal, as `ssh -T` does, whose text names the tunnel;
//! the list of `GET /urls` at port 4300 names it too
//! (`podssh_relay::pinggy::urls`).
//!
//! The host key is checked against `pod-services`' fingerprint of Pinggy's
//! where it names one; where it names none, or for a server that
//! `PODSSH_PINGGY` names, any key passes and is said: the end-to-end channel
//! keeps the bytes, so the key guards the tunnel's availability alone.

use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::pinggy::far::Visitor;
use podssh_relay::pinggy::{self, urls, Say, Service};
use podssh_ssh::russh::client::{self, ChannelOpenHandle, KeyboardInteractiveAuthResponse, Msg};
use podssh_ssh::russh::keys::{Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate};
use podssh_ssh::russh::{self, Channel, ChannelMsg};
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, watch};

/// The bound of the TCP connection, of TLS, and of SSH's handshake, each.
pub(crate) const CONNECT_LIMIT: Duration = Duration::from_secs(20);
/// The bound of the tunnel's name, once its forward was taken.
pub(crate) const NAME_LIMIT: Duration = Duration::from_secs(20);
/// SSH's keepalive, so that a proxy or Pinggy does not cut a quiet leg.
const KEEPALIVE: Duration = Duration::from_secs(30);
/// The bound of raw SSH's version line: a proxy that waits for a TLS
/// ClientHello holds raw SSH silent, and TLS is tried after it.
const VERSION_LIMIT: Duration = Duration::from_secs(10);
/// The bytes of the server's first read that may hold the version line.
const VERSION_BYTES: usize = 255;

/// What the leg's SSH client does with what the server sends; Serveo's
/// road takes it too (T-549, `serveo_leg`).
pub(crate) struct Leg {
    /// The fingerprint that the host key must have, when one is pinned.
    host_key: Option<String>,
    /// The fingerprint of the key that the server presented.
    seen: Arc<Mutex<Option<String>>>,
    visitors: mpsc::Sender<Visitor>,
}

impl client::Handler for Leg {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // Pinggy presents a plain key; a certificate names no key of its own here.
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(fingerprint.clone());
        Ok(self.host_key.as_deref().is_none_or(|pinned| pinned == fingerprint))
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _connected_address: &str,
        _connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // The leg asked for one forward alone: each channel is a visitor of it.
        let peer = podssh_ws::dial::authority(originator_address, originator_port as u16);
        let visitor = Visitor { stream: Box::new(channel.into_stream()), peer };
        match self.visitors.try_send(visitor) {
            Ok(()) => reply.accept().await,
            // Too many visitors wait for TLS: this one is refused, not queued.
            Err(_) => reply.reject(russh::ChannelOpenFailure::ResourceShortage).await,
        }
        Ok(())
    }
}

/// A tunnel of Pinggy's that the node holds: its name, and its SSH session,
/// which ends when the free tunnel's hour does.
pub(crate) struct Tunnel {
    pub name: String,
    /// The host key's fingerprint, and whether it was pinned.
    pub host_key: (String, bool),
    /// Raw SSH, or SSH inside TLS.
    pub way: &'static str,
    pub(crate) handle: client::Handle<Leg>,
}

impl Tunnel {
    /// Wait until the tunnel's session ended: Pinggy's end of a free
    /// tunnel, a lost connection, or the keepalive's.
    pub async fn ended(&self) {
        while !self.handle.is_closed() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    /// Close the session, as the node stops.
    pub async fn close(&self) {
        let _ = self.handle.disconnect(russh::Disconnect::ByApplication, "the node stops", "en").await;
    }
}

/// Why SSH failed, and whether the server's SSH version line came first.
pub(crate) struct Failed {
    pub why: String,
    pub version: bool,
}

/// SSH's handshake with `service` over `stream`; `heard` says whether the
/// server's version line came, where a raw SSH is bounded to hear it within
/// [`VERSION_LIMIT`]. The handle, and the host key's fingerprint.
pub(crate) async fn handshake<S>(
    stream: S,
    service: &Service,
    visitors: mpsc::Sender<Visitor>,
    heard: Option<Arc<AtomicBool>>,
) -> Result<(client::Handle<Leg>, String), Failed>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = client::Config {
        keepalive_interval: Some(KEEPALIVE),
        keepalive_max: 3,
        inactivity_timeout: None,
        ..client::Config::default()
    };
    let seen = Arc::new(Mutex::new(None));
    let leg = Leg { host_key: service.host_key.clone(), seen: seen.clone(), visitors };
    let version = || heard.as_ref().is_none_or(|heard| heard.load(Ordering::SeqCst));
    let silent = async {
        tokio::time::sleep(VERSION_LIMIT).await;
        if version() {
            std::future::pending::<()>().await;
        }
    };
    let connecting = client::connect_stream(Arc::new(config), stream, leg);
    let raced = async {
        tokio::select! {
            connected = connecting => Some(connected),
            () = silent => None,
        }
    };
    let failed = |why: String| Failed { why, version: version() };
    let seen_key = || seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    match tokio::time::timeout(CONNECT_LIMIT, raced).await {
        Ok(Some(Ok(handle))) => Ok((handle, seen_key().unwrap_or_default())),
        Ok(Some(Err(e))) => Err(failed(match (&service.host_key, seen_key()) {
            (Some(pinned), Some(key)) if *pinned != key => format!(
                "{service} presented the host key {key}, not the pinned {pinned} (pod-services): a proxy or another \
                 server answered"
            ),
            _ => format!("{service}: SSH: {e}"),
        })),
        Ok(None) => Err(failed(format!("{service}: no SSH version line within {} s", VERSION_LIMIT.as_secs()))),
        Err(_) => Err(failed(format!("{service}: no SSH within {} s", CONNECT_LIMIT.as_secs()))),
    }
}

/// A tunnel at `service`, through `proxy`: raw SSH, else SSH inside TLS
/// that `trust` verifies (this host's, as for a relay host); each visitor
/// goes to `visitors`. Else why there is none.
pub(crate) async fn open(
    service: &Service,
    trust: &Trust,
    proxy: &ProxyChoice,
    visitors: mpsc::Sender<Visitor>,
    say: &Say,
) -> Result<Tunnel, String> {
    let dial = || async {
        podssh_ws::dial::dial(&service.host, service.port, proxy, CONNECT_LIMIT)
            .await
            .map_err(|e| format!("{service}: {e}"))
    };
    // A dial that fails would fail the same for TLS: same host, port, proxy.
    let heard = Arc::new(AtomicBool::new(false));
    let raw = Heard { inner: dial().await?, first: Vec::new(), heard: heard.clone() };
    let (mut handle, key, way) = match handshake(raw, service, visitors.clone(), Some(heard)).await {
        Ok((handle, key)) => (handle, key, "raw SSH"),
        Err(Failed { why, version: true }) => return Err(why),
        Err(Failed { why: raw, version: false }) => {
            say(format!("raw SSH to {service} failed before SSH's version line ({raw}); SSH inside TLS now"));
            let tls = podssh_ws::tls_over(dial().await?, &service.host, trust, CONNECT_LIMIT)
                .await
                .map_err(|e| format!("raw SSH: {raw}; then TLS with {service}: {e}"))?;
            match handshake(tls, service, visitors, None).await {
                Ok((handle, key)) => (handle, key, "SSH inside TLS, verified by this host's trust"),
                Err(failed) => return Err(format!("raw SSH: {raw}; then SSH inside TLS: {}", failed.why)),
            }
        }
    };
    say(format!("the leg to {service} is {way}"));
    if service.host_key.is_none() {
        say(format!("{service}'s host key {key} is taken unpinned: the end-to-end channel keeps the bytes"));
    }
    login(&mut handle, pinggy::TLS_USER).await.map_err(|why| format!("{service}: {why}"))?;
    handle
        .tcpip_forward(pinggy::FORWARD_ADDRESS, 0)
        .await
        .map_err(|e| format!("{service} refused the tunnel's forward: {e}"))?;
    let session = handle.channel_open_session().await.map_err(|e| format!("{service}: a session: {e}"))?;
    session.request_shell(false).await.map_err(|e| format!("{service}: a shell: {e}"))?;
    let (text, heard) = watch::channel(String::new());
    tokio::spawn(drain(session, text));
    let skip: Vec<&str> = [Some(service.host.as_str()), pinggy::dashboard()].into_iter().flatten().collect();
    let named = async {
        tokio::select! {
            Some(name) = from_api(&handle, &skip) => name,
            name = from_text(heard, &skip) => name,
        }
    };
    let name = match tokio::time::timeout(NAME_LIMIT, named).await {
        Ok(name) => name,
        Err(_) => {
            let _ = handle.disconnect(russh::Disconnect::ByApplication, "no name", "en").await;
            return Err(format!("{service} named no tunnel within {} s", NAME_LIMIT.as_secs()));
        }
    };
    Ok(Tunnel { name, host_key: (key, service.host_key.is_some()), way, handle })
}

/// The login of a tunnel with no account, as `user`; else why none passed.
/// Serveo's road (T-549) and the ssh-j road's leg (T-570, `crate::sshj::leg`),
/// whose handler is its own, log in so too.
pub(crate) async fn login<H: client::Handler>(handle: &mut client::Handle<H>, user: &str) -> Result<(), String> {
    let word = |e: russh::Error| format!("the login: {e}");
    if handle.authenticate_none(user).await.map_err(word)?.success() {
        return Ok(());
    }
    // Pinggy asks for a password where a client needs one: any word passes.
    if handle.authenticate_password(user, "").await.map_err(word)?.success() {
        return Ok(());
    }
    let answered = match handle.authenticate_keyboard_interactive_start(user, None::<String>).await.map_err(word)? {
        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
            let answers = vec![String::new(); prompts.len()];
            handle.authenticate_keyboard_interactive_respond(answers).await.map_err(word)?
        }
        other => other,
    };
    if matches!(answered, KeyboardInteractiveAuthResponse::Success) {
        return Ok(());
    }
    // Sandhole lets any key in but asks for one (T-743): a key made for this
    // login alone, never the node's, so that no key of the host goes to it.
    let throwaway = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(|e| format!("the login: {e}"))?;
    let key = PrivateKeyWithHashAlg::new(Arc::new(throwaway), None);
    if handle.authenticate_publickey(user, key).await.map_err(word)?.success() {
        return Ok(());
    }
    Err("no login with no account passed (none, an empty password, keyboard-interactive, a key made for it)".into())
}

/// Read the session's channel to its end, so that it never holds the
/// session back, and keep its first 64 KiB of text.
async fn drain(mut session: Channel<Msg>, text: watch::Sender<String>) {
    while let Some(msg) = session.wait().await {
        let data = match msg {
            ChannelMsg::Data { data } | ChannelMsg::ExtendedData { data, .. } => data,
            _ => continue,
        };
        text.send_if_modified(|kept| {
            let room = urls::MOST.saturating_sub(kept.len());
            kept.push_str(&String::from_utf8_lossy(&data[..data.len().min(room)]));
            room > 0
        });
    }
}

/// The name in the session's text, once it holds one.
async fn from_text(mut heard: watch::Receiver<String>, skip: &[&str]) -> String {
    loop {
        if let Some(name) = urls::names(&urls::in_text(&heard.borrow_and_update()), skip).into_iter().next() {
            return name;
        }
        if heard.changed().await.is_err() {
            // The channel ended with no name: the API's answer may still come.
            std::future::pending::<()>().await;
        }
    }
}

/// The name in the list of `GET /urls`, when the port answers with one.
async fn from_api(handle: &client::Handle<Leg>, skip: &[&str]) -> Option<String> {
    let channel = handle.channel_open_direct_tcpip("localhost", pinggy::URLS_PORT, "127.0.0.1", 0).await.ok()?;
    let mut stream = channel.into_stream();
    stream.write_all(&urls::request()).await.ok()?;
    let mut answer = Vec::new();
    let _ = (&mut stream).take(urls::MOST as u64).read_to_end(&mut answer).await;
    let addresses = urls::response(&answer).ok()?;
    urls::names(&addresses, skip).into_iter().next()
}

/// A stream that notes whether the server's first bytes hold SSH's version
/// line: raw SSH that fails before it is a proxy that passes TLS alone.
struct Heard<S> {
    inner: S,
    first: Vec<u8>,
    heard: Arc<AtomicBool>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Heard<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(cx, buf);
        if self.first.len() < VERSION_BYTES {
            let room = VERSION_BYTES - self.first.len();
            let new = &buf.filled()[before..];
            let take = new.len().min(room);
            let me = &mut *self;
            me.first.extend_from_slice(&new[..take]);
            // RFC 4253 lets lines come before the version line.
            if me.first.windows(4).any(|w| w == b"SSH-") {
                me.heard.store(true, Ordering::SeqCst);
            }
        }
        polled
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Heard<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_version_line_is_heard_after_other_lines_and_not_in_a_tls_record() {
        for (bytes, ssh) in [
            (&b"SSH-2.0-OpenSSH_9.9\r\n"[..], true),
            (b"a line first\r\nSSH-2.0-x\r\n", true),
            (b"\x16\x03\x01\x00\x05hello", false),
            (b"HTTP/1.1 403 Forbidden\r\n\r\n", false),
        ] {
            let (mut near, far) = tokio::io::duplex(1024);
            near.write_all(bytes).await.unwrap();
            drop(near);
            let heard = Arc::new(AtomicBool::new(false));
            let mut stream = Heard { inner: far, first: Vec::new(), heard: heard.clone() };
            let mut got = Vec::new();
            stream.read_to_end(&mut got).await.unwrap();
            assert_eq!(got, bytes, "the bytes pass as they are");
            assert_eq!(heard.load(Ordering::SeqCst), ssh, "{bytes:?}");
        }
    }
}
