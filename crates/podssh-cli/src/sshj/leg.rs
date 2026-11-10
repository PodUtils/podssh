//! The SSH leg to a server of the ssh-j road, the node's and a client's:
//! SSH's handshake over a stream that the caller dialed, the host key's
//! check, and the login of the derived user with no account (no
//! authentication, then an empty password or keyboard-interactive, the
//! Pinggy road's login, `crate::pinggy_leg::login`), as the page's `ssh
//! any-username@ssh-j.com` logs in. The node's leg takes the
//! `forwarded-tcpip` channels of its own name alone, each a visitor.
//!
//! The host key is checked against `pod-services`' fingerprint of ssh-j.com
//! where it names one; where it names none, or for a server that
//! `PODSSH_SSH_J` names, any key passes and the caller says so: the server
//! ends this SSH and so sees the forward's bytes whichever key it shows, and
//! the end-to-end channel above keeps them, so the key guards the road's
//! availability alone.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use podssh_relay::pinggy::far::Visitor;
use podssh_ssh::russh::client::{self, ChannelOpenHandle, Msg};
use podssh_ssh::russh::keys::{HashAlg, PublicKeyOrCertificate};
use podssh_ssh::russh::{self, Channel};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::{Service, NAME_PORT};

/// The bound of the TCP connection, and of SSH's handshake and login, each.
pub(crate) const CONNECT_LIMIT: Duration = Duration::from_secs(20);
/// SSH's keepalive, so that a proxy or the server does not cut a quiet leg.
const KEEPALIVE: Duration = Duration::from_secs(30);

/// Where a node's visitors go: the address of its name, and the queue.
pub(crate) struct Visitors {
    pub address: String,
    pub queue: mpsc::Sender<Visitor>,
}

/// What the leg's SSH client does with what the server sends.
pub(crate) struct Leg {
    /// The fingerprint that the host key must have, when one is pinned.
    host_key: Option<String>,
    /// The fingerprint of the key that the server presented.
    seen: Arc<Mutex<Option<String>>>,
    /// A node's: its visitors; a client's leg takes none.
    visitors: Option<Visitors>,
}

impl client::Handler for Leg {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        // A plain key; a certificate names no key of its own here.
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        let fingerprint = key.fingerprint(HashAlg::Sha256).to_string();
        *self.seen.lock().unwrap_or_else(PoisonError::into_inner) = Some(fingerprint.clone());
        Ok(self.host_key.as_deref().is_none_or(|pinned| pinned == fingerprint))
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: Channel<Msg>,
        connected_address: &str,
        connected_port: u32,
        originator_address: &str,
        originator_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut client::Session,
    ) -> Result<(), Self::Error> {
        // The server names the forward that a visitor came by: the node's
        // own name, or nothing that the node asked for.
        let Some(visitors) = self.visitors.as_ref().filter(|v| v.address == connected_address) else {
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        };
        if connected_port != NAME_PORT {
            reply.reject(russh::ChannelOpenFailure::AdministrativelyProhibited).await;
            return Ok(());
        }
        let peer = podssh_ws::dial::authority(originator_address, originator_port as u16);
        let visitor = Visitor { stream: Box::new(channel.into_stream()), peer };
        match visitors.queue.try_send(visitor) {
            Ok(()) => reply.accept().await,
            // Too many visitors wait for the layer: this one is refused, not queued.
            Err(_) => reply.reject(russh::ChannelOpenFailure::ResourceShortage).await,
        }
        Ok(())
    }
}

/// A leg that logged in: its handle, and the host key's fingerprint with
/// whether it was pinned.
pub(crate) struct Opened {
    pub handle: client::Handle<Leg>,
    pub host_key: (String, bool),
}

/// SSH with `service` over `stream`, logged in as `user`; a node's leg
/// passes its `visitors`. Else why not, which names a host key that is not
/// the pinned one.
pub(crate) async fn open<S>(
    stream: S,
    service: &Service,
    user: &str,
    visitors: Option<Visitors>,
) -> Result<Opened, String>
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
    let seen_key = || seen.lock().unwrap_or_else(PoisonError::into_inner).clone();
    let connecting = client::connect_stream(Arc::new(config), stream, leg);
    let mut handle = match tokio::time::timeout(CONNECT_LIMIT, connecting).await {
        Ok(Ok(handle)) => handle,
        Ok(Err(e)) => {
            return Err(match (&service.host_key, seen_key()) {
                (Some(pinned), Some(key)) if *pinned != key => format!(
                    "{service} presented the host key {key}, not ssh-j.com's {pinned} (pod-services): a proxy or \
                     another server answered"
                ),
                _ => format!("{service}: SSH: {e}"),
            });
        }
        Err(_) => return Err(format!("{service}: no SSH within {} s", CONNECT_LIMIT.as_secs())),
    };
    let login = crate::pinggy_leg::login(&mut handle, user);
    match tokio::time::timeout(CONNECT_LIMIT, login).await {
        Ok(Ok(())) => {}
        Ok(Err(why)) => return Err(format!("{service}: {why}")),
        Err(_) => return Err(format!("{service}: no login within {} s", CONNECT_LIMIT.as_secs())),
    }
    Ok(Opened { handle, host_key: (seen_key().unwrap_or_default(), service.host_key.is_some()) })
}

/// The line of the host key, for the node's stderr and a client's `-v`.
pub(crate) fn host_key_line(service: &Service, (key, pinned): &(String, bool)) -> String {
    match pinned {
        true => format!("{service}'s host key {key} (pinned by pod-services)"),
        false => format!("{service}'s host key {key}, taken unpinned: the end-to-end channel keeps the bytes"),
    }
}
