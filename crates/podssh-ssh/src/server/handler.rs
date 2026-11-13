//! The server's answers (T-107): public-key authentication against the
//! authorized keys, and a clean refusal of each request that a later entry
//! serves. russh's defaults send no reply to a channel request, and a client
//! then waits (podssh's own for 30 s): each request here is answered.

use std::sync::Arc;

use russh::server::{Auth, ChannelOpenHandle, Msg, PublicKeyOffer, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId, ChannelOpenFailure, Pty};

use super::Authorized;

/// One connection's handler.
pub struct Served {
    pub(super) authorized: Arc<Authorized>,
}

impl Served {
    /// Refuse a request on `channel`, with the reply that the client waits
    /// for when it asked for one.
    fn refuse(channel: ChannelId, session: &mut Session) -> Result<(), russh::Error> {
        session.channel_failure(channel)
    }
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

    // A session channel opens; each request on it is refused below until
    // T-108 serves exec and a shell. The channel's own stream is not kept:
    // nothing reads it here, and a full one would hold the connection.
    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
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

    // The environment is T-108's.
    async fn env_request(
        &mut self,
        channel: ChannelId,
        _name: &str,
        _value: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Self::refuse(channel, session)
    }

    // A shell and exec are T-108's.
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        Self::refuse(channel, session)
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        _data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        Self::refuse(channel, session)
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
