//! iroh's relay protocol at `/relay` (T-720), with iroh-relay's own server
//! code (its feature `server`, the vendored 1.4.2 of PodUtils/podcrates):
//! its handshake, by which a client proves its endpoint's key; its hook of
//! access; and its registry of clients, which forwards each datagram to the
//! key that it names and tells a sender's peers when it is gone.
//! iroh-relay serves the route with hyper on a listener of its own; here the
//! role's listener read TLS and the request's head already, so the upgrade
//! is answered here, and the session's messages go to iroh-relay as its
//! embedders hand them (its `tests/relay_axum.rs`). Whom it admits follows
//! `--mint`: anyone, or the keys of its list and the members of its net, as
//! a key of podssh's identity is an iroh endpoint's key. The datagrams are
//! QUIC's, sealed end to end: the role sees keys, sizes and times.

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use futures_channel::mpsc;
use iroh_relay::http::ProtocolVersion;
use iroh_relay::protos::handshake;
use iroh_relay::protos::streams::StreamError;
use iroh_relay::server::client::Config as ClientConfig;
use iroh_relay::server::clients::Clients;
use iroh_relay::server::streams::RelayedStream;
use iroh_relay::server::{Access, AccessControl, ClientRequest, ConnectionId, DynAccessControl, Metrics};
use iroh_relay::{ExportKeyingMaterial, KeyCache};
use n0_error::AnyError;
use n0_future::{Sink, SinkExt, Stream, StreamExt};
use podssh_ws::frame as ws;
use podssh_ws::http::request::{self, Request};
use podssh_ws::server;
use podssh_ws::session::RelaySession;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use super::super::{answer, keys, Config, Mint};
use crate::identity::PublicKey;

/// The largest message that a client may send: iroh-relay's own bound of a
/// frame (`MAX_FRAME_SIZE`), which its server gives tokio-websockets.
const MAX_MESSAGE: usize = 1024 * 1024;
/// The messages that wait each way between the session and iroh-relay.
const QUEUE: usize = 64;
/// How long a client has for its handshake, as iroh-relay's server bounds
/// the establishment of a connection.
const HANDSHAKE: Duration = Duration::from_secs(10);
/// The endpoints' keys that iroh-relay keeps parsed.
const KEY_CACHE: usize = 1024;

/// The relay of this process: one role serves it, so it lives beside the
/// role's `Config`, as DERP's hub does.
struct Relay {
    clients: Clients,
    keys: KeyCache,
    metrics: Arc<Metrics>,
}

static RELAY: OnceLock<Relay> = OnceLock::new();

fn relay() -> &'static Relay {
    RELAY.get_or_init(|| Relay {
        clients: Clients::default(),
        keys: KeyCache::new(KEY_CACHE),
        metrics: Arc::new(Metrics::default()),
    })
}

/// Serve one client at `/relay`: the upgrade, the handshake, the hook of
/// access, then its datagrams in iroh-relay's registry until its end.
pub async fn request<S>(mut stream: S, head: Request, pending: Vec<u8>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let key = match server::check_upgrade(&head) {
        Ok(key) => key,
        Err(refused) => return answer(&mut stream, refused.answer()).await,
    };
    let Some(version) = version_of(&head) else {
        let why = format!("/relay: a WebSocket of a subprotocol of {}", ProtocolVersion::all_joined());
        return answer(&mut stream, request::refusal(400, &why, &[])).await;
    };
    if stream.write_all(&server::switching_to(&key, Some(version.to_str()))).await.is_err() {
        return;
    }
    let session = server::session(stream, pending, None);
    session.set_receive_cap(MAX_MESSAGE);
    let mut frames = bridge(Arc::new(session));
    // No header of keying material: the exporter of the role's TLS is not
    // reachable here, so the challenge proves the key, one round trip more.
    let proven = match tokio::time::timeout(HANDSHAKE, handshake::serverside(&mut frames, None)).await {
        Ok(Ok(proven)) => proven,
        Ok(Err(why)) => return cfg.event(&format!("iroh: a handshake failed: {why}")),
        Err(_) => return cfg.event("iroh: a handshake took more than 10 s"),
    };
    let asked = ClientRequest::new(proven.client_key, version, parts_of(&head));
    let door: Arc<dyn DynAccessControl> = Arc::new(Door { cfg: cfg.clone() });
    // A key that the door refused got iroh's denial; the door said why.
    let Ok(guard) = proven.authorize_with(&asked, &door, &mut frames).await else { return };
    let relay = relay();
    let stream = RelayedStream::new(frames, relay.keys.clone());
    relay.clients.register(ClientConfig::new(guard, stream, version), relay.metrics.clone());
}

/// The newest version of the protocol that the client offers, as
/// iroh-relay's server picks it; none for a request that offers none.
fn version_of(head: &Request) -> Option<ProtocolVersion> {
    head.headers
        .iter()
        .filter(|(name, _)| name == "sec-websocket-protocol")
        .flat_map(|(_, value)| value.split(','))
        .filter_map(|offered| ProtocolVersion::match_from_str(offered.trim()))
        .max()
}

/// The request's head as iroh-relay's hook of access reads it; a head that
/// `http` does not take is given as `GET /`, as the hook reads the key alone.
fn parts_of(head: &Request) -> http::request::Parts {
    let mut built = http::Request::builder().method("GET").uri(head.target.as_str());
    for (name, value) in &head.headers {
        built = built.header(name.as_str(), value.as_str());
    }
    match built.body(()) {
        Ok(asked) => asked.into_parts().0,
        Err(_) => http::Request::new(()).into_parts().0,
    }
}

/// Whether the role admits the endpoint of `key`: as `--mint` admits a key,
/// anyone, or the keys of its list and the members of its net; `Err` says
/// why not.
pub fn admits(mint: &Mint, key: &PublicKey) -> Result<(), String> {
    match keys::Whom::of(mint) {
        Some(whom) => whom.admits(key).map(|_| ()),
        None if matches!(mint, Mint::Anyone) => Ok(()),
        None => Err("this relay admits no iroh endpoint, as it mints for nobody".into()),
    }
}

/// The hook of access: [`admits`] for each client, and each up and down in
/// the role's events.
struct Door {
    cfg: Arc<Config>,
}

impl std::fmt::Debug for Door {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Door")
    }
}

impl AccessControl for Door {
    async fn on_connect(&self, asked: &ClientRequest) -> Access {
        let key = PublicKey(*asked.endpoint_id().as_bytes());
        match admits(&self.cfg.mint, &key) {
            Ok(()) => {
                self.cfg.event(&format!("iroh: the endpoint {} is up", key.fingerprint()));
                Access::Allow
            }
            Err(why) => {
                self.cfg.event(&format!("iroh: refused the endpoint {}: {why}", key.fingerprint()));
                // iroh's own word, as its relays deny a key.
                Access::Deny { reason: Some("not authorized".into()) }
            }
        }
    }

    fn on_disconnect(&self, endpoint: iroh_base::EndpointId, _: ConnectionId) {
        let key = PublicKey(*endpoint.as_bytes());
        self.cfg.event(&format!("iroh: the endpoint {} is down", key.fingerprint()));
    }
}

/// The binary messages of the role's session, as iroh-relay's server takes
/// a WebSocket: a stream of them and a sink of them. A task of each way
/// moves them through a queue, as the session is read and written by
/// `&self` from two tasks.
pub struct Frames {
    from: mpsc::Receiver<Bytes>,
    to: mpsc::Sender<Bytes>,
}

/// [`Frames`] over `session`: its end, either way, ends both.
pub fn bridge<S>(session: Arc<RelaySession<S>>) -> Frames
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (mut came, from) = mpsc::channel::<Bytes>(QUEUE);
    let (to, mut going) = mpsc::channel::<Bytes>(QUEUE);
    let reader = session.clone();
    tokio::spawn(async move {
        loop {
            match reader.read_frame().await {
                Ok(message) if message.opcode == ws::OPCODE_BINARY => {
                    if came.send(Bytes::from(message.payload)).await.is_err() {
                        return;
                    }
                }
                // A Close was echoed by the session; the end of `came` ends
                // iroh-relay's client.
                Ok(message) if message.opcode == ws::OPCODE_CLOSE => return,
                // The protocol has no text; one is skipped, as iroh's server
                // skips it.
                Ok(_) => {}
                Err(_) => return,
            }
        }
    });
    tokio::spawn(async move {
        while let Some(message) = going.next().await {
            if session.send_binary(&message).await.is_err() {
                return;
            }
        }
        // iroh-relay let go of its client: the session ends with it.
        let _ = session.send_close(1000, "").await;
    });
    Frames { from, to }
}

/// A queue whose other end is gone: the session ended.
fn gone(_: mpsc::SendError) -> StreamError {
    AnyError::from_string("the relay's session with this client ended".into())
}

impl Stream for Frames {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Stream::poll_next(Pin::new(&mut self.from), cx).map(|message| message.map(Ok))
    }
}

impl Sink<Bytes> for Frames {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        Sink::poll_ready(Pin::new(&mut self.to), cx).map_err(gone)
    }

    fn start_send(mut self: Pin<&mut Self>, message: Bytes) -> Result<(), StreamError> {
        Sink::start_send(Pin::new(&mut self.to), message).map_err(gone)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        Sink::poll_flush(Pin::new(&mut self.to), cx).map_err(gone)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), StreamError>> {
        Sink::poll_close(Pin::new(&mut self.to), cx).map_err(gone)
    }
}

/// None: the role's TLS is not reachable from its session, so a client's
/// header of keying material never matches, and the challenge is asked.
impl ExportKeyingMaterial for Frames {
    fn export_keying_material<T: AsMut<[u8]>>(&self, _: T, _: &[u8], _: Option<&[u8]>) -> Option<T> {
        None
    }
}

#[cfg(test)]
#[path = "meet_iroh_tests.rs"]
mod tests;
