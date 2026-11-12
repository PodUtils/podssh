//! A link to a peer of Yggdrasil's network: a WebSocket with the subprotocol
//! `ygg-ws` at the peer's URL (`wss://` through TLS, `ws://` for a test's
//! own node), whose binary messages carry a byte stream each way, and the
//! `meta` handshake on that stream ([`super::meta`]). The stream after it is
//! the one that Ironwood takes for the peer. No token and no account: a
//! public peer takes any node that passes the handshake.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use podssh_ws::frame::{OPCODE_BINARY, OPCODE_CLOSE};
use podssh_ws::session::RelaySession;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};

use super::meta::{self, Meta};

/// The subprotocol of Yggdrasil's WebSocket links.
pub const SUBPROTOCOL: &str = "ygg-ws";
/// What podssh says it is.
pub const USER_AGENT: &str = concat!("podssh/", env!("CARGO_PKG_VERSION"));
/// The bound of the connection, of TLS and of the upgrade, each.
pub const CONNECT_LIMIT: Duration = Duration::from_secs(20);
/// The bound of the handshake, as Yggdrasil's own nodes bound it.
pub const HANDSHAKE_LIMIT: Duration = Duration::from_secs(6);
/// The bound of each write, and of silence: Ironwood keeps a link busy.
const WRITE_LIMIT: Duration = Duration::from_secs(20);
const IDLE_LIMIT: Duration = Duration::from_secs(60);
/// The bytes between the WebSocket and Ironwood, each way.
const BUFFER: usize = 256 * 1024;
/// The largest message read from a peer.
const RECEIVE_CAP: usize = 1 << 20;

/// A peer's URL: `wss://HOST[:PORT][/PATH]`, or `ws://` for a test's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Peer {
    /// A `wss://` or `ws://` URL; no other scheme.
    pub fn parse(url: &str) -> Result<Peer, String> {
        let refused = || format!("{url}: a peer of Yggdrasil is wss://HOST[:PORT][/PATH]");
        let (tls, rest) = if let Some(rest) = url.strip_prefix("wss://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("ws://") {
            (false, rest)
        } else {
            return Err(refused());
        };
        let (authority, path) = rest.find('/').map_or((rest, "/"), |at| (&rest[..at], &rest[at..]));
        let default = if tls { 443 } else { 80 };
        let (host, port) = match authority.strip_prefix('[') {
            // A literal of IPv6: its brackets, then the port after them.
            Some(rest) => {
                let (host, after) = rest.split_once(']').ok_or_else(refused)?;
                match after.strip_prefix(':') {
                    Some(port) => (host, port.parse::<u16>().map_err(|_| refused())?),
                    None if after.is_empty() => (host, default),
                    None => return Err(refused()),
                }
            }
            None => match authority.rsplit_once(':') {
                Some((host, port)) => (host, port.parse::<u16>().map_err(|_| refused())?),
                None => (authority, default),
            },
        };
        if host.is_empty() {
            return Err(refused());
        }
        Ok(Peer { tls, host: host.to_string(), port, path: path.to_string() })
    }

    fn authority(&self) -> String {
        let host = if self.host.contains(':') { format!("[{}]", self.host) } else { self.host.clone() };
        if self.port == if self.tls { 443 } else { 80 } {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", if self.tls { "wss" } else { "ws" }, self.authority(), self.path)
    }
}

/// A byte stream to a peer, before its upgrade.
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> Io for T {}
pub type BoxIo = Box<dyn Io>;
pub type Dialing = Pin<Box<dyn Future<Output = Result<BoxIo, String>> + Send>>;
/// How to reach a peer: through `HTTPS_PROXY` ([`dial`]), or a test's way.
pub type Dial = Arc<dyn Fn(&Peer) -> Dialing + Send + Sync>;

/// TCP through `proxy`, then TLS verified with `trust` for a `wss://` peer.
pub fn dial(trust: Trust, proxy: ProxyChoice) -> Dial {
    Arc::new(move |peer: &Peer| -> Dialing {
        let (peer, trust, proxy) = (peer.clone(), trust.clone(), proxy.clone());
        Box::pin(async move {
            let host = peer.host.as_str();
            if peer.tls {
                let opened = podssh_ws::client::open_tls(host, peer.port, host, &trust, &proxy, CONNECT_LIMIT);
                Ok(Box::new(opened.await.map_err(|e| format!("{peer}: {e}"))?) as BoxIo)
            } else {
                let tcp = podssh_ws::dial::dial(host, peer.port, &proxy, CONNECT_LIMIT).await;
                Ok(Box::new(tcp.map_err(|e| format!("{peer}: {e}"))?) as BoxIo)
            }
        })
    })
}

/// The upgrade request, with `key` as its `Sec-WebSocket-Key`.
pub fn request(peer: &Peer, key: &str) -> Vec<u8> {
    format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\r\n",
        peer.path,
        peer.authority()
    )
    .into_bytes()
}

/// The link to `peer`: dialed, upgraded, and its handshake done as
/// `secret`; the peer's word of itself, and the stream for Ironwood.
pub async fn open(peer: &Peer, dial: &Dial, secret: &SigningKey) -> Result<(Meta, DuplexStream), String> {
    let io = dial(peer).await?;
    let key = podssh_ws::handshake::generate_key().map_err(|e| e.to_string())?;
    let ask = request(peer, &key);
    let asked = podssh_ws::client::upgrade_with(io, &ask, &key);
    let (io, pending) = match tokio::time::timeout(CONNECT_LIMIT, asked).await {
        Err(_) => return Err(format!("{peer} did not answer the upgrade within {} s", CONNECT_LIMIT.as_secs())),
        Ok(Err(e)) => return Err(format!("{peer} refused Yggdrasil's WebSocket: {e}")),
        Ok(Ok(upgraded)) => upgraded,
    };
    let session = RelaySession::new(io, pending, Some(IDLE_LIMIT), WRITE_LIMIT).without_pings();
    session.set_receive_cap(RECEIVE_CAP);
    let mut stream = pump(Arc::new(session));
    let met = tokio::time::timeout(HANDSHAKE_LIMIT, meta::exchange(&mut stream, secret, 0)).await;
    let meta =
        met.map_err(|_| format!("{peer} did not finish the handshake in time"))?.map_err(|e| format!("{peer}: {e}"))?;
    Ok((meta, stream))
}

/// A byte stream over the WebSocket's binary messages: each read of the far
/// side goes as one message, each message comes as bytes. Either side's end
/// ends both.
fn pump<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(session: Arc<RelaySession<S>>) -> DuplexStream {
    let (near, far) = tokio::io::duplex(BUFFER);
    let (mut from, mut to) = tokio::io::split(far);
    let reader = session.clone();
    tokio::spawn(async move {
        while let Ok(frame) = reader.read_frame().await {
            if frame.opcode == OPCODE_CLOSE
                || (frame.opcode == OPCODE_BINARY && to.write_all(&frame.payload).await.is_err())
            {
                break;
            }
        }
        let _ = to.shutdown().await;
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if session.send_binary(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = session.send_close(1000, "").await;
    });
    near
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_s_url_reads_and_its_upgrade_asks_for_ygg_ws() {
        let peer = Peer::parse("wss://ygg.example.net/ws").unwrap();
        assert_eq!(
            (peer.tls, peer.host.as_str(), peer.port, peer.path.as_str()),
            (true, "ygg.example.net", 443, "/ws")
        );
        assert_eq!(peer.to_string(), "wss://ygg.example.net/ws");
        let local = Peer::parse("ws://127.0.0.1:9001").unwrap();
        assert_eq!((local.tls, local.port, local.path.as_str()), (false, 9001, "/"));
        let text = String::from_utf8(request(&local, "k")).unwrap();
        assert!(text.starts_with("GET / HTTP/1.1\r\nHost: 127.0.0.1:9001\r\n"), "{text}");
        assert!(text.contains("\r\nSec-WebSocket-Protocol: ygg-ws\r\n") && text.ends_with("\r\n\r\n"));
        let v6 = Peer::parse("wss://[2001:db8::1]:8443").unwrap();
        assert_eq!((v6.host.as_str(), v6.port), ("2001:db8::1", 8443));
        assert_eq!(v6.to_string(), "wss://[2001:db8::1]:8443/");
        assert_eq!(Peer::parse("wss://[2001:db8::1]").unwrap().port, 443);
        for refused in ["tcp://1.2.3.4:1", "wss://", "wss://h:x"] {
            assert!(Peer::parse(refused).is_err(), "{refused}");
        }
    }
}
