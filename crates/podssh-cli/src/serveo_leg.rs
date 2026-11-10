//! The SSH legs of the Serveo road (T-549): the node's, which holds an
//! alias of its key at Serveo, and the client's hop, which jumps to it. Each
//! is SSH to Serveo's server, raw, through `HTTPS_PROXY`'s CONNECT, on port
//! 443 then 22, as `ssh -p 443 ... serveo.net` reaches it; Serveo documents
//! no SSH inside TLS, so a proxy that passes TLS alone leaves this road out.
//! The handshake, the check of the host key and the login with no account
//! are the Pinggy road's (`pinggy_leg`), as user `anonymous`.
//!
//! The node asks the remote forward of its alias, port 22, as `ssh -R
//! ALIAS:22:localhost:22 serveo.net` does; Serveo refuses an alias that
//! another tunnel holds ("Alias already taken", or a forward that failed),
//! and the node then asks the next of its series. Each `forwarded-tcpip`
//! channel is a client's, handed to `podssh_relay::pinggy::far` with no TLS.
//! The client opens a `direct-tcpip` channel to the alias, as `ssh -J
//! serveo.net user@ALIAS` does (<https://serveo.net/docs/>, read
//! 2026-11-10), trying the series in its order.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use podssh_relay::pinggy::far::Visitor;
use podssh_relay::pinggy::Say;
use podssh_relay::serveo::{self, Service};
use podssh_ssh::russh::client::{self, Msg};
use podssh_ssh::russh::{self, ChannelStream};
use podssh_ws::ProxyChoice;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use crate::pinggy_leg::{self, Leg, Tunnel, CONNECT_LIMIT};

/// The bound of a client's channel to one alias: Serveo answers an alias
/// that no tunnel holds at once, so this bounds a tunnel that went silent.
const OPEN_LIMIT: Duration = Duration::from_secs(10);

/// An SSH session at Serveo, logged in: its handle, the fingerprint of the
/// host key that it presented, and the port that carried it.
struct Session {
    handle: client::Handle<Leg>,
    key: String,
    port: u16,
}

/// SSH at `service`, on each of its ports in turn, through `proxy`; each
/// `forwarded-tcpip` channel goes to `visitors`. Else why none passed.
async fn session(service: &Service, proxy: &ProxyChoice, visitors: mpsc::Sender<Visitor>) -> Result<Session, String> {
    let mut failed = Vec::new();
    for &port in &service.ports {
        let at = service.at(port);
        let tcp = match podssh_ws::dial::dial(&at.host, port, proxy, CONNECT_LIMIT).await {
            Ok(tcp) => tcp,
            Err(e) => {
                failed.push(format!("port {port}: {e}"));
                continue;
            }
        };
        // Raw SSH alone: no version line to wait for before a TLS that
        // Serveo does not take.
        match pinggy_leg::handshake(tcp, &at, visitors.clone(), None).await {
            Ok((mut handle, key)) => {
                let login = pinggy_leg::login(&mut handle, serveo::USER).await;
                login.map_err(|why| format!("{service} on port {port}: {why}"))?;
                return Ok(Session { handle, key, port });
            }
            Err(failed_ssh) => failed.push(format!("port {port}: {}", failed_ssh.why)),
        }
    }
    Err(format!("{service}: {}", failed.join("; ")))
}

/// The place of `k` in a series, for a line.
fn nth(k: u8) -> String {
    match k {
        0 => "first".into(),
        1 => "second".into(),
        2 => "third".into(),
        k => format!("{}th", k + 1),
    }
}

/// A tunnel at `service` under the first alias of the series of the node's
/// key, whose fingerprint is `fingerprint`, that Serveo grants; each client
/// goes to `visitors`. The tunnel's name is the alias. Else why none.
pub(crate) async fn open(
    service: &Service,
    fingerprint: &str,
    proxy: &ProxyChoice,
    visitors: mpsc::Sender<Visitor>,
    say: &Say,
) -> Result<Tunnel, String> {
    let Session { handle, key, port } = session(service, proxy, visitors).await?;
    say(format!("the leg to {service} is raw SSH on port {port}"));
    if service.host_key.is_none() {
        say(format!("{service}'s host key {key} is taken unpinned: the end-to-end channel keeps the bytes"));
    }
    for k in 0..serveo::SERIES {
        let alias = serveo::alias(fingerprint, k);
        let forwarded = handle.tcpip_forward(alias.as_str(), serveo::ALIAS_PORT).await;
        match forwarded {
            Ok(_) => {
                let host_key = (key, service.host_key.is_some());
                return Ok(Tunnel { name: alias, host_key, way: "raw SSH", handle });
            }
            // Another tunnel holds it: a stranger, or this node's last one,
            // which Serveo keeps a while after an abrupt end.
            Err(russh::Error::RequestDenied) => say(format!(
                "{service} refused the alias {alias}, the {} alias of the node's key: another tunnel holds it, or this \
                 node's last one that {service} has not let go; the next of its series",
                nth(k)
            )),
            Err(e) => {
                let _ = handle.disconnect(russh::Disconnect::ByApplication, "no alias", "en").await;
                return Err(format!("{service} refused the alias's forward: {e}"));
            }
        }
    }
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "no alias", "en").await;
    Err(format!("{service} refused each of the {} aliases of the node's key", serveo::SERIES))
}

/// A client's link to the node: SSH at Serveo, then a `direct-tcpip` channel
/// to the first alias of the series of each key of `fingerprints` that
/// opens. `say` hears which one, for `-v`. Else why none opened.
pub(crate) async fn hop(
    service: &Service,
    fingerprints: &[String],
    proxy: &ProxyChoice,
    say: &(dyn Fn(String) + Send + Sync),
) -> Result<Hop, String> {
    // A client asks no forward: a channel that Serveo opened to it anyway is
    // refused, as no receiver takes it.
    let (visitors, _) = mpsc::channel(1);
    let Session { handle, port, .. } = session(service, proxy, visitors).await?;
    let mut refused = Vec::new();
    for fingerprint in fingerprints {
        for k in 0..serveo::SERIES {
            let alias = serveo::alias(fingerprint, k);
            let opening = handle.channel_open_direct_tcpip(alias.as_str(), serveo::ALIAS_PORT, "127.0.0.1", 0);
            let opened = tokio::time::timeout(OPEN_LIMIT, opening).await;
            match opened {
                Ok(Ok(channel)) => {
                    say(format!("the Serveo road jumps to {alias}, the {} alias of the key {fingerprint}", nth(k)));
                    return Ok(Hop { stream: channel.into_stream(), _handle: handle });
                }
                Ok(Err(e)) => refused.push(format!("{alias}: {e}")),
                Err(_) => refused.push(format!("{alias}: no answer within {} s", OPEN_LIMIT.as_secs())),
            }
        }
    }
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "no alias", "en").await;
    Err(format!(
        "{service} on port {port} opened no alias of the node's key, so no node holds one there now: {}",
        refused.join("; ")
    ))
}

/// A client's link over Serveo: the channel to the alias, and the SSH
/// session that carries it, which ends with the link.
pub(crate) struct Hop {
    stream: ChannelStream<Msg>,
    _handle: client::Handle<Leg>,
}

impl AsyncRead for Hop {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hop {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_places_of_a_series_read_as_words() {
        let words: Vec<String> = (0..serveo::SERIES + 1).map(nth).collect();
        assert_eq!(words, ["first", "second", "third", "4th", "5th"]);
    }
}
