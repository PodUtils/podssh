//! A client's link on the ssh-j road: the server as the first hop of
//! `node://NAME`'s road, as `ssh -J USER@ssh-j.com ADDRESS` takes it. Its
//! leg is SSH to the server on port 22, through `HTTPS_PROXY`'s CONNECT
//! where one is set; where that dial fails (a proxy that refuses port 22, or
//! a network with no way out to it), the forwarders that the binary names
//! carry it, as the operator's ruling Q56 lets them carry SSH when no relay
//! host answers, unless `PODSSH_FORWARDER_FALLBACK` says no. Then a
//! `direct-tcpip` channel to the node's derived name, whose stream the
//! resumable layer and the end-to-end channel run over: the server ends this
//! SSH and passes the layer's bytes, which the channel keeps from it.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use podssh_relay::opentunnel::dial::BoxIo;
use podssh_ssh::russh::client;
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::leg::{self, Leg, CONNECT_LIMIT};
use super::{JumpName, Service, NAME_PORT};
use crate::forwarder;

/// A link to the node, over a channel of the server: the channel's stream,
/// and the leg's session, which lives as long as the link.
pub struct Link {
    stream: BoxIo,
    _leg: client::Handle<Leg>,
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sshj::Link(..)")
    }
}

/// The stream to the server: directly or by the proxy's CONNECT, else
/// through the forwarders of Q56; else why neither carried it.
async fn first_hop(service: &Service, trust: &Trust, log: &Arc<Log>) -> Result<BoxIo, String> {
    first_hop_to(&service.host, service.port, &service.to_string(), trust, log).await
}

/// A stream to `host`:`port`, which the words name `shown`, as [`first_hop`]
/// reaches the server: directly or by the proxy's CONNECT, else through the
/// forwarders of Q56; the bore road (T-569) reaches a node's public port so.
pub(crate) async fn first_hop_to(
    host: &str,
    port: u16,
    shown: &str,
    trust: &Trust,
    log: &Arc<Log>,
) -> Result<BoxIo, String> {
    let proxy = ProxyChoice::FromEnvironment;
    let direct = match podssh_ws::dial::dial(host, port, &proxy, CONNECT_LIMIT).await {
        Ok(tcp) => return Ok(Box::new(tcp)),
        Err(e) => format!("{shown}: {e}"),
    };
    let fallback = forwarder::fallback::FALLBACK_ENV;
    match forwarder::fallback::on_from(forwarder::fallback::env_value(), crate::settings::here()) {
        Ok(true) => {}
        Ok(false) => return Err(format!("{direct}; {fallback}=no keeps the forwarders out")),
        Err(refusal) => return Err(format!("{direct}; {}", refusal.message)),
    }
    log.verbose(&format!("{direct}; the forwarders that the binary names now (Q56)"));
    let forwarders = forwarder::public::chain(forwarder::builtins(), &forwarder::public::forwarders());
    match forwarder::reach::carry(&forwarders, trust, host, port, log, true).await {
        Ok(reached) => Ok(Box::new(reached.stream)),
        Err(not) if not.lines.is_empty() => Err(format!("{direct}; no forwarder carried it")),
        Err(not) => Err(format!("{direct}; {}", not.lines.join("; "))),
    }
}

/// A new link to the node of `name` at `service`, once the server opened
/// its channel; else why there is none. `say` hears the host key's line.
pub async fn link(
    service: &Service,
    name: &JumpName,
    trust: &Trust,
    log: &Arc<Log>,
    say: &(dyn Fn(String) + Send + Sync),
) -> Result<Link, String> {
    let stream = first_hop(service, trust, log).await?;
    let opened = leg::open(stream, service, &name.user, None).await?;
    say(leg::host_key_line(service, &opened.host_key));
    let channel = opened.handle.channel_open_direct_tcpip(name.address.as_str(), NAME_PORT, "127.0.0.1", 0);
    let channel = tokio::time::timeout(CONNECT_LIMIT, channel).await;
    match channel {
        Ok(Ok(channel)) => Ok(Link { stream: Box::new(channel.into_stream()), _leg: opened.handle }),
        // The server refuses a name that no forward of this user holds.
        Ok(Err(e)) => Err(format!(
            "{service} has no node at {name} ({e}): the node is not there now, or its key is not the one expected"
        )),
        Err(_) => Err(format!("{service}: no channel to {name} within {} s", CONNECT_LIMIT.as_secs())),
    }
}

impl AsyncRead for Link {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Link {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
