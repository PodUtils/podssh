//! One connection of the role's own listener, which `podssh relay serve`
//! owns (T-169): TLS, with the handshake alone for a CA's TLS-ALPN-01
//! (T-447); or, when its first byte begins no TLS handshake, the cleartext
//! road ([`super::cleartext`], T-326), unless the owner turned it off. The
//! byte is peeked, so TLS reads its ClientHello whole. One listener, the one
//! that the user asked for: the cleartext road adds none. A client whose TLS
//! chose `h2` gets HTTP/2 with extended CONNECT ([`super::http2`], T-321).
//! Where the owner named an sshd, a connection whose first four bytes are
//! `SSH-` goes to it, peeked too ([`super::sshd`], T-644). Where the owner
//! publishes names, a ClientHello that names one goes to its pair's node
//! before any handshake, peeked whole, so that the node's own TLS answers it
//! ([`super::published`], T-649). Behind a balancer that the owner named,
//! the PROXY header that it writes first names the client
//! ([`super::proxy_header`], T-807).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::tls_server::{TlsAcceptor, ACME_TLS_1};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

use super::proxy_header::{self, Trusted};
use super::published::Published;
use super::slots::Slots;
use super::Config;

/// How long a client has to begin, and to finish, TLS.
pub const HANDSHAKE_WAIT: Duration = Duration::from_secs(30);

/// How the listener takes a connection: TLS with `acceptor`, the cleartext
/// road beside it when `cleartext`, an SSH client to `sshd` when the owner
/// named one, and a name of `published` to its pair's node.
#[derive(Clone)]
pub struct Door {
    pub acceptor: TlsAcceptor,
    pub cleartext: bool,
    /// The owner's sshd, for a connection whose first bytes are `SSH-`
    /// (T-644); none unless named.
    pub sshd: Option<SocketAddr>,
    /// The names that the owner publishes, each to a pair's node (T-649);
    /// none unless named.
    pub published: Arc<Published>,
    /// The balancers whose PROXY header names the client (T-807); none
    /// unless named.
    pub proxy: Arc<Trusted>,
}

/// Serve `tcp`, of a client at `peer`, as `door` says. A peer that is no
/// balancer of the owner's and begins with a PROXY header is closed.
pub async fn connection(mut tcp: TcpStream, peer: IpAddr, door: Door, cfg: Arc<Config>) {
    let Some(peer) = client(&mut tcp, peer, &door, &cfg).await else { return };
    served(tcp, peer, door, cfg).await
}

/// A connection of a balancer that the owner named: its PROXY header first,
/// then a slot of the client that it names, so that the slots count each
/// client apart (T-807). A slot refused is said in the role's log.
pub async fn balanced(mut tcp: TcpStream, balancer: IpAddr, door: Door, cfg: Arc<Config>, slots: Slots) {
    let Some(peer) = client(&mut tcp, balancer, &door, &cfg).await else { return };
    let slot = match slots.admit(peer) {
        Ok(slot) => slot,
        Err(line) => return line.into_iter().for_each(|line| cfg.event(&line)),
    };
    super::sockets::bound_unsent(&tcp);
    slot.holding(served(tcp, peer, door, cfg)).await
}

/// The client of `tcp` from `peer`, by the PROXY header where `peer` is a
/// balancer of the owner's; none once the connection is to close.
async fn client(tcp: &mut TcpStream, peer: IpAddr, door: &Door, cfg: &Config) -> Option<IpAddr> {
    match proxy_header::client_of(tcp, peer, &door.proxy, HANDSHAKE_WAIT).await {
        Ok(client) => Some(client),
        Err(why) => {
            cfg.event(&format!("closed a connection: {why}"));
            None
        }
    }
}

/// Serve `tcp` of a client at `peer`, its PROXY header read.
async fn served(tcp: TcpStream, peer: IpAddr, door: Door, cfg: Arc<Config>) {
    if door.cleartext || door.sshd.is_some() {
        // One bound for the first byte and for the start of SSH after it.
        let deadline = tokio::time::Instant::now() + HANDSHAKE_WAIT;
        match super::cleartext::first_byte(&tcp, HANDSHAKE_WAIT).await {
            Some(first) if super::cleartext::is_tls(first) => {}
            Some(_) => {
                // An SSH client's version line goes to the owner's sshd; a
                // start that is no SSH goes on as before.
                if let Some(sshd) = door.sshd
                    && super::sshd::opens(&tcp, deadline).await
                {
                    // Boxed: a session's future stays off the caller's.
                    return Box::pin(super::sshd::serve(tcp, sshd, cfg)).await;
                }
                if door.cleartext {
                    return super::cleartext::serve(tcp, cfg, Some(peer)).await;
                }
            }
            // Nothing came, or the client went: no TLS to wait for either.
            None => return,
        }
    }
    // A name that the owner publishes: the node's TLS answers it, each byte
    // left in the socket for it; none at once with no name published.
    if let Some(routed) = door.published.peek(&tcp).await {
        // Boxed: a session's future stays off the caller's.
        return Box::pin(super::reverse::publish::carry(tcp, routed, cfg)).await;
    }
    let Ok(Ok(mut tls)) = tokio::time::timeout(HANDSHAKE_WAIT, door.acceptor.accept(tcp)).await else { return };
    // A CA's validation of TLS-ALPN-01 wants the handshake alone (RFC 8737,
    // section 3).
    if tls.get_ref().1.alpn_protocol() == Some(ACME_TLS_1) {
        let _ = tls.shutdown().await;
        return;
    }
    // The name that the client asked for, which a key's signed mint must
    // name (T-448).
    let sni = tls.get_ref().1.server_name().map(str::to_string);
    // The exporter of this handshake, which a delegated credential binds
    // (T-765): the same bytes at both ends.
    let exporter = podssh_ws::delegated::server_exporter(tls.get_ref().1);
    // HTTP/2, where the client chose it by ALPN (T-321): each stream is a
    // request of its own to the routes below.
    if tls.get_ref().1.alpn_protocol() == Some(super::http2::H2) {
        return super::http2::serve(tls, cfg, sni, Some(peer), exporter).await;
    }
    // The TCP peer, by whom the brake of mints and pairs counts (T-454): no
    // header of a client's.
    super::serve_tls(tls, cfg, sni, Some(peer), exporter).await;
}
