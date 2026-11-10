//! The node's end of the Pinggy road: each visitor that Pinggy sends down
//! the node's SSH session (a `forwarded-tcpip` channel, as the caller's SSH
//! client takes it) still holds the visitor's TLS, from its ClientHello on;
//! the node ends it with its own certificate ([`super::tls`] says why one of
//! its own, and how the client pins its key), then serves the resumable layer's far end with the node's
//! keeper, which another road may share, so that a session resumes on either
//! and moves from one tunnel to the next. A new session reaches its target
//! only after its handshake, and the end-to-end channel above it.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use podssh_ws::tls_server::{self, Served, TlsAcceptor};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::Say;
use crate::opentunnel::dial::BoxIo;
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::{far, Settings};

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// The bound of a visitor's TLS handshake.
pub const TLS_LIMIT: Duration = Duration::from_secs(20);

/// A visitor, as the node's SSH session hands it over: its stream, and
/// where Pinggy says it came from, for the lines.
pub struct Visitor {
    pub stream: BoxIo,
    pub peer: String,
}

/// The acceptor of the node's TLS: the certificate and the key of `served`,
/// with no ALPN, as the client offers none.
pub fn acceptor(served: Arc<Served>) -> Result<TlsAcceptor, String> {
    tls_server::acceptor_for(served, &[]).map_err(|why| format!("the node's TLS: {why}"))
}

/// The certificate and the key that the node presents, from PEM: the node
/// keeps the key, whose pin clients hold, and makes the certificate of it
/// at each start.
pub fn served(cert_pem: &str, key_pem: &str) -> Result<Arc<Served>, String> {
    let pair = tls_server::certified(cert_pem.as_bytes(), key_pem.as_bytes())
        .map_err(|why| format!("the node's certificate: {why}"))?;
    Ok(Served::new(Some(pair)))
}

/// Start the sweep of `keeper`'s lost sessions; it ends with the keeper.
pub fn sweep<A>(keeper: &Arc<Keeper<A>>)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let keeper = Arc::downgrade(keeper);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_EVERY).await;
            let Some(keeper) = keeper.upgrade() else { return };
            keeper.expire().await;
        }
    });
}

/// Serve each visitor of `visitors` until its sender ends (the tunnel's SSH
/// session ended): its TLS with `acceptor`, then the layer's far end with
/// `keeper`, whose sessions outlive this tunnel for the next one.
pub async fn serve<A, O, F>(
    mut visitors: mpsc::Receiver<Visitor>,
    acceptor: TlsAcceptor,
    settings: Settings,
    budget: usize,
    open: O,
    keeper: Arc<Keeper<A>>,
    say: Say,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    while let Some(visitor) = visitors.recv().await {
        let (acceptor, keeper, open, say) = (acceptor.clone(), keeper.clone(), open.clone(), say.clone());
        tokio::spawn(async move {
            let Visitor { stream, peer } = visitor;
            let tls = match tokio::time::timeout(TLS_LIMIT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => return say(format!("a visitor from {peer}: TLS failed: {e}")),
                Err(_) => return say(format!("a visitor from {peer}: no TLS within {} s", TLS_LIMIT.as_secs())),
            };
            far::serve(tls, Role::NODE, settings, &keeper, budget, open).await;
        });
    }
}
