//! The road's two ends under the resumable layer, as the other roads of a
//! pair are: a client's link ([`dial`], whose link the race of
//! `podssh ssh node://NAME` takes like any other road's), and a node that
//! waits at its door for ever and serves each link that a hello opens with
//! the layer's far end, its sessions kept by one keeper across links and
//! roads ([`serve_kept`]). The end-to-end channel runs above the layer.
//!
//! Each link's requests and the door's polls take turns at the carrier's
//! gate, so a node holds one connection of the road at a time however many
//! links run.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

use super::carrier::Carrier;
use super::link::{self, Link};
use crate::session::far as layer;
use crate::session::keep::Keeper;
use crate::session::record::Role;
use crate::session::Settings;

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// The pause after a door that failed in a way that a poll does not tell:
/// the carrier's own polls keep their pace within each wait.
const AGAIN: Duration = Duration::from_secs(5);

/// A client's new link to the node of `carrier`'s pair: a hello at the
/// node's door, then the two ways as the pieces come.
pub async fn dial(carrier: &Arc<Carrier>) -> Result<Link, String> {
    link::dial(carrier.clone()).await
}

/// Serve the sessions of each link of `carrier`'s door, for ever, with
/// `keeper`, which another road's far end may share, so that a session
/// resumes on either road; a new session's target comes from `open`, and
/// the replay buffers of all sessions stay within `budget` bytes.
pub async fn serve_kept<A, O, F>(
    carrier: Arc<Carrier>,
    settings: Settings,
    budget: usize,
    open: O,
    keeper: Arc<Keeper<A>>,
) where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    // The sweep ends with the keeper, when the node and its sessions end.
    {
        let keeper = Arc::downgrade(&keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
    loop {
        // A door with no hello within its wait is asked again at once: the
        // carrier paces its polls itself.
        match link::accept(carrier.clone()).await {
            Ok(link) => {
                let (keeper, open) = (keeper.clone(), open.clone());
                tokio::spawn(async move { layer::serve(link, Role::NODE, settings, &keeper, budget, open).await });
            }
            Err(why) if why.starts_with("no client's hello") => {}
            Err(_) => tokio::time::sleep(AGAIN).await,
        }
    }
}
