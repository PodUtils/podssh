//! The file hosts' road beside a pair's road at the node (T-738), the last
//! of the last fallbacks of Q78, after the smee.io road: the node polls its
//! door at the public MQTT broker of the road (`crate::filehost_road`),
//! whose topic comes from the pair's connect token, and serves each link
//! that a client's hello asks for with the resumable layer's far end under
//! the node's keeper, as the smee.io road's links are served: the
//! end-to-end channel runs above it. With no pair, the road off, or a build
//! without the feature `filehost`, the pair's road runs alone.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::filehost::{self, Carrier};
use podssh_relay::pair::Pair;
use podssh_relay::session::keep::Keeper;
use tokio::io::DuplexStream;

use crate::node_expiry::Say;

/// The node's road: the carrier of the pair.
pub(crate) struct Road {
    carrier: Arc<Carrier>,
}

/// The road beside the pair `pair`, when it is on in this build; its line,
/// and the board's third party's line. Each host's line comes before its
/// first upload.
pub(crate) fn beside(pair: Option<&Pair>, say: Say) -> Option<Road> {
    let pair = pair?;
    let ids = crate::filehost_road::on()?;
    let lines: filehost::Say = {
        let say = say.clone();
        Arc::new(move |line| say(format!("the file-host road: {line}")))
    };
    match crate::filehost_road::built(&ids, &pair.name, pair.connect_token(), lines) {
        Ok(built) => {
            say(format!(
                "and through the public file hosts {}, with notes at {}, the last of the last fallbacks of the \
                 operator's ruling Q78; slow, for output and files ({}=no turns it off)",
                built.hosts.join(", "),
                built.board,
                crate::filehost_road::ENV
            ));
            say(crate::filehost_road::board_line(&built.board));
            Some(Road { carrier: built.carrier })
        }
        Err(why) => {
            say(format!("no file-host road: {why}"));
            None
        }
    }
}

/// `pair_road` with the file hosts' road `road` beside it, under `keeper`,
/// until the pair's road ends: its end is the node's.
pub(crate) async fn alongside<P, O, F>(
    mut pair_road: P,
    road: Option<Road>,
    open: O,
    keeper: Arc<Keeper<DuplexStream>>,
) -> P::Output
where
    P: Future + Unpin,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    let Some(road) = road else { return pair_road.await };
    let (settings, budget) = (crate::layered::settings(), podssh_relay::reverse::layered::NODE_BUDGET);
    let served = Box::pin(filehost::road::serve_kept(road.carrier, settings, budget, open, keeper));
    tokio::select! {
        out = &mut pair_road => out,
        // The road waits for ever; the pair's road ends the node.
        () = served => pair_road.await,
    }
}
