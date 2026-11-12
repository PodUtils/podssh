//! The smee.io road beside a pair's road at the node (T-741), a last fallback
//! of Q78 after the onion road: the node reads its door's channel at
//! smee.io's server (`crate::smee_road`), whose name comes from the pair's
//! connect token, and serves each link that a client's hello asks for with
//! the resumable layer's far end under the node's keeper, as the Piping
//! Server road's links are served: the end-to-end channel runs above it.
//! With no pair, or the road off, the pair's road runs alone.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::pair::Pair;
use podssh_relay::session::keep::Keeper;
use podssh_relay::smee::far;
use tokio::io::DuplexStream;

use crate::node_expiry::Say;

/// The node's road: the server's node of the pair.
pub(crate) struct Road {
    node: far::Node,
}

/// The road beside the pair `pair`, when it is on; its line, with the third
/// party's words when the server is the listed one.
pub(crate) fn beside(pair: Option<&Pair>, trust: &podssh_ws::Trust, say: Say) -> Option<Road> {
    let pair = pair?;
    let (server, public) = crate::smee_road::server()?;
    let why = if public { "the last fallback of the operator's ruling Q78" } else { "the server that you named" };
    say(format!("and through smee.io's server {server}, {why} ({}=no turns it off)", crate::smee_road::ENV));
    if public {
        let line = crate::smee_road::third_party_line(&server);
        say(line.replace("carries this session", "carries the sessions of this road"));
    }
    let lines: podssh_relay::smee::Say = {
        let say = say.clone();
        Arc::new(move |line| say(format!("the smee.io road: {line}")))
    };
    // A listed server is a public one, checked with the host's trust; one
    // that the user names, with the trust of the pair's run, as the Piping
    // Server road's.
    let trust = if public { crate::pairs::trust(None) } else { trust.clone() };
    Some(Road { node: crate::smee_road::node(&pair.name, pair.connect_token(), &server, &trust, lines) })
}

/// `pair_road` with the smee.io road `road` beside it, under `keeper`, until
/// the pair's road ends: its end is the node's.
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
    let served = Box::pin(far::serve_kept(road.node, settings, budget, open, keeper));
    tokio::select! {
        out = &mut pair_road => out,
        // The road waits for ever; the pair's road ends the node.
        () = served => pair_road.await,
    }
}
