//! Yggdrasil's road beside a pair's road at the node (T-735), a last
//! fallback of Q78 after the Tox road: the node joins Yggdrasil's network
//! through one public peer under the key that the pair's connect token makes
//! (`podssh_relay::ygg::pair`), and serves each session's stream with the
//! resumable layer's far end under the node's keeper, as the bore road's
//! visitors are served: the end-to-end channel runs above it. With no pair,
//! or the road off, or a build without the feature, the pair's road runs
//! alone.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::pair::Pair;
use podssh_relay::session::keep::Keeper;
use tokio::io::DuplexStream;

use crate::node_expiry::Say;

/// The node's road: the pair's name and token, the peer, and its lines.
#[cfg_attr(not(feature = "yggdrasil"), allow(dead_code))]
pub(crate) struct Road {
    name: String,
    token: String,
    peer: String,
    say: Say,
}

/// The road beside the pair `pair`, when the road is on in this build; its
/// line, with the third party's words when the peer is `pod-services`'.
pub(crate) fn beside(pair: Option<&Pair>, say: Say) -> Option<Road> {
    let pair = pair?;
    let (peer, public) = crate::yggdrasil::peer_for(&pair.name)?;
    let why = if public { "the last fallback of the operator's ruling Q78" } else { "the peer that you named" };
    say(format!(
        "and through Yggdrasil's network by the peer {peer}, {why} ({}=no turns it off)",
        crate::yggdrasil::ENV
    ));
    if public {
        say(crate::yggdrasil::third_party_line(&peer)
            .replace("carries this session", "carries the sessions of this road"));
    }
    Some(Road { name: pair.name.clone(), token: pair.connect_token().to_string(), peer, say })
}

/// `pair_road` with Yggdrasil's road `road` beside it, under `keeper`, until
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
    let served = Box::pin(serve(road, open, keeper));
    tokio::select! {
        out = &mut pair_road => out,
        // The road waits for ever; the pair's road ends the node.
        () = served => pair_road.await,
    }
}

#[cfg(feature = "yggdrasil")]
async fn serve<O, F>(road: Road, open: O, keeper: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    use podssh_relay::pinggy::far::{self, Visitor};
    use podssh_relay::ygg::pair::{node_secret, Ends, Serve};
    let say = road.say.clone();
    let lines: podssh_relay::ygg::router::Say = Arc::new(move |line| say(format!("Yggdrasil's road: {line}")));
    let router = match crate::yggdrasil::router(node_secret(&road.name, &road.token), &road.peer, lines) {
        Ok(router) => router,
        Err(e) => {
            (road.say)(format!("Yggdrasil's road: {e}"));
            return std::future::pending().await;
        }
    };
    (road.say)("Yggdrasil's road: waits for its operators in Yggdrasil's network".into());
    let (streams, mut came) = tokio::sync::mpsc::channel(64);
    let (queue, visitors) = tokio::sync::mpsc::channel::<Visitor>(64);
    Ends::start(router, Some(Serve { token: road.token.clone(), visitors: streams }));
    let peer = format!("Yggdrasil's network by {}", road.peer);
    tokio::spawn(async move {
        while let Some(stream) = came.recv().await {
            if queue.send(Visitor { stream: Box::new(stream), peer: peer.clone() }).await.is_err() {
                return;
            }
        }
    });
    // The sweep ends with the keeper, when the node and its sessions end.
    far::sweep(&keeper);
    let (settings, budget) = (crate::layered::settings(), podssh_relay::reverse::layered::NODE_BUDGET);
    let say: podssh_relay::pinggy::Say = road.say.clone();
    far::serve(visitors, None, settings, budget, open, keeper, say).await;
    std::future::pending().await
}

#[cfg(not(feature = "yggdrasil"))]
async fn serve<O, F>(_: Road, _: O, _: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    // `beside` gives no road without the feature.
    std::future::pending().await
}
