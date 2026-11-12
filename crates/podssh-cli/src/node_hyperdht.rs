//! HyperDHT's road beside a pair's road at the node (T-736), where UDP
//! passes, after Yggdrasil's road: the node joins HyperDHT under the key that
//! the pair's connect token makes (`podssh_relay::hyperdht`), announces its
//! topic, and serves each session's stream with the resumable layer's far end
//! under the node's keeper, as the bore road's visitors are served: the
//! end-to-end channel runs above it. Where no bootstrap node answers, UDP
//! does not pass, and the node says so and serves its other roads. With no
//! pair, or the road off, or a build without the feature, the pair's road
//! runs alone.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::pair::Pair;
use podssh_relay::session::keep::Keeper;
use tokio::io::DuplexStream;

use crate::node_expiry::Say;

/// The node's road: the pair's name and token, the bootstrap, and its lines.
#[cfg_attr(not(feature = "hyperdht"), allow(dead_code))]
pub(crate) struct Road {
    name: String,
    token: String,
    bootstrap: Vec<String>,
    say: Say,
}

/// The road beside the pair `pair`, when the road is on in this build; its
/// line, with the third party's words when the DHT is the public one.
pub(crate) fn beside(pair: Option<&Pair>, say: Say) -> Option<Road> {
    let pair = pair?;
    let (bootstrap, public) = crate::hyperdht::bootstrap()?;
    let why = if public { "where UDP passes, by the operator's rulings Q77 and Q82" } else { "the DHT that you named" };
    say(format!("and through HyperDHT, {why} ({}=no turns it off)", crate::hyperdht::ENV));
    if public {
        say(crate::hyperdht::third_party_line().replace("carries this session", "carries the sessions of this road"));
    }
    Some(Road { name: pair.name.clone(), token: pair.connect_token().to_string(), bootstrap, say })
}

/// `pair_road` with HyperDHT's road `road` beside it, under `keeper`, until
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

#[cfg(feature = "hyperdht")]
async fn serve<O, F>(road: Road, open: O, keeper: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    use podssh_relay::hyperdht::{join, node_keys};
    use podssh_relay::pinggy::far::{self, Visitor};
    let say = road.say.clone();
    let lines: podssh_relay::hyperdht::Say = Arc::new(move |line| say(format!("HyperDHT's road: {line}")));
    let end = match join(&road.bootstrap, Some(node_keys(&road.name, &road.token))).await {
        Ok(end) => end,
        Err(e) => {
            lines(format!("{e}; the node serves its other roads"));
            return std::future::pending().await;
        }
    };
    let (streams, mut came) = tokio::sync::mpsc::channel(64);
    let (queue, visitors) = tokio::sync::mpsc::channel::<Visitor>(64);
    tokio::spawn(end.serve(streams, lines));
    tokio::spawn(async move {
        while let Some(stream) = came.recv().await {
            if queue.send(Visitor { stream: Box::new(stream), peer: "HyperDHT".into() }).await.is_err() {
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

#[cfg(not(feature = "hyperdht"))]
async fn serve<O, F>(_: Road, _: O, _: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    // `beside` gives no road without the feature.
    std::future::pending().await
}
