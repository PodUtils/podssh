//! ZeroTier's road beside a pair's road at the node (T-733), the last
//! fallback of Q78 after croc's: the node holds a member of the pair's own
//! ad-hoc network at the identity that both ends make of the pair's secret
//! (`podssh_zerotier::pair`), through ZeroTier Inc.'s TCP relay, and serves
//! each connection to its port with the resumable layer's far end under the
//! node's keeper, as the bore road's visitors are served: the end-to-end
//! channel runs above it. With no pair, or the road off, or a build without
//! the feature, the pair's road runs alone.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::pair::Pair;
use podssh_relay::session::keep::Keeper;
use tokio::io::DuplexStream;

use crate::node_expiry::Say;

/// The node's road: the pair's name and token, the relay, and its lines.
#[cfg_attr(not(feature = "zerotier"), allow(dead_code))]
pub(crate) struct Road {
    name: String,
    token: String,
    relay: std::net::SocketAddr,
    say: Say,
}

/// The road beside the pair `pair`, when the road is on in this build; its
/// line, with the third party's words when the relay is `pod-services`'.
pub(crate) fn beside(pair: Option<&Pair>, say: Say) -> Option<Road> {
    let (pair, (relay, public)) = (pair?, crate::zerotier::relay()?);
    let why = if public { "the last fallback of the operator's ruling Q78" } else { "the relay that you named" };
    say(format!("and through ZeroTier's TCP relay {relay}, {why} ({}=no turns it off)", crate::zerotier::ENV));
    if public {
        say(crate::zerotier::third_party_line(relay).replace("carry this session", "carry the sessions of this road"));
    }
    Some(Road { name: pair.name.clone(), token: pair.connect_token().to_string(), relay, say })
}

/// `pair_road` with ZeroTier's road `road` beside it, under `keeper`, until
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

#[cfg(feature = "zerotier")]
async fn serve<O, F>(road: Road, open: O, keeper: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    use podssh_relay::pinggy::far::{self, Visitor};
    let pair_road = match crate::zerotier::pair_road(&road.name, &road.token).await {
        Ok(pair_road) => pair_road,
        Err(why) => {
            (road.say)(format!("ZeroTier's road: {why}"));
            return std::future::pending().await;
        }
    };
    let say = road.say.clone();
    let lines: podssh_zerotier::road::Say = Arc::new(move |line| say(line));
    let (streams, mut came) = tokio::sync::mpsc::channel(64);
    let (queue, visitors) = tokio::sync::mpsc::channel::<Visitor>(64);
    tokio::spawn(podssh_zerotier::road::serve(pair_road, crate::zerotier::dial(road.relay), streams, lines));
    tokio::spawn(async move {
        while let Some((stream, peer)) = came.recv().await {
            if queue.send(Visitor { stream: Box::new(stream), peer }).await.is_err() {
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

#[cfg(not(feature = "zerotier"))]
async fn serve<O, F>(_: Road, _: O, _: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    // `beside` gives no road without the feature.
    std::future::pending().await
}
