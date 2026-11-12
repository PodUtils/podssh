//! The onion road beside a pair's road at the node (T-578), the last fallback
//! of the operator's ruling Q78, after Syncthing's relay road: the node
//! bootstraps Arti through the Tor road, in directories of its own under its
//! label, launches an onion service whose key Arti keeps there, so that its
//! address stays from one start to the next, and lists the pair's key of
//! restricted discovery (`crate::onion`), so that only the pair's operators
//! can find it. Each stream to the service's virtual port is served with the
//! resumable layer's far end under the node's keeper, as HyperDHT's road
//! serves its streams; the end-to-end channel runs above it. Every circuit
//! of the service is a connection out to a Tor relay: the node binds nothing.
//! Its line says the address, which a node of this host also keeps in the
//! cache. With no pair, or the road off, or a build without the feature
//! `tor`, the pair's road runs alone.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::pair::Pair;
use podssh_relay::session::keep::Keeper;
use tokio::io::DuplexStream;

use crate::node_expiry::Say;

/// The node's road: its label, the pair's key of restricted discovery, and
/// its lines.
#[cfg_attr(not(feature = "tor"), allow(dead_code))]
pub(crate) struct Road {
    label: String,
    /// The public half of the pair's key, as Arti lists it.
    allowed: String,
    say: Say,
}

/// The road beside the pair `pair` of the node `label`, when the road is on
/// in this build; its line, with the third party's words.
pub(crate) fn beside(label: &str, pair: Option<&Pair>, say: Say) -> Option<Road> {
    let pair = pair?;
    if !crate::onion::on() {
        return None;
    }
    say(format!(
        "and as an onion service of the Tor network, the last fallback of the operator's ruling Q78 ({}=no turns \
         it off)",
        crate::onion::ENV
    ));
    let line = crate::onion::third_party_line(crate::onion::network_named().as_deref());
    say(line.replace("carries this session", "carries the sessions of this road"));
    Some(Road { label: label.to_string(), allowed: allowed(pair), say })
}

/// The public half of the pair's key of restricted discovery.
#[cfg(feature = "tor")]
fn allowed(pair: &Pair) -> String {
    let secret = crate::onion::discovery_secret(&pair.name, pair.connect_token());
    podssh_tor::Discovery::from_secret(secret).public()
}

#[cfg(not(feature = "tor"))]
fn allowed(_: &Pair) -> String {
    // `beside` gives no road without the feature.
    String::new()
}

/// `pair_road` with the onion road `road` beside it, under `keeper`, until
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

/// How long the node waits for its descriptor to be published before it
/// says so; the service goes on trying.
#[cfg(feature = "tor")]
const PUBLISH_WAIT: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(feature = "tor")]
async fn serve<O, F>(road: Road, open: O, keeper: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    use podssh_relay::pinggy::far::{self, Visitor};
    let say = road.say.clone();
    let line = move |words: String| say(format!("the onion road: {words}"));
    let (told, more) = (line.clone(), line.clone());
    let info = move |words: &str| told(words.to_string());
    let verbose = move |words: &str| more(words.to_string());
    // The node's trust is the host's: a bridge's transport checks its TLS
    // with it, as a client's Tor road does.
    let trust = crate::pairs::trust(None);
    let shown = format!("the onion service of {}", road.label);
    let booted = crate::ssh::cloud::tor::road::bootstrap_at(&shown, Some(&road.label), &trust, &info, &verbose);
    let tor = match booted.await {
        Ok((tor, how)) => {
            line(format!("Tor bootstrapped, {how}"));
            tor
        }
        Err((why, _)) => {
            line(format!("{why}; the node serves its other roads"));
            return std::future::pending().await;
        }
    };
    let options = podssh_tor::ServiceOptions {
        nickname: crate::onion::NICKNAME.to_string(),
        port: crate::onion::VIRTUAL_PORT,
        allowed: vec![road.allowed.clone()],
    };
    let mut onion = match tor.serve_onion(&options) {
        Ok(onion) => onion,
        Err(failure) => {
            line(format!("{failure}; the node serves its other roads"));
            return std::future::pending().await;
        }
    };
    let address = onion.address().to_string();
    crate::onion::keep(&road.label, &address);
    line(format!(
        "its address is {address}, which only the pair's operators can find; {}={address} names it to a client \
         on another host",
        crate::onion::ENV
    ));
    match onion.published(PUBLISH_WAIT).await {
        Ok(()) => line("its descriptor is published".to_string()),
        Err(failure) => line(format!("{failure}; it goes on trying")),
    }
    let (queue, visitors) = tokio::sync::mpsc::channel::<Visitor>(64);
    tokio::spawn(async move {
        while let Some(stream) = onion.accept().await {
            let visitor = Visitor { stream: Box::new(stream), peer: "the onion service".into() };
            if queue.send(visitor).await.is_err() {
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

#[cfg(not(feature = "tor"))]
async fn serve<O, F>(_: Road, _: O, _: Arc<Keeper<DuplexStream>>)
where
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    // `beside` gives no road without the feature.
    std::future::pending().await
}
