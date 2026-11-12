//! croc's relay road of a pair (T-694): croc's public relays behind
//! croc-web's WebSocket bridge, a last fallback of the operator's ruling
//! Q78, as a carrier between a node and its operators that needs no relay
//! of the operator's. The bridge is the service `croc` of `pod-services`;
//! `PODSSH_CROC=no` or `PODSSH_LAST_RESORT=no` turns it off, and a URL names
//! a bridge of the user's own (croc-web before `croc relay`). The rooms and
//! the proof of the pair come from the pair's connect token, which both ends
//! hold, so a node that has a pair waits in a room there too, with one
//! keeper for each road, so that a session resumes on any; and `podssh ssh
//! node://` races it after the transit relay, only when each road before it
//! failed. Never with `--plain` or `--no-e2e`: the relay is a stranger's, so
//! the layer and the end-to-end channel run above it.

use std::future::Future;
use std::sync::Arc;

use podssh_relay::croc::{self, far, Bridge, Dialer, Rooms, Setting};
use podssh_relay::pair::{self, OperatorPart, Pair};
use podssh_relay::reverse;
use podssh_relay::session::keep::Keeper;
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};
use tokio::io::DuplexStream;

use crate::node_expiry::Say;
use crate::relay_settings::Refusal;

/// `PODSSH_CROC` and `PODSSH_LAST_RESORT`, read: a value of `PODSSH_CROC`
/// that is none of its forms is a setting that cannot be used (78).
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let value = std::env::var(croc::ENV).ok();
    let last = std::env::var(croc::LAST_RESORT).ok();
    croc::setting(value.as_deref(), last.as_deref()).map_err(Refusal::config)
}

/// The variable, checked before anything connects.
pub(crate) fn check() -> Result<(), Refusal> {
    setting().map(|_| ())
}

/// The bridge of the road, when the road is on.
pub(crate) fn bridge() -> Option<Bridge> {
    match setting() {
        Ok(Setting::On(bridge)) => Some(bridge),
        Ok(Setting::Off(_)) | Err(_) => None,
    }
}

/// The pair's rooms now: those of `pair` until it expires, then those of a
/// later pair stored under `label` since, which the node goes on with at
/// the expiry (T-395), as its operators do.
fn rooms_now(label: &str, pair: &Pair, stored: bool) -> far::RoomsNow {
    let (label, first, ends_ms) =
        (label.to_string(), Rooms::of_pair(&pair.name, pair.connect_token()), pair.expires_ms);
    Arc::new(move || {
        let now = crate::pairs::now_ms();
        if !stored || now < ends_ms {
            return first.clone();
        }
        let later = pair::load(&label).ok().flatten();
        match crate::node_expiry::next_pair(later, ends_ms, now) {
            Some(next) => Rooms::of_pair(&next.name, next.connect_token()),
            None => first.clone(),
        }
    })
}

/// The trust of the bridge: the public one takes the host's trust
/// (`SSL_CERT_FILE`, `CaFile`, else the default stores), never the pair
/// relay's `--ca-file`, which names that relay's own CA; a bridge that
/// `PODSSH_CROC` names takes the pair's, as it may be the user's own, under
/// the same CA.
fn trust_for(bridge: &Bridge, pair: &Trust, host: Trust) -> Trust {
    if bridge.public {
        host
    } else {
        pair.clone()
    }
}

/// The node of the road for the pair `pair`, through `bridge`, and the line
/// that says so, with the third party's words when the bridge is public.
pub(crate) fn road(label: &str, pair: &Pair, stored: bool, trust: &Trust, bridge: Bridge, say: Say) -> far::Node {
    let why =
        if bridge.public { "the last fallback of the operator's ruling Q78" } else { "the bridge that you named" };
    say(format!("and through croc's relay behind {}, {why} ({}=no turns it off)", bridge.url.shown(), croc::ENV));
    if bridge.public {
        say(croc::third_party_line(&bridge.url.shown())
            .replace("carries this session", "carries the sessions of this road"));
    }
    let rooms = rooms_now(label, pair, stored);
    let trust = trust_for(&bridge, trust, crate::pairs::trust(None));
    far::Node { bridge, rooms, trust, proxy: ProxyChoice::FromEnvironment, say }
}

/// The last roads of a pair at the node: croc's relay, then ZeroTier's
/// network (T-733), then a Tox relay (T-734), then Yggdrasil's network
/// (T-735), then HyperDHT where UDP passes (T-736), then a relay of
/// Syncthing's (T-571), then an onion service of the Tor network (T-578),
/// each where it is on.
pub(crate) struct Beside {
    pub croc: Option<far::Node>,
    pub zerotier: Option<crate::node_zerotier::Road>,
    pub tox: Option<crate::node_tox::Road>,
    pub ygg: Option<crate::node_ygg::Road>,
    pub dht: Option<crate::node_hyperdht::Road>,
    pub syncthing: Option<crate::node_strelay::Road>,
    pub onion: Option<crate::node_onion::Road>,
}

/// The roads beside another node road's pair (`--derp`, the Piping Server
/// road), the last of its roads: none with no pair there, or each road off.
pub(crate) fn beside(label: &str, pair: Option<(&Pair, bool)>, trust: &Trust, say: Say) -> Beside {
    let croc = pair.and_then(|(pair, stored)| Some(road(label, pair, stored, trust, bridge()?, say.clone())));
    let zerotier = crate::node_zerotier::beside(pair.map(|(pair, _)| pair), say.clone());
    let tox = crate::node_tox::beside(pair.map(|(pair, _)| pair), say.clone());
    let ygg = crate::node_ygg::beside(pair.map(|(pair, _)| pair), say.clone());
    let dht = crate::node_hyperdht::beside(pair.map(|(pair, _)| pair), say.clone());
    let syncthing = crate::node_strelay::beside(pair.map(|(pair, _)| pair), say.clone());
    let onion = crate::node_onion::beside(label, pair.map(|(pair, _)| pair), say);
    Beside { croc, zerotier, tox, ygg, dht, syncthing, onion }
}

/// `pair_road` with croc's relay road and ZeroTier's of `beside` beside it,
/// under `keeper`, until the pair's road ends: its end is the node's, as the
/// roads' rooms and network are the pair's. With none, the pair's road alone.
pub(crate) async fn alongside<P, O, F>(
    pair_road: P,
    beside: Beside,
    open: O,
    keeper: Arc<Keeper<DuplexStream>>,
) -> P::Output
where
    P: Future + Unpin,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<DuplexStream, String>> + Send + 'static,
{
    let onion = crate::node_onion::alongside(pair_road, beside.onion, open.clone(), keeper.clone());
    let syncthing = crate::node_strelay::alongside(Box::pin(onion), beside.syncthing, open.clone(), keeper.clone());
    let dht = crate::node_hyperdht::alongside(Box::pin(syncthing), beside.dht, open.clone(), keeper.clone());
    let ygg = crate::node_ygg::alongside(Box::pin(dht), beside.ygg, open.clone(), keeper.clone());
    let tox = crate::node_tox::alongside(Box::pin(ygg), beside.tox, open.clone(), keeper.clone());
    let zerotier = crate::node_zerotier::alongside(Box::pin(tox), beside.zerotier, open.clone(), keeper.clone());
    let mut pair_road = Box::pin(zerotier);
    let Some(road) = beside.croc else { return pair_road.await };
    let (settings, budget) = (crate::layered::settings(), reverse::layered::NODE_BUDGET);
    let croc_road = Box::pin(far::serve_kept(road, settings, budget, open, keeper));
    tokio::select! {
        out = &mut pair_road => out,
        // The road waits for ever; the pair's road ends the node.
        () = croc_road => pair_road.await,
    }
}

/// The client's dialer of the pair whose operator's part is `part`; its
/// lines go to `-v` under `shown`. `None` with the road off.
pub(crate) fn dialer(part: &OperatorPart, trust: &Trust, log: &Arc<Log>, shown: &str) -> Option<Dialer> {
    let bridge = bridge()?;
    let say: croc::Say = {
        let (log, shown) = (log.clone(), shown.to_string());
        Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
    };
    let rooms = Rooms::of_pair(&part.name, part.connect_token());
    let trust = trust_for(&bridge, trust, crate::pairs::trust(None));
    Some(Dialer::new(bridge, rooms, trust, ProxyChoice::FromEnvironment, say))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_public_bridge_takes_the_host_s_trust_and_a_named_one_the_pair_s() {
        let pair = Trust::File("/the/pair/relay/ca.pem".into());
        let url = podssh_ws::url::WsUrl::parse("wss://bridge.example.test/ws").unwrap();
        let public = Bridge { public: true, ..Bridge::named(url.clone()) };
        assert!(matches!(trust_for(&public, &pair, Trust::Default), Trust::Default));
        let own = Bridge::named(url);
        assert!(
            matches!(trust_for(&own, &pair, Trust::Default), Trust::File(ref f) if f == std::path::Path::new("/the/pair/relay/ca.pem"))
        );
    }
}
