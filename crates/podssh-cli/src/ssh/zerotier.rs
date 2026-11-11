//! ZeroTier's road of `podssh ssh node://NAME` (T-733), a last fallback of
//! the operator's ruling Q78, after croc's relay: a member of the pair's own
//! ad-hoc network, with an identity made for the run, through ZeroTier
//! Inc.'s roots and TCP relay (`crate::zerotier`), to the node's address,
//! which both ends make of the pair's secret. So it needs the pair here;
//! never with --no-e2e, as the end-to-end channel checks the node's key
//! above it. Before its first link, a line names ZeroTier Inc. as the third
//! party that carries the session.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct ZeroTierRoads {
    name: String,
    token: String,
    relay: std::net::SocketAddr,
    public: bool,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    #[cfg(feature = "zerotier")]
    road: tokio::sync::OnceCell<podssh_zerotier::pair::PairRoad>,
    log: Arc<Log>,
    shown: String,
}

impl ZeroTierRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off or not in this build, or with --no-e2e (`off`).
    pub(crate) fn new(part: Option<&OperatorPart>, off: bool, log: &Arc<Log>, shown: &str) -> Option<ZeroTierRoads> {
        if off {
            return None;
        }
        let (part, (relay, public)) = (part?, crate::zerotier::relay()?);
        Some(ZeroTierRoads {
            name: part.name.clone(),
            token: part.connect_token().to_string(),
            relay,
            public,
            said: AtomicBool::new(false),
            #[cfg(feature = "zerotier")]
            road: tokio::sync::OnceCell::new(),
            log: log.clone(),
            shown: shown.to_string(),
        })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::ZeroTier);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if self.public && !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::zerotier::third_party_line(self.relay)));
        }
        self.linked().await
    }

    #[cfg(feature = "zerotier")]
    async fn linked(&self) -> Result<Road, String> {
        use podssh_zerotier::road;
        let made = self.road.get_or_try_init(|| crate::zerotier::pair_road(&self.name, &self.token)).await?;
        let to = road::node_at(made);
        self.log.verbose(&format!(
            "{}: ZeroTier's road to [{}]:{} through {}",
            self.shown,
            to.ip(),
            to.port(),
            self.relay
        ));
        let link = road::link(made, &crate::zerotier::dial(self.relay), road::CONNECT_LIMIT).await?;
        Ok(Road::ZeroTier(Box::new(link)))
    }

    #[cfg(not(feature = "zerotier"))]
    async fn linked(&self) -> Result<Road, String> {
        // `relay()` gives no road without the feature.
        let _ = (&self.name, &self.token);
        Err("this build has no ZeroTier road".into())
    }
}
