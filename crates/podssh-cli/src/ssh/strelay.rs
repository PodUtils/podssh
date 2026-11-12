//! Syncthing's relay road of `podssh ssh node://NAME` (T-571), a last
//! fallback of the operator's ruling Q78, after HyperDHT's road: a request
//! with a fresh certificate to the relay of the pair (`crate::strelay`) for
//! the node's device ID, which both ends make of the pair's secret, and the
//! session's own connection. So it needs the pair here; never with --no-e2e,
//! as the end-to-end channel checks the node's key above it. Before its
//! first link, a line names the pool's relay as the third party.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct StRoads {
    name: String,
    token: String,
    relay: crate::strelay::Relay,
    public: bool,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl StRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off or not in this build, or with --no-e2e (`off`).
    pub(crate) fn new(part: Option<&OperatorPart>, off: bool, log: &Arc<Log>, shown: &str) -> Option<StRoads> {
        if off {
            return None;
        }
        let part = part?;
        let (relay, public) = crate::strelay::relay_for(&part.name)?;
        Some(StRoads {
            name: part.name.clone(),
            token: part.connect_token().to_string(),
            relay,
            public,
            said: AtomicBool::new(false),
            log: log.clone(),
            shown: shown.to_string(),
        })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Syncthing);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if self.public && !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::strelay::third_party_line(self.relay.at)));
        }
        self.linked().await
    }

    #[cfg(feature = "strelay")]
    async fn linked(&self) -> Result<Road, String> {
        use podssh_relay::strelay::pair;
        self.log.verbose(&format!("{}: Syncthing's relay road through {}", self.shown, self.relay.at));
        let node = pair::node_identity(&self.name, &self.token).id();
        let relay = crate::strelay::library(self.relay);
        let stream = pair::link(&crate::strelay::dial(), &relay, node, LIMIT)
            .await
            .map_err(|e| format!("Syncthing's relay {}: {e}", self.relay.at))?;
        Ok(Road::Syncthing(Box::new(stream)))
    }

    #[cfg(not(feature = "strelay"))]
    async fn linked(&self) -> Result<Road, String> {
        // `relay_for` gives no road without the feature.
        let _ = (&self.name, &self.token);
        Err("this build has no road of Syncthing's relays".into())
    }
}

/// How long the client waits for its session.
#[cfg(feature = "strelay")]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
