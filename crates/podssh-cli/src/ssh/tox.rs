//! Tox's relay road of `podssh ssh node://NAME` (T-734), a last fallback of
//! the operator's ruling Q78, after ZeroTier's: a connection with a fresh
//! key to the relay of the pair (`crate::tox`), a hello to the node's key,
//! which both ends make of the pair's secret, and a routed connection of
//! the session's own. So it needs the pair here; never with --no-e2e, as the
//! end-to-end channel checks the node's key above it. Before its first link,
//! a line names the Tox project's relay as the third party.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct ToxRoads {
    name: String,
    token: String,
    relay: crate::tox::Relay,
    public: bool,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl ToxRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off or not in this build, or with --no-e2e (`off`).
    pub(crate) fn new(part: Option<&OperatorPart>, off: bool, log: &Arc<Log>, shown: &str) -> Option<ToxRoads> {
        if off {
            return None;
        }
        let part = part?;
        let (relay, public) = crate::tox::relay_for(&part.name)?;
        Some(ToxRoads {
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
        kinds.push(Kind::Tox);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if self.public && !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::tox::third_party_line(self.relay.at)));
        }
        self.linked().await
    }

    #[cfg(feature = "tox")]
    async fn linked(&self) -> Result<Road, String> {
        use podssh_relay::tox::pair;
        self.log.verbose(&format!("{}: the Tox road through {}", self.shown, self.relay.at));
        let node = pair::node_keys(&self.name, &self.token).public();
        let dial = crate::tox::dial(self.relay.at);
        let stream = pair::link(&dial, self.relay.key, node, LIMIT)
            .await
            .map_err(|e| format!("the Tox relay {}: {e}", self.relay.at))?;
        Ok(Road::Tox(Box::new(stream)))
    }

    #[cfg(not(feature = "tox"))]
    async fn linked(&self) -> Result<Road, String> {
        // `relay_for` gives no road without the feature.
        let _ = (&self.name, &self.token);
        Err("this build has no Tox road".into())
    }
}

/// How long the client waits for the node's answer on the relay.
#[cfg(feature = "tox")]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(30);
