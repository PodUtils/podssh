//! HyperDHT's road of `podssh ssh node://NAME` (T-736), where UDP passes,
//! after Yggdrasil's road: this end joins HyperDHT with a fresh key, once a
//! run, looks the topic of the node's key up, which both ends make of the
//! pair's secret, and connects by that key. So it needs the pair here; never
//! with --no-e2e, as the end-to-end channel checks the node's key above it.
//! Where no bootstrap node answers, UDP does not pass, and the road fails
//! with that word. Before it joins the public DHT, a line names it as the
//! third party.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct DhtRoads {
    name: String,
    token: String,
    bootstrap: Vec<String>,
    public: bool,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
    /// This end in HyperDHT, joined at the first link of the run.
    #[cfg(feature = "hyperdht")]
    end: tokio::sync::OnceCell<tokio::sync::Mutex<podssh_relay::hyperdht::End>>,
}

impl DhtRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off or not in this build, or with --no-e2e (`off`).
    pub(crate) fn new(part: Option<&OperatorPart>, off: bool, log: &Arc<Log>, shown: &str) -> Option<DhtRoads> {
        if off {
            return None;
        }
        let part = part?;
        let (bootstrap, public) = crate::hyperdht::bootstrap()?;
        Some(DhtRoads {
            name: part.name.clone(),
            token: part.connect_token().to_string(),
            bootstrap,
            public,
            said: AtomicBool::new(false),
            log: log.clone(),
            shown: shown.to_string(),
            #[cfg(feature = "hyperdht")]
            end: tokio::sync::OnceCell::new(),
        })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::HyperDht);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first packet goes to the third party.
        if self.public && !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::hyperdht::third_party_line()));
        }
        self.linked().await
    }

    #[cfg(feature = "hyperdht")]
    async fn linked(&self) -> Result<Road, String> {
        use podssh_relay::hyperdht::{join, node_keys};
        let end = self
            .end
            .get_or_try_init(|| async { join(&self.bootstrap, None).await.map(tokio::sync::Mutex::new) })
            .await
            .map_err(|e| format!("HyperDHT's road: {e}"))?;
        self.log.verbose(&format!("{}: HyperDHT's road by the node's key", self.shown));
        let node = node_keys(&self.name, &self.token).public_key;
        let stream = end.lock().await.link(node, LIMIT).await.map_err(|e| format!("HyperDHT's road: {e}"))?;
        Ok(Road::HyperDht(Box::new(stream)))
    }

    #[cfg(not(feature = "hyperdht"))]
    async fn linked(&self) -> Result<Road, String> {
        // `bootstrap` gives no road without the feature.
        let _ = (&self.name, &self.token, &self.bootstrap);
        Err("this build has no HyperDHT road".into())
    }
}

/// How long the client looks for the node: the first lookups and the punch
/// through both NATs take some seconds.
#[cfg(feature = "hyperdht")]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(45);
