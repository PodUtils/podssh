//! Yggdrasil's road of `podssh ssh node://NAME` (T-735), a last fallback of
//! the operator's ruling Q78, after the Tox road's: this end joins the
//! network through the pair's peer with a fresh key, once a run, says hello
//! to the node's key, which both ends make of the pair's secret, with a
//! proof of it, and carries each link as a stream of its own. So it needs
//! the pair here; never with --no-e2e, as the end-to-end channel checks the
//! node's key above it. Before its first link, a line names the public peer
//! as the third party.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct YggRoads {
    name: String,
    token: String,
    peer: String,
    public: bool,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
    /// This end in the network, joined at the first link of the run.
    #[cfg(feature = "yggdrasil")]
    ends: tokio::sync::OnceCell<Arc<podssh_relay::ygg::pair::Ends>>,
}

impl YggRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off or not in this build, or with --no-e2e (`off`).
    pub(crate) fn new(part: Option<&OperatorPart>, off: bool, log: &Arc<Log>, shown: &str) -> Option<YggRoads> {
        if off {
            return None;
        }
        let part = part?;
        let (peer, public) = crate::yggdrasil::peer_for(&part.name)?;
        Some(YggRoads {
            name: part.name.clone(),
            token: part.connect_token().to_string(),
            peer,
            public,
            said: AtomicBool::new(false),
            log: log.clone(),
            shown: shown.to_string(),
            #[cfg(feature = "yggdrasil")]
            ends: tokio::sync::OnceCell::new(),
        })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Ygg);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if self.public && !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::yggdrasil::third_party_line(&self.peer)));
        }
        self.linked().await
    }

    #[cfg(feature = "yggdrasil")]
    async fn linked(&self) -> Result<Road, String> {
        use podssh_relay::ygg::pair::{fresh_secret, node_secret, Ends};
        let ends = self
            .ends
            .get_or_try_init(|| async {
                let (log, shown) = (self.log.clone(), self.shown.clone());
                let say: podssh_relay::ygg::router::Say =
                    Arc::new(move |line| log.verbose(&format!("{shown}: {line}")));
                crate::yggdrasil::router(fresh_secret(), &self.peer, say).map(|router| Ends::start(router, None))
            })
            .await?;
        self.log.verbose(&format!("{}: Yggdrasil's road through the peer {}", self.shown, self.peer));
        let node = node_secret(&self.name, &self.token).verifying_key().to_bytes();
        let stream = ends.link(node, &self.token, LIMIT).await.map_err(|e| format!("Yggdrasil's road: {e}"))?;
        Ok(Road::Ygg(Box::new(stream)))
    }

    #[cfg(not(feature = "yggdrasil"))]
    async fn linked(&self) -> Result<Road, String> {
        // `peer_for` gives no road without the feature.
        let _ = (&self.name, &self.token);
        Err("this build has no Yggdrasil road".into())
    }
}

/// How long the client waits for the node's welcome: the first lookup
/// across the network takes a few seconds.
#[cfg(feature = "yggdrasil")]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(45);
