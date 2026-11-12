//! The smee.io road of `podssh ssh node://NAME` (T-741), a last fallback of
//! the operator's ruling Q78 after the onion road: the channels of the pair
//! at smee.io's server (`crate::smee_road`), a hello at the node's door, and
//! a link of numbered POSTs and a stream of events each way. So it needs the
//! pair here; never with --no-e2e, as anyone who knows a channel's name
//! reads its events and the end-to-end channel checks the node's key above
//! it. Before its first link through a listed server, a line names it as
//! the third party.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_relay::smee::Dialer;
use podssh_ssh::Log;
use podssh_ws::Trust;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct SmeeRoads {
    dialer: Dialer,
    /// Whether the server is the listed one, a third party's.
    public: bool,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl SmeeRoads {
    /// The road of the pair `part`; none with no pair here, with the road
    /// off, or with --no-e2e (`off`).
    pub(crate) fn new(
        part: Option<&OperatorPart>,
        off: bool,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<SmeeRoads> {
        if off {
            return None;
        }
        let part = part?;
        let (server, public) = crate::smee_road::server()?;
        // A listed server takes the host's trust, as at the node.
        let trust = if public { crate::pairs::trust(None) } else { trust.clone() };
        let dialer = crate::smee_road::dialer(part, &server, &trust, log, shown);
        Some(SmeeRoads { dialer, public, said: AtomicBool::new(false), log: log.clone(), shown: shown.to_string() })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Smee);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if self.public && !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, crate::smee_road::third_party_line(self.dialer.server())));
        }
        self.log.verbose(&format!("{}: the smee.io road through {}", self.shown, self.dialer.server()));
        self.dialer.link().await.map(|link| Road::Smee(Box::new(link)))
    }
}
