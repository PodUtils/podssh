//! croc's relay road of `podssh ssh node://NAME` (T-694), a last fallback
//! of the operator's ruling Q78: a room of the pair at croc's relay, behind
//! croc-web's WebSocket bridge, where the node waits; raced last, once each
//! road before it failed, as the transit relay's is. Its rooms and the proof
//! of the pair come from the pair's connect token, so it needs the pair
//! here; never with --no-e2e, as the end-to-end channel checks the node's
//! key above it, nor where a road found the WebSocket upgrade refused on the
//! way, as the bridge is a WebSocket too. Before its first link through the
//! public bridge, a line names croc's relays as third parties that nobody
//! vouches for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::croc::{self, Dialer};
use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use super::road_link::{Kind, Road};
use super::roads::Going;

/// The road to the node of one run.
pub(crate) struct CrocRoads {
    dialer: Dialer,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl CrocRoads {
    /// The road to the node of the pair `part`; none with no pair here, with
    /// the road off, or when `off`: --no-e2e, or the upgrade refused on the
    /// way.
    pub(crate) fn new(
        part: Option<&OperatorPart>,
        off: bool,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<CrocRoads> {
        if off {
            return None;
        }
        let dialer = crate::node_croc::dialer(part?, trust, log, shown)?;
        Some(CrocRoads { dialer, said: AtomicBool::new(false), log: log.clone(), shown: shown.to_string() })
    }

    /// The road's place in the race: last, once each road before it failed.
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Croc);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if self.dialer.bridge().public && !self.said.swap(true, Ordering::SeqCst) {
            let line = croc::third_party_line(&self.dialer.bridge().url.shown());
            self.log.info(&format!("{}: {line}", self.shown));
        }
        self.dialer.link().await.map(Road::Transit)
    }
}
