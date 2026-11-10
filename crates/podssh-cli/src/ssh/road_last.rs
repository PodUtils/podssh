//! The last roads of `podssh ssh node://NAME`'s race (`super`), apart from
//! `roads.rs` for its length: the node's name at ssh-j.com (T-570,
//! `crate::ssh::sshj`), then its port at bore.pub (T-569, [`bore`]), each of
//! the node's key, each once each road before it failed, the last fallbacks
//! of the operator's ruling Q78. The ssh-j road goes first: a server that
//! ends SSH by name, where bore's port is a raw one that more cages refuse.

use std::sync::Arc;

use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use super::Going;
use crate::ssh::road_link::Kind;
use crate::ssh::sshj::SshJRoads;

// A port of the node's key at bore.pub (T-569).
#[path = "bore.rs"]
pub(crate) mod bore;

/// The last roads of one run, each when it would race.
#[derive(Default)]
pub(crate) struct Lasts {
    sshj: Option<SshJRoads>,
    bore: Option<bore::BoreRoads>,
}

impl Lasts {
    /// The last roads to the node `label`.
    pub(crate) fn new(label: &str, ask: &crate::channel::Ask, trust: &Trust, log: &Arc<Log>, shown: &str) -> Lasts {
        let sshj = SshJRoads::new(label, ask, trust, log, shown);
        let bore = bore::BoreRoads::new(label, ask, trust, log, shown);
        Lasts { sshj, bore }
    }

    /// Whether any of them races.
    pub(crate) fn is_some(&self) -> bool {
        self.sshj.is_some() || self.bore.is_some()
    }

    /// Their places in the race, after each other road: ssh-j's, then bore's.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        if let Some(sshj) = &self.sshj {
            sshj.push(list, kinds);
        }
        if let Some(bore) = &self.bore {
            bore.push(list, kinds);
        }
    }
}
