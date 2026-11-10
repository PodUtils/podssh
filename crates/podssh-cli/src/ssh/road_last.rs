//! The last fallbacks of the operator's ruling Q78 in the race of `podssh
//! ssh node://NAME` (`super`), apart from `roads.rs` for its length: each a
//! road whose name the node's key gives, so that a client that holds the
//! key races it with no word of the node's, last of all, once each road
//! before it failed: Serveo's alias (T-549, `crate::ssh::serveo`), then the
//! node's name at ssh-j.com (T-570, `crate::ssh::sshj`), then its name at
//! localtunnel's server (T-568, [`localtunnel`]). The order is the node's:
//! a node that would serve none of the roads before them unasked serves
//! them in this order.

use std::sync::Arc;

use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use super::Going;
use crate::ssh::road_link::Kind;

// The localtunnel road of node://NAME, the last of all (T-568).
#[path = "localtunnel.rs"]
pub(crate) mod localtunnel;

/// The last fallbacks of one run, each where it races.
pub(crate) struct LastRoads {
    serveo: Option<crate::ssh::serveo::ServeoRoads>,
    sshj: Option<crate::ssh::sshj::SshJRoads>,
    localtunnel: Option<localtunnel::LocalTunnelRoads>,
}

impl LastRoads {
    /// The roads to the node `label`, each where its server is on and a key
    /// of the node is known; never with --no-e2e.
    pub(crate) fn new(label: &str, ask: &crate::channel::Ask, trust: &Trust, log: &Arc<Log>, shown: &str) -> Self {
        LastRoads {
            serveo: crate::ssh::serveo::ServeoRoads::new(label, ask, log, shown),
            sshj: crate::ssh::sshj::SshJRoads::new(label, ask, trust, log, shown),
            localtunnel: localtunnel::LocalTunnelRoads::new(label, ask, trust, log, shown),
        }
    }

    /// None of them: a measure of `podssh ping` never sends a byte to a
    /// third party of Q78 unasked, and none of them is ever asked.
    pub(crate) fn none() -> Self {
        LastRoads { serveo: None, sshj: None, localtunnel: None }
    }

    /// Whether one of them races.
    pub(crate) fn any(&self) -> bool {
        self.serveo.is_some() || self.sshj.is_some() || self.localtunnel.is_some()
    }

    /// Their places in the race, in their order.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        if let Some(serveo) = &self.serveo {
            serveo.push(list, kinds);
        }
        if let Some(sshj) = &self.sshj {
            sshj.push(list, kinds);
        }
        if let Some(localtunnel) = &self.localtunnel {
            localtunnel.push(list, kinds);
        }
    }
}
