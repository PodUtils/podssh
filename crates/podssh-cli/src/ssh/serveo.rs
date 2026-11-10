//! The Serveo road of `podssh ssh node://NAME` (T-549), the last fallback of
//! the operator's ruling Q78, the last of all: SSH to Serveo's server, raw,
//! through `HTTPS_PROXY`, then a `direct-tcpip` channel to the node's alias,
//! as `ssh -J serveo.net user@ALIAS` jumps (`crate::serveo_leg`). The alias
//! is derived from the node's key, so no name is given or kept: the key is
//! `--node-key`'s, else the one that the net names for the member, else the
//! pins of NAME, which the first session over another road wrote. With no
//! key known, or with `--no-e2e`, the road is left out. It starts only once
//! each road before it failed, and a line names Serveo as a third party that
//! nobody vouches for before its first link. The end-to-end channel then
//! checks the node's key, as on whichever road wins, so a stranger that
//! holds the alias is refused there.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::identity::KeyName;
use podssh_relay::serveo::{self, Service};
use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::ProxyChoice;

use super::road_link::{Kind, Road};
use super::roads::Going;

/// The fingerprints of the node's keys, whose aliases the road tries:
/// `--node-key`'s, else the key that the net names for the member, else the
/// pins of `label`, in the order that the end-to-end channel checks them.
fn fingerprints(label: &str, ask: &crate::channel::Ask) -> Vec<String> {
    if let Some(name) = &ask.node_key {
        return vec![name.fingerprint()];
    }
    if let Some(member) = crate::net::lookup::member(label) {
        return vec![member.key.fingerprint()];
    }
    serveo::pinned(label).iter().map(KeyName::fingerprint).collect()
}

/// Whether the road to `label` would race: on, with a server, a key to
/// derive the aliases from, and the end-to-end channel, which is its check.
pub(crate) fn named(label: &str, ask: &crate::channel::Ask) -> bool {
    !ask.off && matches!(crate::node_serveo::service(), Ok(Ok(_))) && !fingerprints(label, ask).is_empty()
}

/// The road to the node of one run.
pub(crate) struct ServeoRoads {
    service: Service,
    fingerprints: Vec<String>,
    proxy: ProxyChoice,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl ServeoRoads {
    /// The road to the node `label`; none with the road off, with no server,
    /// with no key of the node known, or with no end-to-end channel.
    pub(crate) fn new(label: &str, ask: &crate::channel::Ask, log: &Arc<Log>, shown: &str) -> Option<ServeoRoads> {
        if ask.off {
            return None;
        }
        let service = crate::node_serveo::service().ok()?.ok()?;
        let fingerprints = fingerprints(label, ask);
        if fingerprints.is_empty() {
            return None;
        }
        let proxy = ProxyChoice::FromEnvironment;
        let (log, shown, said) = (log.clone(), shown.to_string(), AtomicBool::new(false));
        Some(ServeoRoads { service, fingerprints, proxy, said, log, shown })
    }

    /// The road's place in the race: last, once each road before it failed
    /// (Q78), as nobody names the road.
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Serveo);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, serveo::third_party_line(&self.service)));
        }
        let say = |line: String| self.log.verbose(&format!("{}: {line}", self.shown));
        let hop = crate::serveo_leg::hop(&self.service, &self.fingerprints, &self.proxy, &say).await?;
        Ok(Road::Serveo(Box::new(hop)))
    }
}
