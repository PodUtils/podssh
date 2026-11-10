//! The bore road of `podssh ssh node://NAME` (T-569), the last fallback of
//! the operator's ruling Q78, after the ssh-j road: a public port of the
//! node's key at bore.pub, or at the server of `PODSSH_BORE`
//! (`podssh_relay::bore`). The key is the ssh-j road's (`crate::ssh::sshj`):
//! `--node-key`, else the net's key of NAME, else the pins of NAME; with
//! none, the road does not race, as no port can be derived. Each link is raw
//! TCP to a port of the key, directly or by `HTTPS_PROXY`'s CONNECT, else
//! through the forwarders that the binary names (Q56), whose URL names the
//! port, as a proxy that allows 443 alone refuses the port itself
//! (`crate::sshj::client::first_hop_to`). Never with `--no-e2e`: the server
//! sees each byte that the end-to-end channel does not keep. Before its first
//! link, a line names the server as a third party that nobody vouches for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::bore::{self, Dialer, Setting};
use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// Whether the road to `label` would race: on with a server, a key to
/// derive the ports from, and an end-to-end channel (`ask.off` is --no-e2e).
pub(crate) fn named(label: &str, ask: &crate::channel::Ask) -> bool {
    let on = matches!(bore::from_env(), Ok(Setting::On(_)));
    !ask.off && on && crate::ssh::sshj::node_key(label, ask).is_some()
}

/// The way to each port: directly, by CONNECT, else through Q56's forwarders.
fn visit(trust: &Trust, log: &Arc<Log>) -> bore::Dial {
    let (trust, log) = (trust.clone(), log.clone());
    Arc::new(move |host: &str, port: u16| -> bore::Dialing {
        let (host, trust, log) = (host.to_string(), trust.clone(), log.clone());
        Box::pin(async move {
            let shown = podssh_ws::dial::authority(&host, port);
            crate::sshj::client::first_hop_to(&host, port, &shown, &trust, &log).await
        })
    })
}

/// The road to the node of one run.
pub(crate) struct BoreRoads {
    dialer: Dialer,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl BoreRoads {
    /// The road to the node `label`, when [`named`]; else none, and `-v`
    /// says why where the road is on.
    pub(crate) fn new(
        label: &str,
        ask: &crate::channel::Ask,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<BoreRoads> {
        let Ok(Setting::On(service)) = bore::from_env() else { return None };
        if ask.off {
            return None;
        }
        let Some(key) = crate::ssh::sshj::node_key(label, ask) else {
            log.verbose(&format!("{shown}: no bore road: no key of the node to derive its ports from"));
            return None;
        };
        let say: bore::Say = {
            let (log, shown) = (log.clone(), shown.to_string());
            Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
        };
        let dialer = Dialer::new(service, &key.fingerprint(), visit(trust, log), say);
        Some(BoreRoads { dialer, said: AtomicBool::new(false), log: log.clone(), shown: shown.to_string() })
    }

    /// The road's place in the race: last of all, once each road before it
    /// failed (Q78).
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Bore);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, bore::third_party_line(self.dialer.service())));
            let ports: Vec<String> = self.dialer.ports().iter().map(u16::to_string).collect();
            let (shown, server) = (&self.shown, self.dialer.service());
            self.log.verbose(&format!("{shown}: the bore road tries the ports {} at {server}", ports.join(", ")));
        }
        self.dialer.link().await.map(Road::Bore)
    }
}
