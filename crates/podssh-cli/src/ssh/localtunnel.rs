//! The localtunnel road of `podssh ssh node://NAME` (T-568), the last
//! fallback of the operator's ruling Q78: a WebSocket to the node's name at
//! localtunnel's server, `NAME.ZONE` on port 443, by TLS that the host's
//! roots check, through `HTTPS_PROXY` (`podssh_relay::localtunnel::link`).
//! The name comes from the node's key, as the node derives it
//! (`podssh_relay::localtunnel::name_of`): `--node-key`, else the key that
//! the net names for NAME, else the key that the pins of NAME hold, as the
//! ssh-j road takes it (`super::sshj::node_key`); with none, the road does
//! not race. It races last of all, once each road before it failed, and
//! never with `--no-e2e`, as the server ends the visitors' TLS and would see
//! each byte. Before its first link, a line names the server as a third
//! party that nobody vouches for.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::localtunnel::{self, link, Service, Setting};
use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::{ProxyChoice, Trust};

use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// Whether the road to `label` would race: on with a server, a key to
/// derive the name from, and an end-to-end channel (`ask.off` is --no-e2e).
pub(crate) fn named(label: &str, ask: &crate::channel::Ask) -> bool {
    !ask.off && matches!(localtunnel::from_env(), Ok(Setting::On(_))) && crate::ssh::sshj::node_key(label, ask).is_some()
}

/// The road to the node of one run.
pub(crate) struct LocalTunnelRoads {
    service: Service,
    /// The node's name, `NAME.ZONE`.
    host: String,
    trust: Trust,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl LocalTunnelRoads {
    /// The road to the node `label`, when [`named`]; else none, and `-v`
    /// says why where the road is on.
    pub(crate) fn new(
        label: &str,
        ask: &crate::channel::Ask,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<LocalTunnelRoads> {
        let Ok(Setting::On(service)) = localtunnel::from_env() else { return None };
        if ask.off {
            return None;
        }
        let Some(key) = crate::ssh::sshj::node_key(label, ask) else {
            log.verbose(&format!("{shown}: no localtunnel road: no key of the node to derive its name from"));
            return None;
        };
        let host = format!("{}.{}", localtunnel::name_of(&key.fingerprint()), service.zone);
        // The hosted server's names are under a public CA: the host's roots,
        // never the pair relay's --ca-file; a server named by the variable
        // takes the run's trust, as it may be the user's own.
        let trust = match Service::hosted() {
            Some(hosted) if hosted == service => crate::pairs::trust(None),
            _ => trust.clone(),
        };
        let (log, shown) = (log.clone(), shown.to_string());
        Some(LocalTunnelRoads { service, host, trust, said: AtomicBool::new(false), log, shown })
    }

    /// The road's place in the race: last, once each road before it failed (Q78).
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::LocalTunnel);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, localtunnel::third_party_line(&self.service)));
            self.log.verbose(&format!("{}: the localtunnel road dials {}", self.shown, self.host));
        }
        let timeout = podssh_relay::open::CONNECT_TIMEOUT;
        let session = link::open(&self.host, &self.trust, &ProxyChoice::FromEnvironment, timeout).await?;
        Ok(Road::LocalTunnel(podssh_ssh::relay_stream::spawn(session).0))
    }
}
