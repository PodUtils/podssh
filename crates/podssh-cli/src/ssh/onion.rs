//! The onion road of `podssh ssh node://NAME` (T-578), the last fallback of
//! the operator's ruling Q78, after Syncthing's relay road: this end
//! bootstraps Arti through the Tor road, once a run, puts the pair's key of
//! restricted discovery in its keystore, which both ends make of the pair's
//! secret, and opens a stream to the node's onion service. So it needs the
//! pair here; never with --no-e2e, as the end-to-end channel checks the
//! node's key above it. The address is the one of `PODSSH_ONION`, else the
//! one kept under NAME by a node of this host or by a run that was given it.
//! Before the first circuit, a line names the Tor network as the third party.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use podssh_relay::pair::OperatorPart;
use podssh_relay::session::race::Start;
use podssh_ssh::Log;
use podssh_ws::Trust;

use crate::onion::Setting;
use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The road to the node of one run.
pub(crate) struct OnionRoads {
    label: String,
    /// The address that `PODSSH_ONION` names, which is kept once it carried.
    given: Option<String>,
    /// The secret of the pair's key of restricted discovery.
    #[cfg_attr(not(feature = "tor"), allow(dead_code))]
    discovery: [u8; 32],
    trust: Trust,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
    /// This end's client of Tor, bootstrapped at the first link of the run.
    #[cfg(feature = "tor")]
    tor: tokio::sync::OnceCell<podssh_tor::Tor>,
}

impl OnionRoads {
    /// The road of the pair `part` to the node `label`; none with no pair
    /// here, with the road off or not in this build, or with --no-e2e
    /// (`off`).
    pub(crate) fn new(
        label: &str,
        part: Option<&OperatorPart>,
        off: bool,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<OnionRoads> {
        if off || !cfg!(feature = "tor") {
            return None;
        }
        let part = part?;
        let Ok(Setting::On(given)) = crate::onion::setting() else { return None };
        Some(OnionRoads {
            label: label.to_string(),
            given,
            discovery: crate::onion::discovery_secret(&part.name, part.connect_token()),
            trust: trust.clone(),
            said: AtomicBool::new(false),
            log: log.clone(),
            shown: shown.to_string(),
            #[cfg(feature = "tor")]
            tor: tokio::sync::OnceCell::new(),
        })
    }

    /// The road's place in the race: once each road before it failed.
    pub(crate) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        list.push((Start::WhenAllFailed, Box::pin(self.link())));
        kinds.push(Kind::Onion);
    }

    /// The node's address: the one given, else the one kept.
    fn address(&self) -> Result<String, String> {
        self.given.clone().or_else(|| crate::onion::kept(&self.label)).ok_or_else(|| {
            format!(
                "the onion road: no onion address of the node; its line says it, and {}=ADDRESS names it",
                crate::onion::ENV
            )
        })
    }

    async fn link(&self) -> Result<Road, String> {
        let address = self.address()?;
        // The line of Q78, before the first circuit goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            let network = crate::onion::network_named();
            self.log.info(&format!("{}: {}", self.shown, crate::onion::third_party_line(network.as_deref())));
        }
        let road = self.linked(&address).await?;
        if self.given.is_some() {
            crate::onion::keep(&self.label, &address);
        }
        Ok(road)
    }

    #[cfg(feature = "tor")]
    async fn linked(&self, address: &str) -> Result<Road, String> {
        let (info, more) = (self.log.clone(), self.log.clone());
        let say = move |line: &str| info.info(line);
        let verbose = move |line: &str| more.verbose(line);
        let tor = self
            .tor
            .get_or_try_init(|| async {
                let booted = crate::ssh::cloud::tor::road::bootstrap(&self.shown, &self.trust, &say, &verbose).await;
                booted.map(|(tor, _)| tor).map_err(|(line, _)| format!("the onion road: {line}"))
            })
            .await?;
        self.log.verbose(&format!("{}: the onion road to the node's service", self.shown));
        let key = podssh_tor::Discovery::from_secret(self.discovery);
        let port = crate::onion::VIRTUAL_PORT;
        let stream = tor.connect_onion(address, port, Some(&key), LIMIT).await;
        let stream = stream.map_err(|f| format!("the onion road: {f}"))?;
        Ok(Road::Onion(Box::new(podssh_tor::onion::bridged(stream))))
    }

    #[cfg(not(feature = "tor"))]
    async fn linked(&self, _: &str) -> Result<Road, String> {
        // `new` gives no road without the feature.
        let _ = &self.trust;
        Err("this build has no onion road".into())
    }
}

/// How long the client looks for the node: a descriptor fetched from its
/// HSDirs, an introduction and a rendezvous, each a circuit of three hops or
/// more through relays of the cage's first hops.
#[cfg(feature = "tor")]
const LIMIT: std::time::Duration = std::time::Duration::from_secs(120);
