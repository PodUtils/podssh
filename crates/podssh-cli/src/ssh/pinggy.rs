//! The Pinggy road of `podssh ssh node://NAME` (T-548), a last fallback of
//! the operator's ruling Q78: the tunnel's name and the pin of the node's
//! TLS key, as the node prints them, given as `--pinggy-name NAME#PIN`, or
//! kept under NAME in the cache from a run that gave them, or by a node of
//! this host. An address given races 250 ms after the road before it; a
//! kept one only once each road before it failed, last of all. A name with
//! no pin is a usage error, and a kept name with none is not raced. Before
//! its first link, a line names Pinggy as a third party that nobody vouches
//! for. Each link is TLS by the name on port 443, through `HTTPS_PROXY`,
//! with no upgrade, which takes only a certificate of the pinned key (the
//! node's certificate is its own, so no CA vouches for it); the end-to-end
//! channel checks the node's own key by the pins of NAME, or `--node-key`,
//! on whichever road wins.
//!
//! The address of `--pinggy-name` is read with the destination and kept for
//! the race in a static, as `--spares` keeps its number: the race of each
//! command (ssh, a copy, ping) reads it there, so no other road's types
//! carry it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use podssh_relay::opentunnel::dial;
use podssh_relay::pinggy::{self, Address, Dialer, Service};
use podssh_relay::session::race::{Start, HEAD_START};
use podssh_ssh::Log;
use podssh_ws::ProxyChoice;

use super::args::SshArgs;
use super::road_link::{Kind, Road};
use super::roads::Going;
use crate::relay_settings::Refusal;

/// The address of `--pinggy-name` of this run, once the destination is read.
static GIVEN: Mutex<Option<Address>> = Mutex::new(None);

/// `--pinggy-name` and the road's variables of a `node://NAME` destination,
/// checked before anything connects: a bad name is a usage error (64), a bad
/// variable a configuration error (78); a name given is kept for the race.
pub(super) fn race(args: &SshArgs) -> Result<(), Refusal> {
    let name = match &args.pinggy_name {
        Some(text) => Some(Address::parse(text).map_err(|why| Refusal::usage(format!("--pinggy-name: {why}")))?),
        None => None,
    };
    if let (Some(_), Err(by)) = (&name, crate::node_pinggy::service()?) {
        return Err(Refusal::usage(format!("--pinggy-name: {by}=no turns the Pinggy road off")));
    }
    *GIVEN.lock().unwrap_or_else(PoisonError::into_inner) = name;
    Ok(())
}

/// The address kept under `label`, when one is and it reads as one: a name
/// kept with no pin, by an earlier version, is none.
pub(crate) fn kept(label: &str) -> Option<Address> {
    let text = podssh_relay::cache::load_file(&crate::node_pinggy::name_file(label))?;
    Address::parse(text.trim()).ok()
}

/// Whether the road to `label` would race: on, with an address given or kept,
/// and an end-to-end channel (`off` is --no-e2e); [`PinggyRoads::new`]
/// makes it, so that a node with no other road beside the pair's races it.
pub(crate) fn named(label: &str, off: bool) -> bool {
    let given = GIVEN.lock().unwrap_or_else(PoisonError::into_inner).is_some();
    let on = matches!(crate::node_pinggy::service(), Ok(Ok(_)));
    on && !off && (given || kept(label).is_some())
}

/// The road to the node of one run, when it has a name and is on.
pub(crate) struct PinggyRoads {
    dialer: Dialer,
    asked: bool,
    service: Service,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    log: Arc<Log>,
    shown: String,
}

impl PinggyRoads {
    /// The road to the node `label`: the address given, else the one kept;
    /// none with no address, with the road off, or with no end-to-end
    /// channel (`off`). An address given is kept under the label.
    pub(crate) fn new(label: &str, off: bool, log: &Arc<Log>, shown: &str) -> Option<PinggyRoads> {
        let service = crate::node_pinggy::service().ok()?.ok()?;
        let given = GIVEN.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let (address, asked) = match given {
            Some(address) => (address, true),
            None => (kept(label)?, false),
        };
        if off {
            return None;
        }
        if asked {
            let file = crate::node_pinggy::name_file(label);
            match podssh_relay::cache::store_file(&file, format!("{address}\n").as_bytes()) {
                Ok(path) => log.verbose(&format!("{shown}: the Pinggy name is kept in {}", path.display())),
                Err(why) => log.verbose(&format!("{shown}: the Pinggy name could not be kept: {why}")),
            }
        }
        let say: pinggy::Say = {
            let (log, shown) = (log.clone(), shown.to_string());
            Arc::new(move |line: String| log.verbose(&format!("{shown}: {line}")))
        };
        let dialer = Dialer::new(address, dial::tcp(ProxyChoice::FromEnvironment), say);
        let (log, shown) = (log.clone(), shown.to_string());
        Some(PinggyRoads { dialer, asked, service, said: AtomicBool::new(false), log, shown })
    }

    /// Whether the user gave the name in this run.
    pub(super) fn asked(&self) -> bool {
        self.asked
    }

    /// The road's place in the race: 250 ms after the road before it when
    /// its name was given; else last, once each road before it failed (Q78).
    pub(super) fn push<'r>(&'r self, list: &mut Vec<(Start, Going<'r>)>, kinds: &mut Vec<Kind>) {
        let start = if self.asked { Start::After(HEAD_START) } else { Start::WhenAllFailed };
        list.push((start, Box::pin(self.link())));
        kinds.push(Kind::Pinggy);
    }

    async fn link(&self) -> Result<Road, String> {
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, pinggy::third_party_line(&self.service)));
        }
        self.dialer.link().await.map(Road::Pinggy)
    }
}
