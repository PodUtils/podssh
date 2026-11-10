//! The Pinggy road of `podssh ssh node://NAME` (T-548), a last fallback of
//! the operator's ruling Q78: the tunnel's name and the pin of the node's
//! TLS key, as the node prints them, given as `--pinggy-name NAME#PIN`; else
//! the address of the node's record of pkarr (T-445), for a member that the
//! net names by its key; else the one kept under NAME in the cache from a
//! run that gave them, or by a node of this host. An address given races
//! 250 ms after the road before it; one of the record or kept only once each
//! road before it failed, last of all. A name with no pin is a usage error,
//! and a kept name with none is not raced. Before
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

use podssh_relay::opentunnel::dial::{self, Visit};
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

/// Where the address of a link came from, for `-v`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Source {
    Given,
    Record,
    Kept,
}

/// The road to the node of one run, when it has an address, or a record
/// that may name one, and is on.
pub(crate) struct PinggyRoads {
    /// The address of `--pinggy-name`: the user's word wins.
    given: Option<Address>,
    /// The address kept under the label, for a run whose record names none.
    kept: Option<Address>,
    /// Whether the node's record is asked in this run (T-445).
    record: bool,
    visit: Visit,
    say: pinggy::Say,
    service: Service,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    /// The address that the last link dialed and where it came from, so
    /// that `-v` says each change once.
    last: Mutex<Option<(Address, Source)>>,
    log: Arc<Log>,
    shown: String,
}

impl PinggyRoads {
    /// The road to the node `label`: the address given, else the record's
    /// when `record` is asked, else the one kept; none with no address and
    /// no record, with the road off, or with no end-to-end channel (`off`).
    /// An address given is kept under the label.
    pub(crate) fn new(label: &str, off: bool, record: bool, log: &Arc<Log>, shown: &str) -> Option<PinggyRoads> {
        let service = crate::node_pinggy::service().ok()?.ok()?;
        let given = GIVEN.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let kept = if given.is_some() { None } else { kept(label) };
        if off || (given.is_none() && kept.is_none() && !record) {
            return None;
        }
        if let Some(address) = &given {
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
        let visit = dial::tcp(ProxyChoice::FromEnvironment);
        let (log, shown, last) = (log.clone(), shown.to_string(), Mutex::new(None));
        Some(PinggyRoads { given, kept, record, visit, say, service, said: AtomicBool::new(false), last, log, shown })
    }

    /// Whether the user gave the name in this run.
    pub(super) fn asked(&self) -> bool {
        self.given.is_some()
    }

    /// Where an address that nobody gave in this run comes from, for the
    /// race's order in `-v`; none when one was given.
    pub(super) fn unasked(&self) -> Option<&'static str> {
        match (&self.given, self.record, &self.kept) {
            (Some(_), _, _) => None,
            (None, true, Some(_)) => Some("the node's record, else a kept name"),
            (None, true, None) => Some("the node's record"),
            (None, false, _) => Some("a kept name"),
        }
    }

    /// The road's place in the race: 250 ms after the road before it when
    /// its name was given; else last, once each road before it failed (Q78).
    /// `record` is the run's record, which this road asks for its address
    /// as the record's other roads do, so it is asked once.
    pub(super) fn push<'r>(
        &'r self,
        list: &mut Vec<(Start, Going<'r>)>,
        kinds: &mut Vec<Kind>,
        record: Option<&'r super::iroh::RecordRoads<'_>>,
    ) {
        let start = if self.asked() { Start::After(HEAD_START) } else { Start::WhenAllFailed };
        list.push((start, Box::pin(self.link(record))));
        kinds.push(Kind::Pinggy);
    }

    /// The address of a link: the one given; else the record's, read again
    /// at each link, as the node puts a new one at each tunnel; else the
    /// one kept. A record that names none, or that cannot be read, leaves
    /// the kept one.
    async fn address(&self, record: Option<&super::iroh::RecordRoads<'_>>) -> Result<(Address, Source), String> {
        if let Some(given) = &self.given {
            return Ok((given.clone(), Source::Given));
        }
        let mut why = None;
        if let Some(record) = record.filter(|_| self.record) {
            match record.pinggy().await {
                Ok(address) => return Ok((address, Source::Record)),
                Err(not) => why = Some(not),
            }
        }
        match (&self.kept, why) {
            (Some(kept), _) => Ok((kept.clone(), Source::Kept)),
            (None, Some(why)) => Err(why),
            (None, None) => Err("no Pinggy address: none given, kept or of a record".into()),
        }
    }

    async fn link(&self, record: Option<&super::iroh::RecordRoads<'_>>) -> Result<Road, String> {
        let (address, source) = self.address(record).await?;
        self.say_address(&address, source);
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, pinggy::third_party_line(&self.service)));
        }
        // A dialer holds no state but its address, so one for each link.
        let dialer = Dialer::new(address, self.visit.clone(), self.say.clone());
        dialer.link().await.map(Road::Pinggy)
    }

    /// For `-v`, once for each address and its source: the record's is the
    /// node's word, signed by its key, so its pin is as good as the node's
    /// own line.
    fn say_address(&self, address: &Address, source: Source) {
        let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        if last.as_ref() == Some(&(address.clone(), source)) {
            return;
        }
        let from = match source {
            Source::Given => "given by --pinggy-name",
            Source::Record => "the address of its record of pkarr, signed by the node's key",
            Source::Kept => "the address kept in the cache",
        };
        self.log.verbose(&format!("{}: the Pinggy road dials {address}, {from}", self.shown));
        *last = Some((address.clone(), source));
    }
}
