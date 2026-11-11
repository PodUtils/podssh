//! The road of a tunnel of HTTP made by `ssh -R` of `podssh ssh
//! node://NAME` (T-565), localhost.run's, the last fallback of the
//! operator's ruling Q78: the tunnel's name as the node prints it, given as
//! `--tunnel-url https://HOST`; else the name of the node's record of pkarr
//! (T-445), for a member that the net names by its key; else the one kept
//! under NAME in the cache, from a run that gave it, or by a node of this
//! host. A name given races 250 ms after the road before it; one of the
//! record or kept only once each road before it failed, last, after the
//! ssh-j road and before the localtunnel road (`road_last.rs`). Before its first link, a line names the service as a
//! third party that nobody vouches for. Each link is a WebSocket at `/` of
//! the name, on port 443 through `HTTPS_PROXY`, as the quick tunnel of a
//! record is taken (`podssh_ws::cloudflare::connect`): the service's edge ends TLS
//! with a certificate that this host's trust verifies, and the end-to-end
//! channel checks the node's own key, by the pins of NAME or `--node-key`,
//! on whichever road wins; so `--no-e2e` leaves the road out. Its failure
//! names `wss://NAME/`, never `cf://` or Cloudflare Access: the edge is the
//! service's, not Cloudflare's. A name under Sandhole's tunnels' zone is
//! Sandhole's (T-743): its switch `PODSSH_SANDHOLE` and its line hold.
//!
//! The name of `--tunnel-url` is read with the destination and kept for
//! the race in a static, as `--pinggy-name` keeps its own. A module of
//! `roads`, beside its member's and frp's roads, as `ssh/mod.rs` is full.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use podssh_relay::session::race::{Start, HEAD_START};
use podssh_relay::ssh_http::{self, name, Setting, Word};
use podssh_ssh::Log;
use podssh_ws::client::DEFAULT_IDLE_TIMEOUT;
use podssh_ws::cloudflare::{self, Access};
use podssh_ws::url::WsUrl;
use podssh_ws::{ProxyChoice, Trust};

use crate::relay_settings::Refusal;
use crate::ssh::args::SshArgs;
use crate::ssh::road_link::{Kind, Road};
use crate::ssh::roads::Going;

/// The word of a name: Sandhole's for a name under its tunnels' zone, else
/// localhost.run's (T-743), whose switch and line the link takes.
fn word_of(name: &str) -> Word {
    ssh_http::word_of_name(name)
}

/// The name of `--tunnel-url` of this run, once the destination is read.
static GIVEN: Mutex<Option<String>> = Mutex::new(None);

/// The variable that turns the road off, when one does; a bad value is a
/// configuration error (78). A client needs no server: it dials the name.
fn off(word: Word) -> Result<Option<&'static str>, Refusal> {
    match ssh_http::from_env(word).map_err(Refusal::config)? {
        Setting::Off(by) => Ok(Some(by)),
        Setting::On(_) | Setting::Unnamed => Ok(None),
    }
}

/// Whether a word of the road is on, and no variable of one is bad: a name
/// that the record gives later takes its own word's switch at its link.
fn any_on() -> bool {
    let read: Vec<_> = ssh_http::WORDS.iter().map(|&word| off(word)).collect();
    read.iter().all(Result::is_ok) && read.iter().any(|off| matches!(off, Ok(None)))
}

/// `--tunnel-url` and the road's variables of a `node://NAME` destination,
/// checked before anything connects: a bad URL is a usage error (64), a bad
/// variable a configuration error (78); a name given is kept for the race.
pub(crate) fn race(args: &SshArgs) -> Result<(), Refusal> {
    let name = match &args.tunnel_url {
        Some(text) => Some(name::of_url(text).map_err(|why| Refusal::usage(format!("--tunnel-url: {why}")))?),
        None => None,
    };
    if name.is_some() && args.no_e2e {
        let why = "--no-e2e cannot go with --tunnel-url: anyone may visit a tunnel's name, so the node lets in the \
                   key that the end-to-end channel proves";
        return Err(Refusal::usage(why));
    }
    for word in ssh_http::WORDS {
        off(*word)?;
    }
    // A bad PODSSH_BARE is refused here, before anything connects (T-740).
    super::last::bare::node()?;
    if let Some(given) = &name {
        let word = word_of(given);
        if let Some(by) = off(word)? {
            return Err(Refusal::usage(format!("--tunnel-url: {by}=no turns the {} road off", word.name)));
        }
    }
    *GIVEN.lock().unwrap_or_else(PoisonError::into_inner) = name;
    Ok(())
}

/// The name kept under `label`, when one is and it reads as one.
fn kept(label: &str) -> Option<String> {
    let text = podssh_relay::cache::load_file(&crate::node_ssh_http::name_file(label))?;
    name::of_url(&text).ok()
}

/// Whether the road to `label` would race: on, with a name given or kept,
/// and an end-to-end channel (`off` is --no-e2e); a record's name makes it
/// race too, which [`SshHttpRoads::new`] reads.
pub(crate) fn named(label: &str, no_e2e: bool) -> bool {
    let given = GIVEN.lock().unwrap_or_else(PoisonError::into_inner).is_some();
    !no_e2e && any_on() && (given || kept(label).is_some())
}

/// The road to the node of one run, when it has a name, or a record that
/// may name one, and is on.
pub(crate) struct SshHttpRoads {
    /// The name of `--tunnel-url`: the user's word wins.
    given: Option<String>,
    /// The name kept under the label, for a run whose record names none.
    kept: Option<String>,
    /// Whether the node's record is asked in this run (T-445).
    record: bool,
    trust: Trust,
    /// Whether the line of the third party was said, once a run.
    said: AtomicBool,
    /// Whether the line of the Bare hop was said, once a run.
    said_bare: AtomicBool,
    /// The name that the last link dialed, so that `-v` says each change once.
    last: Mutex<Option<String>>,
    log: Arc<Log>,
    shown: String,
}

impl SshHttpRoads {
    /// The road to the node `label`: the name given, else the record's when
    /// `record` is asked, else the one kept; none with no name and no
    /// record, with the road off, or with no end-to-end channel (`no_e2e`).
    /// A name given is kept under the label.
    pub(crate) fn new(
        label: &str,
        no_e2e: bool,
        record: bool,
        trust: &Trust,
        log: &Arc<Log>,
        shown: &str,
    ) -> Option<SshHttpRoads> {
        if no_e2e || !any_on() {
            return None;
        }
        let given = GIVEN.lock().unwrap_or_else(PoisonError::into_inner).clone();
        let kept = if given.is_some() { None } else { kept(label) };
        if given.is_none() && kept.is_none() && !record {
            return None;
        }
        if let Some(name) = &given {
            let file = crate::node_ssh_http::name_file(label);
            match podssh_relay::cache::store_file(&file, format!("https://{name}\n").as_bytes()) {
                Ok(path) => log.verbose(&format!("{shown}: the tunnel's name is kept in {}", path.display())),
                Err(why) => log.verbose(&format!("{shown}: the tunnel's name could not be kept: {why}")),
            }
        }
        let (trust, log, shown, last) = (trust.clone(), log.clone(), shown.to_string(), Mutex::new(None));
        let said = (AtomicBool::new(false), AtomicBool::new(false));
        Some(SshHttpRoads { given, kept, record, trust, said: said.0, said_bare: said.1, last, log, shown })
    }

    /// The Bare hop of the same name (T-740, `road_bare`): last of all, once
    /// each road before it failed, through the node of `node`.
    pub(super) fn push_bare<'r>(
        &'r self,
        node: &'r WsUrl,
        list: &mut Vec<(Start, Going<'r>)>,
        kinds: &mut Vec<Kind>,
        record: Option<&'r crate::ssh::iroh::RecordRoads<'_>>,
    ) {
        list.push((Start::WhenAllFailed, Box::pin(self.bare_link(node, record))));
        kinds.push(Kind::Bare);
    }

    async fn bare_link(
        &self,
        node: &WsUrl,
        record: Option<&crate::ssh::iroh::RecordRoads<'_>>,
    ) -> Result<Road, String> {
        let name = self.name(record).await?;
        let word = word_of(&name);
        if let Ok(Some(by)) = off(word) {
            return Err(format!("wss://{name}/: {by}=no turns the {} road off", word.name));
        }
        let far = super::last::bare::far(&name)?;
        // Its own line of Q78, once a run, before the first byte goes to the node.
        if !self.said_bare.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, super::last::bare::line(node, &far)));
        }
        let (proxy, limit) = (ProxyChoice::FromEnvironment, podssh_relay::open::CONNECT_TIMEOUT);
        match podssh_ws::bare::dial(node, &far, &self.trust, &proxy, limit, Some(DEFAULT_IDLE_TIMEOUT)).await {
            Ok(session) => Ok(Road::SshHttp(podssh_ssh::relay_stream::spawn(session).0)),
            Err(e) => Err(format!("{} through {}: {e}", far.shown(), node.shown())),
        }
    }

    /// Whether the user gave the name in this run.
    pub(super) fn asked(&self) -> bool {
        self.given.is_some()
    }

    /// The road's place in the race: 250 ms after the road before it when
    /// its name was given; else last, once each road before it failed (Q78).
    pub(super) fn push<'r>(
        &'r self,
        list: &mut Vec<(Start, Going<'r>)>,
        kinds: &mut Vec<Kind>,
        record: Option<&'r crate::ssh::iroh::RecordRoads<'_>>,
    ) {
        let start = if self.asked() { Start::After(HEAD_START) } else { Start::WhenAllFailed };
        list.push((start, Box::pin(self.link(record))));
        let known = self.given.as_ref().or(self.kept.as_ref());
        let sandhole = known.is_some_and(|name| word_of(name).id == ssh_http::SANDHOLE.id);
        kinds.push(Kind::SshHttp(self.asked(), sandhole));
    }

    /// The name of a link: the one given; else the record's, read again at
    /// each link, as the node puts each new one; else the one kept.
    async fn name(&self, record: Option<&crate::ssh::iroh::RecordRoads<'_>>) -> Result<String, String> {
        if let Some(given) = &self.given {
            return Ok(given.clone());
        }
        let mut why = None;
        if let Some(record) = record.filter(|_| self.record) {
            match record.tunnel().await {
                Ok(name) => return Ok(name),
                Err(not) => why = Some(not),
            }
        }
        match (&self.kept, why) {
            (Some(kept), _) => Ok(kept.clone()),
            (None, Some(why)) => Err(why),
            (None, None) => Err("no tunnel's name: none given, kept or of a record".into()),
        }
    }

    async fn link(&self, record: Option<&crate::ssh::iroh::RecordRoads<'_>>) -> Result<Road, String> {
        let name = self.name(record).await?;
        let word = word_of(&name);
        if let Ok(Some(by)) = off(word) {
            return Err(format!("wss://{name}/: {by}=no turns the {} road off", word.name));
        }
        // The line of Q78, before the first byte goes to the third party.
        if !self.said.swap(true, Ordering::SeqCst) {
            self.log.info(&format!("{}: {}", self.shown, ssh_http::client_line(word, &name)));
        }
        // In a block of its own: no guard is held across the dial.
        {
            let mut last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
            if last.as_deref() != Some(name.as_str()) {
                self.log.verbose(&format!("{}: the {} road dials wss://{name}/", self.shown, word.name));
                *last = Some(name.clone());
            }
        }
        let (access, proxy, limit) =
            (Access::default(), ProxyChoice::FromEnvironment, podssh_relay::open::CONNECT_TIMEOUT);
        match cloudflare::connect(&name, &access, &self.trust, &proxy, limit, Some(DEFAULT_IDLE_TIMEOUT)).await {
            Ok(session) => Ok(Road::SshHttp(podssh_ssh::relay_stream::spawn(session).0)),
            Err(e) => Err(format!("wss://{name}/: {e}")),
        }
    }
}
