//! A node's net from a signed document at an `https://` URL (T-715): `podssh
//! node --net-url URL --net-owner KEY`, so that a change of a fleet needs no
//! copy of a file to each node. TLS alone is not the trust: each document is
//! checked against `--net-owner`, then taken by the rule of `store::take` (the
//! owner held, a higher serial, an end to come) in the place where each door
//! reads the net, so the door follows it at the next session. It is fetched
//! once before the node goes online (78 when that fails and no copy from the
//! URL is held), then again each `--net-ttl` (300 s, never under 60 s) on a
//! thread of its own, one read at a time, 64 KiB at most, through the host's
//! proxy, with no redirect: the ninth exception of rule 2 (Q105). A copy older
//! than its TTL and `--net-stale` (3600 s) closes the net's door to new
//! sessions; those that live go on. The record of the last fetch
//! (`net-url.json` in the cache) gives the copy's age to the next start and to
//! `podssh status --net`. The URL's path may hold a secret of its server: a
//! line and the record name its host alone. `podssh serve --gateway
//! net:NAME --net-url URL` reads its routes so (T-902, [`start_as`]).

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use podssh_relay::identity::KeyName;
use podssh_relay::serve::keys::list::Fetch;
use serde_json::{json, Value};
use sha2::Digest;

use super::sign;
use super::store::{self, Place, Taken};
use crate::node::NodeArgs;
use crate::relay_serve::keys_url::{Https, Url};
use crate::relay_settings::Refusal;
use crate::settings::Defaults;

/// How often the document is fetched again, by default, in seconds.
pub const TTL: u64 = 300;
/// The shortest `--net-ttl` (Q105).
pub const TTL_LEAST: u64 = 60;
const TTL_MOST: u64 = 86_400;
/// How long past its TTL a copy is read while its server fails, by default.
pub const STALE: u64 = 3600;
const STALE_MOST: u64 = 7 * 86_400;
/// The largest answer read (Q105): a document and its signature fit in it.
pub const DOC_MOST: usize = 64 * 1024;
/// The record of the last fetch, in the cache.
pub const RECORD: &str = "net-url.json";

/// Now, in ms since 1970: the process's clock, or a test's.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;
/// Where the node says its lines.
pub type Say = Arc<dyn Fn(String) + Send + Sync>;

/// What the node was asked, from its flags, else from the settings file.
pub(crate) struct Plan {
    /// The whole URL: it may hold a secret, and is never shown.
    pub url: String,
    pub owner: KeyName,
    pub ttl: u64,
    pub stale: u64,
}

/// The plan of `args`, the flags first, then `NetUrl` and `NetOwner` of
/// `file`; none without a URL. A fault of the words is a usage error (64).
pub(crate) fn plan_with(args: &NodeArgs, file: &Defaults) -> Result<Option<Plan>, Refusal> {
    let text = |value: &Option<crate::settings::Value>| value.as_ref().map(|v| v.text.clone());
    let url = args.net_url.clone().or_else(|| text(&file.net_url));
    let Some(url) = url else {
        if args.net_owner.is_some() || args.net_ttl.is_some() || args.net_stale.is_some() {
            return Err(Refusal::usage("--net-owner, --net-ttl and --net-stale go with --net-url URL"));
        }
        return Ok(None);
    };
    check_url(&url).map_err(|why| Refusal::usage(format!("--net-url: {why}")))?;
    if args.temporary.is_some() {
        return Err(Refusal::usage("--net-url does not go with --temporary, whose door is one client key"));
    }
    let owner = args.net_owner.clone().or_else(|| text(&file.net_owner)).ok_or_else(|| {
        Refusal::usage("--net-url needs --net-owner KEY: the owner's signature is the trust of a net, never TLS alone")
    })?;
    let owner = owner_of(&owner).map_err(Refusal::usage)?;
    let ttl = seconds("--net-ttl", args.net_ttl.as_deref(), TTL_LEAST, TTL_MOST, TTL)?;
    let stale = seconds("--net-stale", args.net_stale.as_deref(), 0, STALE_MOST, STALE)?;
    Ok(Some(Plan { url, owner, ttl, stale }))
}

/// The owner of `--net-owner KEY`: its OpenSSH key, by the fingerprint
/// that a document's owner has, or that fingerprint itself.
pub(crate) fn owner_of(text: &str) -> Result<KeyName, String> {
    super::owner_key_name(text)
        .or_else(|| KeyName::parse(text.trim()))
        .ok_or_else(|| format!("--net-owner {text:?}: not a key's fingerprint (SHA256:...) nor an OpenSSH public key"))
}

/// A URL of a net's document: `https://` alone, as an `http://` one would
/// come in cleartext and a hop could keep an old serial; no user in it.
pub(crate) fn check_url(url: &str) -> Result<(), String> {
    let scheme = url.get(..8).unwrap_or(url).to_ascii_lowercase();
    if scheme.starts_with("http://") {
        return Err("a net's document is fetched over TLS alone: give its https:// URL".into());
    }
    if scheme != "https://" {
        return Err(format!("{:?} is not an https:// URL", shown_head(url)));
    }
    Url::parse(url).map(|_| ())
}

/// The start of a word that is no URL, so that a path is never shown whole.
fn shown_head(word: &str) -> String {
    word.chars().take(12).collect()
}

/// `text` of `flag` as whole seconds from `least` to `most`; `default` with
/// none.
fn seconds(flag: &str, text: Option<&str>, least: u64, most: u64, default: u64) -> Result<u64, Refusal> {
    let Some(text) = text else { return Ok(default) };
    match text.trim().parse::<u64>() {
        Ok(n) if (least..=most).contains(&n) => Ok(n),
        _ => Err(Refusal::usage(format!("{flag} {text:?}: seconds, from {least} to {most}"))),
    }
}

/// What a fetch came to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Got {
    /// A newer document, taken in place of the serial before (none: the first).
    New { serial: u64, before: Option<u64> },
    /// The document held: the copy is new again.
    Same(u64),
}

impl Got {
    fn words(&self) -> String {
        match self {
            Got::New { serial, before: Some(before) } => format!("serial {serial}, in place of {before}"),
            Got::New { serial, before: None } => format!("serial {serial}, the first held here"),
            Got::Same(serial) => format!("serial {serial}, the one held"),
        }
    }
}

/// The copy's state: when the server last gave a document that holds, its
/// serial, and the last fault.
#[derive(Debug, Clone, Default)]
struct State {
    at_ms: Option<i64>,
    serial: Option<u64>,
    error: Option<String>,
    /// The line of a door that closed was said: once until it opens.
    closed_said: bool,
}

/// The net of a URL, as a node keeps it.
pub struct Remote {
    from: Box<dyn Fetch>,
    owner: KeyName,
    ttl: u64,
    stale: u64,
    place: Place,
    clock: Clock,
    /// The URL's digest: the record names it so, never by its path.
    id: String,
    /// Where the record goes; none keeps none (a test's).
    dirs: Option<Vec<PathBuf>>,
    state: Mutex<State>,
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(|e| e.into_inner())
}

/// The digest of a URL, in hex.
pub(crate) fn id_of(url: &str) -> String {
    sha2::Sha256::digest(url.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

impl Remote {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from: Box<dyn Fetch>,
        owner: KeyName,
        ttl: u64,
        stale: u64,
        place: Place,
        clock: Clock,
        id: String,
        dirs: Option<Vec<PathBuf>>,
    ) -> Remote {
        Remote { from, owner, ttl, stale, place, clock, id, dirs, state: Mutex::new(State::default()) }
    }

    /// `https://HOST/...`.
    pub fn shown(&self) -> String {
        self.from.shown()
    }

    /// Why the net's door is closed now, or none: no copy came, or the copy
    /// is past its TTL and its stale window.
    pub fn closed(&self) -> Option<String> {
        let now = (self.clock)();
        let state = lock(&self.state);
        let limit = i64::try_from(self.ttl.saturating_add(self.stale).saturating_mul(1000)).unwrap_or(i64::MAX);
        match state.at_ms {
            None => Some(format!("no copy of the net from {} has come, so the net lets nobody in", self.shown())),
            Some(at) if now >= at.saturating_add(limit) => Some(format!(
                "the copy of the net from {} of {} s ago is past --net-ttl and --net-stale, so the net lets \
                 nobody in until a fetch works",
                self.shown(),
                now.saturating_sub(at) / 1000
            )),
            Some(_) => None,
        }
    }

    /// Take `body`, the server's answer: the owner's document, by the rule of
    /// the store. Its owner is checked first, against `--net-owner`.
    pub fn accept(&self, body: &[u8]) -> Result<Got, String> {
        if body.len() > DOC_MOST {
            return Err("an answer of more than 64 KiB, which no net's document is".into());
        }
        let signed = sign::verify_signed(body)?;
        owner_is(&signed, &self.owner)?;
        let serial = signed.doc.serial;
        match store::take_at(&self.place, &signed, Some(&self.owner), (self.clock)() / 1000) {
            Ok(Taken::Kept { before, .. }) => Ok(Got::New { serial, before }),
            Ok(Taken::Same) => Ok(Got::Same(serial)),
            Err(why) => Err(format!("not taken: {why}")),
        }
    }

    /// Fetch the document once, now, and take it; the record follows.
    pub async fn refresh(&self) -> Result<Got, String> {
        let got = self.from.fetch().await.and_then(|body| self.accept(&body));
        let now = (self.clock)();
        {
            let mut state = lock(&self.state);
            match &got {
                Ok(Got::New { serial, .. } | Got::Same(serial)) => {
                    *state = State { at_ms: Some(now), serial: Some(*serial), error: None, closed_said: false };
                }
                Err(why) => state.error = Some(why.clone()),
            }
        }
        self.record(now);
        got
    }

    /// The copy of an earlier run, when its record names this URL and the
    /// owner, and the document held is the one it fetched: its age goes on.
    pub fn earlier(&self) {
        let Some(dirs) = &self.dirs else { return };
        let Some(text) = podssh_relay::cache::load_file_from(dirs, RECORD) else { return };
        let Ok(record) = serde_json::from_str::<Value>(&text) else { return };
        let held = store::held_at(&self.place).ok().flatten().map(|held| held.signed.doc.serial);
        let same = record["id"].as_str() == Some(self.id.as_str())
            && record["owner"].as_str() == Some(self.owner.fingerprint().as_str())
            && held.is_some()
            && record["serial"].as_u64() == held;
        if let (true, Some(at)) = (same, record["fetched_ms"].as_i64()) {
            *lock(&self.state) = State { at_ms: Some(at), serial: held, ..State::default() };
        }
    }

    /// The age of the copy, in seconds, when there is one.
    pub fn age_s(&self) -> Option<i64> {
        let at = lock(&self.state).at_ms?;
        Some(((self.clock)() - at).max(0) / 1000)
    }

    /// Keep the record of the last fetch, for the next start and for
    /// `status --net`; a cache that takes none keeps none.
    fn record(&self, now: i64) {
        let Some(dirs) = &self.dirs else { return };
        let state = lock(&self.state).clone();
        let value = json!({
            "url": self.shown(),
            "id": self.id,
            "owner": self.owner.fingerprint(),
            "serial": state.serial,
            "fetched_ms": state.at_ms,
            "ttl_s": self.ttl,
            "stale_s": self.stale,
            "error": state.error,
            "checked_ms": now,
        });
        let _ = podssh_relay::cache::store_file_in_first(dirs, RECORD, value.to_string().as_bytes());
    }

    /// The fetches after the first, each TTL, one at a time, for as long as
    /// the caller's runtime runs: a line for a newer serial, for a fetch that
    /// fails and the first that works after it, and once for a door that
    /// closes.
    pub async fn keep(self: Arc<Self>, say: Say) {
        let mut failing = false;
        loop {
            tokio::time::sleep(Duration::from_secs(self.ttl)).await;
            let got = self.refresh().await;
            match &got {
                Ok(got @ Got::New { .. }) => say(format!("the net from {}: {}", self.shown(), got.words())),
                Ok(got) if failing => say(format!("the net from {}: fetched again, {}", self.shown(), got.words())),
                Ok(_) => {}
                Err(why) => {
                    let holds = match self.closed() {
                        None => "its copy is read until --net-stale passes",
                        Some(_) => "the net lets nobody in until a fetch works",
                    };
                    say(format!("the net from {}: {why}; {holds}", self.shown()));
                }
            }
            failing = got.is_err();
            if let Some(why) = self.closed() {
                let said = std::mem::replace(&mut lock(&self.state).closed_said, true);
                if !said {
                    say(why);
                }
            }
        }
    }
}

/// `signed`'s owner is `named`, else why not: the check of `--net-owner`,
/// for each document, the first and each later one.
pub(crate) fn owner_is(signed: &sign::Signed, named: &KeyName) -> Result<(), String> {
    let print = sign::owner_fingerprint(&signed.doc.owner);
    match named.fingerprint() == print {
        true => Ok(()),
        false => Err(format!("its owner is {print}, and --net-owner names {}", named.fingerprint())),
    }
}

/// The net of the URL of this process, once it started.
static REMOTE: OnceLock<Arc<Remote>> = OnceLock::new();

/// Why the net's door of this node is closed, when it reads its net from a
/// URL whose copy is too old; none otherwise.
pub fn door_closed() -> Option<String> {
    REMOTE.get()?.closed()
}

/// The net of `--net-url`, fetched before the node goes online, then kept
/// on a thread of its own; nothing without the flag. A first fetch that
/// fails with no copy from the URL held stops the start (78). A detached
/// node's first process checks the words alone: its child fetches.
pub(crate) fn start(args: &NodeArgs) -> Result<(), Refusal> {
    let label = args.name.clone().unwrap_or_default();
    start_as(args, Reader { head: format!("podssh node: {label}"), fresh_enough: false })
}

/// Who reads the net of the URL: the head of its lines, and whether a copy
/// from the URL younger than its TTL is read with no fetch at the start.
pub(crate) struct Reader {
    pub head: String,
    /// `podssh serve --stdio --gateway net:NAME` (T-902) starts once for
    /// each client, as a ProxyCommand: a fetch at each start would break
    /// Q105's one GET each TTL.
    pub fresh_enough: bool,
}

/// [`start`] for `reader`: `podssh serve` reads the net of `--net-url` so too.
pub(crate) fn start_as(args: &NodeArgs, reader: Reader) -> Result<(), Refusal> {
    // One reader of a URL for a process: `serve NAME --gateway net:NAME`
    // started it before its node, whose own start finds it here.
    if REMOTE.get().is_some() {
        return Ok(());
    }
    let Some(plan) = plan_with(args, crate::settings::here())? else { return Ok(()) };
    let place = match store::place() {
        Ok(Place::Off) => return Err(Refusal::config(format!("--net-url: {}=no turns the net off", store::ENV))),
        Ok(place) => place,
        Err(why) => return Err(Refusal::config(why)),
    };
    if args.detach && !crate::detach::is_child() {
        return Ok(());
    }
    let url = Url::parse(&plan.url).map_err(|why| Refusal::usage(format!("--net-url: {why}")))?;
    // --relay-addr and its kin name the URL's host too, as each road reads them.
    crate::pins::apply(args.relay_addr.as_deref())?;
    // One GET for each fetch: a net's document follows no redirect (Q105).
    let from = Https::new(url, crate::pairs::trust(args.ca_file.as_deref()), DOC_MOST, 0);
    let dirs = Some(podssh_relay::cache::candidate_dirs());
    let (ttl, stale) = (plan.ttl, plan.stale);
    let clock: Clock = Arc::new(crate::pairs::now_ms);
    let remote = Remote::new(Box::new(from), plan.owner, ttl, stale, place, clock, id_of(&plan.url), dirs);
    let remote = Arc::new(remote);
    remote.earlier();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Refusal::config(format!("could not start the async runtime: {e}")))?;
    let fresh = reader.fresh_enough && remote.age_s().is_some_and(|age| age < i64::try_from(ttl).unwrap_or(i64::MAX));
    let first = if fresh { None } else { Some(runtime.block_on(remote.refresh())) };
    runtime.shutdown_timeout(Duration::from_secs(1));
    let head = reader.head;
    let say: Say = Arc::new(move |line: String| podssh_ssh::err_line!("{head}: {line}"));
    let shown = remote.shown();
    let read = format!("fetched again each {ttl} s, and read {stale} s more while its server fails");
    match (first, remote.age_s()) {
        (Some(Ok(got)), _) => say(format!("the net from {shown}: {}; {read}", got.words())),
        (None, Some(age)) => {
            say(format!("the net from {shown}: its copy of {age} s ago is read, younger than {ttl} s"))
        }
        (Some(Err(why)), Some(age)) => {
            say(format!("the net from {shown}: {why}; its copy of {age} s ago is read; {read}"))
        }
        (Some(Err(why)), None) => return Err(Refusal::config(format!("--net-url {shown}: {why}"))),
        (None, None) => return Err(Refusal::config(format!("--net-url {shown}: no copy from it is held"))),
    }
    if let Some(why) = remote.closed() {
        say(why);
    }
    let _ = REMOTE.set(Arc::clone(&remote));
    std::thread::Builder::new()
        .name("net-url".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return };
            runtime.block_on(remote.keep(say));
        })
        .map_err(|e| Refusal::config(format!("could not start the fetches of --net-url: {e}")))?;
    Ok(())
}

/// The field `url` of `status --net`: the record of the last fetch, with the
/// copy's age, whether it is past its TTL (stale) and past its stale window
/// too (closed); null with no record.
pub fn status_value(now_ms: i64) -> Value {
    let dirs = podssh_relay::cache::candidate_dirs();
    match podssh_relay::cache::load_file_from(&dirs, RECORD) {
        Some(text) => status_of(&text, now_ms),
        None => Value::Null,
    }
}

/// [`status_value`] of a record's `text`.
pub(crate) fn status_of(text: &str, now_ms: i64) -> Value {
    let Ok(record) = serde_json::from_str::<Value>(text) else { return json!({ "error": "the record does not read" }) };
    let (ttl, stale) = (record["ttl_s"].as_i64().unwrap_or(0), record["stale_s"].as_i64().unwrap_or(0));
    let age = record["fetched_ms"].as_i64().map(|at| (now_ms - at).max(0) / 1000);
    json!({
        "url": record["url"],
        "serial": record["serial"],
        "age_s": age,
        "ttl_s": ttl,
        "stale_s": stale,
        "stale": age.is_none_or(|age| age >= ttl),
        "closed": age.is_none_or(|age| age >= ttl.saturating_add(stale)),
        "error": record["error"],
    })
}

#[cfg(test)]
#[path = "remote_tests.rs"]
mod tests;
