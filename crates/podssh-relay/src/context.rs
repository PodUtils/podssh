//! podssh's context of the relay client (`pod-relay` of PodUtils/podcrates,
//! T-684): each call that reaches a relay takes a `pod_relay::Context`, and
//! podssh makes it here from its own parts. The way out is podssh-ws's for a
//! [`ProxyChoice`]; the places of the cache are podssh's (`PODSSH_CACHE_DIR`);
//! the settings are the `PODSSH_*` variables, read at each call as podssh read
//! them, with what the settings file and the net gave the process; the
//! resolver is the process's. The state that the sessions of the process share
//! (the gates of each origin, the limits in use, the races of the rank, the
//! pool of HTTP/2, what the QUIC road learned) is one for the process: each
//! context is a clone of one base.

use std::sync::{Arc, OnceLock, PoisonError, RwLock};

use pod_identity::KeyName;
use pod_relay::cache::Cache;
use pod_relay::context::ProxyOf;
use pod_relay::gate::Gates;
use pod_relay::pool::members::Member;
pub use pod_relay::{Context, Names, Settings};
use podssh_ws::ProxyChoice;

/// What the settings file and the net gave the process: no variable holds it.
struct Given {
    keys: Vec<(KeyName, String)>,
    members: Vec<Member>,
    rank: bool,
    rank_auto: bool,
}

static GIVEN: RwLock<Given> =
    RwLock::new(Given { keys: Vec::new(), members: Vec::new(), rank: true, rank_auto: false });

/// The base of each context: it holds the shared state of the process.
static BASE: OnceLock<Context> = OnceLock::new();

fn base() -> &'static Context {
    BASE.get_or_init(|| Context::new(podssh_ws::client::way(&ProxyChoice::FromEnvironment), cache()))
}

/// The context of the process, through the proxy that the environment names.
pub fn process() -> Context {
    of(&ProxyChoice::FromEnvironment)
}

/// The context of the process, through `proxy`: the settings and the cache
/// as the environment gives them now, and the resolver that the dialer takes
/// now (`--relay-addr` makes it again).
pub fn of(proxy: &ProxyChoice) -> Context {
    let mut ctx = base()
        .clone()
        .with_way(podssh_ws::client::way(proxy))
        .with_proxy_of(proxy_of(proxy))
        .with_resolver(podssh_ws::resolve::resolver())
        .with_settings(settings());
    ctx.cache = cache();
    ctx
}

/// The gates of each relay origin, which the sessions of the process share.
pub fn gates() -> &'static Gates {
    base().gates()
}

/// The proxy that the dialer of `proxy` takes for a host.
fn proxy_of(proxy: &ProxyChoice) -> ProxyOf {
    match proxy.clone() {
        ProxyChoice::FromEnvironment => Arc::new(|host| podssh_ws::dial::proxy_from_env(host).ok().flatten()),
        ProxyChoice::Direct => Arc::new(|_| None),
        ProxyChoice::Via(via) => Arc::new(move |_| Some(via.clone())),
    }
}

/// podssh's places of the cache, as `PODSSH_CACHE_DIR` says now.
pub fn cache() -> Cache {
    let var = |name: &str| std::env::var_os(name);
    Cache::new(crate::cache::pod_places(), pod_core::files::chosen_from(&crate::cache::POD_APP, &var))
}

/// The settings of the relay client: each variable as the environment holds
/// it now, and what the settings file and the net gave the process.
pub fn settings() -> Settings {
    let var = |name: &str| std::env::var(name).ok();
    let given = GIVEN.read().unwrap_or_else(PoisonError::into_inner);
    Settings {
        token: var(crate::token::TOKEN_ENV),
        offline: crate::open::offline(),
        keys: var(crate::pool::signed::KEYS_ENV),
        keys_by_settings: given.keys.clone(),
        members: given.members.clone(),
        rank: var(crate::rank_list::ENV),
        rank_by_file: given.rank,
        rank_auto_by_file: given.rank_auto,
        rank_pace: var(crate::rank_auto::PACE_ENV),
        h2: var(crate::h2_road::H2_ENV),
        quic: var(crate::quic_road::QUIC_ENV),
        cleartext: var(crate::cleartext::CLEARTEXT_ENV),
        names: Names::podssh(),
    }
}

/// The keys of the settings file and of the net's relay members.
pub(crate) fn give_keys(keys: Vec<(KeyName, String)>) {
    GIVEN.write().unwrap_or_else(PoisonError::into_inner).keys = keys;
}

/// The relay members of the net that this host holds.
pub(crate) fn give_members(members: Vec<Member>) {
    GIVEN.write().unwrap_or_else(PoisonError::into_inner).members = members;
}

/// The settings file's `RelayRank no` (`false`).
pub(crate) fn give_rank(on: bool) {
    GIVEN.write().unwrap_or_else(PoisonError::into_inner).rank = on;
}

/// The settings file's `RelayRank auto`.
pub(crate) fn give_rank_auto(auto: bool) {
    GIVEN.write().unwrap_or_else(PoisonError::into_inner).rank_auto = auto;
}

/// The members that the net gave the process.
pub(crate) fn members() -> Vec<Member> {
    GIVEN.read().unwrap_or_else(PoisonError::into_inner).members.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each context of the process shares one state, and speaks with
    /// podssh's names and user agent, whatever its proxy.
    #[test]
    fn each_context_of_the_process_shares_its_state_and_names_podssh() {
        let (here, direct) = (process(), of(&ProxyChoice::Direct));
        assert!(std::ptr::eq(here.gates(), direct.gates()), "one gate of each origin for the process");
        assert!(std::ptr::eq(here.gates(), gates()));
        assert!(Arc::ptr_eq(here.races(), direct.races()), "one count of the races");
        assert_eq!(direct.settings.names, Names::podssh());
        assert_eq!(direct.way.user_agent, podssh_ws::dial::user_agent());
        assert!((direct.proxy_of)("relay.example").is_none(), "a direct context names no proxy");
    }
}
