//! The public proxy nodes of aggregator lists, the last fallback of the
//! forward road (T-574, the operator's rulings Q78, Q79 and Q90). When each
//! relay host, each forwarder and each `ws://` form failed, podssh asks the
//! lists for VLESS and Trojan nodes and tries them in turn, a few at most
//! ([`podssh_ws::proxy_nodes`]). The lists, and the short list of nodes that
//! the binary falls back to where no list can be fetched, are the services of
//! the kinds `proxy-list` and `proxy-node` of `pod-services`: podssh holds no
//! host and no node of another party. A node is a third party that nobody
//! vouches for: it sees the target's name and the session's bytes, which SSH
//! and its host key keep private, so the line before the round says it, and
//! the line of the node that carries names its host. `PODSSH_PROXY_LISTS=no`
//! and `PODSSH_LAST_RESORT=no` turn it off. With no such service in the
//! catalog the round has nothing to try, says nothing and costs nothing.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use podssh_ssh::Log;
use podssh_ws::proxy_nodes::list::{self, Listed};
use podssh_ws::proxy_nodes::{carry, Carried, Dial};
use podssh_ws::vless::{self, AtEnd};
use podssh_ws::{ProxyChoice, Trust};

use crate::ssh::transport::Reached;

/// The kind of service in `pod-services` that holds a list's address.
pub const KIND_LIST: &str = "proxy-list";
/// The kind that holds the nodes of the binary, one `link` fact each.
pub const KIND_NODE: &str = "proxy-node";
/// The variable of these roads alone.
pub const LISTS_ENV: &str = "PODSSH_PROXY_LISTS";
/// The one variable of each last fallback of Q78 (T-548's Decision).
pub const LAST_RESORT_ENV: &str = "PODSSH_LAST_RESORT";

/// The bound on a node's session, its dial and its first word together.
pub const NODE_WAIT: Duration = Duration::from_secs(12);
/// The bound on a list's fetch.
pub const FETCH_WAIT: Duration = Duration::from_secs(15);
/// The nodes tried from one list, and in all: a list changes within hours,
/// so a run does not walk a list of thousands.
pub const PER_LIST: usize = 8;
pub const TOTAL: usize = 16;

/// A public list of nodes: where it is, from the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// What the catalog gives: the lists by rank, and the nodes of the binary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    pub lists: Vec<List>,
    /// Share links, tried only where no list could be read.
    pub built_in: Vec<String>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        self.lists.is_empty() && self.built_in.is_empty()
    }
}

/// The plan of the catalog of `pod-services`. A service without its
/// endpoint `list` or its fact `link` is left out: a bad row must not end
/// the fallback.
pub static PLAN: LazyLock<Plan> = LazyLock::new(|| {
    let lists = pod_services::of_kind(KIND_LIST)
        .filter_map(|s| {
            let e = s.endpoint("list").filter(|e| e.scheme() == "https")?;
            Some(List {
                id: s.id().into(),
                host: e.host().into(),
                port: e.port(),
                path: e.path().unwrap_or("/").into(),
            })
        })
        .collect();
    let built_in = pod_services::of_kind(KIND_NODE).filter_map(|s| s.text("link")).map(str::to_string).collect();
    Plan { lists, built_in }
});

/// Whether the round is on: neither variable says no. Another word is no
/// either, as the safe side of a road that sends the target to a stranger.
pub fn on_from(lists: Option<String>, last_resort: Option<String>) -> bool {
    let says_yes =
        |v: Option<String>| v.filter(|v| !v.trim().is_empty()).is_none_or(|v| super::fallback::word(&v) == Some(true));
    says_yes(lists) && says_yes(last_resort)
}

/// [`on_from`] for the process.
pub fn on() -> bool {
    on_from(std::env::var(LISTS_ENV).ok(), std::env::var(LAST_RESORT_ENV).ok())
}

/// The line before the round: what goes to whom, and the bounds.
pub fn announce(target: &str, plan: &Plan) -> String {
    let from = match (plan.lists.is_empty(), plan.built_in.is_empty()) {
        (false, _) => {
            let hosts: Vec<&str> = plan.lists.iter().map(|l| l.host.as_str()).collect();
            format!("the public lists of proxy nodes at {}", hosts.join(", "))
        }
        _ => "the short list of public proxy nodes that this binary names".to_string(),
    };
    format!(
        "no forwarder carried it: podssh sends {target} to a public VLESS or Trojan node from {from}, a third party \
         that nobody vouches for, which sees the target's name and the bytes of the session (SSH and its host key \
         keep them private); {TOTAL} nodes at most, {} s each; {LISTS_ENV}=no or {LAST_RESORT_ENV}=no turns this off",
        NODE_WAIT.as_secs()
    )
}

/// The line of the node that carried: its host, its road and its source.
pub fn carries_line(c: &Carried, source: &str, target: &str) -> String {
    format!(
        "the public {} node {} ({}, {source}) carries the session to {target}, in place of the relay; it is a third \
         party that nobody vouches for",
        c.node.road(),
        c.node.shown(),
        c.how
    )
}

/// The cache's name of a list's kept lines.
fn cached_name(list: &List) -> String {
    format!("proxy-nodes-{}.txt", list.id)
}

/// A list fetched, read, and its kept lines put in the cache.
async fn fetch(list: &List, trust: &Trust) -> Result<Listed, String> {
    let get = podssh_ws::client::https_get(
        &list.host,
        list.port,
        &list.path,
        list::MAX_BODY,
        trust,
        &ProxyChoice::FromEnvironment,
        FETCH_WAIT,
    );
    let response = get.await.map_err(|e| format!("the list at {}: {e}", list.host))?;
    if response.status != 200 {
        return Err(format!("the list at {}: HTTP {}", list.host, response.status));
    }
    let listed = list::parse(&response.body).map_err(|why| format!("the list at {}: {why}", list.host))?;
    if !listed.lines.is_empty() {
        // The cache is a convenience: a host that refuses a file does not end the round.
        let _ = podssh_relay::cache::store_file(&cached_name(list), listed.lines.join("\n").as_bytes());
    }
    Ok(listed)
}

/// The nodes that an earlier run kept for `list`, read again through the filters.
fn cached(list: &List) -> Option<Listed> {
    let text = podssh_relay::cache::load_file(&cached_name(list))?;
    list::parse(text.as_bytes()).ok().filter(|l| !l.nodes.is_empty())
}

/// How a session is asked of a node: a stream that SSH reads, or a pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Use {
    Stream,
    Pipe,
}

/// One round over `plan`: the lists in rank, each fetched (or read from the
/// cache where the fetch failed), then the binary's nodes where no list
/// could be read at all. `info` has the lines that say what is tried, `fail`
/// those of a failure.
pub async fn round(
    plan: &Plan,
    (host, port): (&str, u16),
    trust: &Trust,
    how: Use,
    info: &mut (dyn FnMut(&str) + Send),
    fail: &mut (dyn FnMut(&str) + Send),
) -> Option<(Carried, String)> {
    let dial = Dial {
        trust,
        proxy: &ProxyChoice::FromEnvironment,
        timeout: NODE_WAIT - Duration::from_secs(4),
        answer: if how == Use::Pipe { vless::EARLY_WAIT } else { NODE_WAIT - Duration::from_secs(4) },
        silence_is_ready: how == Use::Pipe,
        at_end: if how == Use::Pipe { AtEnd::AfterPeer } else { AtEnd::Now },
    };
    let mut tried = 0;
    let mut read_one = false;
    for list in &plan.lists {
        if tried >= TOTAL {
            return None;
        }
        let (listed, source) = match fetch(list, trust).await {
            Ok(listed) => (listed, format!("from the list at {}", list.host)),
            Err(why) => {
                fail(&why);
                match cached(list) {
                    Some(listed) => (listed, format!("from the list at {}, as an earlier run kept it", list.host)),
                    None => continue,
                }
            }
        };
        read_one = true;
        if let Some(note) = listed.note() {
            info(&format!("the list at {}: {note}", list.host));
        }
        let take = PER_LIST.min(TOTAL - tried).min(listed.nodes.len());
        tried += take;
        if let Ok(carried) = carry(&listed.nodes, host, port, &dial, (NODE_WAIT, take), &mut *fail).await {
            return Some((carried, source));
        }
    }
    if read_one {
        return None;
    }
    // No list could be read: the nodes that the binary names, each checked
    // before its release (Q90) and filtered here as a list's are.
    let listed = list::parse(plan.built_in.join("\n").as_bytes()).ok()?;
    let take = PER_LIST.min(listed.nodes.len());
    carry(&listed.nodes, host, port, &dial, (NODE_WAIT, take), fail)
        .await
        .ok()
        .map(|c| (c, "a node of this binary".into()))
}

/// The line before the round, or `None` where there is none to run: nothing
/// in the catalog, or a variable that says no.
pub fn announcement(target: &str) -> Option<String> {
    (!PLAN.is_empty() && on()).then(|| announce(target, &PLAN))
}

/// The stream for a session through a public node, once each other road of
/// the forward road failed; `None` when the round is off, has nothing to
/// try, or no node carries.
pub async fn after_stream(target: &str, trust: &Trust, (host, port): (&str, u16), log: &Arc<Log>) -> Option<Reached> {
    if PLAN.is_empty() {
        return None;
    }
    let Some(line) = announcement(target) else {
        log.verbose(&format!("the public proxy nodes are not tried: {LISTS_ENV} or {LAST_RESORT_ENV} says no"));
        return None;
    };
    log.info(&line);
    let (info_log, fail_log) = (log.clone(), log.clone());
    let mut info = move |line: &str| info_log.verbose(line);
    let mut fail = move |line: &str| fail_log.verbose(line);
    let (carried, source) = round(&PLAN, (host, port), trust, Use::Stream, &mut info, &mut fail).await?;
    log.info(&carries_line(&carried, &source, target));
    // A write that makes no progress fails as on the relay leg (T-227).
    let stream = podssh_ws::write_limit::WriteLimit::new(carried.stream, podssh_ws::client::WRITE_TIMEOUT);
    Some(Reached { stream: Box::new(stream), relay: None, direct_proxy: None, layer: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(lists: &[&str], nodes: &[&str]) -> Plan {
        let list = |h: &&str| List { id: h.replace('.', "-"), host: (*h).into(), port: 443, path: "/l.txt".into() };
        Plan { lists: lists.iter().map(list).collect(), built_in: nodes.iter().map(|n| n.to_string()).collect() }
    }

    /// The catalog of `pod-services` v0.7.0 has neither kind: the round has
    /// nothing to try and says nothing (T-574 waits for podcrates' list).
    #[test]
    fn a_catalog_with_no_list_and_no_node_is_an_empty_plan() {
        assert!(PLAN.lists.len() <= pod_services::of_kind(KIND_LIST).count());
        assert!(Plan::default().is_empty());
        assert!(!plan(&["l.example"], &[]).is_empty());
    }

    /// Each variable turns the round off, a bad word is no, and an empty
    /// one is no variable.
    #[test]
    fn the_round_is_on_unless_a_variable_says_no_or_a_word_that_is_not_yes() {
        let on = |a: Option<&str>, b: Option<&str>| on_from(a.map(str::to_string), b.map(str::to_string));
        assert!(on(None, None));
        assert!(on(Some("yes"), Some(" ")));
        assert!(!on(Some("no"), None));
        assert!(!on(None, Some("off")));
        assert!(!on(Some("maybe"), None), "a word that is not yes is no");
    }

    /// The line names each list's host, the third party, the end-to-end
    /// channel, the bound and both switches; and the binary's own list
    /// where no list is named.
    #[test]
    fn the_announcement_says_the_third_party_and_names_the_hosts() {
        let line = announce("192.0.2.1:22", &plan(&["l1.example", "l2.example"], &[]));
        assert!(line.starts_with("no forwarder carried it: podssh sends 192.0.2.1:22 to a public VLESS or Trojan node"));
        assert!(line.contains("at l1.example, l2.example"), "{line}");
        assert!(line.contains("a third party that nobody vouches for"), "{line}");
        assert!(line.contains("SSH and its host key keep them private"), "{line}");
        assert!(line.contains("16 nodes at most, 12 s each"), "{line}");
        assert!(line.ends_with("PODSSH_PROXY_LISTS=no or PODSSH_LAST_RESORT=no turns this off"), "{line}");
        let built = announce("192.0.2.1:22", &plan(&[], &["x"]));
        assert!(built.contains("the short list of public proxy nodes that this binary names"), "{built}");
    }

    /// With no list readable and no node of the binary, nothing is tried and
    /// no line is said; a list whose host cannot be reached is said once and
    /// the binary's nodes follow.
    #[tokio::test]
    async fn a_round_with_no_node_to_try_carries_nothing() {
        let (said, failed) = (std::sync::Mutex::new(Vec::<String>::new()), std::sync::Mutex::new(Vec::<String>::new()));
        let trust = Trust::Default;
        let mut info = |l: &str| said.lock().unwrap().push(l.into());
        let mut fail = |l: &str| failed.lock().unwrap().push(l.into());
        let got = round(&Plan::default(), ("127.0.0.1", 22), &trust, Use::Stream, &mut info, &mut fail).await;
        assert!(got.is_none() && said.lock().unwrap().is_empty() && failed.lock().unwrap().is_empty());
        // A built-in node that the filters refuse (a private address) is no node.
        let link = ["vless://550e8400-e29b-41d4", "-a716-446655440000@", "10.0.0.1:443?type=ws&security=tls"].concat();
        let junk = plan(&[], &[link.as_str()]);
        let got = round(&junk, ("127.0.0.1", 22), &trust, Use::Stream, &mut info, &mut fail).await;
        assert!(got.is_none() && failed.lock().unwrap().is_empty(), "{:?}", failed.lock().unwrap());
    }
}
