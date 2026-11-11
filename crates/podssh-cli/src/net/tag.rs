//! A destination that names a tag (T-750, the block "agentanycast 4" of
//! PodUtils/podnet#438): `[user@]tag:NAME` is each member of the net held
//! that the policy's tag NAME holds and that has the role `node`, in a
//! shuffled order, so that the load of many runs spreads, with each member
//! that missed in the last [`HOLD`] put last, so that a node that is down is
//! not asked first again and again. `podssh ssh` opens them in turn until a
//! race reaches one; a member is left for the next only when no road reached
//! it, so a command that started is never run again on another. The holds
//! are kept in the cache (`net-tag-holds.json`), by name and time alone.

use std::collections::BTreeMap;
use std::time::Duration;

use rand::seq::SliceRandom;
use serde_json::Value;

use super::store;

/// How long a member that no road reached goes last.
pub const HOLD: Duration = Duration::from_secs(30);
/// The cache's file of the holds.
const FILE: &str = "net-tag-holds.json";

/// `[user@]tag:NAME` as the user and NAME; `None` for another destination.
pub fn parse(text: &str) -> Option<(Option<String>, String)> {
    let (user, rest) = match text.rsplit_once('@') {
        Some((user, rest)) if !user.is_empty() => (Some(user.to_string()), rest),
        Some(_) => return None,
        None => (None, text),
    };
    rest.strip_prefix("tag:").map(|tag| (user, tag.to_string()))
}

/// The names of the members that `tag` holds with the role `node`, in the
/// document held; why none, as a usage error.
pub fn members(tag: &str) -> Result<Vec<String>, String> {
    let held = store::held_or_none().ok_or("tag:NAME names a tag of the net held, and this host holds no net")?;
    let doc = &held.signed.doc;
    let Some(policy) = &doc.policy else {
        return Err(format!("tag:{tag}: the net {} has no policy, so no tags", doc.name));
    };
    let names: Vec<String> = doc
        .members
        .iter()
        .filter(|m| m.has_role("node") && policy.tagged(tag, &m.name))
        .map(|m| m.name.clone())
        .collect();
    match names.is_empty() {
        true => Err(format!("tag:{tag}: no member of the net {} with the role node has the tag {tag}", doc.name)),
        false => Ok(names),
    }
}

/// `names` shuffled, each held at `now_ms` put last, in the order of their holds.
pub fn order(mut names: Vec<String>, holds: &BTreeMap<String, u64>, now_ms: u64) -> Vec<String> {
    names.shuffle(&mut rand::rng());
    let held_until = |name: &String| holds.get(name).copied().filter(|until| *until > now_ms);
    let (mut held, free): (Vec<String>, Vec<String>) = names.into_iter().partition(|n| held_until(n).is_some());
    held.sort_by_key(|n| held_until(n));
    free.into_iter().chain(held).collect()
}

/// The holds kept: each member's end of hold, in milliseconds since 1970.
pub fn holds() -> BTreeMap<String, u64> {
    let text = podssh_relay::cache::load_file(FILE).unwrap_or_default();
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let pairs = value.as_object().into_iter().flatten();
    pairs.filter_map(|(name, until)| Some((name.clone(), until.as_u64()?))).collect()
}

/// Hold `name` for [`HOLD`] from `now_ms`; the holds that ended go. A hold
/// that cannot be kept costs the order, nothing else.
pub fn hold(name: &str, now_ms: u64) {
    let mut all = holds();
    all.retain(|_, until| *until > now_ms);
    all.insert(name.to_string(), now_ms + HOLD.as_millis() as u64);
    let _ = podssh_relay::cache::store_file(FILE, serde_json::to_string(&all).unwrap_or_default().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tag_destination_and_its_user() {
        assert_eq!(parse("tag:arm64"), Some((None, "arm64".to_string())));
        assert_eq!(parse("ci@tag:arm64"), Some((Some("ci".to_string()), "arm64".to_string())));
        assert_eq!(parse("node://lab"), None);
        assert_eq!(parse("@tag:x"), None);
    }

    /// The Prove's case: 20 orders in the hold never put the held member first.
    #[test]
    fn a_held_member_goes_last_and_the_others_are_shuffled() {
        let names: Vec<String> = ["a", "b", "c"].iter().map(|n| n.to_string()).collect();
        let holds = BTreeMap::from([("a".to_string(), 10_000)]);
        let mut firsts = std::collections::BTreeSet::new();
        for _ in 0..20 {
            let order = order(names.clone(), &holds, 5_000);
            assert_eq!(order.last().map(String::as_str), Some("a"), "{order:?}");
            firsts.insert(order[0].clone());
        }
        assert!(firsts.len() == 2, "b and c each come first some time: {firsts:?}");
        let ended = order(names, &holds, 20_000);
        assert_eq!(ended.len(), 3, "a hold that ended orders nothing");
    }
}
