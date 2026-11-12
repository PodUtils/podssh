//! HyperDHT as a road of a pair where UDP passes (T-736, the operator's
//! rulings Q77 and Q82, after Yggdrasil's road): each end joins HyperDHT
//! through its bootstrap nodes, the node announces a topic of a key that the
//! pair's connect token makes, and the client connects by that key, a hole
//! punched through both NATs. The bootstrap comes from the service
//! `hyperdht-bootstrap` of `pod-services` (asked of podcrates as a COORD
//! issue); `PODSSH_HYPERDHT=HOST:PORT[,HOST:PORT...]` names a DHT of the
//! user's own, which `PODSSH_LAST_RESORT` leaves on; `PODSSH_HYPERDHT=no`,
//! or `PODSSH_LAST_RESORT=no` for the public DHT, turns the road off. A build
//! without the feature `hyperdht` has no road, and says nothing of it.

use crate::relay_settings::Refusal;

/// `no` turns the road off; `HOST:PORT[,...]` names a DHT of one's own.
pub const ENV: &str = "PODSSH_HYPERDHT";
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The id of the bootstrap nodes in `pod-services`.
pub const SERVICE_ID: &str = "hyperdht-bootstrap";

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable or list that says so.
    Off(&'static str),
    /// The bootstrap nodes; whether they are `pod-services`' own.
    On(Vec<String>, bool),
}

fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// A bootstrap node as HyperDHT takes it: `HOST:PORT`, or `IP@NAME:PORT`.
fn node(text: &str) -> Option<String> {
    let text = text.trim();
    let (host, port) = text.rsplit_once(':')?;
    let host = host.rsplit('@').next().unwrap_or_default();
    let fine = !host.is_empty() && port.parse::<u16>().is_ok_and(|p| p > 0) && !text.contains(char::is_whitespace);
    fine.then(|| text.to_string())
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// with `listed`, the bootstrap of `pod-services`. A DHT that the user names
/// is no third party's: [`LAST_RESORT`] leaves it on.
pub fn setting_of(value: Option<&str>, last: Option<&str>, listed: Vec<String>) -> Result<Setting, String> {
    let said = says_no(value);
    if said.is_none() {
        let refused = || format!("{ENV} is no, or the bootstrap of a DHT, HOST:PORT[,HOST:PORT...]");
        let nodes: Option<Vec<String>> = value.unwrap_or_default().split(',').map(node).collect();
        return Ok(Setting::On(nodes.filter(|n| !n.is_empty()).ok_or_else(refused)?, false));
    }
    if said == Some(true) {
        return Ok(Setting::Off(ENV));
    }
    if says_no(last).unwrap_or(true) {
        return Ok(Setting::Off(LAST_RESORT));
    }
    if listed.is_empty() {
        return Ok(Setting::Off("pod-services"));
    }
    Ok(Setting::On(listed, true))
}

/// The bootstrap of `pod-services`: none until its service lists it.
fn listed() -> Vec<String> {
    let Some(service) = pod_services::get(SERVICE_ID) else { return Vec::new() };
    service.texts("nodes").unwrap_or_default().iter().filter_map(|n| node(n)).collect()
}

/// The variables, read.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    setting_of(value.as_deref(), last.as_deref(), listed()).map_err(Refusal::config)
}

/// The bootstrap, when the road is on in this build; whether it is the
/// public DHT's.
pub(crate) fn bootstrap() -> Option<(Vec<String>, bool)> {
    match setting() {
        Ok(Setting::On(nodes, public)) if cfg!(feature = "hyperdht") => Some((nodes, public)),
        _ => None,
    }
}

/// The line of Q78, before this end joins the public DHT.
pub fn third_party_line() -> String {
    format!(
        "HyperDHT's public network carries this session where UDP passes, a road of Q77 and Q82: its nodes see this \
         end's address and the node's topic, and the hole punched between the two ends; the end-to-end channel keeps \
         the bytes ({ENV}=no turns it off)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `pod-services` of podcrates v0.28.0 lists HyperDHT's three bootstrap
    /// nodes: each reads.
    #[test]
    fn the_listed_bootstrap_reads() {
        let nodes = listed();
        let named = pod_services::get(SERVICE_ID).and_then(|s| s.texts("nodes")).map_or(0, |t| t.len());
        assert_eq!(nodes.len(), named, "a node left out: {nodes:?}");
        assert!(nodes.len() >= 3, "{nodes:?}");
    }

    #[test]
    fn the_variables_turn_the_road_off_or_name_a_dht() {
        let listed = vec!["192.0.2.1@node.example.net:49737".to_string()];
        assert_eq!(setting_of(None, None, listed.clone()), Ok(Setting::On(listed.clone(), true)));
        assert_eq!(setting_of(None, None, Vec::new()), Ok(Setting::Off("pod-services")));
        assert_eq!(setting_of(Some("no"), None, listed.clone()), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), listed.clone()), Ok(Setting::Off(LAST_RESORT)));
        let own = setting_of(Some("127.0.0.1:49737, 127.0.0.1:49738"), Some("no"), Vec::new()).unwrap();
        assert_eq!(own, Setting::On(vec!["127.0.0.1:49737".into(), "127.0.0.1:49738".into()], false));
        for refused in ["127.0.0.1", "host:0", "host:x", ":1", "a b:1", "127.0.0.1:1,"] {
            assert!(setting_of(Some(refused), None, Vec::new()).unwrap_err().contains(ENV), "{refused}");
        }
        assert!(third_party_line().contains("PODSSH_HYPERDHT=no"));
    }
}
