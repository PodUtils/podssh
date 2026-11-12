//! Yggdrasil's network as a road of a pair (T-735), a last fallback of the
//! operator's ruling Q78 after the Tox road: each end links to one public
//! `wss://` peer of the network by one connection through `HTTPS_PROXY`,
//! and the two reach each other by their keys across it, the node under a
//! key that the pair's connect token makes. The peers come from the service
//! `yggdrasil-wss-peer` of `pod-services` (asked of podcrates as a COORD
//! issue), picked by the SHA-256 of the pair's name, so that both ends take
//! the same one and the path between them is short; `PODSSH_YGGDRASIL=URL`
//! names a peer of the user's own (yggdrasil-go with a `ws://` or `wss://`
//! Listen), which `PODSSH_LAST_RESORT` leaves on; `PODSSH_YGGDRASIL=no`, or
//! `PODSSH_LAST_RESORT=no` for the listed peers, turns the road off. A build
//! without the feature `yggdrasil` has no road, and says nothing of it.

use crate::relay_settings::Refusal;

/// `no` turns the road off; a `wss://` or `ws://` URL names a peer of one's own.
pub const ENV: &str = "PODSSH_YGGDRASIL";
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The id of the peers in `pod-services`.
pub const SERVICE_ID: &str = "yggdrasil-wss-peer";

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable or list that says so.
    Off(&'static str),
    /// The peers to pick from; whether they are `pod-services`' own.
    On(Vec<String>, bool),
}

fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// A peer's URL as the road takes it: `wss://` or `ws://`, and a host.
fn peer_url(text: &str) -> Option<String> {
    let text = text.trim();
    let rest = text.strip_prefix("wss://").or_else(|| text.strip_prefix("ws://"))?;
    let host = rest.split('/').next().unwrap_or_default();
    (!host.is_empty() && !host.starts_with(':') && !text.contains(char::is_whitespace)).then(|| text.to_string())
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// with `listed`, the peers of `pod-services`. A peer that the user names
/// is no third party's: [`LAST_RESORT`] leaves it on.
pub fn setting_of(value: Option<&str>, last: Option<&str>, listed: Vec<String>) -> Result<Setting, String> {
    let said = says_no(value);
    if said.is_none() {
        let refused = || format!("{ENV} is no, or a peer's wss://HOST[:PORT][/PATH]");
        let url = peer_url(value.unwrap_or_default()).ok_or_else(refused)?;
        return Ok(Setting::On(vec![url], false));
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

/// The peers of `pod-services`: none until its service lists them.
fn listed() -> Vec<String> {
    let Some(service) = pod_services::get(SERVICE_ID) else { return Vec::new() };
    service.texts("urls").unwrap_or_default().iter().filter_map(|url| peer_url(url)).collect()
}

/// The variables, read.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    setting_of(value.as_deref(), last.as_deref(), listed()).map_err(Refusal::config)
}

/// Whether the road is on in this build.
pub(crate) fn on() -> bool {
    cfg!(feature = "yggdrasil") && matches!(setting(), Ok(Setting::On(..)))
}

/// The peer of the pair `name`, when the road is on in this build; whether
/// it is `pod-services`' own.
pub(crate) fn peer_for(name: &str) -> Option<(String, bool)> {
    match setting() {
        Ok(Setting::On(peers, public)) if cfg!(feature = "yggdrasil") => Some((pick(name, &peers)?.clone(), public)),
        _ => None,
    }
}

/// The peer among `peers` for the pair `name`, by the SHA-256 of the name.
fn pick<'a>(name: &str, peers: &'a [String]) -> Option<&'a String> {
    use sha2::{Digest, Sha256};
    if peers.is_empty() {
        return None;
    }
    let digest = Sha256::digest(name.as_bytes());
    let n = u64::from_be_bytes(digest[..8].try_into().unwrap_or_default());
    peers.get((n % peers.len() as u64) as usize)
}

/// The line of Q78, before the first byte goes to the peer.
pub fn third_party_line(peer: &str) -> String {
    format!(
        "the public peer {peer} of Yggdrasil's network carries this session, a last fallback of Q78: this end joins \
         the network and routes for it while the road is up; the peers on the path see the two ends' keys, the \
         times and the sizes; the end-to-end channel keeps the bytes ({ENV}=no turns it off)"
    )
}

/// A router of this end, linked to `peer` through `HTTPS_PROXY` for its life.
#[cfg(feature = "yggdrasil")]
pub(crate) fn router(
    secret: podssh_relay::ygg::SigningKey,
    peer: &str,
    say: podssh_relay::ygg::router::Say,
) -> Result<std::sync::Arc<podssh_relay::ygg::router::Router>, String> {
    use podssh_relay::ygg::{link, router::Router};
    let peer = link::Peer::parse(peer)?;
    let router = Router::new(secret);
    let dial = link::dial(podssh_ws::Trust::Default, podssh_ws::ProxyChoice::FromEnvironment);
    tokio::spawn(router.clone().peer(peer, dial, say));
    Ok(router)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variables_turn_the_road_off_or_name_a_peer() {
        let listed = vec!["wss://ygg.example.net/".to_string()];
        assert_eq!(setting_of(None, None, listed.clone()), Ok(Setting::On(listed.clone(), true)));
        assert_eq!(setting_of(None, None, Vec::new()), Ok(Setting::Off("pod-services")));
        assert_eq!(setting_of(Some("no"), None, listed.clone()), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), listed.clone()), Ok(Setting::Off(LAST_RESORT)));
        assert_eq!(setting_of(None, Some("maybe"), listed.clone()), Ok(Setting::Off(LAST_RESORT)));
        let own = setting_of(Some("ws://127.0.0.1:9001"), Some("no"), Vec::new()).unwrap();
        assert_eq!(own, Setting::On(vec!["ws://127.0.0.1:9001".into()], false), "one's own peer is no third party's");
        for refused in ["tcp://1.2.3.4:1", "wss://", "wss://:443", "https://x", "wss://a b"] {
            assert!(setting_of(Some(refused), None, Vec::new()).unwrap_err().contains(ENV), "{refused}");
        }
    }

    #[test]
    fn both_ends_pick_the_same_peer_of_a_name() {
        let peers: Vec<String> = (1..=5).map(|i| format!("wss://p{i}.example.net/")).collect();
        assert_eq!(pick("lab", &peers), pick("lab", &peers));
        assert!(pick("lab", &[]).is_none());
        assert!(third_party_line(&peers[0]).contains("PODSSH_YGGDRASIL=no"));
    }
}
