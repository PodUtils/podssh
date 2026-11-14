//! Tox's TCP relays as a road of a pair (T-734), a last fallback of the
//! operator's ruling Q78: both ends meet on one relay of the Tox project's
//! public nodes, by one TCP connection through `HTTPS_PROXY` each, the node
//! under a key that the pair's connect token makes. The relays come from
//! the service `tox-tcp-relay` of `pod-services` (asked of podcrates as
//! COORD-028), picked by the SHA-256 of the pair's name so that both ends
//! take the same one; `PODSSH_TOX=IP:PORT=KEY` names a relay of the user's
//! own (`tox-bootstrapd` with its TCP relay), which `PODSSH_LAST_RESORT`
//! leaves on; `PODSSH_TOX=no`, or `PODSSH_LAST_RESORT=no` for the listed
//! relays, turns the road off. A build without the feature
//! `tox` has no road, and says nothing of it.

use std::net::SocketAddr;

use crate::relay_settings::Refusal;

/// `no` turns the road off; `IP:PORT=KEY` names a relay of one's own.
pub const ENV: &str = "PODSSH_TOX";
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The id of the relays in `pod-services`.
pub const SERVICE_ID: &str = "tox-tcp-relay";
/// A relay's key: 32 bytes, 64 hex digits.
const KEY: usize = 32;

/// A relay: its address and the key that its handshake boxes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relay {
    pub at: SocketAddr,
    pub key: [u8; KEY],
}

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable or list that says so.
    Off(&'static str),
    /// The relays to pick from; whether they are `pod-services`' own.
    On(Vec<Relay>, bool),
}

fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// A key of 64 hex digits.
fn key_of(text: &str) -> Option<[u8; KEY]> {
    let text = text.trim();
    if text.len() != 2 * KEY {
        return None;
    }
    let bytes: Option<Vec<u8>> = (0..KEY).map(|i| u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()).collect();
    bytes?.try_into().ok()
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// with `listed`, the relays of `pod-services`. A relay that the user names
/// is no third party's: [`LAST_RESORT`] leaves it on.
pub fn setting_of(value: Option<&str>, last: Option<&str>, listed: Vec<Relay>) -> Result<Setting, String> {
    let said = says_no(value);
    if said.is_none() {
        let text = value.unwrap_or_default().trim();
        let refused = || format!("{ENV} is no, or a relay's IP:PORT=KEY (its key in 64 hex digits)");
        let (at, key) = text.split_once('=').ok_or_else(refused)?;
        let at = at.trim().parse::<SocketAddr>().map_err(|_| refused())?;
        let key = key_of(key).ok_or_else(refused)?;
        return Ok(Setting::On(vec![Relay { at, key }], false));
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

/// The relays of `pod-services`: none until its service lists them. Each
/// endpoint's key is its fact `public-key-NAME`.
fn listed() -> Vec<Relay> {
    let Some(service) = pod_services::get(SERVICE_ID) else { return Vec::new() };
    service
        .endpoints()
        .iter()
        .filter_map(|endpoint| {
            let at = SocketAddr::new(endpoint.host().parse().ok()?, endpoint.port());
            let key = service.text(&format!("public-key-{}", endpoint.name()))?;
            Some(Relay { at, key: key_of(key)? })
        })
        .collect()
}

/// The variables, read.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    setting_of(value.as_deref(), last.as_deref(), listed()).map_err(Refusal::config)
}

/// Whether the road is on in this build.
pub(crate) fn on() -> bool {
    cfg!(feature = "tox") && matches!(setting(), Ok(Setting::On(..)))
}

/// The relay of the pair `name`, when the road is on in this build; whether
/// it is `pod-services`' own.
pub(crate) fn relay_for(name: &str) -> Option<(Relay, bool)> {
    match setting() {
        Ok(Setting::On(relays, public)) if cfg!(feature = "tox") => {
            let picked = pick(name, &relays)?;
            Some((*picked, public))
        }
        _ => None,
    }
}

/// The relay among `relays` for the pair `name`, by the SHA-256 of the name.
fn pick<'a>(name: &str, relays: &'a [Relay]) -> Option<&'a Relay> {
    use sha2::{Digest, Sha256};
    if relays.is_empty() {
        return None;
    }
    let digest = Sha256::digest(name.as_bytes());
    let n = u64::from_be_bytes(digest[..8].try_into().unwrap_or_default());
    relays.get((n % relays.len() as u64) as usize)
}

/// The line of Q78, before the first byte goes to the relay.
pub fn third_party_line(relay: SocketAddr) -> String {
    format!(
        "the Tox project's public TCP relay {relay} carries this session, a last fallback of Q78: it sees the two \
         ends' keys of the relay, the times and the sizes; the end-to-end channel keeps the bytes ({ENV}=no turns it off)"
    )
}

/// The road's dial: one TCP connection to `relay` through `HTTPS_PROXY`.
#[cfg(feature = "tox")]
pub(crate) fn dial(relay: SocketAddr) -> podssh_relay::tox::pair::Dial {
    use std::sync::Arc;
    Arc::new(move || {
        Box::pin(async move {
            let proxy = podssh_ws::ProxyChoice::FromEnvironment;
            let limit = podssh_relay::open::CONNECT_TIMEOUT;
            let tcp = podssh_ws::dial::dial(&relay.ip().to_string(), relay.port(), &proxy, limit)
                .await
                .map_err(|e| std::io::Error::other(format!("the Tox relay {relay}: {e}")))?;
            Ok(Box::new(tcp) as Box<dyn podssh_relay::tox::pair::Io>)
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "A39D85725A1268F9DC0ABEBCCD196B1E31384900E4F933F780CDF0FE91212617";

    #[test]
    fn the_variables_turn_the_road_off_or_name_a_relay() {
        let listed = vec![Relay { at: "198.51.100.1:443".parse().unwrap(), key: [1; KEY] }];
        assert_eq!(setting_of(None, None, listed.clone()), Ok(Setting::On(listed.clone(), true)));
        assert_eq!(setting_of(None, None, Vec::new()), Ok(Setting::Off("pod-services")));
        assert_eq!(setting_of(Some("no"), None, listed.clone()), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), listed.clone()), Ok(Setting::Off(LAST_RESORT)));
        assert_eq!(setting_of(None, Some("maybe"), listed.clone()), Ok(Setting::Off(LAST_RESORT)));
        let own = setting_of(Some(&format!("127.0.0.1:33446={KEY_HEX}")), None, Vec::new()).unwrap();
        let Setting::On(relays, false) = own else { panic!("{own:?}") };
        assert_eq!((relays[0].at.port(), relays[0].key[0]), (33446, 0xA3));
        // One's own relay is no third party's: the last fallbacks' switch leaves it on.
        let own = setting_of(Some(&format!("127.0.0.1:33446={KEY_HEX}")), Some("no"), Vec::new()).unwrap();
        assert!(matches!(own, Setting::On(_, false)), "{own:?}");
        for refused in ["127.0.0.1:33446", "127.0.0.1:33446=00", "host:1=", "x=y"] {
            assert!(setting_of(Some(refused), None, Vec::new()).unwrap_err().contains(ENV), "{refused}");
        }
    }

    /// `pod-services` of podcrates v0.28.0 lists five relays on 443, each with
    /// its node's key: none is left out as a row that does not read.
    #[test]
    fn the_listed_relays_read_with_their_keys() {
        let relays = listed();
        assert_eq!(relays.len(), pod_services::get(SERVICE_ID).map_or(0, |s| s.endpoints().len()), "a relay left out");
        assert!(relays.len() >= 4, "{relays:?}");
        assert!(relays.iter().all(|r| r.at.port() == 443 && r.key != [0; KEY]));
    }

    #[test]
    fn both_ends_pick_the_same_relay_of_a_name() {
        let relays: Vec<Relay> =
            (1..=5).map(|i| Relay { at: format!("198.51.100.{i}:443").parse().unwrap(), key: [i; KEY] }).collect();
        assert_eq!(pick("lab", &relays), pick("lab", &relays));
        assert!(pick("lab", &[]).is_none());
        assert!(third_party_line(relays[0].at).contains("PODSSH_TOX=no"));
    }
}
