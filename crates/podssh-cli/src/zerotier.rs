//! ZeroTier's road of a pair (T-733), a last fallback of the operator's
//! ruling Q78: both ends join an ad-hoc network of the pair's own through
//! ZeroTier Inc.'s roots and its TCP relay, the service `zerotier-tcp-relay`
//! of `pod-services`, reached by one TCP connection through `HTTPS_PROXY`.
//! `PODSSH_ZEROTIER=no` or `PODSSH_LAST_RESORT=no` turns it off, and
//! `IP:PORT` names a relay of the user's own (ZeroTierOne's `tcp-proxy`).
//! A build without the feature `zerotier` has no road, and says nothing of
//! it: a fallback that is not there is not refused.

use std::net::SocketAddr;

use crate::relay_settings::Refusal;

/// `no` turns the road off; `IP:PORT` names another relay.
pub const ENV: &str = "PODSSH_ZEROTIER";
/// A planet of the user's own roots (the file `planet` of zerotier-one's
/// home, or a world that `mkworld` made), in the place of the core's own,
/// ZeroTier Inc.'s.
pub const PLANET_ENV: &str = "PODSSH_ZEROTIER_PLANET";
/// The largest planet that is read (`ZT_WORLD_MAX_SERIALIZED_LENGTH` is
/// under 16 KiB).
const MOST_PLANET: u64 = 16 * 1024;
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The id of the relay in `pod-services`.
pub const SERVICE_ID: &str = "zerotier-tcp-relay";

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable or list that says so.
    Off(&'static str),
    /// The road, through this relay; whether it is `pod-services`' own.
    On(SocketAddr, bool),
}

/// Whether a switch says no: unset, empty or yes is on.
fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// with `listed`, the relay of `pod-services`.
pub fn setting_of(value: Option<&str>, last: Option<&str>, listed: Option<SocketAddr>) -> Result<Setting, String> {
    // Another word of the switch is no, as for each last fallback.
    if says_no(last).unwrap_or(true) {
        return Ok(Setting::Off(LAST_RESORT));
    }
    match says_no(value) {
        Some(true) => Ok(Setting::Off(ENV)),
        Some(false) => Ok(listed.map_or(Setting::Off("pod-services"), |at| Setting::On(at, true))),
        None => {
            let text = value.unwrap_or_default().trim();
            let at = text.parse::<SocketAddr>().map_err(|_| format!("{ENV} is no, or a relay's IP:PORT"))?;
            Ok(Setting::On(at, false))
        }
    }
}

/// The relay of `pod-services`, an IP literal and its port.
fn listed() -> Option<SocketAddr> {
    let endpoint = pod_services::get(SERVICE_ID)?.endpoint("tcp")?;
    Some(SocketAddr::new(endpoint.host().parse().ok()?, endpoint.port()))
}

/// The variables, read; a planet that cannot be read is refused here, before
/// anything connects.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    let setting = setting_of(value.as_deref(), last.as_deref(), listed()).map_err(Refusal::config)?;
    if matches!(setting, Setting::On(..)) {
        planet().map_err(Refusal::config)?;
    }
    Ok(setting)
}

/// The relay of the road, when the road is on in this build.
pub(crate) fn relay() -> Option<(SocketAddr, bool)> {
    match setting() {
        Ok(Setting::On(at, public)) if cfg!(all(feature = "zerotier", unix)) => Some((at, public)),
        _ => None,
    }
}

/// The line of Q78, before the first byte goes to ZeroTier Inc.
pub fn third_party_line(relay: SocketAddr) -> String {
    format!(
        "ZeroTier Inc.'s roots and its TCP relay {relay} carry this session, a last fallback of Q78: they see the \
         two ZeroTier addresses, the times and the sizes; the end-to-end channel keeps the bytes ({ENV}=no turns it off)"
    )
}

/// The file of the cache that keeps this client's ZeroTier identity: a
/// private key, in a private file as the pins are, never printed.
#[cfg(all(feature = "zerotier", unix))]
const CLIENT_IDENTITY: &str = "zerotier-client.secret";

/// The client's identity kept by an earlier run, when one reads as one.
#[cfg(all(feature = "zerotier", unix))]
pub(crate) fn client_identity() -> Option<Vec<u8>> {
    let text = podssh_relay::cache::load_file(CLIENT_IDENTITY)?;
    let text = text.trim();
    // The core's text form: the address, `0`, the public and the secret keys.
    (text.split(':').count() == 4 && text.len() < 1024).then(|| text.as_bytes().to_vec())
}

/// Keep `identity` for later runs.
#[cfg(all(feature = "zerotier", unix))]
pub(crate) fn keep_client_identity(identity: &[u8]) -> Result<std::path::PathBuf, String> {
    podssh_relay::cache::store_file(CLIENT_IDENTITY, identity)
}

/// The road's dial: one TCP connection to `relay` through `HTTPS_PROXY`,
/// and the relay's framing on it.
#[cfg(all(feature = "zerotier", unix))]
pub(crate) fn dial(relay: SocketAddr) -> podssh_zerotier::road::Dial {
    use std::sync::Arc;
    Arc::new(move || {
        Box::pin(async move {
            let proxy = podssh_ws::ProxyChoice::FromEnvironment;
            let limit = podssh_relay::open::CONNECT_TIMEOUT;
            let tcp = podssh_ws::dial::dial(&relay.ip().to_string(), relay.port(), &proxy, limit)
                .await
                .map_err(|e| format!("ZeroTier's relay {relay}: {e}"))?;
            Ok(podssh_zerotier::road::relay_wire(tcp))
        })
    })
}

/// The planet of [`PLANET_ENV`], when it names one.
pub(crate) fn planet() -> Result<Option<Vec<u8>>, String> {
    let Some(path) = std::env::var_os(PLANET_ENV).filter(|p| !p.is_empty()) else { return Ok(None) };
    let shown = std::path::Path::new(&path).display().to_string();
    let file = std::fs::File::open(&path).map_err(|e| format!("{PLANET_ENV} {shown}: {e}"))?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut std::io::Read::take(file, MOST_PLANET + 1), &mut bytes)
        .map_err(|e| format!("{PLANET_ENV} {shown}: {e}"))?;
    if bytes.is_empty() || bytes.len() as u64 > MOST_PLANET {
        return Err(format!("{PLANET_ENV} {shown}: not a planet of 1 byte to 16 KiB"));
    }
    Ok(Some(bytes))
}

/// The road of the pair `name` with the token `token`, made off the
/// runtime's threads: the node's identity takes a memory-hard hash. Its
/// planet is that of [`PLANET_ENV`], else the core's own.
#[cfg(all(feature = "zerotier", unix))]
pub(crate) async fn pair_road(name: &str, token: &str) -> Result<podssh_zerotier::pair::PairRoad, String> {
    let planet = planet()?;
    let (name, token) = (name.to_string(), token.to_string());
    let made = tokio::task::spawn_blocking(move || podssh_zerotier::pair::PairRoad::of(&name, &token))
        .await
        .map_err(|e| format!("ZeroTier's road: {e}"))?;
    let mut made = made?;
    made.planet = planet;
    Ok(made)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_variables_turn_the_road_off_or_name_a_relay() {
        let listed: SocketAddr = "198.51.100.1:443".parse().unwrap();
        assert_eq!(setting_of(None, None, Some(listed)), Ok(Setting::On(listed, true)));
        assert_eq!(setting_of(None, None, None), Ok(Setting::Off("pod-services")));
        assert_eq!(setting_of(Some("no"), None, Some(listed)), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), Some(listed)), Ok(Setting::Off(LAST_RESORT)));
        let own: SocketAddr = "203.0.113.9:8443".parse().unwrap();
        assert_eq!(setting_of(Some("203.0.113.9:8443"), None, Some(listed)), Ok(Setting::On(own, false)));
        assert!(setting_of(Some("relay.example:443"), None, None).unwrap_err().contains("IP:PORT"));
        assert_eq!(setting_of(None, Some("maybe"), Some(listed)), Ok(Setting::Off(LAST_RESORT)));
    }

    #[test]
    fn the_third_party_line_names_who_sees_what() {
        let line = third_party_line("198.51.100.1:443".parse().unwrap());
        assert!(line.contains("ZeroTier Inc.") && line.contains("Q78") && line.contains("end-to-end"));
    }
}
