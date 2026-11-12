//! Syncthing's relays as a road of a pair (T-571), a last fallback of the
//! operator's ruling Q78 after HyperDHT's road: a relay of Syncthing's pool
//! that listens on 443, by its IP literal, one TLS connection through
//! `HTTPS_PROXY` for the node's join or the client's request, and one plain
//! TCP connection for each session. The relays come from the service
//! `syncthing-relay` of `pod-services` (asked of podcrates as a COORD issue),
//! each a `relay://IP:443/?id=DEVICE-ID` of the pool's list, picked by the
//! SHA-256 of the pair's name, so that both ends take the same one;
//! `PODSSH_SYNCTHING_RELAY=relay://IP:PORT/?id=DEVICE-ID` names a relay of
//! the user's own (`strelaysrv`), which `PODSSH_LAST_RESORT` leaves on;
//! `PODSSH_SYNCTHING_RELAY=no`, or `PODSSH_LAST_RESORT=no` for the pool's,
//! turns the road off. A build without the feature `strelay` has no road.

use std::net::{IpAddr, SocketAddr};

use crate::relay_settings::Refusal;

/// `no` turns the road off; a `relay://` URL names a relay of one's own.
pub const ENV: &str = "PODSSH_SYNCTHING_RELAY";
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The id of the relays in `pod-services`.
pub const SERVICE_ID: &str = "syncthing-relay";

/// A relay: its address and its device ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relay {
    pub at: SocketAddr,
    pub id: [u8; 32],
}

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    Off(&'static str),
    /// The relays to pick from; whether they are `pod-services`' own.
    On(Vec<Relay>, bool),
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Syncthing's check character of a group of base32, its Luhn mod 32.
fn luhn32(group: &[u8]) -> Option<u8> {
    let (mut factor, mut sum) = (1usize, 0usize);
    for c in group {
        let point = BASE32.iter().position(|b| b == c)?;
        let addend = factor * point;
        factor = if factor == 2 { 1 } else { 2 };
        sum += addend / 32 + addend % 32;
    }
    Some(BASE32[(32 - sum % 32) % 32])
}

/// A device ID as Syncthing writes it: 56 characters of base32 in groups,
/// a check character after each 13; dashes and spaces between are left out.
pub fn device_id(text: &str) -> Option<[u8; 32]> {
    let chars: Vec<u8> = text.bytes().filter(|c| *c != b'-' && *c != b' ').map(|c| c.to_ascii_uppercase()).collect();
    if chars.len() != 56 {
        return None;
    }
    let mut data = Vec::with_capacity(52);
    for group in chars.chunks(14) {
        let (body, check) = group.split_at(13);
        if luhn32(body)? != check[0] {
            return None;
        }
        data.extend_from_slice(body);
    }
    // 52 characters of base32 are 260 bits: the 32 bytes and 4 bits of zero.
    let mut out = Vec::with_capacity(33);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in data {
        acc = (acc << 5) | BASE32.iter().position(|b| *b == c)? as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out.truncate(32);
    out.try_into().ok()
}

/// `relay://IP:PORT/?id=DEVICE-ID[&...]`, as the pool lists a relay.
pub fn relay_url(text: &str) -> Option<Relay> {
    let rest = text.trim().strip_prefix("relay://")?;
    let (authority, query) = rest.split_once('?')?;
    let at: SocketAddr = authority.trim_end_matches('/').parse().ok()?;
    let id = query.split('&').find_map(|pair| pair.strip_prefix("id="))?;
    Some(Relay { at, id: device_id(id)? })
}

fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]),
/// with `listed`, the relays of `pod-services`. A relay that the user names
/// is no third party's: [`LAST_RESORT`] leaves it on.
pub fn setting_of(value: Option<&str>, last: Option<&str>, listed: Vec<Relay>) -> Result<Setting, String> {
    let said = says_no(value);
    if said.is_none() {
        let refused = || format!("{ENV} is no, or a relay's relay://IP:PORT/?id=DEVICE-ID");
        return Ok(Setting::On(vec![relay_url(value.unwrap_or_default()).ok_or_else(refused)?], false));
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

/// The relays of `pod-services` on 443, in its order (of the device IDs, so
/// that a hash over it picks the same relay at both ends): each endpoint an
/// IP literal, its device ID the fact `device-id-NAME`.
fn listed() -> Vec<Relay> {
    let Some(service) = pod_services::get(SERVICE_ID) else { return Vec::new() };
    service
        .endpoints()
        .iter()
        .filter_map(|endpoint| {
            let at = SocketAddr::new(endpoint.host().parse().ok()?, endpoint.port());
            let id = service.text(&format!("device-id-{}", endpoint.name()))?;
            Some(Relay { at, id: device_id(id)? })
        })
        .filter(|r| r.at.port() == 443)
        .collect()
}

/// The variables, read.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    setting_of(value.as_deref(), last.as_deref(), listed()).map_err(Refusal::config)
}

/// The relay of the pair `name`, when the road is on in this build; whether
/// it is the pool's.
pub(crate) fn relay_for(name: &str) -> Option<(Relay, bool)> {
    use sha2::{Digest, Sha256};
    match setting() {
        Ok(Setting::On(relays, public)) if cfg!(feature = "strelay") && !relays.is_empty() => {
            let digest = Sha256::digest(name.as_bytes());
            let n = u64::from_be_bytes(digest[..8].try_into().unwrap_or_default());
            Some((relays[(n % relays.len() as u64) as usize], public))
        }
        _ => None,
    }
}

/// The line of Q78, before the first byte goes to the relay.
pub fn third_party_line(relay: SocketAddr) -> String {
    format!(
        "a public relay of Syncthing's pool, {relay}, carries this session, a last fallback of Q78: it sees the two \
         ends' certificates, the times and the sizes; the end-to-end channel keeps the bytes ({ENV}=no turns it off)"
    )
}

/// TCP to a relay through `HTTPS_PROXY`, as the library dials it.
#[cfg(feature = "strelay")]
pub(crate) fn dial() -> podssh_relay::strelay::pair::Dial {
    use std::sync::Arc;
    Arc::new(|ip: IpAddr, port: u16| {
        Box::pin(async move {
            let proxy = podssh_ws::ProxyChoice::FromEnvironment;
            let tcp = podssh_ws::dial::dial(&ip.to_string(), port, &proxy, podssh_relay::open::CONNECT_TIMEOUT)
                .await
                .map_err(|e| std::io::Error::other(format!("Syncthing's relay {ip}:{port}: {e}")))?;
            Ok(Box::new(tcp) as podssh_relay::strelay::pair::BoxIo)
        })
    })
}

/// The library's relay of `relay`.
#[cfg(feature = "strelay")]
pub(crate) fn library(relay: Relay) -> podssh_relay::strelay::pair::Relay {
    podssh_relay::strelay::pair::Relay { ip: relay.at.ip(), port: relay.at.port(), id: relay.id }
}

#[cfg(not(feature = "strelay"))]
#[allow(dead_code)]
fn unused(_: IpAddr) {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each relay of the catalog reads, with its device ID: a row left out
    /// would move the relay that a hash picks.
    #[test]
    fn the_listed_relays_read_with_their_device_ids() {
        let relays = listed();
        assert_eq!(relays.len(), pod_services::get(SERVICE_ID).map_or(0, |s| s.endpoints().len()), "a relay left out");
        assert!(relays.len() >= 5, "{relays:?}");
        assert!(relays.iter().all(|r| r.at.port() == 443 && r.id != [0; 32]));
    }

    /// The node's device ID of the pair ("lab", "token-1"), as strelaysrv
    /// v2.1.7 wrote it in its log; the SHA-256 of that certificate.
    const ID: &str = "ZE4BVOL-HVOZVI2-DO7LY4L-PIAIE37-W652ERN-OOAPMTD-L4RJ3ZY-B4JOAAV";

    #[test]
    fn a_device_id_reads_as_syncthing_writes_it_and_a_bad_check_is_refused() {
        let id = device_id(ID).expect("Syncthing's own ID");
        assert_eq!(id[..4], [0xc9, 0x38, 0x1a, 0xb9], "the first bytes of its base32");
        #[cfg(feature = "strelay")]
        assert_eq!(id, podssh_relay::strelay::pair::node_identity("lab", "token-1").id(), "the pair's certificate");
        assert!(device_id(&ID.replace("ZE4BVOL", "ZE4BVOM")).is_none(), "a changed character fails its check");
        assert!(device_id("ZE4BVOL").is_none());
        let relay = relay_url(&format!("relay://192.0.2.7:443/?id={ID}&pingInterval=1m0s")).unwrap();
        assert_eq!((relay.at.port(), relay.id), (443, id));
    }

    #[test]
    fn the_variables_turn_the_road_off_or_name_a_relay() {
        let listed = vec![relay_url(&format!("relay://192.0.2.7:443/?id={ID}")).unwrap()];
        assert_eq!(setting_of(None, None, listed.clone()), Ok(Setting::On(listed.clone(), true)));
        assert_eq!(setting_of(None, None, Vec::new()), Ok(Setting::Off("pod-services")));
        assert_eq!(setting_of(Some("no"), None, listed.clone()), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no"), listed.clone()), Ok(Setting::Off(LAST_RESORT)));
        let own = setting_of(Some(&format!("relay://127.0.0.1:22067/?id={ID}")), Some("no"), Vec::new()).unwrap();
        assert!(matches!(own, Setting::On(_, false)), "{own:?}");
        for refused in ["relay://127.0.0.1:22067/", "relay://host:443/?id=X", "https://x"] {
            assert!(setting_of(Some(refused), None, Vec::new()).unwrap_err().contains(ENV), "{refused}");
        }
        assert!(third_party_line(listed[0].at).contains("PODSSH_SYNCTHING_RELAY=no"));
    }
}
