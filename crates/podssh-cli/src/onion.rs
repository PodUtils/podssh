//! The onion road of a pair (T-578, the operator's ruling Q78): a node that
//! waits beside the pair's road as an onion service in the Tor network,
//! Arti's in this process through the Tor road (`podssh_tor`), and a client
//! that reaches it by its onion address, when each other road failed. Both
//! ends make a key of restricted discovery of the pair's name and connect
//! token, so the service's descriptor is readable only by the pair's
//! operators; the end-to-end channel above the stream checks the node's key
//! all the same. The address is the node's: its line says it, a node of this
//! host keeps it in the cache under its label, and `PODSSH_ONION=ADDRESS`
//! names it to a client elsewhere. `PODSSH_ONION=no`, or
//! `PODSSH_LAST_RESORT=no`, turns the road off. A build without the feature
//! `tor` has no road, and says nothing of it.

use crate::relay_settings::Refusal;

/// `no` turns the road off; an onion address names the node's.
pub const ENV: &str = "PODSSH_ONION";
/// The switch of each last fallback (Q78).
pub const LAST_RESORT: &str = "PODSSH_LAST_RESORT";
/// The service's virtual port, which the node's road answers: a client of
/// the pair asks no other.
pub const VIRTUAL_PORT: u16 = 22;
/// The service's name in the node's keystore and state.
pub const NICKNAME: &str = "podssh";
/// The length of a v3 onion address's name: 35 bytes in base32.
const NAME_LEN: usize = 56;

/// What the variables ask for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Setting {
    /// No road, and the variable that says so.
    Off(&'static str),
    /// The road, and the node's address when the variable names one.
    On(Option<String>),
}

fn says_no(value: Option<&str>) -> Option<bool> {
    match value.map(str::trim).unwrap_or_default().to_ascii_lowercase().as_str() {
        "" | "yes" | "on" | "true" | "1" => Some(false),
        "no" | "off" | "false" | "0" => Some(true),
        _ => None,
    }
}

/// An onion address of a v3 service in lower case, `NAME.onion` with 56
/// letters of base32 in NAME; its checksum is Arti's to check, at the link.
pub fn address_of(text: &str) -> Option<String> {
    let text = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let name = text.strip_suffix(".onion")?;
    let base32 = name.len() == NAME_LEN && name.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
    base32.then_some(text)
}

/// The setting of `value` (of [`ENV`]) and `last` (of [`LAST_RESORT`]). An
/// address that the user names is a road asked for: [`LAST_RESORT`] leaves
/// it on.
pub fn setting_of(value: Option<&str>, last: Option<&str>) -> Result<Setting, String> {
    match says_no(value) {
        Some(true) => return Ok(Setting::Off(ENV)),
        Some(false) => {}
        None => {
            // Not echoed: an address in a log is the node's to give.
            let given = address_of(value.unwrap_or_default());
            return given
                .map(|a| Setting::On(Some(a)))
                .ok_or_else(|| format!("{ENV} is no, or a node's onion address, 56 letters of base32 and .onion"));
        }
    }
    if says_no(last).unwrap_or(true) {
        return Ok(Setting::Off(LAST_RESORT));
    }
    Ok(Setting::On(None))
}

/// The variables, read.
pub(crate) fn setting() -> Result<Setting, Refusal> {
    let (value, last) = (std::env::var(ENV).ok(), std::env::var(LAST_RESORT).ok());
    setting_of(value.as_deref(), last.as_deref()).map_err(Refusal::config)
}

/// Whether the road is on in this build.
pub(crate) fn on() -> bool {
    matches!(setting(), Ok(Setting::On(_))) && cfg!(feature = "tor")
}

/// The secret of the pair's key of restricted discovery: both ends make it
/// of the pair's name and connect token, so no word passes between them; a
/// later pair makes another.
pub fn discovery_secret(name: &str, token: &str) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hash = sha2::Sha256::new();
    hash.update(b"podssh onion discovery v1\0");
    hash.update(name.as_bytes());
    hash.update([0]);
    hash.update(token.as_bytes());
    hash.finalize().into()
}

/// The file of the cache that keeps the onion address of the node `label`.
pub(crate) fn kept_file(label: &str) -> String {
    format!("onion-{}.name", podssh_relay::cache::safe_name(label))
}

/// The address kept under `label`, when one is and it reads as one.
pub(crate) fn kept(label: &str) -> Option<String> {
    address_of(&podssh_relay::cache::load_file(&kept_file(label))?)
}

/// Keep `address` under `label`, for a later run of this host; a cache that
/// cannot be written costs only that.
pub(crate) fn keep(label: &str, address: &str) {
    let _ = podssh_relay::cache::store_file(&kept_file(label), address.as_bytes());
}

/// The line of Q78, before the first circuit of the road: the Tor network's
/// volunteers carry the session, or the network of `network` (the file of
/// `PODSSH_TOR_NETWORK`) when it is not Tor's own.
pub fn third_party_line(network: Option<&str>) -> String {
    let which = network.map_or_else(
        || "the Tor network's volunteer relays carry this session".to_string(),
        |file| format!("the Tor network of {file} carries this session"),
    );
    format!(
        "{which} through an onion service, the last fallback of Q78: no relay sees both ends, and the end-to-end \
         channel keeps the bytes ({ENV}=no turns it off)"
    )
}

/// The network of `PODSSH_TOR_NETWORK`, as the line names it.
pub(crate) fn network_named() -> Option<String> {
    let file = std::env::var_os(crate::ssh::cloud::tor::NETWORK_ENV).filter(|v| !v.is_empty())?;
    Some(std::path::PathBuf::from(file).display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: &str = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion";

    #[test]
    fn the_variables_turn_the_road_off_or_name_the_node_s_address() {
        assert_eq!(setting_of(None, None), Ok(Setting::On(None)));
        assert_eq!(setting_of(Some("yes"), None), Ok(Setting::On(None)));
        assert_eq!(setting_of(Some("no"), None), Ok(Setting::Off(ENV)));
        assert_eq!(setting_of(None, Some("no")), Ok(Setting::Off(LAST_RESORT)));
        let upper = ADDRESS.to_ascii_uppercase();
        assert_eq!(setting_of(Some(&upper), Some("no")), Ok(Setting::On(Some(ADDRESS.into()))));
        for refused in ["maybe", "example.onion", "www.torproject.org", &ADDRESS.replace(".onion", ".onion.x")] {
            let why = setting_of(Some(refused), None).unwrap_err();
            assert!(why.contains(ENV) && !why.contains(refused), "{refused}: {why}");
        }
    }

    #[test]
    fn both_ends_make_one_key_of_discovery_of_the_pair_and_another_pair_another() {
        let one = discovery_secret("lab", "token-one");
        assert_eq!(one, discovery_secret("lab", "token-one"));
        assert_ne!(one, discovery_secret("lab", "token-two"));
        assert_ne!(one, discovery_secret("lab2", "token-one"));
        // The name and the token do not run together.
        assert_ne!(discovery_secret("ab", "c"), discovery_secret("a", "bc"));
    }

    #[test]
    fn the_line_names_the_tor_network_and_the_switch() {
        let line = third_party_line(None);
        assert!(line.contains("Tor network") && line.contains("Q78") && line.contains("PODSSH_ONION=no"), "{line}");
        assert!(third_party_line(Some("/n/arti.toml")).contains("Tor network of /n/arti.toml"));
        assert!(kept_file("lab").starts_with("onion-") && kept_file("lab").ends_with(".name"));
    }
}
